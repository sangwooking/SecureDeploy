"""Bounded PyJWT-compatible call evidence. Never loads target modules or stores key values."""
import ast
from dataclasses import replace


class TokenEvidence:
    LIMIT = 200
    LIMITATIONS = ["PYJWT_2_API_SHAPE_LIBRARY_VERSION_NOT_VERIFIED", "EXTERNAL_TOKEN_VALIDATION_NOT_VERIFIED",
                   "STATIC_FLOW_NOT_EXPLOIT_PROOF"]

    def __init__(self, analyzer, value):
        self.a, self.V = analyzer, value
        self.uses = []

    def record(self, node, operation, signature, key, value):
        if len(self.uses) >= self.LIMIT:
            self.a.note("TOKEN_RESULT_LIMIT")
            return None
        entry = dict(operation=operation, location=self.a.loc(node, "TOKEN_API_CALL"),
                     signatureStatus=signature, keySource=key, usageStatus="NO_SECURITY_DECISION_TRACED",
                     trace=list(value.trace)[:40], limitations=list(self.LIMITATIONS))
        self.uses.append(entry)
        return len(self.uses) - 1

    def call(self, node, function, base, name, args, keywords):
        if function.symbol in {"os.getenv", "os.environ.get"} and not function.unknown:
            # Even an environment reference is not proof of entropy, rotation or runtime configuration.
            fallback = args[1] if len(args) > 1 else keywords.get("default")
            return self.V(tag="token-key-env-fallback" if fallback and isinstance(fallback.literal, (str, bytes)) else "token-key-env", unknown=True)
        if base and base.tag == "token-claims" and base.tokens and name == "get" and not base.unknown:
            return replace(base, literal=None, tag="token-claim")
        if function.symbol not in {"jwt.decode", "jwt.encode"} or function.unknown:
            return None
        if any(p == "jwt.py" or p.endswith("/jwt.py") or p.startswith("jwt/") or "/jwt/" in p for p in self.a.modules):
            self.a.note("TOKEN_LIBRARY_LOCAL_SHADOW")
            return self.V(unknown=True)
        parameters = ("payload", "key", "algorithm", "headers", "json_encoder", "sort_headers") if function.symbol == "jwt.encode" else ("jwt", "key", "algorithms", "options", "verify", "detached_payload", "audience", "issuer", "leeway")
        if len(args) > len(parameters) or any(p in keywords for p in parameters[:len(args)]):
            self.a.note("TOKEN_ARGUMENT_BINDING_UNRESOLVED")
            return self.V(unknown=True)
        key = args[1] if len(args) > 1 else keywords.get("key", self.V(unknown=True))
        if key.tag == "token-key-env":
            origin = "ENVIRONMENT_REFERENCE"
        elif key.tag == "token-key-env-fallback":
            origin = "ENVIRONMENT_WITH_LITERAL_FALLBACK"
        elif not key.unknown and isinstance(key.literal, (str, bytes)) and key.literal:
            text = key.literal.decode(errors="ignore") if isinstance(key.literal, bytes) else key.literal
            origin = "FIXED_EXAMPLE" if text.lower() in {"secret", "test", "dummy", "changeme", "your_secret_here", "example", "password"} else "FIXED_LITERAL"
        else:
            origin = "UNKNOWN"
        if function.symbol == "jwt.encode":
            algorithm = args[2] if len(args) > 2 else keywords.get("algorithm", self.V(literal="HS256"))
            signature = "HMAC_SIGN_CALL" if not algorithm.unknown and algorithm.literal in {"HS256", "HS384", "HS512"} else "SIGNING_OPTIONS_UNRESOLVED"
            if len(args) > 3 or "headers" in keywords:
                signature = "SIGNING_OPTIONS_UNRESOLVED"
            index = self.record(node, "SIGN", signature, origin, key)
            if index is not None and signature == "HMAC_SIGN_CALL" and origin == "FIXED_LITERAL" and not self.a.partial:
                self.candidate(index, node, "PY_JWT_FIXED_SIGNING_KEY", "CWE-321",
                               "로그인 토큰 서명에 코드의 고정 키를 사용하는지 검토해 주세요.",
                               "키를 외부 비밀 설정으로 분리하고 교체 절차를 확인하세요. 키 길이나 알고리즘 이름만으로 안전성을 보증하지 않습니다.")
            return self.V(unknown=True)
        token = args[0] if args else keywords.get("jwt", self.V(unknown=True))
        options = args[3] if len(args) > 3 else keywords.get("options")
        disabled = False
        known = options is None
        if options is not None and options.tag == "token-options" and options.elements is not None:
            known = not options.unknown
            pairs = options.elements
            for i in range(0, len(pairs), 2):
                if pairs[i].literal == "verify_signature":
                    disabled = pairs[i+1].literal is False
                    known &= pairs[i+1].literal is True or disabled
        # PyJWT 2.x ignores legacy verify=False; do not interpret it as signature bypass.
        signature = "EXPLICITLY_DISABLED" if known and disabled else "DEFAULT_OR_ENABLED_CALL" if known else "VERIFICATION_OPTIONS_UNRESOLVED"
        if "verify" in keywords or len(args) > 4:
            signature = "LEGACY_VERIFY_ARGUMENT_VERSION_DEPENDENT"
        index = self.record(node, "DECODE", signature, origin, token)
        return self.V(trace=token.trace, tokens=() if index is None else (index,), unknown=token.unknown or self.a.partial, tag="token-claims")

    def decision(self, value, node, env):
        denied = self.a.authorization.denial(node.body, env) or self.a.authorization.denial(node.orelse, env)
        for index in value.tokens:
            item = self.uses[index]
            if denied or item["usageStatus"] != "ACCESS_REJECTION_BRANCH":
                item["usageStatus"] = "ACCESS_REJECTION_BRANCH" if denied else "CONDITIONAL_USE_NOT_PROVEN_AUTHORIZATION"
            if (value.unknown or self.a.partial) and "TOKEN_VALUE_OR_EXECUTION_UNRESOLVED" not in item["limitations"]:
                item["limitations"].append("TOKEN_VALUE_OR_EXECUTION_UNRESOLVED")
            location = self.a.loc(node.test, "TOKEN_CLAIM_DECISION")
            if location not in item["trace"] and len(item["trace"]) < 40:
                item["trace"].append(location)
            if denied and item["signatureStatus"] == "EXPLICITLY_DISABLED" and not value.unknown and not self.a.partial and item["trace"]:
                self.candidate(index, node.test, "PY_JWT_UNVERIFIED_ACCESS_DECISION", "CWE-347",
                               "로그인 토큰을 신뢰하기 전에 서명을 확인하는지 검토해 주세요.",
                               "검증을 생략한 claim으로 접근을 결정하지 마세요. 고정된 허용 알고리즘과 검증 키로 서명·필수 claim을 확인하고 변조 토큰 거부 테스트를 추가하세요.")

    def uncertain_call(self, values, env):
        affected = {index for value in values for index in value.tokens}
        for name, value in list(env.items()):
            if affected.intersection(value.tokens):
                env[name] = replace(value, unknown=True)
        for index in affected:
            item = self.uses[index]
            if "TOKEN_TRANSFORM_OR_EXTERNAL_VALIDATION_UNKNOWN" not in item["limitations"]:
                item["limitations"].append("TOKEN_TRANSFORM_OR_EXTERNAL_VALIDATION_UNKNOWN")

    def candidate(self, index, node, rule, cwe, message, recommendation):
        item = self.uses[index]
        if len(self.a.findings) >= self.LIMIT:
            self.a.note("TOKEN_RESULT_LIMIT")
            return
        source = item["location"] if rule == "PY_JWT_FIXED_SIGNING_KEY" else item["trace"][0]
        if rule != "PY_JWT_FIXED_SIGNING_KEY" and not source["kind"] in {"REQUEST_HEADER", "QUERY_PARAMETER", "REQUEST_BODY", "ROUTE_PARAMETER"}:
            return
        finding = dict(ruleId=rule, kind=cwe, confidence="HIGH", disposition="REVIEW_REQUIRED", source=source,
                       sink=self.a.loc(node, "TOKEN_SECURITY_USE"), flow=[*item["trace"], item["location"]][:40], defenses=[],
                       limitations=list(self.LIMITATIONS), message=message, recommendation=recommendation)
        if finding not in self.a.findings:
            self.a.findings.append(finding)
