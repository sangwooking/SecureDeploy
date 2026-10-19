"""Synthetic sources only; PyJWT/Django are never installed, imported or executed."""
import json
import unittest
from worker import Analyzer


def run(body, helper="", extra=()):
    code = "import jwt\nimport os\nfrom rest_framework.decorators import api_view\nfrom rest_framework.exceptions import PermissionDenied\n" + helper
    code += "\n@api_view(['GET'])\ndef endpoint(request):\n" + "\n".join("    " + s for s in body.splitlines())
    return Analyzer([dict(filePath="api.py", content=code), *extra]).run()


DECODE = "claims=jwt.decode(request.headers['Authorization'], options={'verify_signature':False})\n"
GUARD = "if claims['role'] != 'admin':\n raise PermissionDenied()\nreturn 'allowed'"


def findings(result):
    return [f for f in result['findings'] if f['ruleId'].startswith('PY_JWT_')]


class TokenTests(unittest.TestCase):
    def test_disabled_signature_requires_access_decision(self):
        self.assertEqual(len(findings(run(DECODE + GUARD))), 1)
        result = run(DECODE + "return claims['role']")
        self.assertFalse(findings(result))
        self.assertEqual(result['tokenUses'][0]['usageStatus'], 'NO_SECURITY_DECISION_TRACED')

    def test_default_enabled_and_legacy_options_are_not_bypass(self):
        for kwargs in ("key=os.getenv('TEST_KEY'),algorithms=['HS256']", "options={'verify_signature':True},algorithms=['HS256']", "verify=False"):
            result=run("claims=jwt.decode(request.headers['Authorization'],"+kwargs+")\n"+GUARD)
            self.assertFalse(findings(result), kwargs)
            self.assertNotEqual(result['tokenUses'][0]['signatureStatus'],'EXPLICITLY_DISABLED')

    def test_fixed_key_requires_actual_hmac_signing_use_and_is_redacted(self):
        marker='synthetic-signing-material-not-a-real-key'
        result=run("return jwt.encode({'sub':'fixture'},'"+marker+"',algorithm='HS256')")
        self.assertEqual(len(findings(result)),1)
        self.assertNotIn(marker,json.dumps(result))
        for value in ("os.getenv('TEST_KEY')", "'example'", "external_key()"):
            self.assertFalse(findings(run("return jwt.encode({},"+value+",algorithm='HS256')")))
        self.assertFalse(findings(run("unused='"+marker+"'\nreturn 'ok'")))

    def test_unknown_transforms_and_dynamic_options_remain_unresolved(self):
        for body in ("claims=jwt.decode(request.body,options=external_options())\n"+GUARD,
                     DECODE+"claims=external_verify(claims)\n"+GUARD,
                     DECODE+"external_verify(claims)\n"+GUARD,
                     "opts={'verify_signature':False}\nexternal_configure(opts)\nclaims=jwt.decode(request.body,options=opts)\n"+GUARD,
                     "claims=external_decode(request.body)\n"+GUARD):
            self.assertFalse(findings(run(body)))

    def test_values_helpers_options_alias_and_overwrite(self):
        helper="def unpack(value):\n return jwt.decode(value,options={'verify_signature':False})\n"
        self.assertEqual(len(findings(run("claims=unpack(request.headers['Authorization'])\n"+GUARD, helper))),1)
        self.assertFalse(findings(run(DECODE+"claims={'role':'admin'}\n"+GUARD)))
        self.assertEqual(len(findings(run("opts={'verify_signature':False}\nclaims=jwt.decode(request.body,options=opts)\n"+GUARD))),1)
        self.assertEqual(len(findings(run("claims=jwt.decode(request.body,'', ['HS256'], {'verify_signature':False})\n"+GUARD))),1)
        self.assertFalse(findings(run("return jwt.encode({},'synthetic-not-a-real-key',headers={'alg':'none'})")))
        self.assertFalse(findings(run("claims=jwt.decode(request.body,'',[],{},options={'verify_signature':False})\n"+GUARD)))

    def test_non_security_condition_and_unresolved_rejection(self):
        for ending in ("if claims['role']:\n return 'display'\nreturn ''", "if claims['role'] != 'admin':\n external_deny()\nreturn 'ok'"):
            self.assertFalse(findings(run(DECODE+ending)))

    def test_local_jwt_module_and_rebound_import_not_treated_as_pyjwt(self):
        self.assertFalse(findings(run(DECODE+GUARD,extra=[dict(filePath='jwt.py',content='def decode(x): return x')])) )
        self.assertFalse(findings(run("jwt=external_library()\n"+DECODE+GUARD)))

    def test_hashes_random_and_json_are_not_password_or_token_findings(self):
        for expression in ("hashlib.sha256(request.body).hexdigest()", "hashlib.md5(request.body).hexdigest()", "random.random()", "secrets.token_urlsafe(32)", "json.loads(request.body)"):
            self.assertFalse(findings(run("return "+expression)))

    def test_source_without_request_and_uncertain_execution_are_not_confirmed(self):
        self.assertFalse(findings(run("claims=jwt.decode('fixture-only',options={'verify_signature':False})\n"+GUARD)))
        self.assertFalse(findings(run("for x in []:\n pass\n"+DECODE+GUARD)))
        result=Analyzer([dict(filePath='unused.py',content="import jwt\ndef unused(token):\n return jwt.decode(token,options={'verify_signature':False})")]).run()
        self.assertFalse(result['tokenUses'])
        self.assertIn('TOKEN_CALLS_OUTSIDE_TRACED_FLOW',result['files'][0]['limitations'])

    def test_limit_and_env_fallback_are_explicit(self):
        result=run("return jwt.encode({},os.getenv('TEST_KEY','example'),algorithm='HS256')")
        self.assertEqual(result['tokenUses'][0]['keySource'],'ENVIRONMENT_WITH_LITERAL_FALLBACK')
        self.assertFalse(findings(result))
        result=run('\n'.join("jwt.decode(request.body,options={'verify_signature':False})" for _ in range(205)))
        self.assertEqual(len(result['tokenUses']),200)
        self.assertIn('TOKEN_RESULT_LIMIT',result['files'][0]['limitations'])


if __name__=='__main__': unittest.main()
