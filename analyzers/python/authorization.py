"""Bounded Django evidence, driven by the trusted worker's existing evaluator.

No target imports, permission execution, absence-based vulnerability inference or runtime assurance.
"""
import ast
from dataclasses import replace


class AuthorizationEvidence:
    KNOWN = {"IsAuthenticated", "IsAdminUser", "AllowAny", "IsAuthenticatedOrReadOnly", "DjangoModelPermissions", "DjangoObjectPermissions"}
    DENIED = {"django.core.exceptions.PermissionDenied", "rest_framework.exceptions.PermissionDenied", "rest_framework.exceptions.NotAuthenticated"}

    def __init__(self, analyzer, value_type):
        self.a, self.V = analyzer, value_type
        self.active, self.refs = None, {}
        self.global_cache = None

    def add(self, key, value):
        if self.active is None:
            return
        if value not in self.active[key]:
            if len(self.active[key]) < 40:
                self.active[key].append(value)
            elif "AUTH_DETAIL_LIMIT" not in self.active["limitations"]:
                self.active["limitations"].append("AUTH_DETAIL_LIMIT")
                self.a.note("AUTH_DETAIL_LIMIT")

    def resolved(self, node, env=None, path=None):
        if isinstance(node, ast.Name) and env is not None and node.id in env:
            return env[node.id].symbol if not env[node.id].unknown else ""
        if isinstance(node, ast.Attribute) and env is not None:
            base = self.resolved(node.value, env, path)
            return base + "." + node.attr if base else ""
        return self.a.symbol(node, path or self.a.path)

    def permission_names(self, node, path, instances=False):
        if not isinstance(node, (ast.List, ast.Tuple)) or len(node.elts) > 20:
            return None
        result = []
        for item in node.elts:
            self.a.tick()
            if instances:
                if not isinstance(item, ast.Call) or item.args or item.keywords:
                    return None
                item = item.func
            symbol = item.value if isinstance(item, ast.Constant) and isinstance(item.value, str) else self.a.symbol(item, path)
            result.append(symbol.removeprefix("rest_framework.permissions.") if symbol in {"rest_framework.permissions." + p for p in self.KNOWN} else "CUSTOM_PERMISSION_UNKNOWN")
        return result

    def attr(self, cls, name, seen=()):
        if cls not in self.a.classes or cls in seen or len(seen) >= 5:
            return None
        path, node = self.a.classes[cls]
        own = [n for n in node.body if isinstance(n, (ast.Assign, ast.AnnAssign)) and any(isinstance(t, ast.Name) and t.id == name for t in (n.targets if isinstance(n, ast.Assign) else [n.target]))]
        if len(own) == 1:
            return path, own[0]
        if own:
            return path, None
        parents = [self.a.symbol(b, path) for b in node.bases]
        # Unknown bases can change resolution; do not pick an arbitrary local parent.
        if len(parents) == 1 and parents[0] in self.a.classes:
            return self.attr(parents[0], name, (*seen, cls))
        return None

    def method(self, cls, name, seen=()):
        if cls not in self.a.classes or cls in seen or len(seen) >= 5:
            return None
        key = cls + "." + name
        if key in self.a.functions:
            return self.a.functions[key]
        path, node = self.a.classes[cls]
        parents = [self.a.symbol(b, path) for b in node.bases]
        if len(parents) == 1 and parents[0] in self.a.classes:
            return self.method(parents[0], name, (*seen, cls))
        return None

    def static_permissions(self, statements, path, action, depth=0):
        if depth >= 5:
            return None
        statements = [s for s in statements if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]
        if len(statements) == 1 and isinstance(statements[0], ast.Return):
            return self.permission_names(statements[0].value, path, instances=True)
        if statements and isinstance(statements[0], ast.If):
            branch = statements[0]
            test = branch.test
            if action is not None and isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.left, ast.Attribute) and isinstance(test.left.value, ast.Name) and test.left.value.id == "self" and test.left.attr == "action" and isinstance(test.comparators[0], ast.Constant) and isinstance(test.comparators[0].value, str) and isinstance(test.ops[0], (ast.Eq, ast.NotEq)):
                chosen = action == test.comparators[0].value
                if isinstance(test.ops[0], ast.NotEq):
                    chosen = not chosen
                return self.static_permissions(branch.body if chosen else [*branch.orelse, *statements[1:]], path, action, depth + 1)
        return None

    def is_viewset(self, cls, seen=()):
        if cls not in self.a.classes or cls in seen or len(seen) >= 5:
            return False
        path, node = self.a.classes[cls]
        return any(self.a.symbol(base, path) in {"rest_framework.viewsets.ViewSet", "rest_framework.viewsets.GenericViewSet", "rest_framework.viewsets.ModelViewSet", "rest_framework.viewsets.ReadOnlyModelViewSet"} or self.is_viewset(self.a.symbol(base, path), (*seen, cls)) for base in node.bases)

    def known_inheritance(self, cls, seen=()):
        if cls not in self.a.classes or cls in seen or len(seen) >= 5:
            return False
        path, node = self.a.classes[cls]
        if len(node.bases) != 1:
            return False
        base=self.a.symbol(node.bases[0],path)
        return base in {"rest_framework.views.APIView","rest_framework.viewsets.ViewSet","rest_framework.viewsets.GenericViewSet","rest_framework.viewsets.ModelViewSet","rest_framework.viewsets.ReadOnlyModelViewSet","django.views.View","django.views.generic.View","django.views.generic.base.View"} or self.known_inheritance(base,(*seen,cls))

    def global_permissions(self):
        if self.global_cache is not None:
            return self.global_cache
        candidates = []
        for path, tree in self.a.modules.items():
            for node in tree.body:
                self.a.tick()
                if not isinstance(node, ast.Assign) or not any(isinstance(t, ast.Name) and t.id == "REST_FRAMEWORK" for t in node.targets):
                    continue
                names = None
                if isinstance(node.value, ast.Dict):
                    entries = [(k, v) for k, v in zip(node.value.keys, node.value.values) if isinstance(k, ast.Constant) and k.value == "DEFAULT_PERMISSION_CLASSES"]
                    if len(entries) == 1 and all(k is not None for k in node.value.keys):
                        names = self.permission_names(entries[0][1], path)
                candidates.append((path, node, names))
        self.global_cache = candidates[:40]
        return self.global_cache

    def begin(self, key):
        a = self.a
        path, node, cls = a.functions[key]
        self.refs = {}
        self.active = dict(authenticationStatus="UNKNOWN", objectAuthorizationStatus="NOT_ESTABLISHED", permissionSource="UNKNOWN",
                           permissionDeclarations=[], principalReferences=[], ownershipComparisons=[], accesses=[],
                           limitations=["AUTH_MIDDLEWARE_AND_RUNTIME_NOT_VERIFIED", "AUTHENTICATION_IS_NOT_OBJECT_AUTHORIZATION"])
        declarations, source, location = None, "UNKNOWN", a.loc(node, "PERMISSION_SCOPE_UNKNOWN")
        drf = bool(cls and a.framework_class(cls) == "drf") or any(a.symbol(d.func if isinstance(d, ast.Call) else d, path) == "rest_framework.decorators.api_view" for d in node.decorator_list)
        if cls and drf:
            custom = self.method(cls, "get_permissions")
            if custom:
                cp, method, _ = custom
                declarations = self.static_permissions(method.body, cp, node.name if self.is_viewset(cls) else None) if not method.decorator_list else None
                source = "GET_PERMISSIONS"; location = self.location(cp, method, "GET_PERMISSIONS_DECLARATION", method.name)
                self.add("limitations", "CUSTOM_PERMISSION_EXECUTION_NOT_VERIFIED")
            else:
                attribute = self.attr(cls, "permission_classes")
                if attribute:
                    cp, assignment = attribute
                    declarations = self.permission_names(assignment.value, cp) if assignment else None
                    source = "VIEW_CLASS"; location = self.location(cp, assignment or node, "VIEW_PERMISSION_DECLARATION", node.name)
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Call) and a.symbol(decorator.func, path) == "rest_framework.decorators.action":
                        for keyword in decorator.keywords:
                            if keyword.arg == "permission_classes":
                                declarations = self.permission_names(keyword.value, path); source = "ACTION_DECORATOR"
                                location = a.loc(decorator, "ACTION_PERMISSION_DECLARATION")
            if self.method(cls, "dispatch") or self.method(cls, "initial"):
                self.add("limitations", "CUSTOM_DISPATCH_AUTH_EXECUTION_UNKNOWN")
        elif drf:
            api_index = next(i for i, d in enumerate(node.decorator_list) if a.symbol(d.func if isinstance(d, ast.Call) else d, path) == "rest_framework.decorators.api_view")
            declared = [(i, d) for i, d in enumerate(node.decorator_list) if isinstance(d, ast.Call) and a.symbol(d.func, path) == "rest_framework.decorators.permission_classes"]
            if declared:
                index, decorator = declared[0]; source = "VIEW_DECORATOR"; location = a.loc(decorator, "VIEW_PERMISSION_DECLARATION")
                declarations = self.permission_names(decorator.args[0], path) if len(declared) == 1 and index > api_index and decorator.args else None
                if index < api_index:
                    self.add("limitations", "PERMISSION_DECORATOR_ORDER_UNKNOWN")
        if source == "UNKNOWN" and drf:
            source = "GLOBAL_CANDIDATE_ACTIVATION_UNKNOWN"
            for cp, assignment, names in self.global_permissions():
                self.add("permissionDeclarations", dict(source=source, permissions=names if names is not None else ["UNKNOWN"], location=self.location(cp, assignment, "GLOBAL_PERMISSION_CANDIDATE", "<module>")))
            self.add("limitations", "GLOBAL_SETTINGS_SELECTION_AND_OVERRIDES_UNKNOWN")
        else:
            self.add("permissionDeclarations", dict(source=source, permissions=declarations if declarations is not None else ["UNKNOWN"], location=location))
        self.active["permissionSource"] = source
        if declarations is not None:
            self.active["authenticationStatus"] = "DECLARED_STAFF_REQUIRED" if "IsAdminUser" in declarations else "DECLARED_LOGIN_REQUIRED" if "IsAuthenticated" in declarations else "DECLARED_PUBLIC" if not declarations or declarations == ["AllowAny"] else "UNKNOWN"
            if any(p in {"CUSTOM_PERMISSION_UNKNOWN", "DjangoObjectPermissions", "DjangoModelPermissions", "IsAuthenticatedOrReadOnly"} for p in declarations):
                self.add("limitations", "PERMISSION_POLICY_REQUIRES_ADDITIONAL_CONTEXT")
        for decorator in node.decorator_list:
            name = a.symbol(decorator.func if isinstance(decorator, ast.Call) else decorator, path)
            if name in {"django.contrib.auth.decorators.login_required", "django.contrib.admin.views.decorators.staff_member_required", "django.contrib.auth.decorators.permission_required"}:
                self.add("permissionDeclarations", dict(source="DJANGO_DECORATOR", permissions=["LOGIN_REQUIRED" if name.endswith("login_required") else "STAFF_REQUIRED" if name.endswith("staff_member_required") else "PERMISSION_REQUIRED"], location=a.loc(decorator, "DJANGO_AUTH_DECORATOR")))
                self.active["authenticationStatus"] = "DECLARED_LOGIN_REQUIRED" if name.endswith("login_required") else "DECLARED_STAFF_REQUIRED" if name.endswith("staff_member_required") else "UNKNOWN"
                if source == "UNKNOWN":
                    self.active["permissionSource"] = "DJANGO_DECORATOR"
        if cls:
            cp, class_node = a.classes[cls]
            for base in class_node.bases:
                if a.symbol(base, cp) in {"django.contrib.auth.mixins.LoginRequiredMixin", "django.contrib.auth.mixins.PermissionRequiredMixin", "django.contrib.auth.mixins.UserPassesTestMixin"}:
                    self.add("permissionDeclarations", dict(source="DJANGO_MIXIN", permissions=["MIXIN_EXECUTION_UNKNOWN"], location=self.location(cp, base, "DJANGO_AUTH_MIXIN", class_node.name)))
                    self.add("limitations", "MIXIN_ORDER_AND_DISPATCH_EXECUTION_UNKNOWN")
            for method_name in ("get_queryset", "get_object"):
                custom = self.method(cls, method_name)
                if custom:
                    self.add("permissionDeclarations", dict(source="CUSTOM_RESOURCE_METHOD", permissions=["CUSTOM_QUERYSET" if method_name == "get_queryset" else "CUSTOM_GET_OBJECT"], location=self.location(custom[0], custom[1], "CUSTOM_RESOURCE_METHOD", method_name)))
            self.add("limitations", "INHERITED_RESOURCE_AND_PERMISSION_METHODS_NOT_EXECUTED")
            if not self.known_inheritance(cls) or self.method(cls,"dispatch") or self.method(cls,"initial"):
                self.active["authenticationStatus"]="UNKNOWN"
                self.add("limitations","PERMISSION_INHERITANCE_OR_DISPATCH_UNKNOWN")
        return self.active

    def uncertain_call(self,node,values,env):
        refs={v.symbol for v in values if v.tag in {"auth-resource","auth-queryset"}}
        if not refs:
            return
        marker=self.a.loc(node,"AUTH_VALUE_FLOW_UNRESOLVED")
        for name,value in list(env.items()):
            if value.symbol in refs:
                env[name]=replace(value,unknown=True,defenses=(*value.defenses,marker))
        self.add("limitations","AUTH_VALUE_FLOW_UNRESOLVED")

    @staticmethod
    def location(path, node, kind, function):
        return dict(filePath=path, line=node.lineno, column=node.col_offset + 1, functionName=function, kind=kind)

    def user_fields(self, model):
        if model not in self.a.classes:
            return set()
        path, node = self.a.classes[model]
        result = set()
        for field in node.body:
            self.a.tick()
            if isinstance(field, ast.Assign) and isinstance(field.value, ast.Call) and self.a.symbol(field.value.func, path) in {"django.db.models.ForeignKey", "django.db.models.OneToOneField"}:
                target = field.value.args[0] if field.value.args else next((k.value for k in field.value.keywords if k.arg == "to"), None)
                target_name = self.a.symbol(target, path) if target else ""
                if target_name in {"django.conf.settings.AUTH_USER_MODEL", "django.contrib.auth.models.User"}:
                    result.update(t.id for t in field.targets if isinstance(t, ast.Name))
        return result

    def attribute(self, node, base):
        if self.active is None:
            return None
        if base.tag == "self" and node.attr == "request" and self.a.framework_class(base.symbol):
            return self.V(tag="request")
        if base.tag == "request" and node.attr == "user" and not base.unknown:
            self.add("principalReferences", self.a.loc(node, "REQUEST_PRINCIPAL_REFERENCE"))
            return self.V(tag="auth-principal")
        if base.tag == "auth-principal":
            if node.attr in {"id", "pk"}:
                return self.V(tag="auth-principal-id", unknown=base.unknown)
            if node.attr in {"is_authenticated", "is_staff", "is_superuser"}:
                return self.V(tag="auth-role", symbol=node.attr, unknown=base.unknown)
        if base.tag == "auth-resource" and base.symbol in self.refs:
            fields = self.refs[base.symbol]["fields"]
            if node.attr in fields:
                return self.V(tag="auth-owner", symbol=base.symbol)
            if node.attr.endswith("_id") and node.attr[:-3] in fields:
                return self.V(tag="auth-owner-id", symbol=base.symbol)
            if node.attr in {"id", "pk"}:
                return self.V(tag="auth-resource-key", symbol=base.symbol)
        if base.tag == "auth-owner" and node.attr in {"id", "pk"}:
            return self.V(tag="auth-owner-id", symbol=base.symbol)
        return None

    def query(self, node, model, name, keywords, prior=None, env=None):
        if self.active is None:
            return self.V(unknown=True)
        fields = self.user_fields(model)
        scoped = any(not value.unknown and ((key in fields and value.tag == "auth-principal") or (key.endswith("_id") and key[:-3] in fields and value.tag == "auth-principal-id")) for key, value in keywords.items()) if name in {"filter", "get"} else False
        defenses = list(prior.defenses) if prior else []
        if env and "@authorization-guard" in env:
            defenses.extend(env["@authorization-guard"].defenses)
        if scoped:
            defenses.append(self.a.loc(node, "USER_FOREIGN_KEY_QUERY_SCOPE"))
        identifiers = [loc for value in keywords.values() for loc in value.trace]
        ref = "resource:" + str(len(self.refs))
        model_node=self.a.classes[model][1]
        custom_model=any(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name in {"__getattribute__","__getattr__"} or isinstance(n,(ast.Assign,ast.AnnAssign)) and any(isinstance(t,ast.Name) and t.id=="objects" for t in (n.targets if isinstance(n,ast.Assign) else [n.target])) for n in model_node.body)
        self.refs[ref] = dict(model=model, fields=fields, location=self.a.loc(node, "RESOURCE_LOOKUP"), identifiers=identifiers[:40],
                              unresolved=any(v.unknown and v.trace for v in keywords.values()) or self.a.partial or custom_model)
        self.access(node, ref, "QUERYSET_DECLARATION" if name in {"filter", "exclude", "all"} else "RESOURCE_LOOKUP", defenses)
        return self.V(tag="auth-queryset" if name in {"filter", "exclude", "all"} else "auth-resource", symbol=ref, unknown=True, defenses=tuple(defenses))

    def call(self, node, function, base, name, args, keywords, env):
        if self.active is None:
            return None
        if base and base.tag == "auth-queryset" and base.symbol in self.refs and name in {"get", "filter", "exclude", "all", "first"}:
            return self.query(node, self.refs[base.symbol]["model"], name, keywords, base, env)
        if base and base.tag == "auth-resource" and base.symbol in self.refs and name in {"save", "delete"}:
            self.access(node, base.symbol, "WRITE" if name == "save" else "DELETE", list(base.defenses))
            return self.V(unknown=True)
        if base and base.tag == "self" and name == "check_object_permissions" and self.a.framework_class(base.symbol) == "drf":
            resource = args[1] if len(args) >= 2 else keywords.get("obj")
            if resource and resource.tag == "auth-resource":
                self.access(node, resource.symbol, "OBJECT_PERMISSION_CALL", list(resource.defenses))
            self.add("limitations", "OBJECT_PERMISSION_CALL_POLICY_NOT_VERIFIED")
            if self.method(base.symbol, name):
                self.add("limitations", "CUSTOM_OBJECT_PERMISSION_METHOD_UNKNOWN")
                return None
            return self.V(unknown=True)
        return None

    def value(self, node, env):
        if isinstance(node, ast.Name):
            return env.get(node.id, self.V(unknown=True))
        if isinstance(node, ast.Attribute):
            return self.attribute(node, self.value(node.value, env)) or self.V(unknown=True)
        return self.V(unknown=True)

    def helper_after(self, key, args, keywords, caller):
        if self.active is None or key not in self.a.functions:
            return
        path, node, cls = self.a.functions[key]
        if cls or node.decorator_list or node.args.vararg or node.args.kwarg or node.args.kwonlyargs:
            return
        body = [s for s in node.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]
        if not body or not isinstance(body[0], ast.If) or body[0].orelse or len(body) > 2 or len(body) == 2 and not (isinstance(body[1], ast.Return) and (body[1].value is None or isinstance(body[1].value, ast.Constant) and body[1].value.value is None)):
            return
        parameters = node.args.posonlyargs + node.args.args
        if len(args) > len(parameters) or any(p.arg not in keywords for p in parameters[len(args):]) or any(k not in {p.arg for p in parameters} for k in keywords) or any(p.arg in keywords for p in parameters[:len(args)]) or any(p.arg in keywords for p in node.args.posonlyargs):
            return
        local = {name: self.V(symbol=symbol) for name, symbol in self.a.imports[path].items()}
        local.update({p.arg: args[i] if i < len(args) else keywords[p.arg] for i, p in enumerate(parameters)})
        old = self.a.path, self.a.function
        self.a.path, self.a.function = path, node.name
        try:
            protected = self.branch(body[0], local, False)
            for value in protected.values():
                if value.tag != "auth-resource":
                    continue
                for name, prior in list(caller.items()):
                    if prior.tag == "auth-resource" and prior.symbol == value.symbol:
                        caller[name] = replace(prior, defenses=(*prior.defenses, *[d for d in value.defenses if d not in prior.defenses]))
        finally:
            self.a.path, self.a.function = old

    def denial(self, statements, env, path=None):
        if len(statements) != 1:
            return False
        stmt = statements[0]
        if isinstance(stmt, ast.Raise) and stmt.exc is not None:
            return self.resolved(stmt.exc.func if isinstance(stmt.exc, ast.Call) else stmt.exc, env, path) in self.DENIED
        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
            symbol = self.resolved(stmt.value.func, env, path)
            if symbol in {"django.http.HttpResponseForbidden", "django.http.response.HttpResponseForbidden"}:
                return True
            if symbol == "rest_framework.response.Response":
                return not any(k.arg is None for k in stmt.value.keywords) and any(k.arg == "status" and ((isinstance(k.value, ast.Constant) and k.value.value in {401, 403}) or self.resolved(k.value, env, path) in {"rest_framework.status.HTTP_401_UNAUTHORIZED", "rest_framework.status.HTTP_403_FORBIDDEN"}) for k in stmt.value.keywords)
        return False

    def branch(self, node, env, truth):
        if self.active is None:
            return dict(env)
        test = node.test
        role = self.value(test.operand if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not) else test, env)
        if role.tag == "auth-role" and not role.unknown:
            expected = not truth if isinstance(test, ast.UnaryOp) else truth
            opposite = node.orelse if truth else node.body
            if expected and self.denial(opposite, env):
                location = self.a.loc(test, "LOGIN_REJECTION_GUARD" if role.symbol == "is_authenticated" else "ROLE_REJECTION_GUARD")
                self.add("ownershipComparisons", location)
                guarded = {k: replace(v, defenses=(*v.defenses, location)) if v.tag in {"auth-resource", "auth-queryset"} else v for k, v in env.items()}
                prior = env.get("@authorization-guard", self.V()).defenses
                guarded["@authorization-guard"] = self.V(tag="auth-guard-context", defenses=(*prior, location))
                return guarded
        if not isinstance(test, ast.Compare) or len(test.ops) != 1 or not isinstance(test.ops[0], (ast.Eq, ast.NotEq)):
            return dict(env)
        left, right = self.value(test.left, env), self.value(test.comparators[0], env)
        owner, principal = (left, right) if left.tag.startswith("auth-owner") else (right, left)
        if (owner.tag, principal.tag) not in {("auth-owner", "auth-principal"), ("auth-owner-id", "auth-principal-id")}:
            if {left.tag, right.tag} == {"auth-resource-key", "auth-principal-id"}:
                self.add("ownershipComparisons", self.a.loc(test, "RESOURCE_KEY_USER_KEY_NOT_OWNERSHIP_PROOF"))
                self.add("limitations", "RESOURCE_PRIMARY_KEY_NOT_VERIFIED_AS_OWNER_KEY")
            return dict(env)
        if principal.unknown or owner.unknown:
            self.add("limitations", "AUTH_VALUE_FLOW_UNRESOLVED")
            return dict(env)
        opposite = node.orelse if truth else node.body
        equality = truth == isinstance(test.ops[0], ast.Eq)
        kind = "OWNER_COMPARISON_WITHOUT_PROVEN_REJECTION"
        if self.denial(opposite, env):
            kind = "OWNER_REJECTION_GUARD" if equality else "INVERTED_OWNER_REJECTION"
        location = self.a.loc(test, kind)
        self.add("ownershipComparisons", location)
        if kind == "OWNER_COMPARISON_WITHOUT_PROVEN_REJECTION":
            return dict(env)
        return {k: replace(v, defenses=(*v.defenses, location)) if v.symbol == owner.symbol and v.tag == "auth-resource" else v for k, v in env.items()}

    def access(self, node, ref, operation, defenses):
        if ref not in self.refs or self.active is None:
            return
        resource = self.refs[ref]
        kinds = {d["kind"] for d in defenses}
        conclusion = "USER_SCOPE_QUERY_EVIDENCE" if "USER_FOREIGN_KEY_QUERY_SCOPE" in kinds else "OWNER_GUARD_EVIDENCE" if "OWNER_REJECTION_GUARD" in kinds else "ROLE_GUARD_EVIDENCE" if "ROLE_REJECTION_GUARD" in kinds else "OBJECT_AUTHORIZATION_NOT_ESTABLISHED"
        unresolved = resource["unresolved"] or self.a.partial or "AUTH_VALUE_FLOW_UNRESOLVED" in kinds
        inverse = next((d for d in defenses if d["kind"] == "INVERTED_OWNER_REJECTION"), None)
        if operation == "OBJECT_PERMISSION_CALL":
            conclusion = "OBJECT_CHECK_CALLED_POLICY_UNKNOWN"
        constrained = bool(kinds & {"USER_FOREIGN_KEY_QUERY_SCOPE", "OWNER_REJECTION_GUARD", "ROLE_REJECTION_GUARD"}) or self.active["authenticationStatus"] == "DECLARED_STAFF_REQUIRED"
        if inverse and operation in {"WRITE", "DELETE"} and resource["identifiers"] and not unresolved and not constrained:
            conclusion = "INVERTED_OWNER_REJECTION_CANDIDATE"
        if unresolved:
            conclusion = "ACCESS_FLOW_UNRESOLVED"
        location = self.a.loc(node, "RESOURCE_" + operation)
        self.add("accesses", dict(operation=operation, location=location, resourceLocation=resource["location"], identifierInputs=resource["identifiers"],
                                  checks=defenses[-20:], conclusion=conclusion, limitations=["AUTH_MIDDLEWARE_AND_RUNTIME_NOT_VERIFIED", "MODEL_MANAGER_AND_PROPERTIES_NOT_VERIFIED"]))
        if conclusion == "INVERTED_OWNER_REJECTION_CANDIDATE" and len(self.a.findings) < 200:
            flow = [resource["identifiers"][0], resource["location"], inverse, location]
            finding = dict(ruleId="PY_AUTHORIZATION_INVERTED_OWNER_GUARD", kind="CWE-863", confidence="HIGH", disposition="REVIEW_REQUIRED", source=flow[0], sink=location,
                           flow=flow, defenses=defenses[-20:], limitations=["AUTH_LOGIC_CANDIDATE_NOT_EXPLOIT_PROOF", "AUTH_MIDDLEWARE_AND_RUNTIME_NOT_VERIFIED"],
                           message="소유자가 일치할 때 차단하고 다른 분기에서 요청한 객체를 변경하는 흐름입니다. 의도한 권한 정책인지 확인하세요.",
                           recommendation="소유자와 요청 사용자의 비교 방향·거부 분기를 확인하세요. 의도된 예외가 아니라면 소유하지 않은 리소스의 작업을 차단하고 두 사용자 계정의 허용·거부 테스트를 추가하세요.")
            if finding not in self.a.findings:
                self.a.findings.append(finding)

    def finish(self):
        if not self.active:
            return
        conclusions = {r["conclusion"] for r in self.active["accesses"]}
        self.active["objectAuthorizationStatus"] = "RISK_LOGIC_CANDIDATE" if "INVERTED_OWNER_REJECTION_CANDIDATE" in conclusions else "PROTECTION_EVIDENCE_NOT_FULL_ASSURANCE" if conclusions & {"USER_SCOPE_QUERY_EVIDENCE", "OWNER_GUARD_EVIDENCE", "ROLE_GUARD_EVIDENCE"} else "NOT_ESTABLISHED" if conclusions else "NO_RESOURCE_ACCESS_TRACED"
