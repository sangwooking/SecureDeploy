"""Trusted, bounded static parser. Target source is never imported or executed."""
import ast
import json
import sys
import time
import resource
import re
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from collections import Counter

VERSION = "py-django-v2"
MAX_NODES = 60000
MAX_STEPS = 30000
MAX_DEPTH = 5
MAX_RESULTS = 200
UNKNOWN = object()


@dataclass(frozen=True)
class Value:
    trace: tuple = ()
    unknown: bool = False
    literal: object = UNKNOWN
    symbol: str = ""
    tag: str = ""
    defenses: tuple = ()
    elements: tuple | None = None


def merge(*values):
    if not values:
        return Value(unknown=True)
    trace, defenses = [], []
    for value in values:
        for entry in value.trace:
            if entry not in trace:
                trace.append(entry)
        for entry in value.defenses:
            if entry not in defenses:
                defenses.append(entry)
    first = values[0]
    elements = None
    if all(v.elements is not None for v in values) and len({len(v.elements) for v in values}) == 1:
        elements = tuple(merge(*(v.elements[i] for v in values)) for i in range(len(first.elements)))
    return Value(tuple(trace[:40]), any(v.unknown for v in values) or len(trace) > 40,
                 first.literal if all(v.literal == first.literal for v in values) else UNKNOWN,
                 first.symbol if all(v.symbol == first.symbol for v in values) else "",
                 first.tag if all(v.tag == first.tag for v in values) else "", tuple(defenses[:20]), elements)


class BudgetExceeded(Exception):
    pass


class Analyzer:
    def __init__(self, files):
        self.start = time.monotonic()
        self.steps = 0
        self.modules, self.functions, self.classes = {}, {}, {}
        self.coverage, self.imports, self.globals = {}, {}, {}
        self.shadowed = {}
        self.findings, self.sql, self.auth = [], [], []
        self.visited, self.traced = set(), set()
        self.path, self.function, self.stack = "", "<module>", []
        self.partial = False
        self.contexts = []
        self.entries = set()
        self.route_parameters = {}
        node_count = 0
        for item in files:
            path = item["filePath"]
            self.coverage[path] = dict(filePath=path, parseStatus="PARSED", flowStatus="NOT_SUPPORTED",
                                       entrypoints=0, functionsAnalyzed=0, prepareCallSites=0,
                                       tracedPrepareCallSites=0, limitations=[])
            try:
                self.tick()
                tree = ast.parse(item["content"], filename="<source>")
                count = 0
                for _ in ast.walk(tree):
                    count += 1
                    if count > MAX_NODES - node_count:
                        break
                if count > MAX_NODES - node_count:
                    self.coverage[path]["parseStatus"] = "LIMIT_EXCEEDED"
                    self.note("AST_NODE_LIMIT", path)
                    continue
                node_count += count
                if time.monotonic() - self.start > 4:
                    raise BudgetExceeded()
                self.modules[path] = tree
                self.index(path, tree)
            except (SyntaxError, ValueError, RecursionError):
                self.coverage[path]["parseStatus"] = "PARSE_FAILED"
                self.note("INVALID_SYNTAX", path)
            except BudgetExceeded:
                self.coverage[path]["parseStatus"] = "LIMIT_EXCEEDED"
                self.note("ANALYSIS_BUDGET_EXCEEDED", path)

    def tick(self):
        self.steps += 1
        if self.steps > MAX_STEPS or time.monotonic() - self.start > 4:
            raise BudgetExceeded()
        if self.steps % 100 == 0:
            rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            if rss * (1 if sys.platform == "darwin" else 1024) > 384 * 1024 * 1024:
                raise BudgetExceeded()

    def note(self, reason, path=None):
        path = path or self.path
        if reason not in self.coverage[path]["limitations"]:
            self.coverage[path]["limitations"].append(reason)

    def loc(self, node, kind):
        return dict(filePath=self.path, line=node.lineno, column=node.col_offset + 1,
                    functionName=self.function, kind=kind)

    def step(self, value, node, kind):
        if not value.trace:
            return value
        return merge(value, replace(value, trace=(self.loc(node, kind),)))

    def module_name(self, path):
        name = path[:-3].replace("/", ".")
        return name[:-9] if name.endswith(".__init__") else name

    def resolve(self, symbol):
        if symbol in self.functions or symbol in self.classes:
            return symbol
        return None

    def index(self, path, tree):
        module = self.module_name(path)
        imports, globals_ = {}, {}
        bindings = Counter()
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    bindings[alias.asname or alias.name.split(".")[0]] += 1
                    imports[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom):
                parts = module.split(".") if path.endswith("/__init__.py") else module.split(".")[:-1]
                base = ".".join(parts[:len(parts) - node.level + 1]) if node.level and node.level <= len(parts) + 1 else ""
                prefix = ".".join(p for p in [base, node.module] if p) if node.level else node.module or ""
                for alias in node.names:
                    if alias.name != "*":
                        bindings[alias.asname or alias.name] += 1
                        imports[alias.asname or alias.name] = prefix + "." + alias.name
                    else:
                        self.note("STAR_IMPORT_UNSUPPORTED", path)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                bindings[node.name] += 1
                self.functions[module + "." + node.name] = (path, node, None)
            elif isinstance(node, ast.ClassDef):
                bindings[node.name] += 1
                self.classes[module + "." + node.name] = (path, node)
                for method in node.body:
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.functions[module + "." + node.name + "." + method.name] = (path, method, module + "." + node.name)
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                    if isinstance(target, ast.Name):
                        bindings[target.id] += 1
                        globals_[target.id] = Value(literal=node.value.value) if isinstance(node.value, ast.Constant) else Value(unknown=True)
            elif not isinstance(node, (ast.Expr, ast.Pass)):
                self.note("MODULE_CONTROL_FLOW_UNRESOLVED", path)
                for n in ast.walk(node):
                    if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                        bindings[n.id] += 2
        shadowed = {name for name, count in bindings.items() if count > 1}
        for name in shadowed:
            imports.pop(name, None)
            globals_[name] = Value(unknown=True)
        self.shadowed[path] = shadowed
        if shadowed:
            self.note("MODULE_BINDING_REASSIGNED", path)
        self.imports[path], self.globals[path] = imports, globals_
        self.coverage[path]["prepareCallSites"] = sum(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                                                        and n.func.attr in {"execute", "executemany", "raw"} for n in ast.walk(tree))

    def symbol(self, node, path):
        if isinstance(node, ast.Name):
            if node.id in self.shadowed[path]:
                return ""
            return self.imports[path].get(node.id, self.module_name(path) + "." + node.id)
        if isinstance(node, ast.Attribute):
            return self.symbol(node.value, path) + "." + node.attr
        return ""

    def framework_class(self, key, seen=()):
        if key in seen or len(seen) > MAX_DEPTH or key not in self.classes:
            return ""
        path, node = self.classes[key]
        for base in node.bases:
            name = self.symbol(base, path)
            if name in {"django.views.View", "django.views.generic.View", "django.views.generic.base.View"}:
                return "django"
            if name in {"rest_framework.views.APIView", "rest_framework.viewsets.ViewSet", "rest_framework.viewsets.GenericViewSet",
                        "rest_framework.viewsets.ModelViewSet", "rest_framework.viewsets.ReadOnlyModelViewSet"}:
                return "drf"
            inherited = self.framework_class(name, (*seen, key))
            if inherited:
                return inherited
        return ""

    def discover(self):
        # Routing calls must be part of urlpatterns; a similarly named arbitrary function is not a route.
        for path, tree in self.modules.items():
            router_names = set()
            for node in tree.body:
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    if self.symbol(node.value.func, path) in {"rest_framework.routers.DefaultRouter", "rest_framework.routers.SimpleRouter"}:
                        router_names.update(t.id for t in node.targets if isinstance(t, ast.Name))
                if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "urlpatterns" for t in node.targets):
                    for call in ast.walk(node.value):
                        if isinstance(call, ast.Call) and self.symbol(call.func, path) in {"django.urls.path", "django.urls.re_path", "django.conf.urls.url"} and len(call.args) >= 2:
                            target = call.args[1]
                            parameters = {}
                            if self.symbol(call.func, path) == "django.urls.path" and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
                                parameters = {name: converter or "str" for converter, name in re.findall(r"<(?:(\w+):)?(\w+)>", call.args[0].value)}
                            else:
                                self.note("ROUTE_PARAMETERS_UNRESOLVED", path)
                            if isinstance(target, ast.Call) and isinstance(target.func, ast.Attribute) and target.func.attr == "as_view":
                                key = self.symbol(target.func.value, path)
                                self.add_class_entries(key, parameters)
                            else:
                                key = self.symbol(target, path)
                                if key in self.functions:
                                    self.entries.add(key)
                                    self.route_parameters.setdefault(key, {}).update(parameters)
                                else:
                                    self.note("ROUTE_TARGET_UNRESOLVED", path)
            for node in tree.body:
                call = node.value if isinstance(node, ast.Expr) else None
                if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == "register" and isinstance(call.func.value, ast.Name) and call.func.value.id in router_names and len(call.args) >= 2:
                    self.add_class_entries(self.symbol(call.args[1], path), {"pk": "str"})
        for key, (path, node, cls) in self.functions.items():
            if cls:
                continue
            for decorator in node.decorator_list:
                name = self.symbol(decorator.func if isinstance(decorator, ast.Call) else decorator, path)
                if name == "rest_framework.decorators.api_view":
                    self.entries.add(key)

    def add_class_entries(self, key, parameters):
        if not self.framework_class(key):
            return
        for name in ["get", "post", "put", "patch", "delete", "head", "options", "list", "retrieve", "create", "update", "partial_update", "destroy"]:
            if key + "." + name in self.functions:
                self.entries.add(key + "." + name)
                self.route_parameters.setdefault(key + "." + name, {}).update(parameters)

    def run(self):
        self.discover()
        for key in self.entries:
            self.coverage[self.functions[key][0]]["entrypoints"] += 1
        try:
            for key in sorted(self.entries):
                path, node, cls = self.functions[key]
                self.path, self.function = path, node.name
                args = node.args.posonlyargs + node.args.args
                values = []
                for i, arg in enumerate(args):
                    if cls and i == 0:
                        values.append(Value(tag="self", symbol=cls))
                    elif i == (1 if cls else 0):
                        values.append(Value(tag="request"))
                    else:
                        converter = self.route_parameters.get(key, {}).get(arg.arg)
                        if converter == "int":
                            values.append(Value(defenses=(self.loc(arg, "NUMERIC_ROUTE_CONVERTER"),)))
                        elif converter in {"str", "path"}:
                            values.append(Value(trace=(self.loc(arg, "ROUTE_PARAMETER"),)))
                        else:
                            values.append(Value(unknown=True))
                            self.note("ROUTE_PARAMETERS_UNRESOLVED")
                context = dict(entry=self.loc(node, "SERVER_ENTRY"), checks=[], defenses=[], resources=[],
                               conclusion="NOT_ESTABLISHED", limitations=["MIDDLEWARE_SETTINGS_AND_OWNERSHIP_NOT_VERIFIED"])
                self.contexts = [context]
                for dec in node.decorator_list:
                    name = self.symbol(dec.func if isinstance(dec, ast.Call) else dec, path)
                    if name.startswith("django.contrib.auth.decorators.") or name in {"rest_framework.decorators.permission_classes", "rest_framework.decorators.authentication_classes"}:
                        context["checks"].append(self.loc(dec, "AUTH_DECLARATION"))
                if cls:
                    for item in self.classes[cls][1].body:
                        if isinstance(item, ast.Assign) and any(isinstance(t, ast.Name) and t.id in {"permission_classes", "authentication_classes"} for t in item.targets):
                            context["checks"].append(self.loc(item, "AUTH_DECLARATION"))
                self.call_function(key, values, {})
                if len(self.auth) < MAX_RESULTS:
                    self.auth.append(context)
        except (BudgetExceeded, RecursionError):
            self.note("ANALYSIS_BUDGET_EXCEEDED")
        for path, c in self.coverage.items():
            c["functionsAnalyzed"] = sum(p == path for p, _ in self.visited)
            c["tracedPrepareCallSites"] = sum(p == path for p, _ in self.traced)
            if not c["functionsAnalyzed"] and c["parseStatus"] == "PARSED":
                self.note("NO_SUPPORTED_SERVER_ENTRY_OR_CALL", path)
            if c["prepareCallSites"] > c["tracedPrepareCallSites"]:
                self.note("SQL_CALLS_OUTSIDE_TRACED_FLOW", path)
            if c["functionsAnalyzed"]:
                c["flowStatus"] = "PARTIAL" if c["limitations"] else "SUPPORTED_FLOW_ANALYZED"
        deployment = self.deployment_settings()
        return dict(schemaVersion=1, analyzerVersion=VERSION, parserVersion="CPython-" + ".".join(map(str, sys.version_info[:3])),
                    status="PARTIAL" if any(c["limitations"] for c in self.coverage.values()) else "COMPLETE",
                    files=list(self.coverage.values()), findings=self.findings, sqlUses=self.sql, httpUses=[],
                    authorizationContexts=self.auth, limitations=["BOUNDED_DJANGO_DRF_ONLY", "MIDDLEWARE_SETTINGS_AND_OWNERSHIP_NOT_VERIFIED",
                    "STATIC_FLOW_NOT_EXPLOIT_PROOF", "NO_OS_SANDBOX"], validatedFindings=None, deploymentAnalysis=deployment)

    def deployment_settings(self):
        keys = {"DEBUG", "SECRET_KEY", "ALLOWED_HOSTS", "SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE",
                "SECURE_SSL_REDIRECT", "SECURE_HSTS_SECONDS"}
        files, references = [], set()
        framework = any(s.startswith(("django.", "rest_framework.")) for items in self.imports.values() for s in items.values())
        try:
            for path, tree in self.modules.items():
                for node in ast.walk(tree):
                    self.tick()
                    if isinstance(node, ast.Call) and self.symbol(node.func, path) == "os.environ.setdefault" and len(node.args) >= 2:
                        if isinstance(node.args[0], ast.Constant) and node.args[0].value == "DJANGO_SETTINGS_MODULE" and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                            references.add(node.args[1].value)
                    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        for target in node.targets:
                            if isinstance(target, ast.Subscript) and self.symbol(target.value, path) == "os.environ" and isinstance(target.slice, ast.Constant) and target.slice.value == "DJANGO_SETTINGS_MODULE":
                                references.add(node.value.value)
            for path, tree in self.modules.items():
                declared = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
                referenced = self.module_name(path) in references
                conventional = "settings" in PurePosixPath(path).parts or PurePosixPath(path).name == "settings.py"
                structural = {"ROOT_URLCONF", "INSTALLED_APPS"}.issubset(declared)
                if not (referenced or structural or (framework and conventional and keys & declared)):
                    continue
                scope = "MODULE_REFERENCE_ACTIVATION_UNKNOWN" if referenced else "DJANGO_STRUCTURE_ACTIVATION_UNKNOWN"
                if any(p in {"dev", "development", "local", "dev.py", "development.py", "local.py"} for p in PurePosixPath(path).parts):
                    scope = "DEVELOPMENT_NAME_HINT_NOT_RUNTIME_PROOF"
                limits = ["DECLARATIONS_ONLY_RUNTIME_AND_OVERRIDES_UNKNOWN", "IMPORTS_AND_BASE_SETTINGS_NOT_MERGED", "MISSING_SETTINGS_DEFAULTS_NOT_INFERRED"]
                values = self.settings_statements(tree.body, {}, keys, limits)
                observations = []
                for key, (value, line) in sorted(values.items()):
                    if key not in keys:
                        continue
                    known, rule, summary = value is not UNKNOWN, "", "not resolved"
                    if key == "SECRET_KEY":
                        known = isinstance(value, str)
                        summary = "<redacted>" if known else "not resolved"
                        if known and value:
                            rule = "DJANGO_SECRET_LITERAL"
                    elif key == "ALLOWED_HOSTS":
                        known = isinstance(value, (list, tuple)) and all(isinstance(v, str) for v in value)
                        summary = "wildcard host declaration" if known and "*" in value else "host declarations (values omitted)"
                        if known and "*" in value:
                            rule = "DJANGO_ALLOWED_HOSTS"
                    elif key == "SECURE_HSTS_SECONDS":
                        known = type(value) is int
                        summary = "disabled" if known and value == 0 else "static duration"
                        if known and value == 0:
                            rule = "DJANGO_HTTPS"
                    else:
                        known = type(value) is bool
                        summary = str(value).lower() if known else "not resolved"
                        if key == "DEBUG" and value is True:
                            rule = "DJANGO_DEBUG"
                        elif key in {"SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE"} and value is False:
                            rule = "DJANGO_SECURE_COOKIE"
                        elif key == "SECURE_SSL_REDIRECT" and value is False:
                            rule = "DJANGO_HTTPS"
                    observations.append(dict(line=line, scope=scope, setting=key, valueStatus="STATIC" if known else "UNKNOWN",
                                             valueSummary=summary if known else "not resolved", ruleId=rule if known else ""))
                files.append(dict(filePath=path, format="DJANGO", status="PARSED", observations=observations, limitations=list(dict.fromkeys(limits))))
        except (BudgetExceeded, RecursionError):
            files.append(dict(filePath=self.path or next(iter(self.coverage), "unknown.py"), format="DJANGO", status="LIMIT_EXCEEDED",
                              observations=[], limitations=["CONFIG_RESOURCE_LIMIT"]))
        for path, c in self.coverage.items():
            if c["parseStatus"] != "PARSED":
                files.append(dict(filePath=path, format="PYTHON_SETTINGS_CANDIDATE", status=c["parseStatus"], observations=[],
                                  limitations=["SETTINGS_ROLE_NOT_INSPECTED"]))
        return dict(schemaVersion=1, analyzerVersion="deployment-v1", status="PARTIAL" if files else "NOT_APPLICABLE",
                    files=files, findings=[], limitations=["DECLARATIONS_ONLY_RUNTIME_AND_OVERRIDES_UNKNOWN"])

    def settings_statements(self, statements, incoming, keys, limits, depth=0):
        values = dict(incoming)
        if depth > 8:
            raise BudgetExceeded()
        def literal(node):
            self.tick()
            if isinstance(node, ast.Constant) and type(node.value) in {bool, int, str, type(None)}:
                return node.value
            if isinstance(node, ast.Name):
                return values.get(node.id, (UNKNOWN, 1))[0]
            if isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) <= 100:
                items = [literal(x) for x in node.elts]
                return items if all(v is not UNKNOWN for v in items) else UNKNOWN
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
                value = literal(node.operand)
                return not value if type(value) is bool else UNKNOWN
            return UNKNOWN
        for node in statements:
            self.tick()
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                if any(isinstance(n, (ast.Call, ast.NamedExpr)) for n in ast.walk(node)):
                    values = {k: (UNKNOWN, node.lineno) for k in values.keys() | keys}
                    limits.append("DYNAMIC_SETTINGS_WRITE_UNRESOLVED")
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = literal(node.value) if node.value is not None else UNKNOWN
                for target in targets:
                    if isinstance(target, ast.Name):
                        values[target.id] = (value, node.lineno)
                    else:
                        values = {k: (UNKNOWN, node.lineno) for k in values.keys() | keys}
                        limits.append("DYNAMIC_SETTINGS_WRITE_UNRESOLVED")
            elif isinstance(node, ast.If):
                if any(isinstance(n, (ast.Call, ast.NamedExpr)) for n in ast.walk(node.test)):
                    values = {k: (UNKNOWN, node.lineno) for k in values.keys() | keys}
                    limits.append("DYNAMIC_SETTINGS_WRITE_UNRESOLVED")
                condition = literal(node.test)
                if type(condition) is bool:
                    values = self.settings_statements(node.body if condition else node.orelse, values, keys, limits, depth + 1)
                else:
                    left = self.settings_statements(node.body, values, keys, limits, depth + 1)
                    right = self.settings_statements(node.orelse, values, keys, limits, depth + 1)
                    for name in left.keys() | right.keys():
                        a, b = left.get(name, (UNKNOWN, node.lineno)), right.get(name, (UNKNOWN, node.lineno))
                        values[name] = (a[0] if type(a[0]) is type(b[0]) and a[0] == b[0] else UNKNOWN, max(a[1], b[1]))
                    limits.append("CONDITIONAL_SETTINGS_UNRESOLVED")
            elif isinstance(node, ast.ImportFrom):
                if any(a.name == "*" for a in node.names):
                    values = {k: (UNKNOWN, node.lineno) for k in values.keys() | keys}
                    limits.append("BASE_SETTINGS_IMPORT_UNRESOLVED")
                else:
                    for alias in node.names:
                        values[alias.asname or alias.name] = (UNKNOWN, node.lineno)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    values[alias.asname or alias.name.split('.')[0]] = (UNKNOWN, node.lineno)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if isinstance(node, ast.ClassDef) or node.decorator_list or any(isinstance(n, (ast.Call, ast.NamedExpr)) for n in ast.walk(node.args)):
                    values = {k: (UNKNOWN, node.lineno) for k in values.keys() | keys}
                    limits.append("DYNAMIC_SETTINGS_WRITE_UNRESOLVED")
                values[node.name] = (UNKNOWN, node.lineno)
            elif not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)):
                # Unknown module calls, mutation, loops and exception paths may replace settings.
                values = {k: (UNKNOWN, node.lineno) for k in values.keys() | keys}
                limits.append("DYNAMIC_SETTINGS_WRITE_UNRESOLVED")
        return values

    def call_function(self, key, args, keywords):
        if len(self.stack) >= MAX_DEPTH or key in self.stack:
            self.note("CALL_DEPTH_EXCEEDED")
            return replace(merge(*args, *keywords.values()), unknown=True)
        path, node, cls = self.functions[key]
        parameters = node.args.posonlyargs + node.args.args
        names = {p.arg for p in parameters + node.args.kwonlyargs}
        defaults = dict(zip([a.arg for a in parameters[-len(node.args.defaults):]], node.args.defaults)) if node.args.defaults else {}
        kwdefaults = dict(zip([a.arg for a in node.args.kwonlyargs], node.args.kw_defaults))
        invalid = (len(args) > len(parameters) or any(p.arg in keywords for p in parameters[:len(args)])
                   or any(p.arg in keywords for p in node.args.posonlyargs)
                   or any(k not in names for k in keywords)
                   or any(p.arg not in keywords and p.arg not in defaults for p in parameters[len(args):])
                   or any(p.arg not in keywords and kwdefaults[p.arg] is None for p in node.args.kwonlyargs))
        if invalid:
            self.note("CALL_ARGUMENT_BINDING_UNRESOLVED")
            self.partial = True
            return replace(merge(*args, *keywords.values()), unknown=True, literal=UNKNOWN)
        if node.args.vararg or node.args.kwarg:
            self.note("VARIADIC_ARGUMENTS_UNRESOLVED", path)
        old = self.path, self.function, self.partial
        self.path, self.function = path, node.name
        for decorator in node.decorator_list:
            name = self.symbol(decorator.func if isinstance(decorator, ast.Call) else decorator, path)
            if name != "rest_framework.decorators.api_view" and not name.startswith(("django.contrib.auth.decorators.", "rest_framework.decorators.")):
                self.note("DECORATOR_EXECUTION_UNRESOLVED")
                self.partial = True
        self.stack.append(key)
        self.visited.add((path, node.lineno))
        env = dict(self.globals[path])
        for name, symbol in self.imports[path].items():
            env[name] = Value(symbol=symbol)
        module = self.module_name(path)
        for symbol in [*self.functions, *self.classes]:
            tail = symbol[len(module) + 1:] if symbol.startswith(module + ".") else ""
            if tail and "." not in tail:
                env[tail] = Value(unknown=True) if tail in self.shadowed[path] else Value(symbol=symbol)
        for i, parameter in enumerate(parameters):
            value = args[i] if i < len(args) else keywords.get(parameter.arg, Value(unknown=True))
            if i >= len(args) and parameter.arg not in keywords and parameter.arg in defaults and isinstance(defaults[parameter.arg], ast.Constant):
                value = Value(literal=defaults[parameter.arg].value)
            env[parameter.arg] = self.step(value, parameter, "FUNCTION_ARGUMENT")
        for parameter in node.args.kwonlyargs:
            default = kwdefaults[parameter.arg]
            value = keywords.get(parameter.arg, Value(literal=default.value) if isinstance(default, ast.Constant) else Value(unknown=True))
            env[parameter.arg] = self.step(value, parameter, "FUNCTION_ARGUMENT")
        # Python locals shadow globals/imports for the whole function, even before assignment.
        for name in self.local_bindings(node.body) - names:
            env[name] = Value(unknown=True)
        try:
            _, returns, terminated = self.block(node.body, env)
            if not terminated:
                returns.append(Value(literal=None))
            return merge(*returns)
        finally:
            self.stack.pop()
            self.path, self.function, self.partial = old

    def local_bindings(self, statements):
        names = set()
        pending = list(statements)
        while pending:
            node = pending.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
                continue
            if isinstance(node, ast.Lambda):
                continue
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                # Comprehension iteration variables are local, but := binds the containing scope.
                nested = [node]
                while nested:
                    item = nested.pop()
                    if isinstance(item, ast.Lambda):
                        continue
                    if isinstance(item, ast.NamedExpr) and isinstance(item.target, ast.Name):
                        names.add(item.target.id)
                    nested.extend(ast.iter_child_nodes(item))
                continue
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                names.add(node.id)
            if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
                names.add(node.name)
            if isinstance(node, ast.MatchMapping) and node.rest:
                names.add(node.rest)
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names.update(a.asname or a.name.split('.')[0] for a in node.names)
            pending.extend(ast.iter_child_nodes(node))
        return names

    def guard_partial(self, condition, node, env):
        predicate_input = any((isinstance(n, ast.Name) and (
            env.get(n.id, Value()).trace or env.get(n.id, Value()).tag == "input-map"))
            or (isinstance(n, ast.Attribute) and n.attr in {"GET", "POST", "data", "query_params", "headers", "META", "body"}
                and isinstance(n.value, ast.Name) and env.get(n.value.id, Value()).tag == "request")
            for n in ast.walk(node))
        if condition.unknown and (condition.trace or predicate_input):
            self.note("INPUT_GUARD_UNRESOLVED")
            self.partial = True

    def returned(self, value):
        # Carry path uncertainty out of a helper instead of resetting it with the call frame.
        return replace(value, unknown=True) if self.partial else value

    def block(self, statements, env):
        returns = []
        for node in statements:
            self.tick()
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = self.expr(node.value, env)
                for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                    self.assign(target, self.step(value, node, "ASSIGNMENT"), env)
            elif isinstance(node, ast.AugAssign):
                left = self.expr(node.target, env)
                right = self.expr(node.value, env)
                self.assign(node.target, self.construct(left, right, node), env)
            elif isinstance(node, ast.Expr):
                self.expr(node.value, env)
            elif isinstance(node, ast.Return):
                returns.append(self.returned(self.expr(node.value, env)))
                return env, returns, True
            elif isinstance(node, ast.Raise):
                self.expr(node.exc, env)
                return env, returns, True
            elif isinstance(node, ast.If):
                condition = self.expr(node.test, env)
                self.guard_partial(condition, node.test, env)
                for context in self.contexts:
                    if len(context["checks"]) < 40:
                        context["checks"].append(self.loc(node.test, "CONDITIONAL_CHECK"))
                if condition.literal is not UNKNOWN:
                    env, found, end = self.block(node.body if bool(condition.literal) else node.orelse, env)
                    returns += found
                    if end:
                        return env, returns, True
                else:
                    before = self.partial
                    a, ra, ta = self.block(node.body, dict(env))
                    pa = self.partial
                    self.partial = before
                    b, rb, tb = self.block(node.orelse, dict(env))
                    pb = self.partial
                    returns += ra + rb
                    if ta and tb:
                        return env, returns, True
                    env = b if ta else a if tb else self.join_env(a, b)
                    self.partial = pb if ta else pa if tb else pa or pb
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                supported = True
                for item in node.items:
                    value = self.expr(item.context_expr, env)
                    supported &= value.tag == "cursor"
                    if item.optional_vars:
                        self.assign(item.optional_vars, value, env)
                self.partial |= not supported
                if not supported:
                    self.note("CONTEXT_MANAGER_UNRESOLVED")
                env, found, end = self.block(node.body, env)
                returns += found
                if end:
                    return env, returns, True
            elif isinstance(node, ast.Pass):
                pass
            else:
                # Unsupported control flow invalidates state; no invented safe transform or sink execution.
                self.note("UNSUPPORTED_STATEMENT_" + type(node).__name__.upper())
                env = {name: replace(value, unknown=True, literal=UNKNOWN, symbol="", tag="") for name, value in env.items()}
                self.partial = True
        return env, returns, False

    def join_env(self, a, b):
        return {k: merge(a.get(k, Value(unknown=True)), b.get(k, Value(unknown=True))) for k in a.keys() | b.keys()}

    def assign(self, node, value, env):
        if isinstance(node, ast.Name):
            env[node.id] = value
        elif isinstance(node, (ast.Tuple, ast.List)):
            if value.elements is not None and len(node.elts) == len(value.elements) and not value.unknown:
                for target, element in zip(node.elts, value.elements):
                    self.assign(target, self.step(element, target, "ASSIGNMENT"), env)
            else:
                self.note("UNPACKING_UNRESOLVED")
                for target in node.elts:
                    self.assign(target, replace(value, unknown=True, elements=None), env)
        else:
            self.note("MUTABLE_OBJECT_WRITE_UNRESOLVED")
            # Aliases may refer to the same mutated object. Invalidate conservatively.
            for key in env:
                env[key] = replace(env[key], unknown=True, literal=UNKNOWN, elements=None)

    def construct(self, a, b, node):
        result = merge(a, b)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) and isinstance(a.literal, str) and isinstance(b.literal, str):
            result = replace(result, literal=(a.literal + b.literal)[:10000])
        else:
            result = replace(result, literal=UNKNOWN)
        return self.step(result, node, "SQL_STRING_CONSTRUCTION")

    def expr(self, node, env):
        self.tick()
        if node is None:
            return Value(literal=None)
        if isinstance(node, ast.Constant):
            return Value(literal=node.value)
        if isinstance(node, ast.Name):
            return env.get(node.id, Value(symbol=node.id) if node.id in {"str", "int"} else Value(unknown=True))
        if isinstance(node, ast.NamedExpr):
            value = self.expr(node.value, env)
            self.assign(node.target, value, env)
            return value
        if isinstance(node, ast.Attribute):
            base = self.expr(node.value, env)
            if base.tag == "request" and not base.unknown:
                if node.attr in {"GET", "POST", "data", "query_params", "headers", "META", "body"}:
                    kind = "REQUEST_BODY" if node.attr in {"POST", "data", "body"} else "REQUEST_HEADER" if node.attr in {"headers", "META"} else "QUERY_PARAMETER"
                    return Value(trace=(self.loc(node, kind),), tag="input-map")
                if node.attr in {"user", "auth"}:
                    for context in self.contexts:
                        if len(context["checks"]) < 40:
                            context["checks"].append(self.loc(node, "LOGIN_CONTEXT_REFERENCE"))
            if base.tag == "cursor" and not base.unknown:
                return Value(tag="cursor-method", symbol=node.attr)
            if base.symbol:
                return Value(symbol=base.symbol + "." + node.attr, unknown=base.unknown,
                             tag="self-method" if base.tag == "self" else "")
            return replace(base, unknown=True, literal=UNKNOWN, tag="")
        if isinstance(node, ast.Subscript):
            base = self.expr(node.value, env)
            index = self.expr(node.slice, env)
            if base.tag == "input-map" and not base.unknown:
                return replace(base, tag="", literal=UNKNOWN)
            return replace(merge(base, index), unknown=True, literal=UNKNOWN, tag="", symbol="")
        if isinstance(node, ast.BinOp):
            left = self.expr(node.left, env)
            right = self.expr(node.right, env)
            value = self.construct(left, right, node)
            return value if isinstance(node.op, (ast.Add, ast.Mod)) else replace(value, unknown=True)
        if isinstance(node, (ast.JoinedStr, ast.FormattedValue)):
            if isinstance(node, ast.FormattedValue):
                value = self.expr(node.value, env)
                if node.format_spec:
                    value = merge(value, self.expr(node.format_spec, env))
                return value
            values = [self.expr(v, env) for v in node.values]
            return self.step(replace(merge(*values), literal=UNKNOWN), node, "SQL_STRING_CONSTRUCTION")
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            values = tuple(self.expr(n, env) for n in node.elts)
            return replace(merge(*values), tag="tuple" if isinstance(node, ast.Tuple) else "collection", literal=UNKNOWN,
                           elements=values if isinstance(node, (ast.List, ast.Tuple)) else None)
        if isinstance(node, ast.Dict):
            values = []
            for k, v in zip(node.keys, node.values):
                values += [self.expr(k, env), self.expr(v, env)]
            return replace(merge(*values), tag="collection", literal=UNKNOWN)
        if isinstance(node, ast.UnaryOp):
            value = self.expr(node.operand, env)
            if isinstance(node.op, ast.Not) and value.literal is not UNKNOWN:
                return Value(literal=not bool(value.literal))
            return replace(value, unknown=True, literal=UNKNOWN)
        if isinstance(node, ast.IfExp):
            condition = self.expr(node.test, env)
            if condition.literal is not UNKNOWN:
                return self.expr(node.body if bool(condition.literal) else node.orelse, env)
            a, b = dict(env), dict(env)
            self.guard_partial(condition, node.test, env)
            before = self.partial
            va = self.returned(self.expr(node.body, a))
            pa = self.partial
            self.partial = before
            vb = self.returned(self.expr(node.orelse, b))
            self.partial |= pa
            env.update(self.join_env(a, b))
            return merge(va, vb)
        if isinstance(node, ast.BoolOp):
            value = self.expr(node.values[0], env)
            for part in node.values[1:]:
                if value.literal is not UNKNOWN:
                    proceed = bool(value.literal) if isinstance(node.op, ast.And) else not bool(value.literal)
                    if not proceed:
                        break
                    value = self.expr(part, env)
                else:
                    self.guard_partial(value, node, env)
                    optional = dict(env)
                    other = self.returned(self.expr(part, optional))
                    env.update(self.join_env(env, optional))
                    value = merge(value, other)
            return value
        if isinstance(node, ast.Compare):
            left = self.expr(node.left, env)
            uncertain = False
            for op, item in zip(node.ops, node.comparators):
                branch = dict(env) if uncertain else env
                right = self.expr(item, branch)
                if uncertain:
                    env.update(self.join_env(env, branch))
                known = UNKNOWN
                if type(left.literal) in (str, int, bool) and type(right.literal) == type(left.literal):
                    a, b = left.literal, right.literal
                    if isinstance(op, ast.Eq): known = a == b
                    elif isinstance(op, ast.NotEq): known = a != b
                    elif isinstance(op, ast.Lt): known = a < b
                    elif isinstance(op, ast.Gt): known = a > b
                    elif isinstance(op, ast.LtE): known = a <= b
                    elif isinstance(op, ast.GtE): known = a >= b
                if known is False:
                    return Value(literal=False) if not uncertain else Value(unknown=True)
                uncertain |= known is UNKNOWN
                left = right
            return Value(unknown=True) if uncertain else Value(literal=True)
        if isinstance(node, ast.Call):
            return self.call(node, env)
        if isinstance(node, ast.Await):
            self.note("ASYNC_EXECUTION_UNRESOLVED")
            return replace(self.expr(node.value, env), unknown=True)
        self.note("UNSUPPORTED_EXPRESSION_" + type(node).__name__.upper())
        return Value(unknown=True)

    def call(self, node, env):
        # Capture receiver before evaluating arguments: arguments may reassign the receiver's variables.
        base = self.expr(node.func.value, env) if isinstance(node.func, ast.Attribute) else None
        name = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        if base is None:
            function = self.expr(node.func, env)
        else:
            function = Value(symbol=(base.symbol + "." + name) if base.symbol else "", unknown=base.unknown,
                             tag="self-method" if base.tag == "self" else "")
        args = [self.expr(a, env) for a in node.args]
        keywords = {k.arg: self.expr(k.value, env) for k in node.keywords}
        if any(isinstance(a, ast.Starred) for a in node.args) or None in keywords:
            self.note("VARIADIC_CALL_UNRESOLVED")
            return replace(merge(*(args + list(keywords.values()))), unknown=True)
        if base and base.tag == "input-map" and name in {"get", "getlist"} and not base.unknown:
            return replace(merge(base, *args), tag="", literal=UNKNOWN, symbol="")
        if function.symbol == "django.db.connection.cursor" and not function.unknown:
            return Value(tag="cursor")
        if base and base.tag == "cursor" and name in {"execute", "executemany"} and not base.unknown:
            query = args[0] if args else keywords.get("sql", Value(unknown=True))
            params = args[1] if len(args) > 1 else keywords.get("params")
            self.sink(node, query, params)
            return Value(unknown=True)
        # Manager identity must be a local Django model, not an arbitrary object with raw().
        if base and base.symbol.endswith(".objects") and name == "raw" and self.is_model(base.symbol[:-8]) and not base.unknown:
            query = args[0] if args else keywords.get("raw_query", Value(unknown=True))
            self.sink(node, query, args[1] if len(args) > 1 else keywords.get("params"), lazy=True)
            return Value(unknown=True)
        if base and base.symbol.endswith(".objects") and name in {"filter", "exclude", "get"} and self.is_model(base.symbol[:-8]) and not base.unknown:
            if len(self.sql) < MAX_RESULTS:
                location = self.loc(node, "ORM_VALUE_QUERY")
                self.sql.append(dict(kind="ORM_VALUE_QUERY", location=location, trace=[],
                    defenses=[self.loc(node, "ORM_VALUE_PARAMETERS")], limitations=["CUSTOM_MANAGER_AND_RUNTIME_NOT_VERIFIED"],
                    executionObserved=False, executionLocations=[]))
            return Value(unknown=True)
        if name == "format" and base and (isinstance(base.literal, str) or base.trace):
            return self.step(replace(merge(base, *args, *keywords.values()), literal=UNKNOWN, symbol="", tag=""), node, "SQL_STRING_CONSTRUCTION")
        if function.symbol == "str" and len(args) == 1:
            return replace(args[0], literal=UNKNOWN)
        if function.symbol == "int" and len(args) == 1 and not args[0].unknown:
            return Value(defenses=(self.loc(node, "NUMERIC_CONVERSION"),))
        if function.symbol in self.functions and not function.unknown:
            if function.tag == "self-method":
                args = [base] + args
            if isinstance(self.functions[function.symbol][1], ast.AsyncFunctionDef):
                self.note("ASYNC_EXECUTION_UNRESOLVED")
                return replace(merge(*args, *keywords.values()), unknown=True)
            return self.call_function(function.symbol, args, keywords)
        value = merge(*(args + list(keywords.values()) + ([base] if base else [])))
        self.note("CALL_TARGET_UNRESOLVED")
        if any(v.tag == "collection" for v in args + list(keywords.values()) + ([base] if base else [])):
            self.note("MUTABLE_OBJECT_WRITE_UNRESOLVED")
            for key, v in env.items():
                if v.tag == "collection":
                    env[key] = replace(v, unknown=True, elements=None)
        return replace(value, unknown=True, literal=UNKNOWN, symbol="", tag="")

    def is_model(self, key):
        if key not in self.classes:
            return False
        path, node = self.classes[key]
        return any(self.symbol(base, path) == "django.db.models.Model" for base in node.bases)

    def sink(self, node, query, params, lazy=False):
        self.traced.add((self.path, node.lineno))
        limitations = []
        if query.unknown:
            limitations.append("QUERY_HAS_UNRESOLVED_VALUES")
        if self.partial:
            limitations.append("EXECUTION_PATH_PARTIAL")
        if lazy:
            limitations.append("LAZY_RAW_EXECUTION_NOT_VERIFIED")
        location = self.loc(node, "SQL_EXECUTION_CALL")
        defenses = list(query.defenses)
        if params is not None:
            defenses.append(self.loc(node, "VALUE_BINDING"))
        kind = "UNRESOLVED_QUERY" if limitations else "INPUT_IN_QUERY" if query.trace else "PARAMETERIZED_QUERY" if params is not None else "STATIC_QUERY"
        record = dict(kind=kind, location=location, trace=list(query.trace), defenses=defenses, limitations=limitations,
                      executionObserved=not lazy, executionLocations=[] if lazy else [location])
        if len(self.sql) >= MAX_RESULTS:
            self.note("RESULT_LIMIT_EXCEEDED")
            return
        if record not in self.sql:
            self.sql.append(record)
        for context in self.contexts:
            if len(context["resources"]) < 40:
                context["resources"].append(location)
        if limitations:
            for reason in limitations:
                self.note(reason)
        if not query.trace or len(self.findings) >= MAX_RESULTS:
            return
        candidate = dict(ruleId="PY_SQL_INPUT_FLOW", kind="CWE-89", confidence="MEDIUM" if limitations else "HIGH",
                         disposition="REVIEW_REQUIRED", source=query.trace[0], sink=location, flow=list(query.trace),
                         defenses=defenses, limitations=limitations + ["STATIC_FLOW_NOT_EXPLOIT_PROOF"],
                         message="요청 값이 SQL 문자열로 전달되는 경로입니다. 미확인 처리와 실제 실행 환경을 함께 확인하세요.",
                         recommendation="SQL 문법은 고정하고 값은 execute(sql, params)로 분리하거나 Django ORM의 값 매개변수를 사용하세요.")
        if candidate not in self.findings:
            self.findings.append(candidate)


def main():
    # Limits constrain the trusted worker, not an OS sandbox. No target path is opened.
    resource.setrlimit(resource.RLIMIT_CPU, (6, 6))
    if sys.platform != "darwin":
        resource.setrlimit(resource.RLIMIT_AS, (384 * 1024 * 1024, 384 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    raw = sys.stdin.buffer.read(6_000_001)
    if len(raw) > 6_000_000:
        raise ValueError("INPUT_LIMIT")
    files = json.loads(raw)["files"]
    if len(files) > 100 or sum(len(f["content"]) for f in files) > 1_000_000:
        raise ValueError("SOURCE_LIMIT")
    for f in files:
        path = PurePosixPath(f["filePath"])
        if path.is_absolute() or ".." in path.parts or len(f["content"]) > 100_000:
            raise ValueError("INVALID_SOURCE")
    result = Analyzer(files).run()
    if sys.platform == "darwin":
        result["limitations"].append("RSS_CHECK_NOT_HARD_MEMORY_LIMIT")
    output = json.dumps(result, ensure_ascii=True)
    if len(output) > 2_000_000:
        raise ValueError("OUTPUT_LIMIT")
    sys.stdout.write(output)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # No source text, literals, identifiers, exceptions or environment values on stderr.
        sys.exit(2)
