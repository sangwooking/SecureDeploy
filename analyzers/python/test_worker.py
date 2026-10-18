"""Synthetic development regressions; none are private repository source."""
import json
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path
from worker import Analyzer


def analyze(body, extra=None):
    files = {
        "app/urls.py": "from django.urls import path\nfrom .views import endpoint\nurlpatterns=[path('items/<str:key>', endpoint)]",
        "app/views.py": "from django.db import connection\ndef endpoint(request, key):\n" + textwrap.indent(textwrap.dedent(body).strip(), "    "),
    }
    files.update(extra or {})
    return Analyzer([dict(filePath=p, content=c) for p, c in files.items()]).run()


def confirmed(result):
    return [f for f in result["findings"] if f["confidence"] == "HIGH"]


class FlowTest(unittest.TestCase):
    def test_unsafe_construction(self):
        for expression in ["'select ' + value", "f'select {value}'", "'select {}'.format(value)", "'select %s' % value"]:
            with self.subTest(expression=expression):
                r = analyze(f"value=request.GET.get('q')\nwith connection.cursor() as cursor:\n    cursor.execute({expression})")
                self.assertEqual(1, len(confirmed(r)))
                self.assertEqual("CWE-89", r["findings"][0]["kind"])

    def test_sources(self):
        for source in ["request.GET['q']", "request.POST.get('q')", "request.data['q']", "request.query_params.get('q')", "key"]:
            with self.subTest(source=source):
                self.assertEqual(1, len(confirmed(analyze(f"with connection.cursor() as c:\n    c.execute('select ' + {source})"))))

    def test_safe_binding_and_overwrite(self):
        for body in [
            "v=request.GET['q']\nwith connection.cursor() as c:\n    c.execute('select * from t where id=%s', [v])",
            "v=request.GET['q']\nv='fixed'\nwith connection.cursor() as c:\n    c.execute('select '+v)",
            "v=int(request.GET['q'])\nwith connection.cursor() as c:\n    c.execute(f'select {v}')",
            "from somewhere import Model\nreturn Model.objects.filter(id=request.GET['q'])",
        ]:
            with self.subTest(body=body):
                self.assertEqual([], analyze(body)["findings"])

    def test_binding_does_not_repair_constructed_query(self):
        self.assertEqual(1, len(confirmed(analyze("with connection.cursor() as c:\n    c.execute('select '+request.GET['q'], ['other'])"))))

    def test_cross_file_and_local_function(self):
        r = analyze("v=request.GET['q']\nreturn save(v)", {
            "app/views.py": "from django.db import connection\nfrom .db import save\ndef endpoint(request, key):\n    return save(request.GET['q'])",
            "app/db.py": "from django.db import connection\ndef save(value):\n    q='select '+value\n    with connection.cursor() as c:\n        c.execute(q)",
        })
        self.assertEqual(1, len(confirmed(r)))
        self.assertEqual("app/db.py", r["findings"][0]["sink"]["filePath"])

    def test_assignment_evaluation_order(self):
        for expression, count in [("v + (v := '0')", 1), ("(v := '0') + v", 0)]:
            with self.subTest(expression=expression):
                r = analyze(f"v=request.GET['q']\nwith connection.cursor() as c:\n    c.execute({expression})")
                self.assertEqual(count, len(confirmed(r)))

    def test_conditional_and_short_circuit(self):
        for condition, count in [("True", 0), ("False", 1), ("request.GET.get('flag')", 1)]:
            r = analyze(f"v=request.GET['q']\nif {condition}:\n    v='0'\nwith connection.cursor() as c:\n    c.execute('select '+v)")
            self.assertEqual(count, len(confirmed(r)))
        for expression, count in [("False and (v := '0')", 1), ("True and (v := '0')", 0), ("True or (v := '0')", 1)]:
            r = analyze(f"v=request.GET['q']\n{expression}\nwith connection.cursor() as c:\n    c.execute('select '+v)")
            self.assertEqual(count, len(confirmed(r)))

    def test_unknown_transform_is_not_safe_or_confirmed(self):
        r = analyze("v=unknown_transform(request.GET['q'])\nwith connection.cursor() as c:\n    c.execute('select '+v)")
        self.assertEqual([], confirmed(r))
        self.assertEqual(1, len(r["findings"]))
        self.assertEqual("UNRESOLVED_QUERY", r["sqlUses"][0]["kind"])

    def test_unknown_validation_guard_is_not_proven_unguarded_sql(self):
        r = analyze("v=request.GET['q']\nif not allowed(v):\n    return None\nwith connection.cursor() as c:\n    c.execute('select '+v)")
        self.assertEqual([], confirmed(r))
        self.assertTrue(r["findings"])
        self.assertEqual("UNRESOLVED_QUERY", r["sqlUses"][0]["kind"])
        r = analyze("v=request.GET['table']\nif v not in ['table_a', 'table_b']:\n    return None\nwith connection.cursor() as c:\n    c.execute('select * from '+v)")
        self.assertEqual([], confirmed(r))
        self.assertTrue(r["findings"])

    def test_dynamic_control_and_unrelated_execute_not_confirmed(self):
        r = analyze("v=request.GET['q']\nfor i in unknown:\n    v=change(v)\nwith connection.cursor() as c:\n    c.execute('select '+v)")
        self.assertEqual([], confirmed(r))
        self.assertEqual("PARTIAL", r["status"])
        self.assertEqual([], analyze("other.execute('select '+request.GET['q'])")["findings"])

    def test_local_shadowing(self):
        r = analyze("with connection.cursor() as c:\n    c.execute('select '+request.GET['q'])\nconnection=other")
        self.assertEqual([], confirmed(r))
        r = analyze("pass", {"app/views.py": "from django.db import connection\nconnection=unrelated\ndef endpoint(request, key):\n    with connection.cursor() as c:\n        c.execute('select '+key)"})
        self.assertEqual([], confirmed(r))
        self.assertTrue(any("MODULE_BINDING_REASSIGNED" in f["limitations"] for f in r["files"]))

    def test_comparison_short_circuit_preserves_input(self):
        r = analyze("v=request.GET['q']\n0 > 1 > (v := '0')\nwith connection.cursor() as c:\n    c.execute('select '+v)")
        self.assertEqual(1, len(confirmed(r)))

    def test_route_integer_converter_and_unknown_decorator(self):
        body = "with connection.cursor() as c:\n    c.execute('select %s' % key)"
        r = analyze(body, {"app/urls.py": "from django.urls import path\nfrom .views import endpoint\nurlpatterns=[path('<int:key>', endpoint)]"})
        self.assertEqual([], r["findings"])
        r = analyze("pass", {"app/views.py": "from django.db import connection\n@external_decorator\ndef endpoint(request, key):\n    with connection.cursor() as c:\n        c.execute('select '+key)"})
        self.assertEqual([], confirmed(r))
        self.assertTrue(r["findings"])

    def test_lazy_raw_and_orm_not_promoted(self):
        files = {"app/models.py": "from django.db import models\nclass Item(models.Model):\n    pass",
            "app/views.py": "from .models import Item\ndef endpoint(request, key):\n    return Item.objects.raw('select '+request.GET['q'])"}
        r = analyze("pass", files)
        self.assertEqual([], confirmed(r))
        self.assertIn("LAZY_RAW_EXECUTION_NOT_VERIFIED", r["sqlUses"][0]["limitations"])
        files["app/views.py"] = files["app/views.py"].replace("raw('select '+request.GET['q'])", "filter(id=request.GET['q'])")
        r = analyze("pass", files)
        self.assertEqual([], r["findings"])
        self.assertEqual("ORM_VALUE_QUERY", r["sqlUses"][0]["kind"])

    def test_recursion_and_work_budget_report_limits(self):
        r = analyze("pass", {"app/views.py": "from django.db import connection\ndef repeat(v):\n    return repeat(v)\ndef endpoint(request, key):\n    with connection.cursor() as c:\n        c.execute(repeat(request.GET['q']))"})
        self.assertEqual([], confirmed(r))
        self.assertTrue(any("CALL_DEPTH_EXCEEDED" in f["limitations"] for f in r["files"]))
        a = Analyzer([dict(filePath="f.py", content="from rest_framework.decorators import api_view\n@api_view(['GET'])\ndef f(request):\n    return request.GET['q']")])
        a.steps = 30001
        r = a.run()
        self.assertEqual("PARTIAL", r["status"])
        self.assertIn("ANALYSIS_BUDGET_EXCEEDED", r["files"][0]["limitations"])

    def test_class_views_router_and_auth_are_observations(self):
        for base, import_, route in [
            ("View", "from django.views import View", "urlpatterns=[path('', Endpoint.as_view())]"),
            ("APIView", "from rest_framework.views import APIView", "urlpatterns=[path('', Endpoint.as_view())]"),
            ("ViewSet", "from rest_framework.viewsets import ViewSet", "router=DefaultRouter()\nrouter.register('x', Endpoint)"),
        ]:
            method = "list" if base == "ViewSet" else "get"
            r = analyze("pass", {
                "app/urls.py": "from django.urls import path\nfrom rest_framework.routers import DefaultRouter\nfrom .views import Endpoint\n" + route,
                "app/views.py": f"{import_}\nfrom django.db import connection\nclass Endpoint({base}):\n    permission_classes=[IsAuthenticated]\n    def {method}(self, request):\n        if not request.user.is_authenticated:\n            return None\n        with connection.cursor() as c:\n            c.execute('select '+request.data['q'])",
            })
            self.assertEqual(1, len(confirmed(r)), base)
            self.assertEqual("NOT_ESTABLISHED", r["authorizationContexts"][0]["conclusion"])
            self.assertTrue(r["authorizationContexts"][0]["checks"])

    def test_parse_failure_no_execution(self):
        r = analyze("pass", {"app/views.py": "def incomplete("})
        self.assertEqual([], r["findings"])
        self.assertEqual("PARSE_FAILED", r["files"][1]["parseStatus"])
        r = analyze("pass", {"app/trap.py": "raise RuntimeError('TARGET_MUST_NOT_EXECUTE')"})
        self.assertNotIn("TARGET_MUST_NOT_EXECUTE", json.dumps(r))

    def test_worker_bounded_protocol(self):
        code = "from django.db import connection\nfrom rest_framework.decorators import api_view\n@api_view(['GET'])\ndef f(req):\n    with connection.cursor() as c:\n        c.execute('select '+req.GET['q'])"
        process = subprocess.run([sys.executable, "-I", "-S", "-B", str(Path(__file__).with_name("worker.py"))],
                                 input=json.dumps({"files":[{"filePath":"views.py", "content":code}]}), text=True, capture_output=True, timeout=10)
        self.assertEqual(0, process.returncode)
        self.assertEqual("", process.stderr)
        self.assertEqual(1, len(confirmed(json.loads(process.stdout))))


if __name__ == "__main__":
    unittest.main()
