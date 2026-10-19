"""Synthetic authorization evidence. None of the Django target code is imported/executed."""
import unittest
from worker import Analyzer

MODEL = """from django.db import models
from django.conf import settings
class Record(models.Model):
    holder = models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE)
"""
IMPORTS = """from records import Record
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.exceptions import PermissionDenied
"""


def run(body, permissions="IsAuthenticated", helpers="", extra=()):
    code = IMPORTS + helpers + "\n@api_view(['POST'])\n@permission_classes([" + permissions + "])\ndef endpoint(request):\n" + "\n".join("    " + line for line in body.splitlines())
    return Analyzer([dict(filePath="records.py",content=MODEL),dict(filePath="api.py",content=code),*extra]).run()


def detail(result):
    return result["authorizationContexts"][0]["details"]


def auth_findings(result):
    return [f for f in result["findings"] if f["ruleId"].startswith("PY_AUTHORIZATION")]


class AuthorizationTests(unittest.TestCase):
    def test_login_does_not_prove_object_permission(self):
        result=run("obj=Record.objects.get(pk=request.GET['key'])\nobj.delete()")
        self.assertEqual(detail(result)['authenticationStatus'],'DECLARED_LOGIN_REQUIRED')
        self.assertEqual(detail(result)['objectAuthorizationStatus'],'NOT_ESTABLISHED')
        self.assertFalse(auth_findings(result))

    def test_public_api_and_missing_checks_never_generate_idor(self):
        for permission in ('AllowAny',''):
            result=run("obj=Record.objects.get(pk=request.GET['key'])\nobj.delete()",permission)
            self.assertEqual(detail(result)['authenticationStatus'],'DECLARED_PUBLIC')
            self.assertFalse(auth_findings(result))

    def test_user_scope_requires_real_foreign_key_and_actual_principal(self):
        result=run("obj=Record.objects.filter(holder=request.user).get(pk=request.GET['key'])\nobj.delete()")
        self.assertEqual(detail(result)['accesses'][-1]['conclusion'],'USER_SCOPE_QUERY_EVIDENCE')
        self.assertFalse(auth_findings(result))
        result=run("obj=Record.objects.get(holder_id=request.user.pk,pk=request.GET['key'])\nobj.save()")
        self.assertEqual(detail(result)['accesses'][-1]['conclusion'],'USER_SCOPE_QUERY_EVIDENCE')
        result=run("obj=Record.objects.get(holder=request.GET['user'])\nobj.delete()")
        self.assertEqual(detail(result)['accesses'][-1]['conclusion'],'OBJECT_AUTHORIZATION_NOT_ESTABLISHED')

    def test_correct_owner_rejection_is_evidence_not_a_vulnerability(self):
        for op in ('!=','=='):
            body="obj=Record.objects.get(pk=request.GET['key'])\n"
            body += "if obj.holder_id != request.user.id:\n raise PermissionDenied()\nobj.delete()" if op=='!=' else "if obj.holder == request.user:\n obj.delete()\nelse:\n raise PermissionDenied()"
            result=run(body)
            self.assertTrue(any(a['conclusion']=='OWNER_GUARD_EVIDENCE' for a in detail(result)['accesses']))
            self.assertFalse(auth_findings(result))

    def test_inverted_owner_rejection_requires_following_mutation_and_input(self):
        result=run("obj=Record.objects.get(pk=request.GET['key'])\nif obj.holder_id == request.user.id:\n raise PermissionDenied()\nobj.delete()")
        self.assertEqual(len(auth_findings(result)),1)
        self.assertEqual(auth_findings(result)[0]['kind'],'CWE-863')
        self.assertEqual(detail(result)['objectAuthorizationStatus'],'RISK_LOGIC_CANDIDATE')
        result=run("obj=Record.objects.get(pk=1)\nif obj.holder_id == request.user.id:\n raise PermissionDenied()\nobj.delete()")
        self.assertFalse(auth_findings(result))

    def test_user_and_resource_primary_keys_are_not_owner_proof(self):
        result=run("obj=Record.objects.get(pk=request.GET['key'])\nif obj.pk != request.user.pk:\n raise PermissionDenied()\nobj.delete()")
        self.assertFalse(auth_findings(result))
        self.assertIn('RESOURCE_KEY_USER_KEY_NOT_OWNERSHIP_PROOF',[x['kind'] for x in detail(result)['ownershipComparisons']])

    def test_helper_guard_is_limited_to_proven_rejection(self):
        helper="def enforce(actor, item):\n if item.holder_id != actor.user.pk:\n  raise PermissionDenied()\n"
        result=run("obj=Record.objects.get(pk=request.GET['key'])\nenforce(request,obj)\nobj.delete()",helpers=helper)
        self.assertEqual(detail(result)['accesses'][-1]['conclusion'],'OWNER_GUARD_EVIDENCE')
        result=run("obj=Record.objects.get(pk=request.GET['key'])\nexternal_check(request,obj)\nobj.delete()")
        self.assertNotEqual(detail(result)['accesses'][-1]['conclusion'],'OWNER_GUARD_EVIDENCE')
        self.assertFalse(auth_findings(result))

    def test_role_guard_and_permission_declaration_do_not_claim_ownership(self):
        result=run("obj=Record.objects.get(pk=request.GET['key'])\nif not request.user.is_staff:\n raise PermissionDenied\nobj.delete()",'IsAdminUser')
        self.assertEqual(detail(result)['authenticationStatus'],'DECLARED_STAFF_REQUIRED')
        self.assertEqual(detail(result)['accesses'][-1]['conclusion'],'ROLE_GUARD_EVIDENCE')

    def test_login_guard_is_not_object_authorization_and_role_before_lookup_is_preserved(self):
        result=run("if not request.user.is_authenticated:\n raise PermissionDenied()\nobj=Record.objects.get(pk=request.GET['key'])\nobj.delete()",'AllowAny')
        self.assertEqual(detail(result)['accesses'][-1]['conclusion'],'OBJECT_AUTHORIZATION_NOT_ESTABLISHED')
        result=run("if not request.user.is_staff:\n raise PermissionDenied()\nobj=Record.objects.get(pk=request.GET['key'])\nobj.delete()")
        self.assertEqual(detail(result)['accesses'][-1]['conclusion'],'ROLE_GUARD_EVIDENCE')

    def test_separate_owner_scope_or_admin_constraint_prevents_inversion_candidate(self):
        body="obj=Record.objects.get(holder=request.user,pk=request.GET['key'])\nif obj.holder_id == request.user.id:\n raise PermissionDenied()\nobj.delete()"
        self.assertFalse(auth_findings(run(body)))
        self.assertFalse(auth_findings(run(body.replace('holder=request.user,',''),'IsAdminUser')))

    def test_branch_merge_does_not_leak_optional_guard(self):
        result=run("obj=Record.objects.get(pk=request.GET['key'])\nif flag:\n if obj.holder_id != request.user.id:\n  raise PermissionDenied()\nobj.delete()")
        self.assertNotEqual(detail(result)['accesses'][-1]['conclusion'],'OWNER_GUARD_EVIDENCE')
        self.assertFalse(auth_findings(result))

    def test_shadowed_denial_and_unknown_comparison_are_not_trusted(self):
        result=run("obj=Record.objects.get(pk=request.GET['key'])\nPermissionDenied=other_error\nif obj.holder_id != request.user.id:\n raise PermissionDenied()\nobj.delete()")
        self.assertNotEqual(detail(result)['accesses'][-1]['conclusion'],'OWNER_GUARD_EVIDENCE')
        self.assertFalse(auth_findings(result))

    def test_model_field_name_alone_is_not_ownership(self):
        code=IMPORTS+"\n@api_view(['POST'])\ndef endpoint(request):\n obj=Record.objects.get(pk=request.GET['key'])\n if obj.holder_id == request.user.id:\n  raise PermissionDenied()\n obj.delete()"
        result=Analyzer([dict(filePath='records.py',content=MODEL.replace("models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE)","models.CharField(max_length=30)")),dict(filePath='api.py',content=code)]).run()
        self.assertFalse(auth_findings(result))

    def test_unresolved_identifier_transform_cannot_be_high_risk_candidate(self):
        result=run("obj=Record.objects.get(pk=convert(request.GET['key']))\nif obj.holder_id == request.user.id:\n raise PermissionDenied()\nobj.delete()")
        self.assertFalse(auth_findings(result))
        self.assertEqual(detail(result)['accesses'][-1]['conclusion'],'ACCESS_FLOW_UNRESOLVED')

    def test_unknown_resource_mutation_cannot_keep_old_guard_as_proof(self):
        body="obj=Record.objects.get(pk=request.GET['key'])\nif obj.holder_id != request.user.id:\n raise PermissionDenied()\nexternal(obj)\nobj.delete()"
        result=run(body)
        self.assertEqual(detail(result)['accesses'][-1]['conclusion'],'ACCESS_FLOW_UNRESOLVED')
        result=run(body.replace('external(obj)','obj.holder = other'))
        self.assertEqual(detail(result)['accesses'][-1]['conclusion'],'ACCESS_FLOW_UNRESOLVED')

    def test_custom_model_manager_does_not_prove_user_filter_application(self):
        source=IMPORTS+"\n@api_view(['GET'])\ndef endpoint(request):\n obj=Record.objects.get(holder=request.user,pk=request.GET['key'])\n obj.delete()"
        model=MODEL.replace('class Record(models.Model):','class Record(models.Model):\n    objects = external_manager()')
        result=Analyzer([dict(filePath='records.py',content=model),dict(filePath='api.py',content=source)]).run()
        self.assertEqual(detail(result)['accesses'][-1]['conclusion'],'ACCESS_FLOW_UNRESOLVED')


if __name__=='__main__':
    unittest.main()
