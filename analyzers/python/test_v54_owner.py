import unittest
from test_authorization import run,detail,auth_findings,MODEL,IMPORTS
from worker import Analyzer
class OwnerV54Tests(unittest.TestCase):
 def test_shortcut_unscoped_is_review_not_confirmed_idor(self):
  r=run("obj=get_object_or_404(Record,pk=request.GET['key'])\nobj.delete()",helpers='from django.shortcuts import get_object_or_404')
  self.assertEqual(detail(r)['objectAuthorizationStatus'],'OWNER_POLICY_REVIEW_REQUIRED');self.assertFalse(auth_findings(r))
 def test_shortcut_scopes_from_real_user_relation(self):
  for body in ["obj=get_object_or_404(Record,pk=request.GET['key'],holder=request.user)\nobj.save()","scope=Record.objects.filter(holder=request.user)\nobj=get_object_or_404(scope,pk=request.GET['key'])\nobj.delete()"]:
   d=detail(run(body,helpers='from django.shortcuts import get_object_or_404'));self.assertEqual(d['accesses'][-1]['conclusion'],'USER_SCOPE_QUERY_EVIDENCE')
 def test_query_identifier_survives_filter_first_chain(self):
  d=detail(run("obj=Record.objects.filter(pk=request.GET['key']).first()\nobj.delete()"));self.assertTrue(d['accesses'][-1]['identifierInputs']);self.assertEqual(d['objectAuthorizationStatus'],'OWNER_POLICY_REVIEW_REQUIRED')
 def test_bulk_query_writes_respect_scope(self):
  for scoped in [True,False]:
   body="Record.objects.filter(pk=request.GET['key']"+(",holder=request.user" if scoped else "")+").update(label='changed')"
   d=detail(run(body));self.assertEqual(d['accesses'][-1]['operation'],'BULK_WRITE');self.assertEqual(d['accesses'][-1]['conclusion'],'USER_SCOPE_QUERY_EVIDENCE' if scoped else 'REQUEST_KEYED_WRITE_OWNER_POLICY_REVIEW_REQUIRED')
 def test_wrong_object_or_late_check_does_not_protect_write(self):
  for body in ["a=Record.objects.get(pk=request.GET['a'])\nb=Record.objects.get(pk=request.GET['b'])\nif a.holder_id != request.user.id:\n raise PermissionDenied()\nb.delete()","a=Record.objects.get(pk=request.GET['a'])\na.delete()\nif a.holder_id != request.user.id:\n raise PermissionDenied()"]:
   d=detail(run(body));self.assertEqual(next(a for a in d['accesses'] if a['operation']=='DELETE')['conclusion'],'REQUEST_KEYED_WRITE_OWNER_POLICY_REVIEW_REQUIRED')
 def test_cross_file_guard_helper_is_bound_to_actual_object(self):
  helper='from rest_framework.exceptions import PermissionDenied\ndef ensure(obj,user):\n if obj.holder_id != user.id:\n  raise PermissionDenied()\n'
  r=run("obj=Record.objects.get(pk=request.GET['key'])\nensure(obj,request.user)\nobj.delete()",helpers='from security import ensure',extra=[dict(filePath='security.py',content=helper)])
  self.assertEqual(detail(r)['accesses'][-1]['conclusion'],'OWNER_GUARD_EVIDENCE');self.assertFalse(auth_findings(r))
 def test_relation_is_required_not_owner_name(self):
  r=run("obj=get_object_or_404(Record,pk=request.GET['key'],owner=request.user)\nobj.delete()",helpers='from django.shortcuts import get_object_or_404');self.assertNotEqual(detail(r)['accesses'][-1]['conclusion'],'USER_SCOPE_QUERY_EVIDENCE')
 def test_int_url_key_remains_object_access_evidence(self):
  files=[dict(filePath='records.py',content=MODEL),dict(filePath='views.py',content=IMPORTS+'\ndef endpoint(request,key):\n obj=Record.objects.get(pk=key)\n obj.delete()'),dict(filePath='urls.py',content="from django.urls import path\nfrom views import endpoint\nurlpatterns=[path('r/<int:key>',endpoint)]")]
  d=detail(Analyzer(files).run());self.assertTrue(d['accesses'][-1]['identifierInputs']);self.assertEqual(d['objectAuthorizationStatus'],'OWNER_POLICY_REVIEW_REQUIRED')
