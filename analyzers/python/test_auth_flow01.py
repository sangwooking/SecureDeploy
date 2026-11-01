"""Owned policy variants; no absence-based vulnerability claims."""
import unittest
from test_authorization import run,detail,auth_findings
class AuthFlow01Tests(unittest.TestCase):
 def analyze(self,body,permissions='IsAuthenticated',**kw):return run(body,permissions,helpers='from django.http import JsonResponse\n'+kw.pop('helpers',''),**kw)
 def test_read_records_response_sink_and_owner_guard_after_lookup(self):
  lookup="obj=Record.objects.get(pk=request.GET['key'])\n"
  for guard,want in [('', 'REQUEST_KEYED_READ_OWNER_POLICY_REVIEW_REQUIRED'),("if obj.holder_id != request.user.id:\n raise PermissionDenied()\n",'OWNER_GUARD_EVIDENCE')]:
   r=self.analyze(lookup+guard+"return JsonResponse({'label':obj.label})");d=detail(r);self.assertEqual(d['accesses'][-1]['operation'],'READ_RESPONSE');self.assertEqual(d['accesses'][-1]['conclusion'],want);self.assertFalse(auth_findings(r))
 def test_public_read_never_becomes_confirmed_vulnerability(self):
  r=self.analyze("obj=Record.objects.get(pk=request.GET['key'])\nreturn JsonResponse({'label':obj.label})",'AllowAny');self.assertEqual(detail(r)['authenticationStatus'],'DECLARED_PUBLIC');self.assertFalse(auth_findings(r))
 def test_wrong_object_or_late_guard_cannot_hide_unprotected_response(self):
  for body in ["a=Record.objects.get(pk=request.GET['a'])\nb=Record.objects.get(pk=request.GET['b'])\nif a.holder_id != request.user.id:\n raise PermissionDenied()\nreturn JsonResponse({'value':b.label})","obj=Record.objects.get(pk=request.GET['key'])\nreturn JsonResponse({'value':obj.label})\nif obj.holder_id != request.user.id:\n raise PermissionDenied()"]:
   d=detail(self.analyze(body));self.assertEqual(d['accesses'][-1]['conclusion'],'REQUEST_KEYED_READ_OWNER_POLICY_REVIEW_REQUIRED');self.assertEqual(d['objectAuthorizationStatus'],'OWNER_POLICY_REVIEW_REQUIRED')
 def test_cross_file_service_and_guard_preserve_object_identity(self):
  service="from records import Record\ndef load(key):\n return Record.objects.get(pk=key)\n"
  guard="from rest_framework.exceptions import PermissionDenied\ndef ensure(obj,user):\n if obj.holder_id != user.id:\n  raise PermissionDenied()\n"
  r=self.analyze("obj=load(request.GET['key'])\nensure(obj,request.user)\nreturn JsonResponse({'label':obj.label})",helpers='from service import load\nfrom security import ensure',extra=[dict(filePath='service.py',content=service),dict(filePath='security.py',content=guard)])
  d=detail(r);self.assertEqual(d['accesses'][-1]['conclusion'],'OWNER_GUARD_EVIDENCE');self.assertEqual(d['accesses'][-1]['resourceLocation']['filePath'],'service.py');self.assertTrue(any(c['filePath']=='security.py'for c in d['accesses'][-1]['checks']))
 def test_unknown_transform_does_not_invent_read_projection(self):
  d=detail(self.analyze("obj=Record.objects.get(pk=request.GET['key'])\nreturn JsonResponse(serialize(obj))"));self.assertFalse(any(a['operation']=='READ_RESPONSE'for a in d['accesses']));self.assertIn('RESPONSE_PROJECTION_UNRESOLVED',d['limitations'])
 def test_partial_guard_is_not_full_authorization(self):
  d=detail(self.analyze("obj=Record.objects.get(pk=request.GET['key'])\nif request.GET['check'] == 'yes':\n if obj.holder_id != request.user.id:\n  raise PermissionDenied()\nreturn JsonResponse({'label':obj.label})"));self.assertNotEqual(d['accesses'][-1]['conclusion'],'OWNER_GUARD_EVIDENCE')
