"""Independent owner-policy review evidence, never a missing-guard IDOR Finding."""
import unittest
from test_authorization import run, detail, auth_findings
class OwnerReviewTests(unittest.TestCase):
 def test_request_keyed_delete_retains_owner_uncertainty(self):
  r=run("obj=Record.objects.get(pk=request.GET['key'])\nobj.delete()")
  d=detail(r)
  self.assertEqual(d['objectAuthorizationStatus'],'OWNER_POLICY_REVIEW_REQUIRED')
  self.assertEqual(d['accesses'][-1]['conclusion'],'REQUEST_KEYED_WRITE_OWNER_POLICY_REVIEW_REQUIRED')
  self.assertTrue(d['accesses'][-1]['identifierInputs'])
  self.assertFalse(auth_findings(r))
 def test_scoped_or_unknown_helper_is_not_missing_owner_proof(self):
  d=detail(run("obj=Record.objects.filter(holder=request.user).get(pk=request.GET['key'])\nobj.delete()"))
  self.assertEqual(d['accesses'][-1]['conclusion'],'USER_SCOPE_QUERY_EVIDENCE')
  r=run("obj=Record.objects.get(pk=resolve_key(request.GET['key']))\nobj.delete()")
  self.assertNotEqual(detail(r)['accesses'][-1]['conclusion'],'REQUEST_KEYED_WRITE_OWNER_POLICY_REVIEW_REQUIRED')
  self.assertFalse(auth_findings(r))
