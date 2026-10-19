"""Later-authored variants, not an independent external authorization benchmark."""
import unittest
from test_authorization import run, detail, auth_findings


class AuthorizationVariations(unittest.TestCase):
    def test_declared_evaluation_matrix(self):
        cases=[
            ("item=Record.objects.get(pk=request.GET['entry'])\nif item.holder==request.user:\n raise PermissionDenied()\nitem.save()",'', 'CANDIDATE'),
            ("actor=request.user\nitem=Record.objects.get(pk=request.GET['entry'])\nsubject=item.holder_id\nif subject==actor.pk:\n raise PermissionDenied\nitem.delete()",'', 'CANDIDATE'),
            ("item=Record.objects.filter(holder_id=request.user.id).get(pk=request.GET['entry'])\nitem.save()",'', 'PROTECTION'),
            ("item=Record.objects.get(pk=request.GET['entry'])\nif item.holder!=request.user:\n return HttpResponseForbidden()\nitem.delete()",'from django.http import HttpResponseForbidden\n','PROTECTION'),
            ("if not request.user.is_superuser:\n raise PermissionDenied\nitem=Record.objects.get(pk=request.GET['entry'])\nitem.save()",'', 'PROTECTION'),
            ("item=Record.objects.get(pk=request.GET['entry'])\nverify(request,item)\nitem.delete()",'def verify(actor, entry):\n if entry.holder_id!=actor.user.id:\n  raise PermissionDenied\n','PROTECTION'),
            ("item=Record.objects.get(pk=request.GET['entry'])\nitem.delete()",'', 'UNKNOWN'),
            ("item=Record.objects.get(pk=request.GET['entry'])\ncheck_in_middleware(request,item)\nitem.delete()",'', 'UNKNOWN'),
            ("item=Record.objects.get(pk=request.GET['entry'])\nif item.pk!=request.user.id:\n raise PermissionDenied\nitem.delete()",'', 'UNKNOWN'),
            ("item=Record.objects.get(pk=request.GET['entry'])\nif item.holder_id!=request.user.id and extra_check:\n raise PermissionDenied\nitem.delete()",'', 'UNKNOWN'),
            ("return 'public status'",'', 'PUBLIC'),
            ("return {'status':'ok'}",'', 'PUBLIC'),
        ]
        counts=dict(CANDIDATE=0,PROTECTION=0,UNKNOWN=0,PUBLIC=0)
        for index,(body,helpers,expected) in enumerate(cases):
            result=run(body,'AllowAny' if expected=='PUBLIC' else 'IsAuthenticated',helpers)
            context=detail(result)
            observed='CANDIDATE' if auth_findings(result) else 'PROTECTION' if any(a['conclusion'] in {'USER_SCOPE_QUERY_EVIDENCE','OWNER_GUARD_EVIDENCE','ROLE_GUARD_EVIDENCE'} for a in context['accesses']) else 'PUBLIC' if context['authenticationStatus']=='DECLARED_PUBLIC' and not context['accesses'] else 'UNKNOWN'
            self.assertEqual(observed,expected,f'variant {index}')
            counts[observed]+=1
        print('Authorization synthetic variants:',counts,'unexpected Findings=0; missed expected review candidates=0; UNKNOWN is not vulnerability-free')

    def test_context_record_limits_are_visible(self):
        result=run('\n'.join("item=Record.objects.get(pk=request.GET['key'])" for _ in range(60)))
        self.assertEqual(len(detail(result)['accesses']),40)
        self.assertIn('AUTH_DETAIL_LIMIT',detail(result)['limitations'])
        self.assertTrue(any('AUTH_DETAIL_LIMIT' in f['limitations'] for f in result['files']))


if __name__=='__main__':
    unittest.main()
