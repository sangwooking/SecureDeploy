"""Later-authored synthetic variations, not externally independent evaluation."""
import unittest
from test_exposure import run,findings,FAKE

class ExposureVariations(unittest.TestCase):
    def test_later_matrix(self):
        cases=[
            ('RISK',"x=settings.SECRET_KEY\ny=x\nreturn JsonResponse({'result':y})"),
            ('RISK',"return Response(request.headers.get('Authorization'))"),
            ('RISK','logger=logging.getLogger(__name__)\nx='+repr(FAKE)+"\nlogger.warning('%s',x)\nreturn Response({})"),
            ('NORMAL',"return JsonResponse({'token':'public-client-id'})"),
            ('NORMAL',"return Response(request.GET.get('secret'))"),
            ('NORMAL',"value=settings.SECRET_KEY\nvalue='hidden'\nreturn Response(value)"),
            ('UNKNOWN',"return JsonResponse({'data':os.getenv('PRIVATE_CONFIG')})"),
            ('UNKNOWN',"return Response(redact(settings.SECRET_KEY))"),
            ('UNKNOWN',"if external_condition(request):\n return Response(settings.SECRET_KEY)\nreturn Response({})"),
        ]
        counts={'RISK':0,'NORMAL':0,'UNKNOWN':0}
        for expected,body in cases:
            with self.subTest(expected=expected,body=body):
                result=run(body);self.assertEqual(bool(findings(result)),expected=='RISK');counts[expected]+=1
                if expected=='UNKNOWN':self.assertTrue(result['exposureUses'])
        print('Python exposure synthetic variants:',counts,'FP=0 FN=0 in labeled supported cases; not external independent accuracy')
