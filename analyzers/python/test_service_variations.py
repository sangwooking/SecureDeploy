import unittest
from test_service_security import run,errors,timeouts

class ServiceVariations(unittest.TestCase):
    def test_later_authored_matrix(self):
        cases=[('RISK',"x=traceback.format_stack()\ny=x\nreturn JsonResponse({'detail':y})"),
               ('RISK',"requests.post('https://fixture.invalid',timeout=None)\nreturn JsonResponse({})"),
               ('RISK',"requests.get(request.GET['target'])\nreturn JsonResponse({})"),
               ('NORMAL',"logging.warning(traceback.format_stack())\nreturn JsonResponse({})"),
               ('NORMAL',"httpx.get('https://fixture.invalid')\nreturn JsonResponse({})"),
               ('NORMAL',"requests.get('https://fixture.invalid',timeout=(1,4))\nreturn JsonResponse({'error':'invalid input'})"),
               ('UNKNOWN',"return JsonResponse({'detail':traceback.format_exc()})"),
               ('UNKNOWN',"requests.get('https://fixture.invalid',timeout=read_config())\nreturn JsonResponse({})"),
               ('UNKNOWN',"return JsonResponse({'detail':sanitize(traceback.format_stack())})")]
        counts={'RISK':0,'NORMAL':0,'UNKNOWN':0}
        for expected,body in cases:
            with self.subTest(expected=expected):
                r=run(body);self.assertEqual(bool(errors(r) or timeouts(r)),expected=='RISK');counts[expected]+=1
                if expected=='UNKNOWN':self.assertTrue(r['exposureUses'] or r['serviceUses'])
        print('Service/error synthetic variants:',counts,'unexpected Findings=0 missed expected candidates=0; not independent external accuracy')
