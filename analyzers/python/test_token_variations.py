"""Later-authored synthetic variations; not external/blind real-world accuracy evidence."""
import unittest
from test_token_security import run, findings, DECODE, GUARD


class TokenVariations(unittest.TestCase):
    def test_later_authored_risk_normal_and_uncertain_matrix(self):
        cases = [
            ('RISK', DECODE.replace('claims','profile')+GUARD.replace('claims','profile'), ''),
            ('RISK', "claims=unpack(request.body)\n"+GUARD, "def unpack(blob):\n return jwt.decode(blob,options={'verify_signature':False})\n"),
            ('RISK', "seed='fixture-only-material-not-real'\nreturn jwt.encode({},seed,algorithm='HS512')", ''),
            ('NORMAL', DECODE+"return claims.get('display_name')", ''),
            ('NORMAL', "claims=jwt.decode(request.body,key=os.environ['TEST_KEY'],algorithms=['RS256'])\n"+GUARD, ''),
            ('NORMAL', "return jwt.encode({},os.getenv('TEST_KEY'),algorithm='HS256')", ''),
            ('NORMAL', "return jwt.encode({},'example',algorithm='HS256')", ''),
            ('UNKNOWN', "claims=jwt.decode(request.body,verify=False)\n"+GUARD, ''),
            ('UNKNOWN', "claims=jwt.decode(request.body,options=get_settings())\n"+GUARD, ''),
            ('UNKNOWN', DECODE+"claims=custom_verifier(claims)\n"+GUARD, ''),
            ('UNKNOWN', "return jwt.encode({},'fixture-only',headers={'alg':'none'})", ''),
            ('UNKNOWN', DECODE+"if request.GET['extra']:\n claims=external_verify(claims)\n"+GUARD, ''),
        ]
        counts = {'RISK':0,'NORMAL':0,'UNKNOWN':0}
        for expected, body, helpers in cases:
            with self.subTest(expected=expected, body=body):
                result=run(body,helpers)
                self.assertEqual(bool(findings(result)),expected=='RISK')
                self.assertTrue(result['tokenUses'])
                counts[expected]+=1
        print('Token synthetic variations:',counts,'unexpected Findings=0; missed expected candidates=0; UNKNOWN is not safe; not independent external evaluation')
