"""Minimal synthetic sources; neither target code nor credentials are executed/validated."""
import json
import unittest
from worker import Analyzer


FAKE = 'ghp_' + 'a' * 36
def run(body, helpers=''):
    code = "import os\nimport logging\nfrom django.conf import settings\nfrom django.http import JsonResponse\nfrom rest_framework.response import Response\nfrom rest_framework.decorators import api_view\n"+helpers+"\n@api_view(['GET'])\ndef endpoint(request):\n"+'\n'.join('    '+line for line in body.splitlines())
    return Analyzer([dict(filePath='api.py',content=code)]).run()
def findings(result):
    return [f for f in result['findings'] if f['ruleId']=='PY_SENSITIVE_DATA_EXPOSURE']


class ExposureTests(unittest.TestCase):
    def test_credential_shape_to_response_or_log_has_locations_not_values(self):
        for end in ("return JsonResponse({'value':key})", "logging.warning('value=%s',key)\nreturn Response({})", "print(key)\nreturn Response({})"):
            result=run('key='+repr(FAKE)+'\n'+end)
            self.assertEqual(len(findings(result)),1)
            self.assertNotIn(FAKE,json.dumps(result))
            self.assertEqual(result['exposureUses'][0]['status'],'SENSITIVE_FLOW_CANDIDATE')

    def test_framework_setting_and_authentication_header_not_arbitrary_names(self):
        for value in ("settings.SECRET_KEY", "request.headers['Authorization']", "request.META.get('HTTP_AUTHORIZATION')"):
            self.assertEqual(len(findings(run('return Response('+value+')'))),1)
        for value in ("request.GET['Authorization']", "request.GET['password']", "'public-example-identifier'", "os.getenv('API_KEY')", "request.body"):
            self.assertFalse(findings(run('return Response('+value+')')),value)

    def test_constructing_unused_response_is_not_sending_it(self):
        result=run('key='+repr(FAKE)+"\nResponse(key)\nreturn Response('ok')")
        self.assertFalse(findings(result))

    def test_helper_alias_and_overwrite(self):
        helper="def reply(value):\n return JsonResponse({'value':value})\n"
        result=run('key='+repr(FAKE)+'\nreturn reply(key)',helper)
        self.assertEqual(len(findings(result)),1)
        self.assertIn('FUNCTION_ARGUMENT',[loc['kind'] for loc in result['exposureUses'][0]['trace']])
        self.assertFalse(findings(run('key='+repr(FAKE)+"\nkey='public'\nreturn Response(key)")))

    def test_unknown_masking_does_not_claim_safety_or_confirm_leak(self):
        result=run('key='+repr(FAKE)+'\nreturn Response(mask(key))')
        self.assertFalse(findings(result))
        self.assertEqual(result['exposureUses'][0]['status'],'FLOW_UNRESOLVED')

    def test_logging_instance_shadowing_and_disabled_branch(self):
        self.assertEqual(len(findings(run('logger=logging.getLogger(__name__)\nlogger.error(settings.SECRET_KEY)\nreturn Response({})'))),1)
        self.assertEqual(len(findings(run('logger.error(settings.SECRET_KEY)\nreturn Response({})','logger=logging.getLogger(__name__)\n'))),1)
        self.assertFalse(findings(run('if False:\n logging.error(settings.SECRET_KEY)\nreturn Response({})')))
        self.assertFalse(findings(run('logging=custom_logger()\nlogging.error(settings.SECRET_KEY)\nreturn Response({})')))
        uncertain=run('if settings.DEBUG:\n logging.info(settings.SECRET_KEY)\nreturn Response({})')
        self.assertFalse(findings(uncertain));self.assertEqual(uncertain['exposureUses'][0]['status'],'FLOW_UNRESOLVED')
        self.assertFalse(findings(run('return JsonResponse({"value":settings.SECRET_KEY},encoder=custom_encoder)')))

    def test_no_secret_in_name_only_and_normal_diagnostic_logs(self):
        self.assertFalse(findings(run("password='example'\nlogging.info('ready',42)\nreturn Response(password)")))

    def test_environment_observation_does_not_prove_sensitive_value(self):
        result=run("return Response(os.environ['PUBLIC_URL'])")
        self.assertFalse(findings(result))
        self.assertEqual(result['exposureUses'][0]['trace'][0]['kind'],'ENVIRONMENT_VALUE_UNVERIFIED')
