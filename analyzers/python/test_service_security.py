import unittest
from worker import Analyzer

def run(body,helpers=''):
    source='import traceback\nimport requests\nimport httpx\nimport logging\nfrom django.http import JsonResponse\nfrom rest_framework.decorators import api_view\n'+helpers+'\n@api_view(["GET"])\ndef endpoint(request):\n'+'\n'.join('    '+line for line in body.splitlines())
    return Analyzer([dict(filePath='api.py',content=source)]).run()
def errors(r):return [f for f in r['findings'] if f['ruleId']=='PY_ERROR_DETAIL_EXPOSURE']
def timeouts(r):return [f for f in r['findings'] if f['ruleId']=='PY_HTTP_TIMEOUT_REVIEW']

class ServiceTests(unittest.TestCase):
    def test_stack_in_return_is_not_an_unused_response_or_internal_log(self):
        self.assertEqual(len(errors(run("return JsonResponse({'stack':traceback.format_stack()})"))),1)
        for body in ("JsonResponse({'stack':traceback.format_stack()})\nreturn JsonResponse({})", "logging.error(traceback.format_stack())\nreturn JsonResponse({})", "return JsonResponse({'error':'invalid request'})"):
            self.assertFalse(errors(run(body)))

    def test_exc_requires_supported_active_exception_not_a_name_or_outside_handler(self):
        r=run("try:\n raise ValueError('fixture')\nexcept Exception:\n return JsonResponse({'error':traceback.format_exc()})")
        self.assertEqual(len(errors(r)),1)
        self.assertFalse(errors(run("return JsonResponse({'error':traceback.format_exc()})")))
        unknown=run("try:\n external()\nexcept Exception:\n return JsonResponse({'error':traceback.format_exc()})")
        self.assertFalse(errors(unknown));self.assertIn('UNSUPPORTED_STATEMENT_TRY',unknown['files'][0]['limitations'])

    def test_unknown_masking_debug_branch_and_reassignment(self):
        for body in ("return JsonResponse({'error':mask(traceback.format_stack())})", "if external_debug():\n return JsonResponse({'error':traceback.format_stack()})\nreturn JsonResponse({})", "x=traceback.format_stack()\nx='generic'\nreturn JsonResponse({'error':x})"):
            self.assertFalse(errors(run(body)))

    def test_requests_and_httpx_defaults_are_different(self):
        req=run("requests.get('https://fixture.invalid')\nreturn JsonResponse({})")
        htx=run("httpx.get('https://fixture.invalid')\nreturn JsonResponse({})")
        self.assertEqual(len(timeouts(req)),1);self.assertFalse(timeouts(htx))
        self.assertEqual(htx['serviceUses'][0]['status'],'HTTPX_DEFAULT_INACTIVITY_TIMEOUT')

    def test_explicit_disable_bounded_tuple_dynamic_and_input(self):
        for lib in ('requests','httpx'):
            self.assertEqual(len(timeouts(run(lib+".get(request.GET['url'],timeout=None)\nreturn JsonResponse({})"))),1)
            self.assertFalse(timeouts(run(lib+".get(request.GET['url'],timeout=4)\nreturn JsonResponse({})")))
            r=run(lib+".get(request.GET['url'],timeout=external_settings())\nreturn JsonResponse({})")
            self.assertFalse(timeouts(r));self.assertEqual(r['serviceUses'][0]['status'],'TIMEOUT_SETTING_UNRESOLVED')
        self.assertFalse(timeouts(run("requests.get('https://fixture.invalid',timeout=(2,5))\nreturn JsonResponse({})")))

    def test_helpers_unresolved_branches_and_custom_clients(self):
        helper="def outbound(url):\n return requests.get(url,timeout=None)\n"
        self.assertEqual(len(timeouts(run("outbound(request.GET['url'])\nreturn JsonResponse({})",helper))),1)
        self.assertFalse(timeouts(run("if external_guard(request):\n requests.get('https://fixture.invalid',timeout=None)\nreturn JsonResponse({})")))
        self.assertFalse(timeouts(run("custom_client.get(request.GET['url'])\nreturn JsonResponse({})")))

    def test_no_error_or_timeout_contents_in_snapshot(self):
        import json
        marker='fixture-only-internal-error-text'
        r=run("try:\n raise RuntimeError('"+marker+"')\nexcept RuntimeError:\n return JsonResponse({'error':traceback.format_exc()})")
        self.assertEqual(len(errors(r)),1);self.assertNotIn(marker,json.dumps(r))
