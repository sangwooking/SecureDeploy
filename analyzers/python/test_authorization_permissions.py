import unittest
from worker import Analyzer
from test_authorization import MODEL, detail, auth_findings


def view(code, extras=()):
    prefix="from records import Record\nfrom rest_framework.views import APIView\nfrom rest_framework.viewsets import ViewSet\nfrom rest_framework.routers import SimpleRouter\nfrom rest_framework.decorators import action\nfrom rest_framework.permissions import IsAuthenticated,IsAdminUser,AllowAny\nfrom rest_framework.exceptions import PermissionDenied\nfrom django.urls import path\n"
    return Analyzer([dict(filePath='records.py',content=MODEL),dict(filePath='views.py',content=prefix+code),*extras]).run()


class PermissionTests(unittest.TestCase):
    def test_view_class_and_explicit_queryset_call(self):
        result=view("class Endpoint(APIView):\n permission_classes=[IsAuthenticated]\n def get_queryset(self):\n  return Record.objects.filter(holder=self.request.user)\n def get(self,request):\n  item=self.get_queryset().get(pk=request.GET['key'])\n  item.delete()\nurlpatterns=[path('record',Endpoint.as_view())]")
        self.assertEqual(detail(result)['permissionSource'],'VIEW_CLASS')
        self.assertEqual(detail(result)['accesses'][-1]['conclusion'],'USER_SCOPE_QUERY_EVIDENCE')
        self.assertFalse(auth_findings(result))

    def test_object_permission_call_is_not_owner_policy_proof(self):
        result=view("class Endpoint(APIView):\n permission_classes=[IsAuthenticated]\n def get_object(self):\n  obj=Record.objects.get(pk=self.request.GET['key'])\n  self.check_object_permissions(self.request,obj)\n  return obj\n def get(self,request):\n  obj=self.get_object()\n  obj.delete()\nurlpatterns=[path('record',Endpoint.as_view())]")
        self.assertTrue(any(a['conclusion']=='OBJECT_CHECK_CALLED_POLICY_UNKNOWN' for a in detail(result)['accesses']))
        self.assertFalse(auth_findings(result))

    def test_action_overrides_class_but_custom_get_permissions_overrides_action(self):
        base="class Endpoint(ViewSet):\n permission_classes=[AllowAny]\n @action(detail=True,permission_classes=[IsAuthenticated])\n def erase(self,request,pk=None):\n  obj=Record.objects.get(pk=pk)\n  obj.delete()\n"
        router="router=SimpleRouter()\nrouter.register('record',Endpoint)"
        result=view(base+router)
        self.assertEqual(detail(result)['permissionSource'],'ACTION_DECORATOR')
        self.assertEqual(detail(result)['authenticationStatus'],'DECLARED_LOGIN_REQUIRED')
        result=view(base+" def get_permissions(self):\n  if self.action=='erase':\n   return [IsAdminUser()]\n  return [AllowAny()]\n"+router)
        self.assertEqual(detail(result)['permissionSource'],'GET_PERMISSIONS')
        self.assertEqual(detail(result)['authenticationStatus'],'DECLARED_STAFF_REQUIRED')

    def test_dynamic_permissions_and_external_inheritance_stay_unknown(self):
        result=view("class Endpoint(APIView):\n permission_classes=[IsAuthenticated]\n def get_permissions(self):\n  return policy_factory()\n def get(self,request):\n  return request.user\nurlpatterns=[path('record',Endpoint.as_view())]")
        self.assertEqual(detail(result)['authenticationStatus'],'UNKNOWN')
        self.assertEqual(detail(result)['permissionSource'],'GET_PERMISSIONS')
        self.assertFalse(auth_findings(result))

    def test_global_default_candidates_never_assert_active_environment(self):
        result=view("class Endpoint(APIView):\n def get(self,request):\n  return request.user\nurlpatterns=[path('record',Endpoint.as_view())]",[dict(filePath='configuration.py',content="REST_FRAMEWORK={'DEFAULT_PERMISSION_CLASSES':['rest_framework.permissions.IsAuthenticated']}")])
        self.assertEqual(detail(result)['authenticationStatus'],'UNKNOWN')
        self.assertEqual(detail(result)['permissionSource'],'GLOBAL_CANDIDATE_ACTIVATION_UNKNOWN')
        self.assertEqual(detail(result)['permissionDeclarations'][0]['permissions'],['IsAuthenticated'])

    def test_reversed_decorator_order_is_not_applied_permission_proof(self):
        source="from rest_framework.decorators import permission_classes,api_view\nfrom rest_framework.permissions import IsAuthenticated\n@permission_classes([IsAuthenticated])\n@api_view(['GET'])\ndef endpoint(request):\n return request.user"
        result=Analyzer([dict(filePath='view.py',content=source)]).run()
        self.assertEqual(detail(result)['authenticationStatus'],'UNKNOWN')
        self.assertIn('PERMISSION_DECORATOR_ORDER_UNKNOWN',detail(result)['limitations'])

    def test_django_login_decorator_is_separate_from_resource_permission(self):
        source="from django.contrib.auth.decorators import login_required\nfrom django.urls import path\n@login_required\ndef endpoint(request):\n return request.user\nurlpatterns=[path('x',endpoint)]"
        result=Analyzer([dict(filePath='view.py',content=source)]).run()
        self.assertEqual(detail(result)['authenticationStatus'],'DECLARED_LOGIN_REQUIRED')
        self.assertEqual(detail(result)['objectAuthorizationStatus'],'NO_RESOURCE_ACCESS_TRACED')

    def test_unknown_mixin_cannot_turn_declared_permissions_into_effective_login_proof(self):
        result=view("class Endpoint(ExternalMixin,APIView):\n permission_classes=[IsAuthenticated]\n def get(self,request):\n  return request.user\nurlpatterns=[path('record',Endpoint.as_view())]")
        self.assertEqual(detail(result)['authenticationStatus'],'UNKNOWN')
        self.assertIn('PERMISSION_INHERITANCE_OR_DISPATCH_UNKNOWN',detail(result)['limitations'])


if __name__=='__main__':
    unittest.main()
