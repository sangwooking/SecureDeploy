"""Independent synthetic source oracles and in-memory A/B owner-policy execution; no Django/project imports."""
import ast, hashlib, importlib.util, json, pathlib, sys, time, types
worker=pathlib.Path(sys.argv[1]);output=pathlib.Path(sys.argv[2])
sys.path.insert(0,str(worker.parent));spec=importlib.util.spec_from_file_location('dplus_trusted_python_worker',worker);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
model="from django.db import models\nfrom django.conf import settings\nclass Asset(models.Model):\n owner=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE)\n"
header="from inventory import Asset\nfrom rest_framework.decorators import api_view,permission_classes\nfrom rest_framework.permissions import IsAuthenticated\nfrom rest_framework.exceptions import PermissionDenied\n"
rows=[]
for name,op,truth in [('owner-rejection','!=',False),('inverted-owner-rejection','==',True),('authentication-only',None,True)]:
 body="obj=Asset.objects.get(pk=request.GET['asset'])\n"+("if obj.owner_id "+op+" request.user.id:\n raise PermissionDenied()\n" if op else "")+"obj.delete()"
 source=header+"@api_view(['DELETE'])\n@permission_classes([IsAuthenticated])\ndef remove(request):\n"+'\n'.join(' '+line for line in body.splitlines())+'\n'
 files=[dict(filePath='inventory.py',content=model),dict(filePath='api.py',content=source)];start=time.perf_counter();result=module.Analyzer(files).run();duration=(time.perf_counter()-start)*1000
 # Execute ONLY our isolated function AST, with an in-memory manager and explicit owner-only oracle.
 node=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef));node.decorator_list=[]
 class Denied(Exception):pass
 matrix=[]
 for user in ('A','B'):
  for owner in ('A','B'):
   state={'deleted':False}
   def delete():state['deleted']=True
   class Manager:
    def get(self,**kwargs):return types.SimpleNamespace(owner_id=owner,delete=delete)
   scope={'__builtins__':{},'Asset':types.SimpleNamespace(objects=Manager()),'PermissionDenied':Denied};exec(compile(ast.Module(body=[node],type_ignores=[]),'<OWN_SYNTHETIC_POLICY>','exec'),scope)
   request=types.SimpleNamespace(user=types.SimpleNamespace(id=user),GET={'asset':'fixture-object'})
   try:scope['remove'](request);denied=False
   except Denied:denied=True
   matrix.append(dict(user=user,owner=owner,allowed=state['deleted'],expected=user==owner,denied=denied))
 detected=any(f['ruleId'].startswith('PY_AUTHORIZATION') and f['confidence']=='HIGH' for f in result['findings']);actualUnsafe=any(r['allowed'] and not r['expected'] for r in matrix)
 assert actualUnsafe==truth
 rows.append(dict(id=name,oracle='Explicit synthetic owner-only deletion policy; authentication assumed established for both test principals',truth=truth,classification=('TP' if detected else 'FN') if truth else ('FP' if detected else 'TN'),runtimeMatrix=matrix,wallMs=duration,sourceHashes={f['filePath']:hashlib.sha256(f['content'].encode()).hexdigest() for f in files},files=files,analysis=result))
for safe in [False,True]:
 source="from django.db import connection\ndef lookup(request,key):\n with connection.cursor() as cursor:\n  "+("cursor.execute('select label from assets where code=%s',[key])" if safe else "cursor.execute('select label from assets where code='+key)")
 files=[dict(filePath='routes/urls.py',content="from django.urls import path\nfrom .views import lookup\nurlpatterns=[path('assets/<str:key>',lookup)]"),dict(filePath='routes/views.py',content=source)]
 result=module.Analyzer(files).run();detected=any('SQL' in f['ruleId'] and f['confidence']=='HIGH' for f in result['findings'])
 rows.append(dict(id='django-bound' if safe else 'django-concat',truth=not safe,classification=('TN' if not detected else 'FP') if safe else ('TP' if detected else 'FN'),oracle='Code-reviewed query construction/binding; no production DB used',files=files,analysis=result))
counts={k:sum(r['classification']==k for r in rows)for k in ['TP','FP','TN','FN','UNKNOWN']};output.write_text(json.dumps(dict(origin='new synthetic Python evaluation, not a real Django deployment',counts=counts,rows=rows),indent=2));print(counts)
