"""Same-process-shape isolated subprocess measurements, no target imports/execution."""
import sys,json,subprocess,pathlib,hashlib
model='from django.db import models\nfrom django.conf import settings\nclass Record(models.Model):\n holder=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE)\n'
header='from records import Record\nfrom rest_framework.decorators import api_view\n'
scenarios=[]
for name,body in [('queryset-chain',"q=Record.objects.filter(holder=request.user)\n"+"q=q.filter(pk=request.GET['key'])\n"*60+"obj=q.first()\nobj.delete()"),('branches',"obj=Record.objects.get(pk=request.GET['key'])\n"+"if request.GET['flag']:\n x=1\nelse:\n x=2\n"*25+"obj.delete()"),('large-file',"obj=Record.objects.get(pk=request.GET['key'])\n"+"label='normal'\n"*5000+"obj.delete()"),('cycle',"return relay(request)")]:
 files=[dict(filePath='records.py',content=model),dict(filePath='api.py',content=header+'@api_view(["POST"])\ndef endpoint(request):\n'+'\n'.join(' '+l for l in body.splitlines()))]
 if name=='cycle':files[1]['content']='from helper import relay\n'+files[1]['content'];files.append(dict(filePath='helper.py',content='def relay(request):\n return relay(request)'))
 scenarios.append(dict(name=name,files=files))
code='''import sys,json,importlib.util,time,resource,pathlib
p=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(p.parent));spec=importlib.util.spec_from_file_location('perf_worker',p);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
c=json.load(sys.stdin);first=None;times=[]
for _ in range(3):
 start=time.perf_counter();r=m.Analyzer(c['files']).run();times.append((time.perf_counter()-start)*1000)
 if first is not None:assert first==r
 first=r
print(json.dumps(dict(version=first['analyzerVersion'],wallMs=times,maxRssNative=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,status=first['status'],limitations=first['limitations'],fileLimitations=[f['limitations'] for f in first['files']])))'''
rows=[]
for cohort,worker in [('v53',sys.argv[1]),('v54',sys.argv[2])]:
 for s in scenarios:
  r=subprocess.run([sys.executable,'-c',code,worker],input=json.dumps(s),text=True,capture_output=True,timeout=20);assert r.returncode==0,r.stderr;rows.append(dict(cohort=cohort,scenario=s['name'],inputHash=hashlib.sha256(json.dumps(s,sort_keys=True).encode()).hexdigest(),**json.loads(r.stdout)))
pathlib.Path(sys.argv[3]).write_text(json.dumps(dict(scope='Four synthetic stress inputs, three deterministic repetitions in separate same-host Python processes; no production SLA claim',rssUnit='bytes on Darwin, KiB on Linux',rows=rows),indent=2));print('PYTHON_STABILITY_PASS',len(rows))
