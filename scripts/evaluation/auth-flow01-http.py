"""Executes ONLY the owned fixture next to this script using an existing Django runtime.
Usage: PYTHON script.py NEW_PRIVATE_DIRECTORY PUBLIC_RESULT_JSON
No supplied project is imported; SQLite and all credentials are synthetic.
"""
import sys,json,threading,urllib.request,urllib.error,urllib.parse,hashlib,shutil
from pathlib import Path
from wsgiref.simple_server import make_server,WSGIRequestHandler
private,output=map(Path,sys.argv[1:]);private.mkdir(exist_ok=True);app=private/'owned-http';assert not app.exists(),'new output directory required'
shutil.copytree(Path(__file__).parent/'fixtures/auth-flow01/owned',app);sys.path.insert(0,str(app))
urls="from django.urls import path\nfrom lab import views_before as before, views_fixed as fixed\nurlpatterns=[]\nfor prefix,module in [('before',before),('fixed',fixed)]:\n for name in ['read','update','delete','staff','public']:\n  urlpatterns.append(path(prefix+'/'+name+'/<int:key>',getattr(module,name)))\n urlpatterns.append(path(prefix+'/health',module.health))\n"
(app/'urls.py').write_text(urls)
from django.conf import settings
settings.configure(SECRET_KEY='auth-flow01-owned-only-signing-key',DEBUG=False,ROOT_URLCONF='urls',ALLOWED_HOSTS=['127.0.0.1'],INSTALLED_APPS=['django.contrib.auth','django.contrib.contenttypes','lab'],DATABASES={'default':{'ENGINE':'django.db.backends.sqlite3','NAME':str(app/'synthetic.sqlite3')}},MIDDLEWARE=['django.contrib.sessions.middleware.SessionMiddleware','django.contrib.auth.middleware.AuthenticationMiddleware'],SESSION_ENGINE='django.contrib.sessions.backends.signed_cookies',PASSWORD_HASHERS=['django.contrib.auth.hashers.MD5PasswordHasher'])
import django;django.setup()
from django.core.management import call_command
from django.db import connection
call_command('migrate',verbosity=0)
from lab.models import Asset
with connection.schema_editor() as editor:editor.create_model(Asset)
from django.contrib.auth.models import User
from django.test import Client
users={n:User.objects.create_user(n,is_staff=n=='admin') for n in ['A','B','admin']};cookies={}
for name,user in users.items():
 c=Client();c.force_login(user);cookies[name]='; '.join(k+'='+m.value for k,m in c.cookies.items())
from django.core.wsgi import get_wsgi_application
class Quiet(WSGIRequestHandler):
 def log_message(self,*args):pass
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args):return None
server=make_server('127.0.0.1',0,get_wsgi_application(),handler_class=Quiet);threading.Thread(target=server.serve_forever,daemon=True).start();rows=[]
try:
 for phase in ['before','fixed']:
  for actor in ['A','B']:
   for owner in ['A','B']:
    for operation,method in [('read','GET'),('update','POST'),('delete','DELETE')]:
     obj=Asset.objects.create(holder=users[owner],label='original');want=(403 if actor==owner else 200) if phase=='before'and operation=='delete' else 200 if phase=='before'or actor==owner else 403
     url=f'/{phase}/{operation}/{obj.pk}';data=b'label=updated'if method=='POST'else None;headers={'Cookie':cookies[actor],'Content-Type':'application/x-www-form-urlencoded'}
     req=urllib.request.Request('http://127.0.0.1:'+str(server.server_port)+url,data=data,method=method,headers=headers)
     try:r=urllib.request.build_opener(NoRedirect).open(req,timeout=3)
     except urllib.error.HTTPError as e:r=e
     body=r.read();assert r.code==want,(phase,actor,owner,operation,r.code,want)
     exists=Asset.objects.filter(pk=obj.pk).exists()
     if r.code==403:assert exists and Asset.objects.get(pk=obj.pk).label=='original'
     elif operation=='delete':assert not exists
     elif operation=='update':assert Asset.objects.get(pk=obj.pk).label=='updated'
     rows.append(dict(phase=phase,actor=actor,owner=owner,operation=operation,status=r.code,unauthorizedSuccess=actor!=owner and r.code==200))
  for actor,path,want in [('admin','staff',200),('A','staff',403),('anonymous','read',302),('anonymous','public',200)]:
   obj=Asset.objects.create(holder=users['B'],label='public-or-staff');req=urllib.request.Request(f'http://127.0.0.1:{server.server_port}/{phase}/{path}/{obj.pk}',headers={'Cookie':cookies.get(actor,'')})
   try:r=urllib.request.build_opener(NoRedirect).open(req,timeout=3)
   except urllib.error.HTTPError as e:r=e
   assert r.code==want,(actor,path,r.code);r.read();rows.append(dict(phase=phase,actor=actor,operation=path,status=r.code,expected=want))
  for suffix,want in [('read/999999',404),('read/not-an-id',404),('health',200)]:
   req=urllib.request.Request(f'http://127.0.0.1:{server.server_port}/{phase}/{suffix}',headers={'Cookie':cookies['A']})
   try:r=urllib.request.build_opener(NoRedirect).open(req,timeout=3)
   except urllib.error.HTTPError as e:r=e
   body=r.read();assert r.code==want
   if suffix=='health':assert json.loads(body)=={'ready':True,'count':12}
   rows.append(dict(phase=phase,actor='A',operation=suffix,status=r.code,expected=want))
finally:server.shutdown();server.server_close()
output.write_text(json.dumps(dict(passed=True,scope='OWNED_DJANGO_ACTUAL_LOOPBACK_HTTP_SQLITE',django=django.get_version(),newSoftwareInstalled=False,cases=len(rows),rows=rows,sourceHashes={str(p.relative_to(app)):hashlib.sha256(p.read_bytes()).hexdigest()for p in app.rglob('*.py')},routeDenominatorFromOwnedUrlDeclarations=12,sourcePolicy='Owner-only ordinary endpoints; staff-only and intentionally public endpoints separate',passwordLoginTest=False,operatingDb=False),indent=2));print('OWNED_AUTH_HTTP_PASS',len(rows))
