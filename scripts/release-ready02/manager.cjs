const fs=require('fs'),cp=require('child_process'),assert=require('assert/strict'),crypto=require('crypto'),path=require('path');
const root='/private/tmp/securedeploy-ready02-evidence',runtime='/private/tmp/securedeploy-ready02-runtime',repo='/private/tmp/securedeploy-release-ready02',java='/opt/homebrew/opt/openjdk@17/bin/java',base='http://127.0.0.1:58230';
const hash=x=>crypto.createHash('sha256').update(x).digest('hex'),sleep=ms=>new Promise(r=>setTimeout(r,ms));let child;
const env={...process.env};for(const k of ['OPENAI_API_KEY','SECUREDEPLOY_AI_OPENAI_API_KEY','SECUREDEPLOY_EDITING_PERSISTENCE_KEY'])delete env[k];
const pg=['-h','127.0.0.1','-p','58220','-U','ai05_fixture'];
function sql(q,db='ready02_fixture'){return cp.execFileSync('/opt/homebrew/bin/psql',[...pg,'-d',db,'-XqAt','-v','ON_ERROR_STOP=1','-c',q],{encoding:'utf8'}).trim();}
function inventory(){return Object.fromEntries(['users','projects','reviews','vulnerabilities','editing_workspace_v1'].map(t=>[t,sql(`select md5(coalesce(string_agg(h,'' order by h),'')) from (select md5(row_to_json(t)::text) h from ${t} t)x`)]));}
async function http(route,method='GET',body,token,raw){let headers={};if(token)headers.Authorization='Bearer '+token;if(body && !(body instanceof FormData)){headers['Content-Type']='application/json';body=JSON.stringify(body);}const r=await fetch(base+route,{method,headers,body,signal:AbortSignal.timeout(65000)});let bytes=Buffer.from(await r.arrayBuffer());return{status:r.status,headers:r.headers,body:raw?bytes:bytes.length?JSON.parse(bytes.toString()):null};}
async function stop(){if(child){const p=child;child=null;if(p.exitCode!==null||p.signalCode)return;p.kill('SIGTERM');await Promise.race([new Promise(r=>p.once('exit',r)),sleep(15000)]);}}
async function start(mode){await stop();const log=fs.openSync(root+'/'+mode+'-server.log','a');let args;
const common=['--server.address=127.0.0.1','--server.port=58230','--spring.datasource.url=jdbc:postgresql://127.0.0.1:58220/ready02_fixture','--spring.datasource.username=ai05_fixture','--spring.datasource.password=','--spring.datasource.driver-class-name=org.postgresql.Driver','--spring.jpa.hibernate.ddl-auto=validate','--spring.sql.init.mode=never','--securedeploy.jwt.secret=ai02-synthetic-isolated-only-signing-key-0000001','--securedeploy.ai.provider=TEMPLATE','--securedeploy.ai.openai.api-key=','--securedeploy.github.app.enabled=false','--securedeploy.threat-intelligence.enabled=false','--securedeploy.sca.enabled=false','--logging.level.root=OFF','--spring.main.banner-mode=off'];
if(mode==='old')args=['-Xmx384m','-jar','/Users/sangwoo__o/.local/share/securedeploy/cutover/2026-10-31-ux03/release/backend.jar',...common,'--securedeploy.typescript.analyzer-directory=/private/tmp/securedeploy-ux03/analyzers/typescript'];
else if(mode==='recovery')args=['-Xmx384m','-jar',repo+'/build/libs/securedeploy-backend-0.0.1-SNAPSHOT.jar',...common,'--spring.profiles.active=release-recovery'];
else args=['-Xmx384m','-cp',[runtime+'/classes',...JSON.parse(fs.readFileSync(root+'/classpath.json'))].join(':'),'com.securedeploy.editing.ReadyServer'];
child=cp.spawn(java,args,{cwd:repo,env:{...env,READY_MODE:mode==='compatible'?'compatible':'normal'},stdio:['ignore',log,log]});fs.closeSync(log);
for(let i=0;i<200;i++){if(child.exitCode!==null)throw Error('SERVER_EXIT_'+mode);try{const r=await http('/api/ui-capabilities');if([200,401,403].includes(r.status))return;}catch{}await sleep(100);}throw Error('START_TIMEOUT_'+mode);}
async function login(email){const r=await http('/api/auth/login','POST',{email,password:'Synthetic-AI02-135!'});assert.equal(r.status,200);return r.body.accessToken;}
async function get(url,token){const r=await http(url,'GET',null,token);assert.equal(r.status,200,url+':'+r.status);return r.body;}
async function upload(url,token){const f=new FormData();f.append('file',new Blob([fs.readFileSync(root+'/CONTROL.zip')]),'control.zip');const r=await http(url,'POST',f,token);assert.equal(r.status,200,url+':'+r.status);return r.body;}

module.exports={start,stop,http,get,login,upload,sql,inventory,sleep,env,hash,server:()=>child,clear:()=>{child=null;}};
