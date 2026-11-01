// Trusted runner shipped by SecureDeploy. stdin contains data, never executable module paths.
import fs from 'node:fs';import{createRequire}from'node:module';import{spawnSync}from'node:child_process';
const require=createRequire('/usr/local/lib/node_modules/npm/package.json');const cacache=require('cacache');
const npmVersion=require('./package.json').version;
// Refuse execution if the daemon did not actually enforce the required Linux boundaries.
const status=fs.readFileSync('/proc/self/status','utf8');
const cg=file=>fs.readFileSync('/sys/fs/cgroup/'+file,'utf8').trim();
const cpu=cg('cpu.max').split(/\s+/).map(Number);
if(process.getuid()!==65532||!/^CapEff:\s+0+$/m.test(status)||!/^NoNewPrivs:\s+1$/m.test(status)
 ||cg('memory.max')==='max'||Number(cg('memory.max'))>536870912||cg('pids.max')==='max'||Number(cg('pids.max'))>32
 ||!cpu.every(Number.isFinite)||cpu[0]<=0||cpu[0]>cpu[1]||JSON.stringify(fs.readdirSync('/sys/class/net').filter(n=>{const f='/sys/class/net/'+n+'/flags';return fs.existsSync(f)&&(parseInt(fs.readFileSync(f,'utf8').trim(),16)&1);}).sort())!==JSON.stringify(['lo'])
 ||fs.existsSync('/var/run/docker.sock')||fs.existsSync('/Users')
 ||['OPENAI_API_KEY','DB_PASSWORD','DB_URL','GITHUB_TOKEN','GH_TOKEN','JWT_SECRET','WORKSPACE_KEY'].some(k=>process.env[k]!==undefined))throw Error('ISOLATION_POLICY_NOT_ENFORCED');
let readonly=false;try{fs.writeFileSync('/securedeploy-write-probe','owned');}catch(error){readonly=error.code==='EROFS';}if(!readonly)throw Error('ROOTFS_NOT_READONLY');
// BEGIN_INPUT
try {
let raw='';for await(const chunk of process.stdin){raw+=chunk;if(Buffer.byteLength(raw)>48*1024*1024)throw Error('INPUT_LIMIT');}
const input=JSON.parse(raw);if(typeof input.manifest!=='string'||typeof input.lockfile!=='string'||!Array.isArray(input.metadata)||input.metadata.length>64)throw Error('INPUT_FORMAT');
const namePattern=/^(?:@[a-zA-Z0-9_.-]+\/)?[a-zA-Z0-9_.-]+$/;
// Dependency names are bounded prefetch hints only; npm still resolves and the server validates the result.
const pickManifest=require('npm-pick-manifest'),known=new Map(input.metadata.map(row=>[row.name,JSON.parse(row.body)]));
const manifest=JSON.parse(input.manifest),lock=JSON.parse(input.lockfile),queue=[];
for(const section of ['dependencies','devDependencies'])for(const[name,spec]of Object.entries(manifest[section]??{}))if(lock.packages?.['']?.[section]?.[name]!==spec)queue.push([name,spec]);
const missingHints=[],visited=new Set();let steps=0;
while(queue.length){if(++steps>2000)throw Error('GRAPH_PREFETCH_LIMIT');const[name,spec]=queue.shift();if(!namePattern.test(name)||name.includes('..')||typeof spec!=='string'||!spec.match(/^[A-Za-z0-9.*~^<>=| ,+-]+$/))throw Error('REGISTRY_SEMVER_ONLY');const key=name+'@'+spec;if(visited.has(key))continue;visited.add(key);const packument=known.get(name);if(!packument){if(!missingHints.includes(name))missingHints.push(name);continue;}const chosen=pickManifest(packument,spec);const previouslyLocked=Object.entries(lock.packages??{}).some(([p,v])=>(p==='node_modules/'+name||p.endsWith('/node_modules/'+name))&&v.version===chosen.version);for(const section of['dependencies','optionalDependencies','peerDependencies']){if(previouslyLocked&&section==='optionalDependencies')continue;for(const row of Object.entries(chosen[section]??{})){if(section==='peerDependencies'&&chosen.peerDependenciesMeta?.[row[0]]?.optional&&!Object.entries(manifest.devDependencies??{}).some(([n,s])=>n===name&&s!==lock.packages?.['']?.devDependencies?.[n]))continue;queue.push(row);}}}
if(missingHints.length){console.log(JSON.stringify({status:'CACHE_MISS',missing:missingHints.slice(0,24)}));process.exit(0);}
for(const row of input.metadata){if(!namePattern.test(row.name)||row.name.includes('..')||typeof row.body!=='string')throw Error('CACHE_INPUT');const url='https://registry.npmjs.org/'+row.name.replace('/','%2f');await cacache.put('/cache/_cacache','make-fetch-happen:request-cache:'+url,Buffer.from(row.body),{metadata:{time:Date.now(),url,reqHeaders:{accept:'application/json'},resHeaders:{'content-type':'application/vnd.npm.install-v1+json','cache-control':'public, max-age=300'},options:{compress:true}}});}
fs.writeFileSync('/work/package.json',input.manifest,{flag:'wx'});fs.writeFileSync('/work/package-lock.json',input.lockfile,{flag:'wx'});fs.writeFileSync('/tmp/user.npmrc','');fs.writeFileSync('/tmp/global.npmrc','');
const child=spawnSync('/usr/local/bin/node',['/usr/local/lib/node_modules/npm/bin/npm-cli.js','install','--loglevel=http','--offline','--full-metadata','--package-lock-only','--ignore-scripts','--no-audit','--no-fund','--strict-peer-deps','--engine-strict','--registry=https://registry.npmjs.org/','--userconfig=/tmp/user.npmrc','--globalconfig=/tmp/global.npmrc','--cache=/cache'],{cwd:'/work',env:{PATH:'/usr/local/bin:/usr/bin:/bin',HOME:'/tmp',LANG:'en_US.UTF-8'},encoding:'utf8',timeout:25000,maxBuffer:262144});
if(child.status!==0){const missing=[];for(const line of(child.stderr??'').split('\n')){if(!line.includes('ENOTCACHED')&&!line.includes('request to '))continue;for(const match of line.matchAll(/https:\/\/registry\.npmjs\.org\/[^\s]+/g)){try{const u=new URL(match[0]);if(u.protocol==='https:'&&u.hostname==='registry.npmjs.org'&&!u.port&&!u.username&&!u.password&&!u.search&&!u.hash){const name=decodeURIComponent(u.pathname.slice(1));if(namePattern.test(name)&&!name.includes('..')&&!missing.includes(name))missing.push(name);}}catch{}}}
 console.log(JSON.stringify({status:missing.length?'CACHE_MISS':'FAILED',missing:missing.slice(0,24),reason:child.error?.code==='ETIMEDOUT'?'TIMEOUT':'OFFLINE_NPM_REJECTED'}));
}else{const names=fs.readdirSync('/work').sort();if(JSON.stringify(names)!==JSON.stringify(['package-lock.json','package.json']))throw Error('OUTPUT_FILES');const files={};for(const name of names){const stat=fs.lstatSync('/work/'+name);if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||stat.size>262144)throw Error('OUTPUT_LIMIT');files[name]=fs.readFileSync('/work/'+name).toString('base64');}console.log(JSON.stringify({status:'SUCCESS',files,npmVersion,nodeVersion:process.version}));}

} catch(error) {console.log(JSON.stringify({status:"FAILED",reason:["EFBIG","ENOSPC","ENOMEM","EMFILE"].includes(error.code)?"RESOURCE_LIMIT":"INPUT_OR_OUTPUT_REJECTED"}));}
