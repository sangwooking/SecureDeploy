// Authored static ground truth. Frozen before the #26 implementation, not independent review.
const express=body=>({files:[{filePath:'server.cjs',content:`const app=require('express')();const fs=require('node:fs');const path=require('node:path');app.post('/files',(req,res)=>{${body}});`}],nodeManifests:[{filePath:'package.json',express:'4.18.0'}]});
export const file26Cases=[];
for(const [id,truth,body,reason] of [
 ['read','RISK','fs.readFileSync(req.query.name);','Request controls filesystem name'],
 ['write','RISK',"fs.writeFileSync(req.body.name,'fixed');",'Request controls destination, not merely file content'],
 ['delete','RISK','fs.unlinkSync(req.params.name);','Request controls delete path'],
 ['join','RISK',"fs.readFileSync(path.join('/srv/data',req.query.name));",'Parent traversal survives joining'],
 ['resolve','RISK',"fs.readFileSync(path.resolve('/srv/data',req.query.name));",'Absolute paths or parent traversal can escape'],
 ['normalize','RISK','fs.readFileSync(path.normalize(req.query.name));','Normalization does not confine'],
 ['alias','RISK','const p=req.query.name;const box={p};fs.createReadStream(box.p);','Object member carries input'],
 ['helper','RISK','function load(p){fs.readFileSync(p)}load(req.query.name);','Bounded helper receives input'],
 ['choice','RISK',"const p=req.body.flag?'/srv/data/fixed':req.body.name;fs.readFileSync(p);",'Reachable user-controlled arm'],
 ['overwrite-risk','RISK',"let p='/srv/data/fixed';p=req.body.name;fs.unlinkSync(p);",'Later request assignment wins'],
 ['rename','RISK',"fs.rename(req.body.old,'/srv/data/new',()=>{});",'Request controls source of move'],
 ['rename-target','RISK',"fs.rename('/srv/data/old',req.body.name,()=>{});",'Request controls target of move'],
 ['prefix','RISK',"const p=path.resolve('/srv/data',req.body.name);if(!p.startsWith('/srv/data'))return;fs.readFileSync(p);",'Sibling directory prefix is not containment'],
 ['replaced-after-check','RISK',"let p=path.resolve('/srv/data',req.body.name);const rel=path.relative('/srv/data',p);if(rel.startsWith('..')||path.isAbsolute(rel))return;p=req.body.other;fs.readFileSync(p);",'New path is unrelated to checked value'],
 ['fixed','NORMAL',"fs.readFileSync('/srv/data/fixed');",'No request influence on filename'],
 ['content-only','NORMAL',"fs.writeFileSync('/srv/data/fixed',req.body.text);",'Content is not path'],
 ['overwrite-fixed','NORMAL',"let p=req.body.name;p='/srv/data/fixed';fs.readFileSync(p);",'Fixed overwrite removes path influence'],
 ['fixed-choice','NORMAL',"const p=req.body.flag?'/srv/data/a':'/srv/data/b';fs.readFileSync(p);",'All alternatives fixed'],
 ['disconnected','NORMAL',"const p=req.body.name;fs.readFileSync('/srv/data/a');",'Unused input is not a sink path'],
 ['relative-guard','NORMAL',"const p=path.resolve('/srv/data',req.body.name);const rel=path.relative('/srv/data',p);if(rel.startsWith('..')||path.isAbsolute(rel))return;fs.readFileSync(p);",'Lexical confinement on supported runtime paths; symlink/permissions separate'],
 ['constant-map','NORMAL',"const p=req.body.id==='a'?'/srv/data/a':'/srv/data/b';fs.readFileSync(p);",'ID selects fixed names'],
 ['lookalike','NORMAL',"const other={readFileSync(x){return x}};other.readFileSync(req.body.name);",'Not a filesystem API'],
 ['basename','UNKNOWN',"fs.readFileSync(path.join('/srv/data',path.basename(req.body.name)));",'Dot names/platform/symlink and intended file access remain unresolved'],
 ['win32-basename','UNKNOWN',"fs.readFileSync(path.join('/srv/data',path.win32.basename(req.body.name)));",'Explicit Windows syntax does not establish POSIX storage policy'],
 ['sanitizer','UNKNOWN','fs.readFileSync(clean(req.body.name));','Unverified helper may constrain or alter path'],
 ['mutated-api','UNKNOWN','fs.readFileSync=external;fs.readFileSync(req.body.name);','Sink implementation changed'],
 ['dynamic-storage','UNKNOWN','storage.save(req.body.name);','External storage API not proven'],
 ['realpath','RISK',"const p=fs.realpathSync(req.body.name);fs.readFileSync(p);",'Realpath without containment still permits attacker-selected existing files'],
 ['originalname','RISK',"fs.writeFileSync('/srv/data/'+req.file.originalname,'fixed');",'If verified multipart middleware, originalname controls path; currently no middleware proof'],
 ['generated-file','NORMAL',"fs.writeFileSync('/srv/data/server-generated-id','fixed');",'Server controls storage name, not an uploaded original name'],
])file26Cases.push({id:'path-'+id,track:'PATH',truth,reason,input:express(body),grade:'B_SAME_AUTHOR_NONBLIND'});
const uploadedName=file26Cases.find(c=>c.id==='path-originalname');
uploadedName.input.files[0].content=uploadedName.input.files[0].content.replace("app.post('/files',", "const upload=require('multer')({dest:'/srv/private',preservePath:true});app.post('/files',upload.single('file'),");
uploadedName.input.nodeManifests[0].multer='2.0.2';
file26Cases.push({id:'upload-executed',track:'UPLOAD_TYPE',truth:'RISK',reason:'Explicit multipart upload consumed as an executable; no new upload execution contract promised',grade:'B_SAME_AUTHOR_NONBLIND',input:{files:[{filePath:'server.cjs',content:"const app=require('express')();const upload=require('multer')({dest:'/srv/private'});const cp=require('node:child_process');app.post('/',upload.single('file'),(req,res)=>{cp.execFile(req.file.path,[]);});"}],nodeManifests:[{filePath:'package.json',express:'4.18.0',multer:'2.0.2'}]}});
for(const [id,body,reason]of [
 ['mime-only',"const file=req.file;if(file.mimetype!=='image/png')return;store(file);",'MIME does not prove content safety or dangerous execution context'],
 ['public-name',"store(req.file,'public/uploads');",'Directory name does not establish executable deployment'],
 ['external-limit','proxyUpload(req,res);','Proxy and size limits not available'],
 ['custom-storage','customStorage.save(req.file);','Custom engine semantics missing'],
 ['archive','archive.extract(req.file);','Archive path/expansion limits not available'],
])file26Cases.push({id:'upload-'+id,track:'UPLOAD_TYPE',truth:'UNKNOWN',reason,input:express(body),grade:'B_SAME_AUTHOR_NONBLIND'});
for(const [id,truth,body,reason]of [
 ['field','RISK',"const form=await request.formData();await writeFile(form.get('name'),'fixed');",'Form field controls path'],
 ['fixed','NORMAL',"const form=await request.formData();await writeFile('/srv/data/fixed',form.get('content'));",'Form content is not filename'],
 ['filename','RISK',"const form=await request.formData();const file=form.get('file');await writeFile('/srv/data/'+file.name,'fixed');",'File name can be controlled; static File/type connection may remain unsupported'],
])file26Cases.push({id:'next-'+id,track:'PATH',truth,reason,grade:'B_SAME_AUTHOR_NONBLIND',input:{files:[{filePath:'app/api/files/route.ts',content:`import {writeFile} from 'node:fs/promises';export async function POST(request){${body}return Response.json({ok:true});}`}],nodeManifests:[{filePath:'package.json',next:'15.3.0'}]}});
