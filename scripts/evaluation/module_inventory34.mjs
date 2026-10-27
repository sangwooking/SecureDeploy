// Auxiliary syntax inventory, not the Worker's executed module/call graph.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';
const ts=createRequire(new URL('../../analyzers/typescript/analyzer.mjs',import.meta.url))('typescript');
const root=fs.realpathSync(process.argv[2]),raw=JSON.parse(fs.readFileSync(process.argv[3],'utf8'));
const plan=JSON.parse(fs.readFileSync(path.join(root,'application-plan.json'),'utf8'));
const hash=data=>crypto.createHash('sha256').update(data).digest('hex');
if(hash(fs.readFileSync(path.join(root,'application-plan.json')))!==raw.planSha256)throw Error('PLAN_HASH_DRIFT');
const readSource=(base,relative)=>{
 if(typeof relative!=='string'||path.posix.isAbsolute(relative)||relative.split('/').includes('..')||relative.includes('\\'))throw Error('SOURCE_PATH');
 const real=fs.realpathSync(path.join(base,relative)),inside=fs.realpathSync(base)+path.sep;
 if(!real.startsWith(inside)||fs.statSync(real).size>4000000)throw Error('SOURCE_BOUNDARY_OR_SIZE');
 return fs.readFileSync(real);
};
const rows=[];
for(const project of raw.projects){
 const original=plan.projects.find(p=>p.projectId===project.projectId),base=path.join(root,'sources',project.projectId);
 const files=new Map(original.files.map(f=>[f.path,f]));
 let nodes=0,characters=0;const refs=[],shapes=[];
 if(project.runs[0].typescript.files.filter(f=>f.parseStatus==='PARSED').length>100)throw Error('INVENTORY_FILE_BUDGET');
 for(const file of project.runs[0].typescript.files.filter(f=>f.parseStatus==='PARSED')){
  const data=readSource(base,file.filePath);
  if(hash(data)!==files.get(file.filePath)?.sha256)throw Error('SOURCE_HASH_DRIFT');
  const text=data.toString('utf8');characters+=text.length;
  if(text.length>100000||characters>1000000)throw Error('INVENTORY_TEXT_BUDGET');
  const ast=ts.createSourceFile(file.filePath,text,ts.ScriptTarget.Latest,true);
  const site=node=>({filePath:file.filePath,line:ast.getLineAndCharacterOfPosition(node.getStart(ast)).line+1});
  const walk=node=>{
   if(++nodes>200000)throw Error('INVENTORY_AST_BUDGET');
   if((ts.isImportDeclaration(node)||ts.isExportDeclaration(node))&&node.moduleSpecifier&&ts.isStringLiteral(node.moduleSpecifier))
    refs.push({...site(node),kind:ts.isImportDeclaration(node)?'IMPORT':'REEXPORT',specifier:node.moduleSpecifier.text,
     typeOnly:!!node.isTypeOnly||!!node.importClause?.isTypeOnly});
   if(ts.isCallExpression(node)&&ts.isIdentifier(node.expression)&&node.expression.text==='require'
       &&node.arguments.length===1&&ts.isStringLiteral(node.arguments[0]))refs.push({...site(node),kind:'REQUIRE_SYNTAX_BINDING_UNVERIFIED',specifier:node.arguments[0].text});
   if(ts.isVariableStatement(node)&&node.modifiers?.some(m=>m.kind===ts.SyntaxKind.ExportKeyword))for(const d of node.declarationList.declarations){
    if(d.initializer&&ts.isCallExpression(d.initializer)){
     if(ts.isIdentifier(d.name)&&['GET','POST','PATCH','PUT','DELETE','HEAD','OPTIONS'].includes(d.name.text))shapes.push({...site(d),kind:'NAMED_HTTP_CALL_INITIALIZER_SYNTAX_ONLY'});
     if(ts.isObjectBindingPattern(d.name)&&d.name.elements.some(e=>ts.isIdentifier(e.name)&&['GET','POST'].includes(e.name.text)))shapes.push({...site(d),kind:'DESTRUCTURED_HTTP_FACTORY_EXPORT_SYNTAX_ONLY'});
    }
   }
   ts.forEachChild(node,walk);
  };walk(ast);
 }
 rows.push({projectId:project.projectId,parserVersion:ts.version,nodes,characters,
  meaning:'SELECTED_RETAINED_SOURCE_SYNTAX_NOT_RUNTIME_OR_WORKER_CONNECTION_PROOF',references:refs,handlerFactoryShapes:shapes});
}
const candidate=plan.projects.find(p=>p.full_name==='openstarterkit/nextjs-saas-starter-kit');
const diagnostics=[];
if(candidate){
 const paths=new Set(candidate.files.map(f=>'/'+f.path)),dirs=new Set(['/']);
 for(const p of paths){let d=path.posix.dirname(p);while(d!=='/'){dirs.add(d);d=path.posix.dirname(d);}}
 const host={fileExists:p=>paths.has(p),directoryExists:p=>dirs.has(p),getCurrentDirectory:()=> '/',
  readFile:p=>paths.has(p)?readSource(path.join(root,'sources',candidate.projectId),p.slice(1)).toString('utf8'):undefined,
  realpath:p=>p};
 const options={module:ts.ModuleKind.ESNext,moduleResolution:ts.ModuleResolutionKind.Bundler,baseUrl:'/',paths:{'@/*':['./src/*']}};
 for(const specifier of ['@/lib/auth','@/lib/stripe','@/lib/prisma']){
  const base='/src/'+specifier.slice(2);
  const candidates=[base,base+'.ts',base+'.tsx',base+'.js',base+'/index.ts',base+'/index.js'];
  diagnostics.push({projectId:candidate.projectId,specifier,
   inventoryCandidates:candidates.filter(p=>paths.has(p)||dirs.has(p)).map(p=>({path:p.slice(1),kind:dirs.has(p)?'DIRECTORY':'FILE'})),
   officialParserVirtualResolution:ts.resolveModuleName(specifier,'/src/app/api/checkout/route.ts',options,host).resolvedModule?.resolvedFileName?.slice(1)??null,
   targetExecuted:false,meaning:'VIRTUAL_FILE_METADATA_RESOLUTION_ONLY_NOT_DEPLOYMENT_PROOF'});
 }
}
fs.writeFileSync(process.argv[4],JSON.stringify({schemaVersion:1,projects:rows,diagnostics},null,2),{flag:'wx',mode:0o600});
console.log(JSON.stringify(rows.map(r=>({projectId:r.projectId,references:r.references.length,handlerFactoryShapes:r.handlerFactoryShapes})),null,2));
console.log(JSON.stringify(diagnostics,null,2));
