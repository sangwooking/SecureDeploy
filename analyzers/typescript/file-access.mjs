// Static built-in contracts only. Never touch the target filesystem or execute callbacks.
import path from 'node:path';
export function fileAccess(api){
 const {ts,modules,value,unknown,constant,union,step,loc,note,tick,append,result}=api;
 const roots=new Map();
 let ioTrusted;
 // Source-wide mutation/escape checks also cover aliases retained across an await.
 function stableIo(){
  if(ioTrusted!==undefined)return ioTrusted;
  let trusted=true;
  for(const m of modules.values()){
   const i=m.syntaxIndex,names=new Map();
   const root=s=>['fs','fs/promises','util'].includes(s.replace(/^node:/,''))?s.replace(/^node:/,''):undefined;
   for(const [name,b]of m.imports){const r=root(b.spec);if(r)names.set(name,b.exported==='default'||b.exported==='*'?r:r+':'+b.exported);}
   const origin=(n,depth=0)=>{
    if(!n||depth>8)return;
    if(ts.isIdentifier(n))return names.get(n.text);
    if(ts.isPropertyAccessExpression(n)||ts.isElementAccessExpression(n)){
     const key=ts.isPropertyAccessExpression(n)?n.name.text:ts.isStringLiteral(n.argumentExpression)?n.argumentExpression.text:undefined;
     const p=origin(n.expression,depth+1);return p&&key?p+':'+key:undefined;
    }
    if(ts.isCallExpression(n)){
     if(ts.isIdentifier(n.expression)&&n.expression.text==='require'&&n.arguments.length===1&&ts.isStringLiteral(n.arguments[0]))return root(n.arguments[0].text);
     if(origin(n.expression,depth+1)==='util:promisify'&&n.arguments.length===1&&origin(n.arguments[0],depth+1)==='fs:writeFile')return 'fs:promisifiedWriteFile';
    }
   };
   // Constructing another native promisified wrapper does not mutate fs.writeFile.
   // Its completion contract remains unsupported by this model.
   const nativePromisifyArgument=(call,arg)=>ts.isCallExpression(call)&&origin(call.expression)==='util:promisify'
    &&call.arguments.length===1&&/^fs:[A-Za-z]+$/.test(origin(arg)??'');
   for(let pass=0;pass<4;pass++)for(const [name,ds]of i.declarations){
    tick(m);if(names.has(name))continue;
    for(const d of ds){
     let o=origin(d.initializer);
     if(ts.isBindingElement(d)&&ts.isObjectBindingPattern(d.parent)){
      const owner=origin(d.parent.parent.initializer);const key=d.propertyName??d.name;
      if(owner&&ts.isIdentifier(key))o=owner+':'+key.text;
     }
     if(o)names.set(name,o);
    }
   }
   for(const [name]of names){
    tick(m);
    if(i.writes.has(name)||i.exportWrites.has(name)||i.argumentReferenceIncomplete.has(name))trusted=false;
    for(const use of i.argumentUses.get(name)??[]){
     if(!nativePromisifyArgument(use.call,use.call.arguments[0]))trusted=false;
    }
    if((i.aliases.get(name)??[]).some(a=>!names.has(a.declaration.name.text)))trusted=false;
   }
   if(names.size||i.dependencies.some(d=>root(d.spec))){
    const scan=n=>{
     tick(m);
     const assignment=ts.isBinaryExpression(n)&&ts.isAssignmentOperator(n.operatorToken.kind);
     const deletion=ts.isDeleteExpression(n);
     if(assignment||deletion){
      let target=assignment?n.left:n.expression;
      while(ts.isPropertyAccessExpression(target)||ts.isElementAccessExpression(target))target=target.expression;
      if(origin(target))trusted=false;
     }
     if(ts.isCallExpression(n))for(const a of n.arguments){
      if(origin(a)&&!nativePromisifyArgument(n,a))trusted=false;
     }
     ts.forEachChild(n,scan);
    };scan(m.ast);
   }
  }
  ioTrusted=trusted;return trusted;
 }
 function stable(v,state){
  if(!state.nodeMode||!v?.fileNative||v.unknown||v.ref?.unknown||v.ref?.properties.size)return false;
  const supported=['fs','fs/promises','fs:writeFile','fs/promises:writeFile','fs:promisifiedWriteFile','util','util:promisify'].includes(v.fileNative);
  return supported&&stableIo();
 }
 const known=v=>v?.tag==='constant'&&!v.unknown&&Object.hasOwn(v,'constant');
 const native=(name,ref)=>value('file-native',[],{fileNative:name,ref:ref??{properties:new Map(),trace:[],unknown:false,nodeIdentity:{}}});
 function dependency(spec){
  const key=spec.replace(/^node:/,'');
  if(!['fs','fs/promises','path','path/posix','path/win32','util'].includes(key))return;
  const family=key.split('/')[0];
  if(!roots.has(family))roots.set(family,native(family));
  if(!roots.has(key))roots.set(key,native(key,roots.get(family).ref));return roots.get(key);
 }
 function imported(node,state){
  const binding=state.mod.imports.get(node.text);if(!binding)return;
  const root=dependency(binding.spec);if(!root)return;
  if(binding.typeOnly||state.mod.syntaxIndex.writes.has(node.text)||state.mod.syntaxIndex.aliases.has(node.text)){
   note(state.mod,'FILE_MODULE_BINDING_UNVERIFIED');return unknown();
  }
  const isolated=(state.context.isolate??(x=>x))(root);
  return binding.exported==='default'?isolated:property(isolated,binding.exported,node,state)??unknown();
 }
 function property(base,key,node,state){
  if(!base?.fileNative)return;
  if(base.unknown||base.ref?.unknown||base.ref?.properties.has(key))return {...unknown(),trace:base.trace};
  const n=base.fileNative;
  if(n==='util'&&key==='promisify')return native('util:promisify',base.ref);
  if(n==='fs'&&key==='promises')return native('fs/promises',base.ref);
  if(n==='path'&&['posix','win32'].includes(key))return native('path/'+key,base.ref);
  if(n.startsWith('path')&&['join','resolve','normalize','basename','relative','isAbsolute','extname'].includes(key))return native(n+':'+key,base.ref);
  if(['fs','fs/promises'].includes(n)&&['readFile','readFileSync','writeFile','writeFileSync','createReadStream','createWriteStream','unlink','unlinkSync','rename','renameSync','realpathSync','realpath'].includes(key))return native(n+':'+key,base.ref);
  note(state.mod,'FILE_API_NOT_SUPPORTED');return unknown();
 }
 function call(node,callable,args,state){
  if(!callable?.fileNative)return;
  if(!ts.isCallExpression(node)){note(state.mod,'FILE_API_CALL_FORM_UNSUPPORTED');return {value:unknown()};}
  const n=callable.fileNative,at=kind=>loc(node,state.mod,kind,state.fn);
  if(callable.unknown||callable.ref?.unknown){note(state.mod,'FILE_API_ORIGIN_UNKNOWN');return {value:unknown()};}
  if(!n.includes(':')){note(state.mod,'FILE_MODULE_NOT_CALLABLE');return {value:unknown()};}
  if(n==='util:promisify'){
   if(args.length===1&&args[0]?.fileNative==='fs:writeFile'&&stable(callable,state)&&stable(args[0],state))
    // util.promisify returns a new wrapper, not an alias of the fs namespace.
    return {value:native('fs:promisifiedWriteFile')};
   note(state.mod,'FILE_PROMISIFY_ORIGIN_UNKNOWN');return {value:unknown()};
  }
  const io=state.nodeMode&&(n==='fs:promisifiedWriteFile'||n==='fs/promises:writeFile');
  const textCandidate=v=>v&&!v.ref&&v.tag!=='function'&&(!known(v)||typeof v.constant==='string');
  const encoding=!args[2]||known(args[2])&&(args[2].constant===undefined||['utf8','utf-8','ascii','base64','hex','latin1','binary','ucs2','ucs-2','utf16le','utf-16le'].includes(args[2].constant));
  const ioArity=args.length>=2&&args.length<=3&&textCandidate(args[0])&&textCandidate(args[1])&&encoding;
  if(io&&(!stable(callable,state)||!ioArity)){
   note(state.mod,'FILE_IO_PROMISE_CONTRACT_UNKNOWN');return {value:unknown()};
  }
  if(n.startsWith('path:')||n.startsWith('path/')){
   const [family,method]=n.split(':');const incoming=union(...args);
   const derived=step({...incoming,constant:undefined},at('FILE_PATH_'+method.toUpperCase()),state.mod);
   if(['basename','relative','isAbsolute','extname'].includes(method)){
    note(state.mod,'PATH_TRANSFORM_NOT_CONTAINMENT_PROOF');return {value:{...derived,unknown:true}};
   }
   const arity=method==='normalize'?args.length===1:args.length>0;
   const primitive=args.every(a=>!a.ref&&(known(a)?typeof a.constant==='string':a.trace.length>0));
   if(arity&&primitive&&args.every(a=>known(a)&&typeof a.constant==='string')){
    // Do not let the analyzer host's OS/cwd choose a target runtime branch.
    if(method!=='resolve'||family==='path/posix'&&args.some(a=>path.posix.isAbsolute(a.constant))
        ||family==='path/win32'&&args.some(a=>/^(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\[^\\]+)/.test(a.constant))){
     const posix=path.posix[method](...args.map(a=>a.constant)),win=path.win32[method](...args.map(a=>a.constant));
     if(posix===win||family!=='path')return {value:constant(family==='path/win32'?win:posix)};
    }
    return {value:value('fixed-path',[],{unknown:false})};
   }
   return {value:{...derived,tag:'path-input',unknown:derived.unknown||!arity||!primitive}};
  }
  const [family,rawMethod]=n.split(':'),method=rawMethod==='promisifiedWriteFile'?'writeFile':rawMethod;
  if(!method){note(state.mod,'FILE_MODULE_NOT_CALLABLE');return {value:unknown()};}
  if(method.startsWith('realpath')){
   note(state.mod,'REALPATH_CONTAINMENT_AND_CALLBACK_NOT_VERIFIED');return {value:{...union(...args),unknown:true}};
  }
  const sync=method.endsWith('Sync'),promise=family==='fs/promises'||io;
  const stream=method.startsWith('create'),rename=method.startsWith('rename'),write=method.startsWith('write');
  const core=rename||write?2:1,callback=!sync&&!promise&&!stream;
  const options=(method.startsWith('readFile')||write||stream)&&args.length>core+(callback?1:0)?args[core]:undefined;
  const optionsKnown=!options||known(options)&&typeof options.constant==='string';
  const arity=args.length>=core+(callback?1:0)&&args.length<=core+(callback?1:0)+(method.startsWith('readFile')||write||stream?1:0)
   &&(!callback||args.at(-1)?.tag==='function')&&!(promise&&(sync||stream));
  for(const index of rename?[0,1]:[0]){
   tick(state.mod);const p=args[index]??unknown();
   const primitive=!p.ref&&(p.trace?.length>0||p.tag==='fixed-path'||p.filePathChoices?.length||known(p)&&typeof p.constant==='string');
   const unresolved=p.unknown||state.uncertain||!arity||!optionsKnown||!primitive;
   const kind=unresolved?'UNRESOLVED_RESOURCE':p.trace.length?'INPUT_IN_FILE_PATH':'STATIC_FILE_PATH';
   const operation=rename?(index?'RENAME_TARGET':'RENAME_SOURCE'):method.startsWith('unlink')?'DELETE':write||method==='createWriteStream'?'WRITE':'READ';
   const sink=at('NODE_FILE_'+operation);
   const limitations=['SYMLINKS_PERMISSIONS_AND_RUNTIME_NOT_VERIFIED','FILESYSTEM_PLATFORM_NOT_VERIFIED',
    ...(!arity||!optionsKnown?['FILE_OVERLOAD_NOT_SUPPORTED']:[]),...(unresolved?['RESOURCE_FLOW_UNRESOLVED']:[])];
   if(state.context.setup){note(state.mod,'FILE_CALL_OUTSIDE_REQUEST_FLOW');continue;}
   append(result.resourceUses,{ruleId:'JS_FILE_PATH_INPUT_FLOW',kind,location:sink,trace:p.trace,defenses:[],limitations,executionObserved:arity&&optionsKnown},state.mod);
   state.context.resources.push(sink);
   if(unresolved)note(state.mod,'FILE_PATH_FLOW_UNRESOLVED');
   if(!p.trace.length||unresolved)continue;
   append(result.findings,{ruleId:'JS_FILE_PATH_INPUT_FLOW',kind:'CWE-22',confidence:'HIGH',disposition:'REVIEW_REQUIRED',
    source:p.trace[0],sink,flow:p.trace,defenses:[],limitations,
    message:'사용자가 입력한 경로로 서버가 파일을 읽거나 변경할 가능성이 있습니다.',
    recommendation:'사용자 경로 대신 서버의 고정 파일 ID를 사용하세요. 경로가 필요하면 실제 저장 기준과 경로 구성요소 경계를 검사하고, 심볼릭 링크·접근 권한·검증 후 변경을 별도로 확인하세요. 임시 디렉터리에서 정상 파일과 탈출 거부를 검증한 뒤 재검사하세요.'},state.mod);
  }
  return {value:io?api.ioPromise(node,state,n):unknown()};
 }
 return {dependency,imported,property,call,stable};
}
