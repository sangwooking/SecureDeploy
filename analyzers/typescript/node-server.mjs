import path from 'node:path';
import {constructorSummaries} from './constructor-summary.mjs';
import {sequelizeContracts} from './sequelize.mjs';
import {moduleResolution} from './module-resolution.mjs';
import {mongooseContracts} from './mongoose.mjs';
import {fieldValidation} from './field-validation.mjs';

// Library contracts over AST values only. Never require/import/eval target modules.
export function nodeServer(api) {
  const {ts,modules,limits,result,tick,note,value,unknown,constant,loc,append,union,expr,invoke,statement,writtenNames}=api;
  const loaded=new Map(), loading=new Set(), apps=[], routes=[];
  const httpModules=new Map();
  const resolver=moduleResolution(api);
  const object=tag=>value(tag,[],{ref:{properties:new Map(),trace:[],unknown:false,nodeIdentity:{}}});
  const literal=v=>v?.tag==='constant'&&!v.unknown;
  const context=()=>({setup:true,checks:[],defenses:[],resources:[]});
  const native=(name,mod,ref)=>({...object('node-native'),native:name,nativeMod:mod,...(ref?{ref}:{})});
  const validMongo=v=>{
    if(!v||v.unknown||!v.ref)return false;
    const seen=new Set();let ref=v.ref;
    while(ref){if(ref.unknown||seen.has(ref))return false;seen.add(ref);ref=ref.originParent;}
    return true;
  };
  function localsOnlyWrites(node,name,mod) {
    let safe=true;
    const scan=n=>{tick(mod);if(ts.isBinaryExpression(n)&&n.operatorToken.kind>=ts.SyntaxKind.FirstAssignment&&n.operatorToken.kind<=ts.SyntaxKind.LastAssignment){
      let target=n.left;const parts=[];while(ts.isPropertyAccessExpression(target)){parts.unshift(target.name.text);target=target.expression;}
      if(ts.isIdentifier(target)&&target.text===name&&!(parts.length>=2&&parts[0]==='locals'))safe=false;
    }ts.forEachChild(n,scan);};scan(node);return safe;
  }
  const functionValue=(node,state,name='handler')=>{
    if(!api.claimFunction(node,state.mod))return unknown();
    const closure=new Map(state.vars);
    // Captured mutable scalars are not frozen into a falsely certain value.
    for(const key of writtenNames(state.fn.node,state))if(closure.has(key)) {
      if(closure.get(key).tag==='express-router'&&localsOnlyWrites(state.fn.node,key,state.mod))continue;
      closure.set(key,{...closure.get(key),unknown:true,constant:undefined});
    }
    if(name==='handler'&&ts.isBinaryExpression(node.parent)&&ts.isPropertyAccessExpression(node.parent.left))name=node.parent.left.name.text;
    const target={name,node,mod:state.mod,nodeMode:true,closure,lexicalThis:ts.isArrowFunction(node)?state.thisValue:undefined};
    const result={...object('function'),effects:writtenNames(node,state),target};
    const self=node.name?.text??(ts.isVariableDeclaration(node.parent)&&ts.isIdentifier(node.parent.name)?node.parent.name.text:undefined);
    if(self&&!writtenNames(state.fn.node,state).includes(self))closure.set(self,result);
    return result;
  };
  const summaries=constructorSummaries({...api,functionValue,object,validMongo});
  const sequelize=sequelizeContracts({...api,object,native,findModule,observe});
  const mongoose=mongooseContracts({...api,object,native});
  const fields=fieldValidation({...api,native});
  function findModule(mod,spec,mode='require') { return resolver.resolve(mod,spec,mode); }
  function dependency(mod,spec,mode='require') {
    const fileModule=api.filesSupport.dependency(spec);if(fileModule)return fileModule;
    if(spec==='express')return native('express',mod);
    if(spec==='mongodb')return native('mongodb',mod);
    if(spec==='sequelize')return native('sequelize',mod);
    if(spec==='mongoose')return mongoose.dependency(mod);
    if(spec==='validator')return fields.dependency(mod);
    if(['child_process','node:child_process'].includes(spec))return native('node-child-process',mod);
    if(['http','node:http','https','node:https'].includes(spec)){
      const key=spec.replace(/^node:/,'');
      if(!httpModules.has(key))httpModules.set(key,native('node-http',mod));
      return httpModules.get(key);
    }
    const target=findModule(mod,spec,mode);
    if(!target){
      note(mod,'NODE_MODULE_RESOLUTION_UNKNOWN');
      if(!spec.startsWith('.')){
        note(mod,'EXTERNAL_IMPLEMENTATION_UNKNOWN');
        if(/^(?:@[A-Za-z0-9_-]+\/)?[A-Za-z0-9_-]+$/.test(spec))return {...unknown(),externalObject:{unverified:true}};
      }
      return unknown();
    }
    return load(target);
  }
  function load(mod) {
    if(loaded.has(mod))return loaded.get(mod);
    if(loading.has(mod)||loading.size>limits.maxDepth){note(mod,'NODE_MODULE_CYCLE_OR_DEPTH_LIMIT');return unknown();}
    loading.add(mod);
    const summarized=sequelize.summarize(mod);
    if(summarized){loaded.set(mod,summarized);loading.delete(mod);return summarized;}
    const exports=object('node-exports'), module=object('node-module');module.ref.properties.set('exports',exports);
    const state={mod,fn:{name:'module',node:mod.ast},vars:new Map([['module',module],['exports',exports]]),nodeMode:true,context:context(),depth:0,stack:new Set(),uncertain:false};
    try {
      for(const [name,fn]of mod.functions)if(typeof name==='string')state.vars.set(name,{...object('function'),target:{...fn,nodeMode:true,closure:state.vars}});
      for(const s of mod.ast.statements)if(ts.isImportDeclaration(s)&&ts.isStringLiteral(s.moduleSpecifier)&&!s.importClause?.isTypeOnly) {
        const imported=dependency(mod,s.moduleSpecifier.text,'import');
        if(s.importClause?.name)state.vars.set(s.importClause.name.text,imported.native==='express'?imported:imported.ref?.properties.get('default')??imported);
        const bindings=s.importClause?.namedBindings;
        if(bindings&&ts.isNamedImports(bindings))for(const e of bindings.elements){if(e.isTypeOnly)continue;const key=e.propertyName?.text??e.name.text;state.vars.set(e.name.text,property(imported,key,e,state)??imported.ref?.properties.get(key)??unknown());}
        else if(bindings)note(mod,'NODE_NAMESPACE_IMPORT_UNKNOWN');
      }
      for(const s of mod.ast.statements) {
        tick(mod);
        if(ts.isVariableStatement(s)||ts.isExpressionStatement(s)||ts.isIfStatement(s)||ts.isThrowStatement(s)||ts.isReturnStatement(s)) {
          if(statement(s,state).stops){state.context.unresolved=true;note(mod,'NODE_INITIALIZATION_STOPPED_OR_UNRESOLVED');break;}
        }else if(!ts.isImportDeclaration(s)&&!ts.isFunctionDeclaration(s)&&!ts.isExportAssignment(s)&&!ts.isEmptyStatement(s)){
          state.uncertain=true;state.context.unresolved=true;note(mod,'NODE_INITIALIZATION_STRUCTURE_UNKNOWN');
        }
        if(ts.isExportAssignment(s))exports.ref.properties.set('default',expr(s.expression,state));
        if(s.modifiers?.some(m=>m.kind===ts.SyntaxKind.ExportKeyword)) {
          if(ts.isFunctionDeclaration(s)&&s.body){const isDefault=s.modifiers.some(m=>m.kind===ts.SyntaxKind.DefaultKeyword);const name=s.name?.text??'default';exports.ref.properties.set(isDefault?'default':name,state.vars.get(name)??functionValue(s,state,name));}
          if(ts.isVariableStatement(s))for(const d of s.declarationList.declarations)if(ts.isIdentifier(d.name))exports.ref.properties.set(d.name.text,state.vars.get(d.name.text)??unknown());
        }
      }
      const exported=module.ref.properties.get('exports')??unknown();loaded.set(mod,exported);return exported;
    }finally{loading.delete(mod);}
  }
  function property(base,key,node,state) {
    const fileProperty=api.filesSupport.property(base,key,node,state);if(fileProperty)return fileProperty;
    const mongooseProperty=mongoose.property(base,key);if(mongooseProperty)return mongooseProperty;
    if(base.unknown||base.ref?.unknown)return;
    if(base.tag==='function')return base.ref?.properties.get(key)??unknown();
    if(base.native==='mongodb'&&key==='MongoClient')return native('mongo-client',base.nativeMod,base.ref);
    if(base.native==='express'&&key==='Router')return native('router',base.nativeMod,base.ref);
    if(base.native==='sequelize'&&['Sequelize','default'].includes(key))return native('sequelize',base.nativeMod,base.ref);
    if(base.native==='node-http'&&key==='get')return native('node-http-get',base.nativeMod,base.ref);
    if(base.native==='node-child-process'&&['exec','execSync','execFile','execFileSync','spawn','spawnSync'].includes(key))return native('node-child-'+key,base.nativeMod,base.ref);
    if(base.tag==='express-router'&&key==='locals'){
      if(!base.ref.properties.has(key))base.ref.properties.set(key,object('express-locals'));
      return base.ref.properties.get(key);
    }
    if(base.tag==='express-request') {
      if(['file','files'].includes(key)){
        note(state.mod,'UPLOAD_MIDDLEWARE_AND_STORAGE_NOT_VERIFIED');
        return value('input',[loc(node,state.mod,'UPLOAD_FILE_UNVERIFIED',state.fn)],{unknown:true});
      }
      if(['query','body','params'].includes(key))return value('input',[loc(node,state.mod,'EXPRESS_'+key.toUpperCase(),state.fn)],{inputShape:key==='params'?'STRING_MAP':undefined,
        fieldOrigin:fields.root(base,key,node,state),fieldValidationUncertain:base.fieldValidationUncertain});
      if(['user','session'].includes(key)){
        state.context.checks.push(loc(node,state.mod,'PRINCIPAL_CONTEXT_UNVERIFIED',state.fn));return {...unknown(),principal:true};
      }
      return unknown();
    }
    if(base.tag==='express-response')return native('response-'+key,state.mod);
    const field=fields.read(base,key,node,state);if(field)return field;
  }
  function write(receiver,key,v,state) {
    if(!state.nodeMode||!literal(key)||!receiver.ref)return false;
    if(receiver.native){receiver.ref.unknown=true;note(state.mod,'NODE_LIBRARY_MUTATION_UNKNOWN');return true;}
    if(receiver.tag==='function'&&['__proto__','prototype','constructor','caller','arguments'].includes(String(key.constant)))return false;
    if(['node-module','node-exports','express-locals','node-instance','object','function'].includes(receiver.tag)&&!receiver.unknown&&!receiver.ref.unknown) {
      const ref=state.forkRefs?.get(receiver.ref)??receiver.ref;
      if(state.forkRefs&&ref.nodeIdentity)state.nodeMutations?.add(ref.nodeIdentity);
      if(ref.mongooseTracked)ref.mongooseRevision=(ref.mongooseRevision??0)+1;
      ref.properties.set(String(key.constant),v);return true;
    }
    return false;
  }
  function observe(v,node,state,ruleId,kind,operation) {
    if(state.context.setup)return;
    const sink=loc(node,state.mod,operation,state.fn), uncertain=v.unknown||v.ref?.unknown||state.uncertain;
    if(ruleId==='JS_SHELL_COMMAND_INPUT_FLOW'&&v.shellRestricted&&v.fixedShellCommandPrefix&&!uncertain){
      append(result.nodeUses,{ruleId,kind:'RESTRICTED_SHELL_TOKEN',operation,location:sink,trace:v.trace,
        limitations:['ASCII_CAPTURE_ALPHABET_ONLY','ARGUMENT_INJECTION_AND_RUNTIME_NOT_VERIFIED']},state.mod);return;
    }
    const status=v.trace.length?(uncertain?'FLOW_UNRESOLVED':'INPUT_TO_EXECUTION'):uncertain?'UNKNOWN':'STATIC_OR_DATA_ONLY';
    append(result.nodeUses,{ruleId,kind:status,operation,location:sink,trace:v.trace,limitations:['STATIC_PATH_NOT_RUNTIME_EXPLOIT_PROOF',...(uncertain?['NODE_FLOW_UNRESOLVED']:[])]},state.mod);
    state.context.resources.push(sink);
    if(!v.trace.length)return;
    append(result.findings,{ruleId,kind,confidence:uncertain?'MEDIUM':'HIGH',disposition:'REVIEW_REQUIRED',source:v.trace[0],sink,flow:v.trace,
      defenses:state.context.defenses.slice(0,20),limitations:['STATIC_PATH_NOT_RUNTIME_EXPLOIT_PROOF','MIDDLEWARE_AND_RUNTIME_NOT_VERIFIED',...(uncertain?['NODE_FLOW_UNRESOLVED']:[])],
      message:ruleId==='JS_SHELL_COMMAND_INPUT_FLOW'?'사용자가 보낸 값이 서버의 shell 명령 문자열에 전달됩니다.':ruleId==='JS_EVAL_INPUT_FLOW'?'사용자가 보낸 값이 서버의 코드 실행에 전달될 수 있습니다.':'사용자가 보낸 값이 데이터베이스의 실행 문자열에 들어갈 수 있습니다.',
      recommendation:ruleId==='JS_SHELL_COMMAND_INPUT_FLOW'?'요청값을 shell 명령에 결합하지 마세요. 필요한 작업만 서버의 고정된 실행 파일과 shell을 사용하지 않는 인자 배열로 제공하고 입력 형식·허용 작업·실행 권한을 검증하세요. 인자 주입과 운영 환경은 별도 확인이 필요합니다.':ruleId==='JS_EVAL_INPUT_FLOW'?'입력값을 코드로 실행하지 말고 필요한 숫자 변환이나 스키마 검증을 사용하세요.':ruleId==='JS_SEQUELIZE_SQL_INPUT_FLOW'?'SQL 문장을 고정하고 사용자 값은 지원 버전의 bind 또는 replacements 매개변수로 분리하세요. 이미 입력이 결합된 SQL에 바인딩 옵션을 추가하는 것만으로 해결되지 않습니다. 식별자는 서버의 고정된 허용 목록으로 제한하고 설치 버전·방언·정상 동작을 로컬에서 검증하세요.':'$where 문자열 결합을 피하고 일반적인 값 비교 쿼리와 입력 타입 검증을 사용하세요.'},state.mod);
  }
  function queryExecution(queries,origin,node,state,operation,createdAt) {
    for(const query of queries){
      const where=query.ref?.properties.get('$where');
      if(!where&&!query.unknown&&!query.ref?.unknown){
        const location=loc(node,state.mod,'MONGO_RESOURCE_ACCESS',state.fn);
        if(!state.context.setup){append(result.nodeUses,{ruleId:'JS_MONGO_RESOURCE_ACCESS',kind:'DATA_QUERY_NOT_AUTHORIZATION_PROOF',operation,location,
          trace:query.ref?.trace??query.trace,limitations:['OBJECT_OWNERSHIP_AND_MIDDLEWARE_NOT_VERIFIED']},state.mod);state.context.resources.push(location);}
        continue;
      }
      const trace=where?.trace.length?[...where.trace,...(createdAt?[createdAt]:[]),...(origin??[])]:[];
      observe(where?{...where,trace:trace.slice(0,20),unknown:where.unknown||query.unknown||query.ref.unknown||trace.length>20}
        :query.unknown?query:constant(null),node,state,'JS_MONGO_WHERE_INPUT_FLOW','CWE-943',operation);
    }
  }
  function call(node,callee,receiver,args,state,global,callable) {
    if(!state.nodeMode)return;
    const validation=fields.call(node,receiver,args,state);if(validation)return validation;
    const rawQuery=sequelize.call(node,receiver,args,state,callable);if(rawQuery)return rawQuery;
    const selector=mongoose.call(node,callee,receiver,args,state,global,callable);if(selector)return selector;
    if(callable?.native==='node-http-get'&&ts.isCallExpression(node)){
      if(callable.unknown||callable.ref?.unknown){note(state.mod,'NODE_HTTP_GET_ORIGIN_UNKNOWN');return {value:unknown()};}
      const destination=args[0]??unknown();
      const supported=args.length===1&&(['input','url','urlText','constant'].includes(destination.tag)
        ||!destination.ref&&(typeof destination.urlPrefix==='string'||destination.destination));
      if(!supported)note(state.mod,'NODE_HTTP_GET_OVERLOAD_UNSUPPORTED');
      if(!state.context.setup)api.observeHttp({...destination,unknown:destination.unknown||!supported},node,state);
      note(state.mod,'NODE_HTTP_GET_REQUEST_NOT_RUNTIME_SUCCESS');
      return {value:unknown()};
    }
    const method=ts.isPropertyAccessExpression(callee)?callee.name.text:undefined;
    if(global&&ts.isIdentifier(callee)&&callee.text==='require'&&ts.isCallExpression(node))
      return {value:args.length===1&&literal(args[0])&&typeof args[0].constant==='string'
        ? (state.context.isolate??(v=>v))(dependency(state.mod,args[0].constant)):unknown()};
    if(callable?.native?.startsWith('node-child-')&&ts.isCallExpression(node)) {
      const operation=callable.native.slice('node-child-'.length);
      if(callable.unknown||callable.ref?.unknown){note(state.mod,'NODE_PROCESS_API_ORIGIN_UNKNOWN');return {value:unknown()};}
      if(['exec','execSync'].includes(operation)) {
        const option=args[1], callback=operation==='exec'&&option?.tag==='function';
        const optionsKnown=!option||callback||option.tag==='object'&&!option.unknown&&!option.ref?.unknown;
        const shell=option?.ref?.properties.get('shell');
        const contractKnown=optionsKnown&&(!shell||literal(shell)&&typeof shell.constant==='string')&&args.length<=(operation==='exec'?3:2);
        const command=args[0]??unknown();
        if(!contractKnown)note(state.mod,'NODE_PROCESS_OPTIONS_UNVERIFIED');
        observe({...command,unknown:command.unknown||!contractKnown},node,state,'JS_SHELL_COMMAND_INPUT_FLOW','CWE-78','NODE_'+operation.toUpperCase()+'_SHELL');
      }else{
        const directArray=node.arguments?.[1]&&ts.isArrayLiteralExpression(node.arguments[1]);
        const option=args[2];
        const noShellDefault=directArray&&literal(args[0])&&typeof args[0].constant==='string'
          &&(!option||operation==='execFile'&&option.tag==='function')&&args.length<=(operation==='execFile'?3:2)
          &&['execFile','execFileSync'].includes(operation);
        const location=loc(node,state.mod,'NODE_PROCESS_ARGUMENTS',state.fn);
        if(!state.context.setup)append(result.nodeUses,{ruleId:'JS_SHELL_COMMAND_INPUT_FLOW',
          kind:noShellDefault?'ARGV_WITHOUT_SHELL_DECLARED':'PROCESS_CONTRACT_UNKNOWN',operation,location,trace:args[1]?.trace??[],
          limitations:['EXECUTABLE_ARGUMENT_INJECTION_AND_PLATFORM_NOT_VERIFIED']},state.mod);
        note(state.mod,noShellDefault?'NODE_PROCESS_ARGV_NOT_WHOLE_OPERATION_SAFETY':'NODE_PROCESS_ARGV_AND_OPTIONS_NOT_MODELED');
      }
      return {value:unknown()};
    }
    if(!callable?.unknown&&!callable?.ref?.unknown&&(callable?.native==='express'||callable?.native==='router')) {
      if(apps.length>=limits.maxResults){note(state.mod,'EXPRESS_APP_LIMIT');return {value:unknown()};}
      const app=object('express-router');app.app=callable.native==='express';app.routes=[];app.mounts=[];if(app.app)apps.push(app);return {value:app};
    }
    if(receiver?.tag==='express-router') {
      if(receiver.unknown||receiver.ref.unknown){note(state.mod,'EXPRESS_RECEIVER_MUTATION_UNKNOWN');return {value:unknown()};}
      // app.get(setting) reads configuration; it is not a route or an unknown mutator.
      if(receiver.app&&method==='get'&&args.length===1&&literal(args[0])&&typeof args[0].constant==='string') {
        note(state.mod,'EXPRESS_SETTING_READ_NOT_ROUTE');return {value:unknown()};
      }
      if(['get','post','put','patch','delete','head','options','all'].includes(method)&&args.length>=2) {
        if(!literal(args[0])||typeof args[0].constant!=='string'){note(state.mod,'DYNAMIC_EXPRESS_ROUTE_UNKNOWN');return {value:receiver};}
        const handler=args.at(-1);
        if(!handler.target||handler.unknown){note(state.mod,'EXPRESS_HANDLER_UNKNOWN');return {value:receiver};}
        if(routes.length>=limits.maxResults){note(state.mod,'EXPRESS_REGISTRATION_LIMIT');return {value:receiver};}
        const route={target:handler.target,location:loc(node,state.mod,'EXPRESS_REGISTRATION',state.fn),uncertain:state.uncertain,middleware:args.length>2,setupContext:state.context};
        receiver.routes.push(route);routes.push(route);return {value:receiver};
      }
      if(method==='use') {
        const mounted=args.at(-1);
        if(mounted?.tag==='express-router'&&args.length<=2&&(args.length===1||literal(args[0])))receiver.mounts.push(mounted);
        else note(state.mod,'EXPRESS_MIDDLEWARE_EFFECTS_UNKNOWN');
        return {value:receiver};
      }
      if(['set','disable','enable','listen','engine'].includes(method))return {value:receiver};
    }
    if(receiver?.native==='mongo-client'&&!receiver.unknown&&!receiver.ref?.unknown&&method==='connect') {
      const callback=args.at(-1), manifests=(api.input.nodeManifests??[]).filter(m=>state.mod.filePath.startsWith(path.posix.dirname(m.filePath)==='.'?'':path.posix.dirname(m.filePath)+'/'))
        .sort((a,b)=>b.filePath.length-a.filePath.length);
      const major=/^(?:\^|~)?2\./.test(manifests[0]?.mongodb??'');
      if(callback?.target&&major){const db=object('mongo-db');db.ref.driverMajor=2;db.ref.origin=[loc(node,state.mod,'MONGODB_DECLARED_V2_CONNECTION',state.fn)];invoke(callback.target,[constant(null),db],0,state.context,new Set(),state.uncertain);}
      else note(state.mod,'MONGODB_CONNECTION_API_VERSION_UNKNOWN');
      return {value:unknown()};
    }
    if(receiver?.native==='node-http'&&!receiver.unknown&&!receiver.ref?.unknown&&method==='createServer'&&args.some(a=>a.tag==='express-router'&&!a.unknown&&!a.ref.unknown))return {value:object('node-http-server')};
    if(receiver?.tag==='node-http-server'&&method==='listen')return {value:receiver};
    if(callable?.native==='mongo-client'&&!callable.unknown&&!callable.ref?.unknown&&ts.isNewExpression(node)){
      const declarations=(api.input.nodeManifests??[]).filter(m=>state.mod.filePath.startsWith(path.posix.dirname(m.filePath)==='.'?'':path.posix.dirname(m.filePath)+'/')).sort((a,b)=>b.filePath.length-a.filePath.length);
      const major=/^(?:\^|~)?([3-6])\./.exec(declarations[0]?.mongodb??'');
      if(major){const client=object('mongo-client-instance');client.ref.driverMajor=Number(major[1]);return {value:client};}
      note(state.mod,'MONGODB_CONNECTION_API_VERSION_UNKNOWN');return {value:unknown()};
    }
    if(receiver?.tag==='mongo-client-instance'&&!receiver.unknown&&!receiver.ref.unknown&&method==='db'){
      const db=object('mongo-db');db.ref.originParent=receiver.ref;db.ref.driverMajor=receiver.ref.driverMajor;return {value:db};
    }
    if(receiver?.tag==='mongo-db'&&validMongo(receiver)&&method==='collection'&&literal(args[0])){
      const collection=object('mongo-collection');collection.ref.originParent=receiver.ref;collection.ref.driverMajor=receiver.ref.driverMajor;collection.ref.origin=[...(receiver.ref.origin??[]),loc(node,state.mod,'MONGODB_COLLECTION_ORIGIN',state.fn)].slice(-4);return {value:collection};
    }
    if(receiver?.tag==='mongo-collection'&&validMongo(receiver)&&['find','findOne','countDocuments'].includes(method)) {
      const queries=(args[0]?.nodeAlternatives??[args[0]??unknown()]).slice(0,4);
      if(method==='countDocuments'&&receiver.ref.driverMajor<3){note(state.mod,'MONGODB_METHOD_VERSION_UNKNOWN');return {value:unknown()};}
      if(method==='find'){
        const cursor=object('mongo-cursor');cursor.ref.originParent=receiver.ref;cursor.ref.origin=receiver.ref.origin;
        cursor.ref.createdAt=loc(node,state.mod,'MONGODB_CURSOR_CREATION',state.fn);
        queries.forEach((q,i)=>cursor.ref.properties.set(String(i),q));
        if(!state.context.setup)append(result.nodeUses,{ruleId:'JS_MONGO_WHERE_INPUT_FLOW',kind:'CURSOR_CREATED_EXECUTION_NOT_OBSERVED',operation:method,
          location:cursor.ref.createdAt,trace:union(...queries.map(q=>q.ref?.properties.get('$where')??q)).trace,
          limitations:['CURSOR_CONSUMPTION_REQUIRED','NOT_EXECUTION_PROOF']},state.mod);
        return {value:cursor};
      }
      queryExecution(queries,receiver.ref.origin,node,state,'MONGODB_'+method.toUpperCase());return {value:unknown()};
    }
    if(receiver?.tag==='mongo-cursor'&&validMongo(receiver)){
      if(['limit','sort'].includes(method))return {value:args.some(a=>a.unknown||a.ref?.unknown)?{...receiver,unknown:true}:receiver};
      if(['toArray','next'].includes(method)){
        queryExecution([...receiver.ref.properties.values()],receiver.ref.origin,node,state,'MONGODB_CURSOR_'+method.toUpperCase(),receiver.ref.createdAt);
        return {value:unknown()};
      }
    }
    if(global&&ts.isIdentifier(callee)&&callee.text==='eval'&&ts.isCallExpression(node)) {
      observe(args[0]??unknown(),node,state,'JS_EVAL_INPUT_FLOW','CWE-95','EVAL_CALL');
      note(state.mod,'EVAL_SCOPE_EFFECTS_UNKNOWN');
      for(const [key,v]of state.vars)if(!['express-request','express-response'].includes(v.tag))state.vars.set(key,{...v,unknown:true,constant:undefined});
      return {value:unknown()};
    }
    if(receiver?.tag==='express-response'&&['send','json','render','redirect','status','end'].includes(method)) {
      if(['send','json','end'].includes(method)&&args.length){
        if(args.length!==1)note(state.mod,'EXPRESS_RESPONSE_ARGUMENT_CONTRACT_UNKNOWN');
        api.observeExpressResponse(args.length===1?args[0]:union(...args),node,state,
          !!receiver.unknown||!!receiver.ref?.unknown||args.length!==1);
      }
      if(['render','redirect'].includes(method))note(state.mod,'EXPRESS_RESPONSE_RENDER_OR_REDIRECT_NOT_MODELED');
      return {value:receiver};
    }
    if(!state.context.setup&&['find','findOne','countDocuments'].includes(method))for(const query of args[0]?.nodeAlternatives??[args[0]]) {
      const where=query?.ref?.properties.get('$where');
      if(where?.trace.length)append(result.nodeUses,{ruleId:'JS_MONGO_WHERE_INPUT_FLOW',kind:'RECEIVER_NOT_VERIFIED',operation:method,
        location:loc(node,state.mod,'UNVERIFIED_QUERY_CALL',state.fn),trace:where.trace,limitations:['MONGODB_RECEIVER_OR_OBJECT_FLOW_UNRESOLVED']},state.mod);
    }
  }
  function construct(target,args,state) {
    if(ts.isArrowFunction(target.node)||target.node.asteriskToken||target.node.modifiers?.some(m=>m.kind===ts.SyntaxKind.AsyncKeyword)){
      note(target.mod,'NON_CONSTRUCTIBLE_FUNCTION_UNKNOWN');return unknown();
    }
    if(state.depth+1>limits.maxDepth&&!state.stack.has(target)){
      const summarized=summaries.apply(target,args,state);
      if(summarized){
        append(result.nodeUses,{ruleId:'JS_CONSTRUCTOR_EFFECT',kind:'CONSTRUCTOR_SUMMARY_MUST',operation:'READ_ONLY_ARGUMENTS_FRESH_INSTANCE',
          location:loc(target.node,target.mod,'CONSTRUCTOR_SUMMARY_MUST',target),trace:summarized.evidence,
          limitations:['WHITELISTED_CONSTRUCTOR_ONLY','SYNTAX_PLAN_CACHE_NO_SHARED_ARGUMENT_STATE','NOT_WHOLE_FUNCTION_FLOW',...(summarized.truncated?['SUMMARY_EVIDENCE_TRUNCATED']:[])]},target.mod);
        note(target.mod,'CONSTRUCTOR_SUMMARY_APPLIED_NOT_FULL_CALL_TRACE');return summarized.instance;
      }
      note(target.mod,'CONSTRUCTOR_SUMMARY_UNKNOWN');
      append(result.nodeUses,{ruleId:'JS_CONSTRUCTOR_EFFECT',kind:'CONSTRUCTOR_SUMMARY_UNKNOWN',operation:'UNSUPPORTED_OR_UNRESOLVED',
        location:loc(target.node,target.mod,'CONSTRUCTOR_SUMMARY_UNKNOWN',target),trace:[],
        limitations:['NO_READ_ONLY_EFFECT_PROOF','EXISTING_DEPTH_LIMIT_RETAINED']},target.mod);
    }
    const instance=object('node-instance');instance.constructorTarget=target;
    const returned=invoke(target,args,state.depth+1,state.context,state.stack,state.uncertain,false,instance,true);
    if(returned.tag==='function'&&!returned.unknown)return returned;
    if(returned.ref&&!returned.unknown)return returned;
    if(returned.unknown){instance.unknown=true;instance.ref.unknown=true;}
    return instance;
  }
  function discover() {
    const roots=new Set(),parents=new Map();
    for(const mod of modules.values()) {
      let root=false;
      const dependencyEdge=(spec,mode)=>{
        if(spec==='express')root=true;
        if(['koa','@koa/router','koa-compose'].includes(spec))note(mod,'FRAMEWORK_NOT_SUPPORTED');
        if(!spec.startsWith('.'))return;
        const child=findModule(mod,spec,mode);
        if(!child)return;
        if(!parents.has(child))parents.set(child,new Set());parents.get(child).add(mod);
      };
      const scan=node=>{tick(mod);if(ts.isImportDeclaration(node)&&ts.isStringLiteral(node.moduleSpecifier)&&!node.importClause?.isTypeOnly)dependencyEdge(node.moduleSpecifier.text,'import');
        if(ts.isCallExpression(node)&&ts.isIdentifier(node.expression)&&node.expression.text==='require'&&node.arguments.length===1&&ts.isStringLiteral(node.arguments[0]))dependencyEdge(node.arguments[0].text,'require');
        ts.forEachChild(node,scan);};
      try{
        if(mod.syntaxIndex)for(const edge of mod.syntaxIndex.dependencies){tick(mod);dependencyEdge(edge.spec,edge.mode??'require');}
        else scan(mod.ast);
        if(root)roots.add(mod);
      }catch{note(mod,'NODE_DISCOVERY_BUDGET_OR_UNSUPPORTED');}
    }
    // Discover bounded static importers of Express wrappers, never invoke an
    // exported initialization function solely because it exists.
    const queue=[...roots].map(mod=>[mod,0]),seen=new Set();
    for(let i=0;i<queue.length;i++){
      const [mod,depth]=queue[i];if(seen.has(mod))continue;seen.add(mod);
      try{tick(mod);load(mod);}catch{note(mod,'NODE_DISCOVERY_BUDGET_OR_UNSUPPORTED');}
      for(const parent of parents.get(mod)??[]){
        if(seen.has(parent))continue;
        if(depth>=limits.maxDepth){note(parent,'NODE_DISCOVERY_IMPORT_DEPTH_LIMIT');continue;}
        queue.push([parent,depth+1]);
      }
    }
    const reachable=new Set();const visit=app=>{if(reachable.has(app)||app.unknown||app.ref.unknown)return;reachable.add(app);for(const child of app.mounts){tick(child.routes[0]?.target.mod??[...modules.values()][0]);visit(child);}};
    for(const app of apps)visit(app);
    for(const app of reachable)for(const route of app.routes) {
      const mod=route.target.mod;
      if(mod.entries.length>=limits.maxResults){note(mod,'EXPRESS_ENTRY_LIMIT');continue;}
      mod.entries.push({fn:route.target,kind:'EXPRESS_HANDLER',registration:route.location,uncertain:route.uncertain||!!route.setupContext.unresolved,middleware:route.middleware});mod.record.entrypoints++;
      append(result.nodeUses,{ruleId:'JS_SERVER_ENTRY_CONTEXT',kind:'ENTRY_REGISTERED',operation:'EXPRESS_ROUTER_MOUNTED',
        location:route.location,trace:[loc(route.target.node,mod,'EXPRESS_HANDLER_TARGET',route.target)],
        limitations:['STATIC_REGISTRATION_ONLY','MIDDLEWARE_AND_RUNTIME_NOT_VERIFIED']},mod);
    }
    for(const route of routes)if(![...reachable].some(app=>app.routes.includes(route)))note(route.target.mod,'UNMOUNTED_ROUTER_NOT_ANALYZED');
  }
  return {property,write,call,construct,discover,functionValue,awaitValue:mongoose.consume,
    applyFields:fields.apply,typeOfField:fields.typeName,compareFields:fields.compare,refineFields:fields.refine,
    invalidateFields:fields.invalidate,mergeFields:fields.merge,escapeFields:fields.escape};
}
