import path from 'node:path';

// Library contracts over AST values only. Never require/import/eval target modules.
export function nodeServer(api) {
  const {ts,modules,limits,result,tick,note,value,unknown,constant,loc,append,union,expr,invoke,statement,writtenNames}=api;
  const loaded=new Map(), loading=new Set(), apps=[], routes=[];
  const object=tag=>value(tag,[],{ref:{properties:new Map(),trace:[],unknown:false}});
  const literal=v=>v?.tag==='constant'&&!v.unknown;
  const context=()=>({setup:true,checks:[],defenses:[],resources:[]});
  const native=(name,mod,ref)=>({...object('node-native'),native:name,nativeMod:mod,...(ref?{ref}:{})});
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
    const result=value('function',[],{effects:writtenNames(node,state),target});
    const self=node.name?.text??(ts.isVariableDeclaration(node.parent)&&ts.isIdentifier(node.parent.name)?node.parent.name.text:undefined);
    if(self&&!writtenNames(state.fn.node,state).includes(self))closure.set(self,result);
    return result;
  };
  function findModule(mod,spec) {
    if(!spec.startsWith('.')||spec.includes('\\')||spec.includes('\0'))return;
    const base=path.posix.normalize(path.posix.join(path.posix.dirname(mod.filePath),spec));
    if(base.startsWith('../'))return;
    const choices=[base,...['.js','.mjs','.cjs','.ts'].map(e=>base+e),...['js','mjs','cjs','ts'].map(e=>base+'/index.'+e)];
    const matches=[...new Set(choices.filter(p=>modules.has(p)))];
    return matches.length===1?modules.get(matches[0]):undefined;
  }
  function dependency(mod,spec) {
    if(spec==='express')return native('express',mod);
    if(spec==='mongodb')return native('mongodb',mod);
    if(['http','node:http','https','node:https'].includes(spec))return native('node-http',mod);
    const target=findModule(mod,spec);
    if(!target){note(mod,'NODE_MODULE_RESOLUTION_UNKNOWN');return unknown();}
    return load(target);
  }
  function load(mod) {
    if(loading.has(mod)||loading.size>limits.maxDepth){note(mod,'NODE_MODULE_CYCLE_OR_DEPTH_LIMIT');return unknown();}
    if(loaded.has(mod))return loaded.get(mod);
    loading.add(mod);
    const exports=object('node-exports'), module=object('node-module');module.ref.properties.set('exports',exports);
    const state={mod,fn:{name:'module',node:mod.ast},vars:new Map([['module',module],['exports',exports]]),nodeMode:true,context:context(),depth:0,stack:new Set(),uncertain:false};
    try {
      for(const [name,fn]of mod.functions)if(typeof name==='string')state.vars.set(name,value('function',[],{target:{...fn,nodeMode:true,closure:state.vars}}));
      for(const s of mod.ast.statements)if(ts.isImportDeclaration(s)&&ts.isStringLiteral(s.moduleSpecifier)&&!s.importClause?.isTypeOnly) {
        const imported=dependency(mod,s.moduleSpecifier.text);
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
    if(base.unknown||base.ref?.unknown)return;
    if(base.native==='mongodb'&&key==='MongoClient')return native('mongo-client',base.nativeMod,base.ref);
    if(base.native==='express'&&key==='Router')return native('router',base.nativeMod,base.ref);
    if(base.tag==='express-router'&&key==='locals'){
      if(!base.ref.properties.has(key))base.ref.properties.set(key,object('express-locals'));
      return base.ref.properties.get(key);
    }
    if(base.tag==='express-request') {
      if(['query','body','params'].includes(key))return value('input',[loc(node,state.mod,'EXPRESS_'+key.toUpperCase(),state.fn)],{inputShape:key==='params'?'STRING_MAP':undefined});
      if(['user','session'].includes(key)){
        state.context.checks.push(loc(node,state.mod,'PRINCIPAL_CONTEXT_UNVERIFIED',state.fn));return {...unknown(),principal:true};
      }
      return unknown();
    }
    if(base.tag==='express-response')return native('response-'+key,state.mod);
  }
  function write(receiver,key,v,state) {
    if(!state.nodeMode||!literal(key)||!receiver.ref)return false;
    if(receiver.native){receiver.ref.unknown=true;note(state.mod,'NODE_LIBRARY_MUTATION_UNKNOWN');return true;}
    if(['node-module','node-exports','express-locals'].includes(receiver.tag)||state.constructing&&receiver.ref===state.thisValue?.ref) {
      receiver.ref.properties.set(String(key.constant),v);return true;
    }
    return false;
  }
  function observe(v,node,state,ruleId,kind,operation) {
    if(state.context.setup)return;
    const sink=loc(node,state.mod,operation,state.fn), uncertain=v.unknown||v.ref?.unknown||state.uncertain;
    const status=v.trace.length?(uncertain?'FLOW_UNRESOLVED':'INPUT_TO_EXECUTION'):uncertain?'UNKNOWN':'STATIC_OR_DATA_ONLY';
    append(result.nodeUses,{ruleId,kind:status,operation,location:sink,trace:v.trace,limitations:['STATIC_PATH_NOT_RUNTIME_EXPLOIT_PROOF',...(uncertain?['NODE_FLOW_UNRESOLVED']:[])]},state.mod);
    state.context.resources.push(sink);
    if(!v.trace.length)return;
    append(result.findings,{ruleId,kind,confidence:uncertain?'MEDIUM':'HIGH',disposition:'REVIEW_REQUIRED',source:v.trace[0],sink,flow:v.trace,
      defenses:state.context.defenses.slice(0,20),limitations:['STATIC_PATH_NOT_RUNTIME_EXPLOIT_PROOF','MIDDLEWARE_AND_RUNTIME_NOT_VERIFIED',...(uncertain?['NODE_FLOW_UNRESOLVED']:[])],
      message:ruleId==='JS_EVAL_INPUT_FLOW'?'사용자가 보낸 값이 서버의 코드 실행에 전달될 수 있습니다.':'사용자가 보낸 값이 데이터베이스의 실행 문자열에 들어갈 수 있습니다.',
      recommendation:ruleId==='JS_EVAL_INPUT_FLOW'?'입력값을 코드로 실행하지 말고 필요한 숫자 변환이나 스키마 검증을 사용하세요.':'$where 문자열 결합을 피하고 일반적인 값 비교 쿼리와 입력 타입 검증을 사용하세요.'},state.mod);
  }
  function call(node,callee,receiver,args,state,global,callable) {
    if(!state.nodeMode)return;
    const method=ts.isPropertyAccessExpression(callee)?callee.name.text:undefined;
    if(global&&ts.isIdentifier(callee)&&callee.text==='require'&&ts.isCallExpression(node))
      return {value:args.length===1&&literal(args[0])&&typeof args[0].constant==='string'?dependency(state.mod,args[0].constant):unknown()};
    if(!callable?.unknown&&!callable?.ref?.unknown&&(callable?.native==='express'||callable?.native==='router')) {
      if(apps.length>=limits.maxResults){note(state.mod,'EXPRESS_APP_LIMIT');return {value:unknown()};}
      const app=object('express-router');app.app=callable.native==='express';app.routes=[];app.mounts=[];if(app.app)apps.push(app);return {value:app};
    }
    if(receiver?.tag==='express-router') {
      if(receiver.unknown||receiver.ref.unknown){note(state.mod,'EXPRESS_RECEIVER_MUTATION_UNKNOWN');return {value:unknown()};}
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
      if(callback?.target&&major)invoke(callback.target,[constant(null),object('mongo-db')],0,state.context,new Set(),state.uncertain);
      else note(state.mod,'MONGODB_CONNECTION_API_VERSION_UNKNOWN');
      return {value:unknown()};
    }
    if(receiver?.native==='node-http'&&!receiver.unknown&&!receiver.ref?.unknown&&method==='createServer'&&args.some(a=>a.tag==='express-router'&&!a.unknown&&!a.ref.unknown))return {value:object('node-http-server')};
    if(receiver?.tag==='node-http-server'&&method==='listen')return {value:receiver};
    if(callable?.native==='mongo-client'&&!callable.unknown&&!callable.ref?.unknown&&ts.isNewExpression(node)){
      const declarations=(api.input.nodeManifests??[]).filter(m=>state.mod.filePath.startsWith(path.posix.dirname(m.filePath)==='.'?'':path.posix.dirname(m.filePath)+'/')).sort((a,b)=>b.filePath.length-a.filePath.length);
      if(/^(?:\^|~)?[3-6]\./.test(declarations[0]?.mongodb??''))return {value:object('mongo-client-instance')};
      note(state.mod,'MONGODB_CONNECTION_API_VERSION_UNKNOWN');return {value:unknown()};
    }
    if(receiver?.tag==='mongo-client-instance'&&!receiver.unknown&&!receiver.ref.unknown&&method==='db')return {value:object('mongo-db')};
    if(receiver?.tag==='mongo-db'&&!receiver.unknown&&!receiver.ref.unknown&&method==='collection'&&literal(args[0]))return {value:object('mongo-collection')};
    if(receiver?.tag==='mongo-collection'&&!receiver.unknown&&!receiver.ref.unknown&&['find','findOne','countDocuments'].includes(method)) {
      for(const query of (args[0]?.nodeAlternatives??[args[0]??unknown()]).slice(0,4)) {
      const where=query.ref?.properties.get('$where');
      if(!where&&!query.unknown&&!query.ref?.unknown){
        const location=loc(node,state.mod,'MONGO_RESOURCE_ACCESS',state.fn);
        if(!state.context.setup){append(result.nodeUses,{ruleId:'JS_MONGO_RESOURCE_ACCESS',kind:'DATA_QUERY_NOT_AUTHORIZATION_PROOF',operation:method,location,trace:query.ref?.trace??query.trace,limitations:['OBJECT_OWNERSHIP_AND_MIDDLEWARE_NOT_VERIFIED']},state.mod);state.context.resources.push(location);}
        continue;
      }
      observe(where?{...where,unknown:where.unknown||query.unknown||query.ref.unknown}:query.unknown?query:constant(null),node,state,'JS_MONGO_WHERE_INPUT_FLOW','CWE-943','MONGODB_'+method.toUpperCase());
      }
      return {value:object('mongo-cursor')};
    }
    if(receiver?.tag==='mongo-cursor'&&['toArray','limit','sort'].includes(method))return {value:receiver};
    if(global&&ts.isIdentifier(callee)&&callee.text==='eval'&&ts.isCallExpression(node)) {
      observe(args[0]??unknown(),node,state,'JS_EVAL_INPUT_FLOW','CWE-95','EVAL_CALL');
      note(state.mod,'EVAL_SCOPE_EFFECTS_UNKNOWN');
      for(const [key,v]of state.vars)if(!['express-request','express-response'].includes(v.tag))state.vars.set(key,{...v,unknown:true,constant:undefined});
      return {value:unknown()};
    }
    if(receiver?.tag==='express-response'&&['send','json','render','redirect','status','end'].includes(method))return {value:receiver};
    if(!state.context.setup&&['find','findOne','countDocuments'].includes(method))for(const query of args[0]?.nodeAlternatives??[args[0]]) {
      const where=query?.ref?.properties.get('$where');
      if(where?.trace.length)append(result.nodeUses,{ruleId:'JS_MONGO_WHERE_INPUT_FLOW',kind:'RECEIVER_NOT_VERIFIED',operation:method,
        location:loc(node,state.mod,'UNVERIFIED_QUERY_CALL',state.fn),trace:where.trace,limitations:['MONGODB_RECEIVER_OR_OBJECT_FLOW_UNRESOLVED']},state.mod);
    }
  }
  function construct(target,args,state) {
    const instance=object('node-instance');instance.constructorTarget=target;
    invoke(target,args,state.depth+1,state.context,state.stack,state.uncertain,false,instance,true);
    return instance;
  }
  function discover() {
    for(const mod of modules.values()) {
      let root=false;
      const scan=node=>{tick(mod);if(ts.isImportDeclaration(node)&&node.moduleSpecifier.text==='express'&&!node.importClause?.isTypeOnly)root=true;
        if(ts.isCallExpression(node)&&ts.isIdentifier(node.expression)&&node.expression.text==='require'&&node.arguments.length===1&&ts.isStringLiteral(node.arguments[0])&&node.arguments[0].text==='express')root=true;
        ts.forEachChild(node,scan);};
      try{scan(mod.ast);if(root)load(mod);}catch{note(mod,'NODE_DISCOVERY_BUDGET_OR_UNSUPPORTED');}
    }
    const reachable=new Set();const visit=app=>{if(reachable.has(app)||app.unknown||app.ref.unknown)return;reachable.add(app);for(const child of app.mounts){tick(child.routes[0]?.target.mod??[...modules.values()][0]);visit(child);}};
    for(const app of apps)visit(app);
    for(const app of reachable)for(const route of app.routes) {
      const mod=route.target.mod;
      if(mod.entries.length>=limits.maxResults){note(mod,'EXPRESS_ENTRY_LIMIT');continue;}
      mod.entries.push({fn:route.target,kind:'EXPRESS_HANDLER',registration:route.location,uncertain:route.uncertain||!!route.setupContext.unresolved,middleware:route.middleware});mod.record.entrypoints++;
    }
    for(const route of routes)if(![...reachable].some(app=>app.routes.includes(route)))note(route.target.mod,'UNMOUNTED_ROUTER_NOT_ANALYZED');
  }
  return {property,write,call,construct,discover,functionValue};
}
