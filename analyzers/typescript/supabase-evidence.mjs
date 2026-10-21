import path from 'node:path';

// Declaration provenance only. No target evaluation, session validation or database access.
export function linkSupabaseEvidence({ts,modules,snapshot,tick}) {
  if(!snapshot.accesses.length)return;
  let work=0,bytes=Buffer.byteLength(JSON.stringify(snapshot));
  const charge=()=>{if(++work>5000)throw Error('CLIENT_POLICY_LINK_BUDGET_LIMIT');tick();};
  const unwrap=n=>{while(n&&(ts.isAsExpression(n)||ts.isNonNullExpression(n)||ts.isParenthesizedExpression(n)||ts.isAwaitExpression(n)))n=n.expression;return n;};
  const inside=(node,scope)=>{for(let n=node;n;n=n.parent)if(n===scope)return true;return false;};
  const fnOf=node=>{for(let n=node?.parent;n;n=n.parent)if(ts.isFunctionLike(n))return n;return null;};
  const location=(n,m,kind)=>{const p=m.ast.getLineAndCharacterOfPosition(n.getStart(m.ast));return {filePath:m.filePath,line:p.line+1,column:p.character+1,functionName:'',kind};};
  const id=l=>`${l.filePath}:${l.line}:${l.column}`;
  const identity=c=>JSON.stringify([c.location,c.keySource,c.transport,c.trace]);
  const index=m=>m.syntaxIndex;
  const known=spec=>spec==='@supabase/supabase-js'||/^npm:@supabase\/supabase-js@2(?:\.\d+){0,2}$/.test(spec)||/^https:\/\/esm\.sh\/@supabase\/supabase-js@2(?:\.\d+){0,2}$/.test(spec);
  const server=spec=>spec==='@supabase/server'||/^npm:@supabase\/server@1(?:\.\d+){0,2}$/.test(spec);
  const scope=d=>{for(let n=d.parent;n;n=n.parent)if(ts.isFunctionLike(n)||ts.isBlock(n)||ts.isSourceFile(n))return n;return null;};
  function binding(m,name,use) {
    charge();const candidates=(index(m)?.declarations.get(name)??[]).filter(d=>inside(use,scope(d)));
    const ordered=candidates.sort((a,b)=>{let n=use;while(n){if(scope(a)===n)return -1;if(scope(b)===n)return 1;n=n.parent;}return 0;});
    if(!ordered.length)return undefined;
    const nearest=scope(ordered[0]);return ordered.filter(d=>scope(d)===nearest).length===1?ordered[0]:null;
  }
  function imported(m,name,use) {
    if(binding(m,name,use)!==undefined||index(m)?.writes.has(name)||index(m)?.typeOnly.has(name))return null;
    return m.imports.get(name);
  }
  function targetModule(m,spec) {
    if(!spec.startsWith('.'))return null;
    const p=path.posix.normalize(path.posix.join(path.posix.dirname(m.filePath),spec));
    if(p.startsWith('../')||p.startsWith('/'))return null;
    const options=[p,p+'.ts',p+'.tsx',p+'.js',p+'/index.ts',p+'/index.js'].filter(k=>modules.has(k));
    return options.length===1?modules.get(options[0]):null;
  }
  function exported(m,name) {
    const ds=index(m)?.declarations.get(name)??[];
    return ds.length===1&&inside(ds[0],m.ast)&&!fnOf(ds[0])
      &&(ds[0].modifiers?.some(v=>v.kind===ts.SyntaxKind.ExportKeyword)||ds[0].parent?.parent?.modifiers?.some(v=>v.kind===ts.SyntaxKind.ExportKeyword))?ds[0]:null;
  }
  function functionTarget(m,callee) {
    if(!ts.isIdentifier(callee))return null;
    let d=binding(m,callee.text,callee);
    if(d===undefined){const imp=imported(m,callee.text,callee);const other=imp&&targetModule(m,imp.spec);if(!other)return null;m=other;d=exported(m,imp.exported);}
    if(!d||index(m)?.writes.has(d.name?.text??callee.text))return null;
    const fn=ts.isFunctionDeclaration(d)?d:ts.isVariableDeclaration(d)?unwrap(d.initializer):null;
    return fn&&(ts.isArrowFunction(fn)||ts.isFunctionExpression(fn)||ts.isFunctionDeclaration(fn))?{mod:m,fn}:null;
  }
  const property=(node,name)=>{
    node=unwrap(node);if(!node||!ts.isObjectLiteralExpression(node)||node.properties.some(p=>!ts.isPropertyAssignment(p)&&!ts.isShorthandPropertyAssignment(p)))return null;
    const matches=node.properties.filter(p=>p.name&&!ts.isComputedPropertyName(p.name)&&(ts.isIdentifier(p.name)||ts.isStringLiteral(p.name))&&p.name.text===name);
    return matches.length===1?(ts.isShorthandPropertyAssignment(matches[0])?matches[0].name:matches[0].initializer):null;
  };
  function contextClient(m,node) {
    if(!ts.isPropertyAccessExpression(node)||!['supabase','supabaseAdmin'].includes(node.name.text)||!ts.isIdentifier(node.expression))return null;
    const fn=fnOf(node),p=fn?.parameters?.[1],call=fn?.parent;
    if(!p||!ts.isIdentifier(p.name)||p.name.text!==node.expression.text||!call||!ts.isCallExpression(call)||call.arguments[1]!==fn||!ts.isIdentifier(call.expression))return null;
    const imp=imported(m,call.expression.text,call.expression);if(imp?.exported!=='withSupabase'||!server(imp.spec))return null;
    const parent=call.parent,container=parent?.parent;
    if(!ts.isPropertyAssignment(parent)||parent.name.getText(m.ast)!=='fetch'||!ts.isObjectLiteralExpression(container)||!ts.isExportAssignment(container.parent))return null;
    const mode=unwrap(property(call.arguments[0],'auth'));
    if(!mode||!ts.isStringLiteral(mode)||!['user','secret','publishable','none'].includes(mode.text))return null;
    if(index(m).writes.has(p.name.text)||binding(m,p.name.text,node)!==p||escaped(m,p,node))return null;
    const admin=node.name.text==='supabaseAdmin';
    if(!admin&&mode.text!=='user')return null;
    return {location:location(admin?p:call,m,admin?'SUPABASE_ADMIN_CONTEXT':'SUPABASE_SERVER_WRAPPER'),keySource:admin?'SERVER_CLIENT_CONTRACT':'UNKNOWN',
      authContext:mode.text==='user'?'USER_JWT_WRAPPER_DECLARATION':'WRAPPER_CALLER_MODE_NOT_USER_PROOF',
      contract:admin?'SUPABASE_SERVER_ADMIN':'SUPABASE_SERVER_USER',trace:[location(node,m,'CONTEXT_CLIENT_REFERENCE')],
      mode:mode.text,policyScopeEligible:!admin,transport:'WRAPPER_CONTRACT_NOT_RUNTIME_PROOF'};
  }
  function escaped(m,d,use,depth=0,seen=new Set()) {
    if(depth>3||seen.has(d))return true;seen=new Set([...seen,d]);
    if(index(m)?.argumentReferenceIncomplete?.has(d.name.text))return true;
    for(const alias of index(m)?.aliases?.get(d.name.text)??[]){
      charge();if(alias.declaration===d||binding(m,d.name.text,alias.reference)!==d)continue;
      if(index(m).writes.has(alias.declaration.name.text)||escaped(m,alias.declaration,use,depth+1,seen))return true;
    }
    for(const {call,node} of index(m)?.argumentUses?.get(d.name.text)??[]){
      charge();
      if(call.pos<=d.pos||call.pos>=use.pos||inside(use,call))continue;
      if(binding(m,node.text,node)===d)return true;
    }
    return false;
  }
  function resolve(m,original,env=new Map(),depth=0,seen=new Set()) {
    charge();const node=unwrap(original);if(!node||depth>3||seen.has(node))return null;seen=new Set([...seen,node]);
    const ctx=contextClient(m,node);if(ctx)return ctx;
    if(ts.isIdentifier(node)){
      if(index(m)?.writes.has(node.text))return null;
      const d=binding(m,node.text,node);
      if(d&&env.has(d))return resolve(env.get(d).mod,env.get(d).node,env.get(d).env,depth+1,seen);
      if(d&&ts.isParameter(d)){
        if(escaped(m,d,node))return null;
        const fn=d.parent,slot=fn.parameters.indexOf(d),origins=[];
        const name=fn.name?.text??(ts.isVariableDeclaration(fn.parent)&&ts.isIdentifier(fn.parent.name)?fn.parent.name.text:null);
        if(!name)return null;
        for(const mod of modules.values())for(const call of index(mod)?.nodes??[]){
          if(!ts.isIdentifier(call.expression))continue;
          if(call.expression.text!==name&&mod.imports.get(call.expression.text)?.exported!==name)continue;
          const target=functionTarget(mod,call.expression);
          if(target?.fn!==fn)continue;
          if(origins.length>=4)return null;
          const value=resolve(mod,call.arguments[slot],env,depth+1,seen);if(!value)return null;origins.push(value);
        }
        return origins.length&&origins.every(v=>identity(v)===identity(origins[0]))?{...origins[0],trace:[...origins[0].trace,location(node,m,'STATIC_PARAMETER_REFERENCE')].slice(-8)}:null;
      }
      if(d&&ts.isVariableDeclaration(d)&&ts.isIdentifier(d.name)&&(d.parent.flags&ts.NodeFlags.Const))return escaped(m,d,node)?null:resolve(m,d.initializer,env,depth+1,seen);
      if(d!==undefined)return null;
      const imp=imported(m,node.text,node),other=imp&&targetModule(m,imp.spec),decl=other&&exported(other,imp.exported);
      return decl&&ts.isVariableDeclaration(decl)?resolve(other,decl.initializer,env,depth+1,seen):null;
    }
    if(ts.isPropertyAccessExpression(node)){
      let object=unwrap(node.expression);
      if(ts.isIdentifier(object)){
        const d=binding(m,object.text,object);if(!d||!ts.isVariableDeclaration(d)||index(m).writes.has(object.text)||!(d.parent.flags&ts.NodeFlags.Const)||escaped(m,d,node))return null;
        object=unwrap(d.initializer);
      }
      const value=property(object,node.name.text);return value?resolve(m,value,env,depth+1,seen):null;
    }
    if(!ts.isCallExpression(node)||!ts.isIdentifier(node.expression))return null;
    const imp=imported(m,node.expression.text,node.expression);
    const sdk=imp&&known(imp.spec)&&imp.exported==='createClient';
    const ssr=imp?.spec==='@supabase/ssr'&&['createBrowserClient','createServerClient'].includes(imp.exported);
    if((sdk||ssr)&&node.arguments.length>=2&&node.arguments.length<=3){
      let key=unwrap(node.arguments[1]),label;
      if(ts.isIdentifier(key)){const d=binding(m,key.text,key);if(d&&ts.isVariableDeclaration(d)&&!index(m).writes.has(key.text))key=unwrap(d.initializer);}
      if(key&&ts.isPropertyAccessExpression(key)&&(key.expression.getText(m.ast)==='import.meta.env'||key.expression.getText(m.ast)==='process.env'&&binding(m,'process',key)===undefined&&!index(m).writes.has('process')))label=key.name.text;
      if(key&&ts.isCallExpression(key)&&key.expression.getText(m.ast)==='Deno.env.get'&&!index(m).bindings.has('Deno')&&!index(m).writes.has('Deno')&&key.arguments.length===1&&ts.isStringLiteral(key.arguments[0]))label=key.arguments[0].text;
      const keySource=label?/(?:SERVICE_ROLE|SECRET_KEY)/i.test(label)?'SERVER_KEY_NAME_HINT':/(?:PUBLISHABLE|ANON)/i.test(label)?'PUBLIC_KEY_NAME_HINT':'ENVIRONMENT_REFERENCE_UNKNOWN'
        :key&&ts.isStringLiteral(key)&&key.text.startsWith('sb_publishable_')?'PUBLIC_KEY_FORMAT_HINT'
        :key&&ts.isStringLiteral(key)&&key.text.startsWith('sb_secret_')?'SERVER_KEY_FORMAT_HINT':'UNKNOWN';
      const options=unwrap(node.arguments[2]),override=options&&property(options,'global'),fetchOverride=options&&(property(options,'accessToken')||property(override,'fetch'));
      const db=unwrap(property(options,'db')),schema=unwrap(property(db,'schema'));
      const eligible=(!options||ts.isObjectLiteralExpression(options)&&options.properties.every(p=>ts.isPropertyAssignment(p)&&!ts.isComputedPropertyName(p.name)))
        &&(!db||ts.isObjectLiteralExpression(db)&&db.properties.every(p=>ts.isPropertyAssignment(p)&&!ts.isComputedPropertyName(p.name)))
        &&(!override||ts.isObjectLiteralExpression(unwrap(override))&&unwrap(override).properties.every(p=>ts.isPropertyAssignment(p)&&!ts.isComputedPropertyName(p.name)))
        &&!fetchOverride&&(!schema||ts.isStringLiteral(schema)&&schema.text==='public');
      return {location:location(node,m,'SUPABASE_CLIENT_DECLARATION'),keySource,authContext:ssr?'SESSION_REFERENCE_UNVERIFIED':options?'OPTIONS_OR_AUTH_OVERRIDE_NOT_EVALUATED':'SESSION_AND_AUTH_HEADERS_UNKNOWN',
        contract:sdk?'SUPABASE_JS_CREATE_CLIENT':imp.exported==='createServerClient'?'SUPABASE_SSR_SERVER':'SUPABASE_SSR_BROWSER',
        trace:[],policyScopeEligible:eligible,transport:!eligible?'CLIENT_SCHEMA_OR_TRANSPORT_UNVERIFIED':override?'AUTHORIZATION_OVERRIDE_UNVERIFIED':'SESSION_AND_HEADERS_UNKNOWN'};
    }
    const target=functionTarget(m,node.expression);if(!target?.fn?.body)return null;
    const fn=target.fn;
    if(fn.modifiers?.some(p=>p.kind===ts.SyntaxKind.AsyncKeyword)&&!ts.isAwaitExpression(original)&&!ts.isAwaitExpression(node.parent))return null;
    if(node.arguments.length!==fn.parameters.length||fn.parameters.some(p=>!ts.isIdentifier(p.name)||p.dotDotDotToken||p.initializer))return null;
    const statements=ts.isBlock(fn.body)?fn.body.statements:null;
    if(statements&&(statements.length>8||statements.slice(0,-1).some(s=>!ts.isVariableStatement(s)||!(s.declarationList.flags&ts.NodeFlags.Const))||!ts.isReturnStatement(statements.at(-1))))return null;
    const returned=statements?statements.at(-1).expression:fn.body;
    const bindings=new Map(env);fn.parameters.forEach((p,i)=>bindings.set(p,{mod:m,node:node.arguments[i],env}));
    const r=resolve(target.mod,returned,bindings,depth+1,seen);
    return r?{...r,trace:[...r.trace,location(node,m,'STATIC_FACTORY_CALL')].slice(-8)}:null;
  }
  const authCalls=new Map();
  const checksFor=(mod,node,client)=>{
    const fn=fnOf(node),out=[];
    for(const call of authCalls.get(mod)?.get(fn)??[]){
      charge();
      if(out.length>=4)break;
      if(call.pos>=node.pos||fnOf(call)!==fn||!ts.isPropertyAccessExpression(call.expression)||!['getUser','getClaims','getSession'].includes(call.expression.name.text))continue;
      const auth=call.expression.expression;
      if(!ts.isPropertyAccessExpression(auth)||auth.name.text!=='auth'||!ts.isAwaitExpression(call.parent))continue;
      const c=resolve(mod,auth.expression);if(!c||identity(c)!==identity(client))continue;
      out.push({method:call.expression.name.text,location:location(call,mod,'AUTH_API_CALL'),status:call.expression.name.text==='getSession'?'SESSION_READ_UNVERIFIED':'IDENTITY_VERIFICATION_CALL_OBSERVED'});
    }
    return out;
  };
  try {
    const sites=new Map();
    for(const mod of modules.values())for(const node of index(mod)?.nodes??[]){
      charge();
      if(ts.isPropertyAccessExpression(node.expression)&&['getUser','getClaims','getSession'].includes(node.expression.name.text)){
        if(!authCalls.has(mod))authCalls.set(mod,new Map());const key=fnOf(node),calls=authCalls.get(mod).get(key)??[];calls.push(node);authCalls.get(mod).set(key,calls);
      }
      if(ts.isPropertyAccessExpression(node.expression)&&node.expression.name.text==='from'){
        let outer=node;while(ts.isPropertyAccessExpression(outer.parent)&&outer.parent.expression===outer&&ts.isCallExpression(outer.parent.parent))outer=outer.parent.parent;
        const key=id(location(outer,mod,'')),rows=sites.get(key)??[];rows.push({mod,node});sites.set(key,rows);
      }
    }
    for(let i=0;i<snapshot.accesses.length;i++){
      charge();const old=snapshot.accesses[i];
      // The legacy access location is the end of the fluent chain, not from().
      const matches=(sites.get(id(old.location))??[]).filter(s=>s.node.arguments[0]?.text===old.table.slice(7));
      const site=matches.length===1?matches[0]:null;
      let c=site?resolve(site.mod,site.node.expression.expression):null;
      if(!c&&old.clientLocation)c={...snapshot.clients.find(v=>id(v.location)===id(old.clientLocation)),contract:'LEGACY_DIRECT_DECLARATION',trace:[],transport:'AUTH_HEADERS_AND_TRANSPORT_UNVERIFIED'};
      const checks=site&&c?checksFor(site.mod,site.node,c):[];
      const table=snapshot.tables.find(t=>t.table===old.table&&id(t.location)===id(old.policyLocation??{}));
      const ops=table?.operations.filter(o=>o.operation===old.operation)??[];
      const granted=ops.filter(o=>o.grant==='EXPLICIT_GRANT');
      const filters=[];
      if(site){let call=site.node;while(ts.isPropertyAccessExpression(call.parent)&&call.parent.expression===call&&ts.isCallExpression(call.parent.parent)){
        call=call.parent.parent;if(call.expression.name.text==='eq'&&filters.length<4)filters.push(location(call,site.mod,'APPLICATION_FILTER_NOT_AUTHORIZATION_PROOF'));
      }}
      let state='UNKNOWN';
      if(c&&c.contract==='SUPABASE_SERVER_ADMIN')state='ADMIN_ACCESS_REVIEW';
      else if(c?.policyScopeEligible&&old.operation!=='SELECT'&&ops.some(o=>o.candidate))state='BROAD_ACCESS_REVIEW';
      else if(c?.policyScopeEligible&&!['SERVER_KEY_NAME_HINT','SERVER_KEY_FORMAT_HINT'].includes(c.keySource)&&table&&table.rls==='ENABLED'&&granted.some(o=>o.state==='UID_COLUMN_EQUALITY')&&granted.every(o=>['UID_COLUMN_EQUALITY','DENY'].includes(o.state)))state='CONFIRMED_POLICY_EVIDENCE';
      else if(c?.policyScopeEligible&&old.operation==='SELECT'&&ops.some(o=>o.state==='ALLOW'&&o.grant==='EXPLICIT_GRANT'))state='PUBLIC_READ_DECLARATION';
      const evidence={state,clientContract:c?.contract??'UNKNOWN',authStatus:checks.at(-1)?.status??c?.authContext??'UNKNOWN',effectiveRole:'UNKNOWN',
        roleEvidence:c?.contract==='SUPABASE_SERVER_ADMIN'?'ADMIN_WRAPPER_DECLARATION':c?.mode==='user'?'USER_JWT_WRAPPER_DECLARATION':c?.keySource??'UNKNOWN',
        authChecks:checks,clientTrace:c?[c.location,...c.trace].slice(0,8):[],policyLocations:ops.flatMap(o=>o.policyLocations).slice(0,8),
        filterLocations:filters,enclosingFunction:site&&fnOf(site.node)?location(fnOf(site.node),site.mod,'ENCLOSING_FUNCTION_NOT_REQUEST_PROOF'):null,
        policyStates:ops.map(o=>o.role+':'+o.operation+':'+o.state).slice(0,8),
        limitations:['DECLARED_POLICY_NOT_DEPLOYED_DB_PROOF','API_KEY_NOT_USER_IDENTITY','AUTH_CALL_NOT_SUCCESS_OR_AUTHORIZATION_PROOF',
          'APPLICATION_FILTER_NOT_DATABASE_AUTHORIZATION','PROJECT_ASSOCIATION_NOT_VERIFIED','BRANCH_AND_EXTERNAL_CALL_CONTEXTS_NOT_VERIFIED',
          ...(!c?['DYNAMIC_PROXY_ALIAS_AND_MIDDLEWARE_NOT_SUPPORTED']:[]),c?.transport??'CLIENT_ORIGIN_UNRESOLVED']};
      const record={...old,authorizationEvidence:evidence,...(c?{clientStatus:'CLIENT_DECLARATION_LINKED',clientLocation:c.location,keySource:c.keySource}:{})};
      const client=c&&!snapshot.clients.some(v=>id(v.location)===id(c.location))?{location:c.location,keySource:c.keySource,authContext:c.authContext,
        limitations:['KEY_SOURCE_NOT_DB_ROLE_PROOF','DECLARATION_NOT_RUNTIME_EXECUTION_PROOF']}:null;
      const delta=Buffer.byteLength(JSON.stringify(record))-Buffer.byteLength(JSON.stringify(old))+(client?Buffer.byteLength(JSON.stringify(client)):0);
      if(bytes+delta>275000||client&&snapshot.clients.length>=100){snapshot.limitations.push('CLIENT_POLICY_EVIDENCE_OUTPUT_LIMIT');break;}
      if(client)snapshot.clients.push(client);snapshot.accesses[i]=record;bytes+=delta;
    }
  } catch(error) {snapshot.limitations.push(['CLIENT_POLICY_LINK_BUDGET_LIMIT','CLIENT_STEP_BUDGET','SUPABASE_BUDGET'].includes(error?.message)?'CLIENT_POLICY_LINK_BUDGET_LIMIT':'CLIENT_POLICY_LINK_CONTEXT_INCOMPLETE');}
}
