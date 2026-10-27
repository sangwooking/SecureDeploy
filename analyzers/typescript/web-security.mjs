// Versioned declarations and terminal-response paths, not a middleware execution engine.
export function webSecurity(api){
 const {ts,input,value,unknown,constant,loc,note,tick,append,result,native,object}=api;
 const scalar=v=>v?.tag==='constant'&&!v.unknown&&Object.hasOwn(v,'constant');
 const plain=v=>v?.tag==='object'&&v.ref?.plainData&&!v.unknown&&!v.ref.unknown;
 const get=(v,k)=>v?.ref?.properties.get(k);
 const atom=v=>!v?'ABSENT':scalar(v)?[typeof v.constant,v.constant]:['UNKNOWN',v.tag,!!v.unknown,!!v.ref?.unknown];
 const cookieKeys=['secure','httpOnly','sameSite','domain','path','maxAge','expires'];
 function signature(kind,opts){
  return JSON.stringify([!!opts?.unknown,!!opts?.ref?.unknown,
   ...(kind==='cors'?['origin','credentials','preflightContinue'].map(k=>atom(get(opts,k)))
    :[atom(get(opts,'cookie')),...cookieKeys.map(k=>atom(get(get(opts,'cookie'),k)))])]);
 }
 function dependency(mod,spec){
  if(!['cors','express-session'].includes(spec))return;
  return native('web-'+spec,mod);
 }
 function factory(callable,node,args,state){
  if(!callable?.native?.startsWith('web-'))return;
  const kind=callable.native==='web-cors'?'cors':'session';
  const manifest=(input.nodeManifests??[]).filter(m=>state.mod.filePath.startsWith(m.filePath==='package.json'?'':m.filePath.slice(0,-12)))
   .sort((a,b)=>b.filePath.length-a.filePath.length)[0];
  const version=manifest?.[kind==='cors'?'cors':'express-session'];
  const validVersion=version===(kind==='cors'?'2.8.5':'1.18.1');
  const opts=args[0]??object('object');
  const allowed=kind==='cors'?['origin','credentials','preflightContinue']:['secret','cookie','resave','saveUninitialized','name'];
  const secret=get(opts,'secret');
  const secretDeclared=kind==='cors'||secret&&(scalar(secret)&&typeof secret.constant==='string'&&secret.constant.length>0||secret.exposures?.length>0);
  const name=get(opts,'name'),validName=!name||scalar(name)&&typeof name.constant==='string'&&/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name.constant);
  const known=ts.isCallExpression(node)&&!callable.unknown&&!callable.ref?.unknown&&args.length<=1&&validVersion&&secretDeclared&&validName
   &&(args.length===0&&kind==='cors'||plain(opts)&&[...opts.ref.properties.keys()].every(k=>allowed.includes(k)))&&!state.uncertain;
  const middleware=object('web-middleware');
  middleware.web={kind,opts,known,location:loc(node,state.mod,(kind==='cors'?'CORS_FACTORY':'SESSION_FACTORY')+(ts.isSourceFile(state.fn.node)?'_MODULE':''),state.fn),signature:signature(kind,opts)};
  const literalOptions=node.arguments?.[0];
  if(kind==='cors'&&literalOptions&&ts.isObjectLiteralExpression(literalOptions)){
   const origin=literalOptions.properties.find(p=>ts.isPropertyAssignment(p)&&p.name.getText(state.mod.ast)==='origin');
   if(origin&&ts.isArrayLiteralExpression(origin.initializer)&&origin.initializer.elements.length<=8
      &&origin.initializer.elements.length>0&&origin.initializer.elements.every(e=>ts.isStringLiteral(e)&&validOrigin(e.text)))middleware.web.fixedList=true;
  }
  if(!known)note(state.mod,'WEB_MIDDLEWARE_VERSION_OR_OPTIONS_UNKNOWN');
  return {value:middleware};
 }
 function validOrigin(text){try{const u=new URL(text);return ['http:','https:'].includes(u.protocol)&&u.origin===text&&text.length<=260;}catch{return false;}}
 function stack(receiver){return receiver.webStack??(receiver.webStack=[]);}
 function use(receiver,args,node,state){
  const entries=stack(receiver);if(entries.length>=50){receiver.webUnknown=true;note(state.mod,'WEB_MIDDLEWARE_SCOPE_LIMIT');return;}
  const mount=args.length===1?'/':scalar(args[0])?args[0].constant:undefined;
  const middleware=args.at(-1);
  if(middleware?.tag==='express-router'){middleware.webParentUnknown=true;return;}
  if(middleware?.tag==='web-middleware'&&args.length<=2&&typeof mount==='string'&&/^\/[\w/-]*$/.test(mount))
   entries.push({middleware,mount,location:loc(node,state.mod,'WEB_MIDDLEWARE_MOUNT',state.fn)});
  else receiver.webUnknown=true;
 }
 function route(receiver,args,node,state,method){
  const path=scalar(args[0])?args[0].constant:undefined;
  const policies=[...stack(receiver)];let uncertain=!!receiver.webUnknown;
  for(const mid of args.slice(1,-1)){
   if(mid?.tag==='web-middleware')policies.push({middleware:mid,mount:'/',location:loc(node,state.mod,'ROUTE_WEB_MIDDLEWARE',state.fn)});
   else uncertain=true;
  }
  const matched=policies.filter(p=>typeof path==='string'&&(p.mount==='/'||path===p.mount||path.startsWith(p.mount+'/')));
  if(typeof path!=='string'||!/^[\w/-]+$/.test(path))uncertain=true;
  return {policies:matched,uncertain,method,owner:receiver};
 }
 function entry(scope,isolate){
  if(!scope)return;
  return {policies:scope.policies.map(p=>({...p,middleware:isolate(p.middleware),web:{...p.middleware.web,opts:isolate(p.middleware.web.opts)}})),
   uncertain:scope.uncertain||!!scope.owner.webParentUnknown,method:scope.method,
   any:scope.policies.length>0||stack(scope.owner).length>0||!!scope.owner.webParentUnknown};
 }
 function record(ruleId,kind,location,trace,limitations,state){
  append(result.nodeUses,{ruleId,kind,operation:'WEB_RESPONSE_POLICY',location,trace:trace.slice(0,20),limitations:limitations.slice(0,20)},state.mod);
 }
 function candidate(ruleId,kind,source,sink,trace,message,recommendation,limitations,state){
  append(result.findings,{ruleId,kind,confidence:'HIGH',disposition:'REVIEW_REQUIRED',source,sink,flow:trace.slice(0,20),
   defenses:[],limitations,message,recommendation},state.mod);
 }
 function response(body,node,state){
  const scope=state.context.webSecurity;if(!scope?.any)return;
  const sink=loc(node,state.mod,'WEB_HTTP_RESPONSE',state.fn);
  const limits=['DECLARED_POLICY_NOT_BROWSER_OR_AUTHENTICATION_PROOF','PROXY_TLS_AND_DEPLOYMENT_UNKNOWN'];
  const active=scope.policies.filter(p=>p.web.known&&!p.middleware.unknown&&!p.middleware.ref?.unknown
   &&signature(p.web.kind,p.web.opts)===p.web.signature);
  const certain=!scope.uncertain&&!scope.responseMutated&&!state.uncertain&&active.length===scope.policies.length;
  const cors=active.filter(p=>p.web.kind==='cors');
  if(!scope.policies.length)record('JS_WEB_SECURITY_CONTEXT','CORS_POLICY_NOT_APPLICABLE',sink,[],limits,state);
  if(scope.policies.length&&!certain)record('JS_WEB_SECURITY_CONTEXT','WEB_POLICY_UNRESOLVED',sink,[],[...limits,'MIDDLEWARE_SCOPE_OR_MUTATION_UNKNOWN'],state);
  if(cors.length===1&&certain){
   const p=cors[0],o=get(p.web.opts,'origin'),c=get(p.web.opts,'credentials'),pre=get(p.web.opts,'preflightContinue');
   const origin=!o?'WILDCARD':scalar(o)?o.constant:p.web.fixedList?'FIXED_LIST':'UNKNOWN';
   const credentials=scalar(c)?c.constant===true:c?'UNKNOWN':false;
   const trace=[p.web.location,p.location,sink];let status='CORS_POLICY_UNRESOLVED';
   if(scope.method==='options'&&(!pre||scalar(pre)&&pre.constant===false))status='CORS_POLICY_NOT_APPLICABLE';
   else if(origin==='*'||origin==='WILDCARD')status=credentials==='UNKNOWN'?'CORS_POLICY_UNRESOLVED':credentials===true?'CORS_WILDCARD_CREDENTIALS_BLOCKED':'CORS_WILDCARD_DECLARED';
   else if(origin==='FIXED_LIST'||typeof origin==='string'&&validOrigin(origin))status='CORS_FIXED_ORIGIN';
   else if(origin===true&&credentials===true){
    const data=api.responseBody(body),sensitive=data.origins.filter(o=>['SERVER_SECRET_ENVIRONMENT_VALUE','REQUEST_SELECTED_ENVIRONMENT_VALUE','AUTHENTICATION_HEADER','CREDENTIAL_SHAPED_LITERAL'].includes(o.kind));
    status=sensitive.length&&!data.unresolved?'SENSITIVE_REFLECTED_CREDENTIAL_RESPONSE':'CORS_REFLECTION_CONTEXT_UNKNOWN';
    if(status==='SENSITIVE_REFLECTED_CREDENTIAL_RESPONSE'){
     trace.splice(2,0,...sensitive.slice(0,4));
     candidate('JS_CORS_CREDENTIAL_REFLECTION','CWE-942',p.web.location,sink,trace,
      '보호할 응답에 임의 출처를 허용하는 CORS 설정이 연결됩니다.',
      '필요한 웹사이트의 정확한 Origin만 허용하세요. 공개 API와 인증 API의 정책을 분리하고 정상 로그인·허용/비허용 Origin·preflight를 로컬 브라우저에서 검증하세요. CORS 제한은 인증이나 CSRF 검증을 대신하지 않습니다.',limits,state);
    }
   }
   record('JS_CORS_CREDENTIAL_REFLECTION',status,sink,trace,limits,state);
  }
  const sessions=active.filter(p=>p.web.kind==='session');
  if(cors.length>1||sessions.length>1)record('JS_WEB_SECURITY_CONTEXT','WEB_POLICY_COMPOSITION_UNKNOWN',sink,[],limits,state);
  if(sessions.length!==1||!certain||!state.webSessionRead)return;
  const s=sessions[0],cookie=get(s.web.opts,'cookie');
  const validAttribute=(k,v)=>{
   if(!scalar(v))return false;const c=v.constant;
   return k==='secure'?typeof c==='boolean'||c==='auto':k==='httpOnly'?typeof c==='boolean'
    :k==='sameSite'?typeof c==='boolean'||typeof c==='string'&&/^(?:lax|strict|none)$/i.test(c)
    :k==='domain'||k==='path'?typeof c==='string':k==='maxAge'?c===null||typeof c==='number'&&Number.isFinite(c):k==='expires'&&c===null;
  };
  const attrs=plain(cookie)&&[...cookie.ref.properties].every(([k,v])=>cookieKeys.includes(k)&&validAttribute(k,v))?cookie:!cookie?undefined:null;
  const attrLimits=[...limits,'SESSION_COOKIE_REFERENCE_NOT_AUTHENTICATION_SUCCESS'];
  if(attrs===null){record('JS_WEB_SECURITY_CONTEXT','WEB_POLICY_UNRESOLVED',sink,[],attrLimits,state);return;}
  const h=get(attrs,'httpOnly'),secure=get(attrs,'secure');
  const declared=[!h?'COOKIE_HTTPONLY_DEFAULT_ENABLED':scalar(h)&&h.constant===true?'COOKIE_HTTPONLY_ENABLED':scalar(h)&&h.constant===false?'COOKIE_HTTPONLY_DISABLED':'COOKIE_HTTPONLY_UNKNOWN',
   scalar(secure)&&secure.constant===true?'COOKIE_SECURE_ENABLED':scalar(secure)&&secure.constant===false?'COOKIE_SECURE_DISABLED':!secure?'COOKIE_SECURE_DEFAULT_DISABLED':'COOKIE_SECURE_UNKNOWN',
   get(attrs,'sameSite')?'COOKIE_SAMESITE_DECLARED_NOT_CSRF_PROOF':'COOKIE_SAMESITE_UNSET',
   get(attrs,'domain')?'COOKIE_DOMAIN_SHARING_INTENT_UNKNOWN':'COOKIE_HOST_ONLY_DECLARED',
   get(attrs,'maxAge')||get(attrs,'expires')?'COOKIE_EXPIRY_NOT_SERVER_INVALIDATION':'SESSION_EXPIRY_UNKNOWN'];
  const trace=[s.web.location,s.location,sink];
  const status=scalar(h)&&h.constant===false?'SESSION_HTTPONLY_EXPLICITLY_DISABLED':'SESSION_COOKIE_ATTRIBUTES';
  record('JS_SESSION_COOKIE_ATTRIBUTE_REVIEW',status,sink,trace,[...attrLimits,...declared],state);
  if(status==='SESSION_HTTPONLY_EXPLICITLY_DISABLED')candidate('JS_SESSION_COOKIE_ATTRIBUTE_REVIEW','CWE-1004',s.web.location,sink,trace,
   '사용 중인 세션 쿠키의 HttpOnly 설정이 꺼져 있습니다.',
   '세션 식별자는 클라이언트 스크립트가 읽지 않도록 HttpOnly를 검토하세요. 일반 UI 설정 쿠키와 구분하고 로그인·세션 유지 동작을 로컬에서 확인하세요. Secure·SameSite·만료·서버 무효화는 별도로 확인해야 합니다.',[...attrLimits,...declared],state);
  const mutations=state.context.resources.filter(r=>/^NODE_FILE_(?:WRITE|DELETE|RENAME)/.test(r.kind));
  const simple=n=>{tick(state.mod);return ts.isStringLiteralLike(n)||ts.isNumericLiteral(n)||[ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(n.kind)
   ||ts.isObjectLiteralExpression(n)&&n.properties.every(p=>ts.isPropertyAssignment(p)&&!ts.isComputedPropertyName(p.name)&&simple(p.initializer));};
  const sessionRead=n=>ts.isPropertyAccessExpression(n)&&n.name.text==='session'&&ts.isIdentifier(n.expression)&&state.vars.get(n.expression.text)?.tag==='express-request';
  const readOnly=state.fn.node.body&&ts.isBlock(state.fn.node.body)&&state.fn.node.body.statements.every(st=>ts.isVariableStatement(st)
   ?st.declarationList.declarations.every(d=>d.initializer&&(simple(d.initializer)||sessionRead(d.initializer)))
   :ts.isExpressionStatement(st)&&ts.isCallExpression(st.expression)&&ts.isPropertyAccessExpression(st.expression.expression)
    &&ts.isIdentifier(st.expression.expression.expression)&&state.vars.get(st.expression.expression.expression.text)?.tag==='express-response'
    &&['json','send','end'].includes(st.expression.expression.name.text)&&st.expression.arguments.every(simple));
  const guards=originGuard(node,state).filter(g=>mutations.every(m=>m.filePath===g.filePath&&(g.line<m.line||g.line===m.line&&g.column<m.column)));
  record('JS_WEB_SECURITY_CONTEXT',readOnly&&!mutations.length?'CSRF_READ_ONLY_LOCAL_BODY':guards.length&&mutations.length?'CSRF_EXACT_ORIGIN_CONSTRAINT':'CSRF_CONTEXT_UNVERIFIED',sink,
   [...trace,...guards,...mutations].slice(0,20),[...limits,'COOKIE_AUTHENTICATION_NOT_PROVEN',mutations.length?'STATE_CHANGE_CALL_OBSERVED':'STATE_CHANGE_NOT_VERIFIED',
    guards.length?'EXACT_ORIGIN_REJECTION_DECLARED':'CSRF_DEFENSE_UNKNOWN','TOKEN_BINDING_AND_FRAMEWORK_PROTECTION_NOT_VERIFIED'],state);
 }
 function originGuard(sink,state){
  const out=[],body=state.fn.node.body;if(!body||!ts.isBlock(body))return out;
  for(const st of body.statements){
   tick(state.mod);if(st.pos>=sink.pos)break;
   if(!ts.isIfStatement(st)||st.elseStatement){
    if(ts.isVariableStatement(st)&&st.declarationList.declarations.every(d=>d.initializer&&ts.isPropertyAccessExpression(d.initializer)
       &&ts.isIdentifier(d.initializer.expression)&&state.vars.get(d.initializer.expression.text)?.tag==='express-request'&&d.initializer.name.text==='session'))continue;
    break;
   }
   const c=st.expression;if(!ts.isBinaryExpression(c)||c.operatorToken.kind!==ts.SyntaxKind.ExclamationEqualsEqualsToken)break;
   const call=c.left,target=c.right;if(!ts.isCallExpression(call)||!ts.isPropertyAccessExpression(call.expression)
    ||!ts.isIdentifier(call.expression.expression)||state.vars.get(call.expression.expression.text)?.tag!=='express-request'
    ||call.expression.name.text!=='get'||call.arguments.length!==1||!ts.isStringLiteral(call.arguments[0])||call.arguments[0].text.toLowerCase()!=='origin'
    ||!ts.isStringLiteral(target)||!validOrigin(target.text))break;
   const terminal=ts.isBlock(st.thenStatement)&&st.thenStatement.statements.length===1?st.thenStatement.statements[0]:st.thenStatement;
   if(!terminal||!ts.isReturnStatement(terminal))break;
   let safe=!terminal.expression;
   const exit=terminal.expression;
   if(exit&&ts.isCallExpression(exit)&&ts.isPropertyAccessExpression(exit.expression)&&['end','send','json'].includes(exit.expression.name.text)
      &&exit.arguments.every(a=>ts.isStringLiteralLike(a)||ts.isNumericLiteral(a))){
    let base=exit.expression.expression;
    if(ts.isCallExpression(base)&&ts.isPropertyAccessExpression(base.expression)&&base.expression.name.text==='status'&&base.arguments.length===1&&ts.isNumericLiteral(base.arguments[0]))base=base.expression.expression;
    safe=ts.isIdentifier(base)&&state.vars.get(base.text)?.tag==='express-response';
   }
   if(safe)out.push(loc(st,state.mod,'EXACT_ORIGIN_REJECTION_GUARD',state.fn));
  }return out.slice(0,4);
 }
 function request(node,receiver,args,state){
  if(receiver?.tag==='express-request'&&ts.isCallExpression(node)&&ts.isPropertyAccessExpression(node.expression)
    &&node.expression.name.text==='get'&&args.length===1&&scalar(args[0])&&String(args[0].constant).toLowerCase()==='origin')
   return {value:value('input',[loc(node,state.mod,'REQUEST_ORIGIN_HEADER',state.fn)],{inputShape:'STRING',unknown:!!receiver.unknown})};
 }
 function headers(receiver,method,args,state){
  const scope=state.context.webSecurity;if(!scope)return;
  if(receiver?.tag==='express-response'&&method==='status'&&(!scalar(args[0])||[204,304].includes(args[0].constant)))scope.responseMutated=true;
  if(receiver?.tag==='express-response'&&['set','header','setHeader','append','removeHeader','cookie','clearCookie'].includes(method)){
   const key=scalar(args[0])?String(args[0].constant).toLowerCase():undefined;
   if(!key||method==='cookie'||method==='clearCookie'||['set-cookie','access-control-allow-origin','access-control-allow-credentials'].includes(key))scope.responseMutated=true;
  }
 }
 function write(receiver,state){if(receiver?.principal&&state.context.webSecurity)state.context.webSecurity.responseMutated=true;}
 return {dependency,factory,use,route,entry,response,request,headers,write};
}
