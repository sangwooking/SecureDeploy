// Read-only route summary ONLY after a verified setup call. Not an uncalled-factory scan.
export function startupRoutes(api){
 const{ts,tick,note,loc,append,result,functionValue,unknown,limits,modules}=api;
 const supported=new Set(['get','post','put','patch','delete','head','options','all']);
 const property=(node,vars)=>{if(ts.isIdentifier(node))return vars.get(node.text);if(ts.isPropertyAccessExpression(node)){const v=property(node.expression,vars);return !v?.unknown&&!v?.ref?.unknown?v?.ref?.properties.get(node.name.text):undefined;}};
 const paths=n=>ts.isStringLiteral(n)||ts.isNoSubstitutionTemplateLiteral(n)?[n.text]:ts.isArrayLiteralExpression(n)&&n.elements.length<=8&&n.elements.every(e=>ts.isStringLiteral(e))?n.elements.map(e=>e.text):null;
 function summarize(fn,args,depth,context,stack){
  if(!(context.bootstrapConditional||context.asyncPostAwait)||!fn.node.body||!ts.isBlock(fn.node.body)||fn.node.asteriskToken||fn.node.parameters.some(p=>!ts.isIdentifier(p.name)||p.initializer||p.dotDotDotToken))return;
  const appArgs=args.filter(v=>v?.tag==='express-router'&&v.app&&!v.unknown&&!v.ref?.unknown);if(!appArgs.length)return;
  const vars=new Map(fn.closure??[]),appNames=new Set(),mod=fn.mod;
  fn.node.parameters.forEach((p,i)=>{vars.set(p.name.text,args[i]??unknown());if(appArgs.includes(args[i]))appNames.add(p.name.text);});
  let unsafe=false,firstEscape=Infinity,registrations=0,linked=0;
  const inside=n=>{if(n.pos<fn.node.body.pos||n.end>fn.node.body.end)return false;let x=n;for(let i=0;x&&i<64;x=x.parent,i++){if(x===fn.node.body)return true;if(x!==n&&ts.isFunctionLike(x))return false;}return false;};
  const calls=(mod.syntaxIndex?.nodes??[]).filter(inside);
  // Collect only immutable top-level aliases before checking every use/write.
  for(const st of fn.node.body.statements){if(ts.isVariableStatement(st))for(const d of st.declarationList.declarations)if(ts.isIdentifier(d.name)&&d.initializer&&ts.isIdentifier(d.initializer)&&appNames.has(d.initializer.text)){
   if(!(st.declarationList.flags&ts.NodeFlags.Const))unsafe=true;
   appNames.add(d.name.text);vars.set(d.name.text,vars.get(d.initializer.text));
  }}
  for(const n of mod.syntaxIndex?.assignments??[]){tick(mod);let root=n.left;while(ts.isPropertyAccessExpression(root)||ts.isElementAccessExpression(root))root=root.expression;
    if(ts.isIdentifier(root)&&appNames.has(root.text)&&!(ts.isPropertyAccessExpression(n.left)&&ts.isPropertyAccessExpression(n.left.expression)&&n.left.expression.name.text==='locals'))unsafe=true;
  }
  for(const n of mod.syntaxIndex?.mutators??[]){let root=n.expression??n.operand;while(ts.isPropertyAccessExpression(root)||ts.isElementAccessExpression(root))root=root.expression;if(ts.isIdentifier(root)&&appNames.has(root.text))unsafe=true;}
  for(const name of appNames){
   if(mod.syntaxIndex.argumentReferenceIncomplete.has(name))unsafe=true;
   for(const use of mod.syntaxIndex.argumentUses.get(name)??[]){if(use.node.pos>=fn.node.body.pos&&use.node.end<=fn.node.body.end)firstEscape=Math.min(firstEscape,use.call.pos);}
   for(const alias of mod.syntaxIndex.aliases.get(name)??[]){if(alias.declaration.pos>=fn.node.body.pos&&alias.declaration.end<=fn.node.body.end&&!appNames.has(alias.declaration.name.text))unsafe=true;}
  }
  if(unsafe){note(mod,'STARTUP_ROUTE_SUMMARY_APP_ESCAPE_OR_MUTATION');return;}
  const terminal=new WeakMap();
  const reachable=n=>{let child=n;for(let i=0;child.parent&&i<64;i++){
    const parent=child.parent;
    if(ts.isIfStatement(parent)){if(parent.expression.kind===ts.SyntaxKind.FalseKeyword&&child===parent.thenStatement||parent.expression.kind===ts.SyntaxKind.TrueKeyword&&child===parent.elseStatement)return false;}
    if(ts.isBlock(parent)){
      if(!terminal.has(parent))terminal.set(parent,parent.statements.find(s=>ts.isReturnStatement(s)||ts.isThrowStatement(s))?.pos??Infinity);
      if(child.pos>terminal.get(parent))return false;
    }
    if(parent===fn.node.body)return true;child=parent;
  }return false;};
  const state={mod,fn,vars,nodeMode:true,depth,context,stack,uncertain:true};
  function handler(n){
   if(ts.isArrowFunction(n)||ts.isFunctionExpression(n))return functionValue(n,state);
   const direct=property(n,vars);if(direct?.target&&!direct.unknown&&!direct.ref?.unknown)return direct;
   if(ts.isCallExpression(n)&&!n.arguments.length){
    const factory=property(n.expression,vars),target=factory?.target;if(!target||factory.unknown||factory.ref?.unknown||target.node.asteriskToken||target.node.parameters.length||!ts.isBlock(target.node.body))return;
    const body=target.node.body.statements,returns=body.filter(ts.isReturnStatement);
    if(returns.length!==1||!body.every(s=>ts.isFunctionDeclaration(s)||ts.isReturnStatement(s)||ts.isEmptyStatement(s)))return;
    const value=returns[0].expression;if(!value||!(ts.isArrowFunction(value)||ts.isFunctionExpression(value)))return;
    const factoryState={...state,mod:target.mod,fn:target,vars:new Map(target.closure??[])};
    for(const s of body)if(ts.isFunctionDeclaration(s)&&s.name)factoryState.vars.set(s.name.text,functionValue(s,factoryState,s.name.text));
    return functionValue(value,factoryState);
   }
  }
  const visit=n=>{tick(mod);if(ts.isFunctionLike(n))return;

   if(ts.isCallExpression(n)&&ts.isPropertyAccessExpression(n.expression)&&ts.isIdentifier(n.expression.expression)&&appNames.has(n.expression.expression.text)&&supported.has(n.expression.name.text)&&n.arguments.length>=2){
    const pathValues=paths(n.arguments[0]);if(!pathValues){note(mod,'STARTUP_ROUTE_PATH_UNRESOLVED');return;}
    const receiverTrusted=n.pos<firstEscape;
    const selected=receiverTrusted?handler(n.arguments.at(-1)):null,at=loc(n,mod,'CONDITIONAL_EXPRESS_REGISTRATION',fn),trace=[...(context.bootstrapTrace??[])].slice(0,12);
    const target=selected?.target&&!selected.unknown&&!selected.ref?.unknown?selected.target:null;
    if(target)trace.push(loc(target.node,target.mod,'EXPRESS_HANDLER_TARGET',target));
    for(const path of pathValues){
     if(registrations>=Math.min(120,limits.maxResults)){note(mod,'STARTUP_ROUTE_SUMMARY_LIMIT');return;}
     append(result.nodeUses,{ruleId:'JS_SERVER_ENTRY_CONTEXT',kind:receiverTrusted?'STARTUP_ROUTE_REGISTRATION_POSSIBLE':'STARTUP_ROUTE_CALL_RECEIVER_UNVERIFIED',operation:n.expression.name.text.toUpperCase()+' '+path,location:at,trace,
      limitations:[...(!receiverTrusted?['PRIOR_APP_ESCAPE_MAY_REPLACE_REGISTRATION_METHOD']:[]),...(context.startupTestOnly?['TEST_ONLY_NODE_ENV_BRANCH']:[]),'CONDITIONAL_ASYNC_BOOTSTRAP_NOT_RUNTIME_SUCCESS','REGISTRATION_API_NOT_FULL_INITIALIZATION_EFFECTS_PROOF',target?'HANDLER_REFERENCE_LINKED':'HANDLER_REFERENCE_UNRESOLVED','MIDDLEWARE_AND_AUTHORIZATION_UNVERIFIED']},mod);registrations++;
     if(target&&linked<Math.min(16,limits.maxFunctions)&&target.mod.entries.length<limits.maxResults){target.mod.entries.push({fn:target,kind:'EXPRESS_HANDLER',httpMethod:n.expression.name.text.toUpperCase(),httpPath:path,registration:at,uncertain:true,middleware:n.arguments.length>2});target.mod.record.entrypoints++;linked++;}
    }
   }
  };for(const n of calls)if(reachable(n)){if(ts.isPropertyAccessExpression(n.expression)&&ts.isIdentifier(n.expression.expression)&&appNames.has(n.expression.expression.text)&&['use','route'].includes(n.expression.name.text))note(mod,'STARTUP_MIDDLEWARE_MOUNT_OR_CHAIN_NOT_SUMMARIZED');visit(n);}
  if(!registrations)return;
  append(result.nodeUses,{ruleId:'JS_SERVER_ENTRY_CONTEXT',kind:'STARTUP_CONFIGURATION_SUMMARIZED',operation:'READ_ONLY_CONDITIONAL_ROUTE_SUMMARY',location:loc(fn.node,mod,'STARTUP_CONFIGURATION_TARGET',fn),trace:(context.bootstrapTrace??[]).slice(0,12),limitations:['BODY_NOT_FULLY_INTERPRETED',...(firstEscape<Infinity?['APP_ESCAPED_LATER_REGISTRATION_UNVERIFIED']:[]),'FLOW_LINK_BUDGET_MAX_16','RUNTIME_INITIALIZATION_MAY_REJECT_OR_NEVER_COMPLETE']},mod);
  api.onSummary?.();note(mod,'STARTUP_CONFIGURATION_PARTIAL_SUMMARY');for(const app of appArgs)app.controlOpaque=true;return unknown();
 }
 return{summarize};
}
