// At most one supported await and two local outcomes. No general exception executor.
export function asyncExceptions(api){
 const {ts,tick,note,unknown,constant,fork,statement,mergeVars,evidence}=api;
 const stopped=(rejected=false)=>({values:[],stops:true,...(rejected?{asyncRejected:true}:{asyncStopped:true})});
 function copy(state){
  const b=fork(state);b.nodeMutations=new Set(state.nodeMutations);
  b.asyncFrame={...b.asyncFrame,summary:{...b.asyncFrame.summary}};return b;
 }
 function opaque(node,state,reason){
  note(state.mod,reason);state.asyncFrame.summary.unknown=true;
  evidence(reason,node,state);return stopped();
 }
 function shape(block,state,maxAwaits){
  let awaits=0,ok=true;
  const walk=n=>{
   tick(state.mod);
   if(ts.isAwaitExpression(n))awaits++;
   if(ts.isTryStatement(n)||ts.isIfStatement(n)||ts.isSwitchStatement(n)||ts.isIterationStatement(n,false)
     ||ts.isFunctionLike(n)||ts.isClassDeclaration(n)||ts.isBreakStatement(n)||ts.isContinueStatement(n)
     ||ts.isBinaryExpression(n)&&ts.isAssignmentOperator(n.operatorToken.kind)
     ||(ts.isPrefixUnaryExpression(n)||ts.isPostfixUnaryExpression(n))&&[ts.SyntaxKind.PlusPlusToken,ts.SyntaxKind.MinusMinusToken].includes(n.operator))ok=false;
   ts.forEachChild(n,walk);
  };walk(block);
  return ok&&awaits<=maxAwaits&&block.statements.every(s=>ts.isVariableStatement(s)?!!(s.declarationList.flags&ts.NodeFlags.Const)&&s.declarationList.declarations.every(d=>ts.isIdentifier(d.name))
   :ts.isExpressionStatement(s)||ts.isReturnStatement(s)||ts.isThrowStatement(s)||ts.isEmptyStatement(s));
 }
 function run(block,state){
  const prior=new Map(state.vars),locals=[];const values=[];
  for(const s of block.statements)if(ts.isVariableStatement(s))for(const d of s.declarationList.declarations){locals.push(d.name.text);state.vars.set(d.name.text,{...unknown(),uninitialized:true});}
  const restore=()=>{for(const b of [state,...(state.exceptionScope?.errors??[])])for(const name of locals){if(prior.has(name))b.vars.set(name,prior.get(name));else b.vars.delete(name);}};
  const simple=n=>!n||ts.isIdentifier(n)&&(state.vars.has(n.text)&&!state.vars.get(n.text).uninitialized
    ||n.text==='undefined'&&!state.mod.declared.has('undefined'))||ts.isStringLiteral(n)||ts.isNumericLiteral(n)
   ||[ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(n.kind)||ts.isAwaitExpression(n);
  for(const s of block.statements){
   const calls=[];let awaited=0;
   const scan=n=>{tick(state.mod);if(ts.isAwaitExpression(n)){awaited++;return;}if(ts.isCallExpression(n)||ts.isNewExpression(n))calls.push(n);ts.forEachChild(n,scan);};scan(s);
   // Only a whole call statement is inspected before its unknown completion.
   // Other unmodeled calls could throw before a later subexpression's sink.
   const whole=ts.isExpressionStatement(s)&&ts.isCallExpression(s.expression);
   const errorConstruction=ts.isThrowStatement(s)&&calls.length===1&&ts.isIdentifier(calls[0].expression)&&calls[0].expression.text==='Error'
    &&!state.vars.has('Error')&&!state.mod.declared.has('Error')&&!state.mod.imports.has('Error')
    &&!state.mod.syntaxIndex.writes.has('Error')&&!state.mod.syntaxIndex.exportWrites.has('Error')
    &&!state.mod.syntaxIndex.aliases.has('Error')&&!(state.mod.syntaxIndex.argumentUses.get('Error')?.length)
    &&(calls[0].arguments??[]).every(a=>ts.isStringLiteral(a));
   if(calls.length&&(!whole&&!errorConstruction||whole&&calls.length>1)){restore();return opaque(s,state,'ASYNC_EXCEPTION_EXPRESSION_COMPLETION_UNKNOWN');}
   const expressions=ts.isVariableStatement(s)?s.declarationList.declarations.map(d=>d.initializer)
    :ts.isExpressionStatement(s)&&!whole?[s.expression]:ts.isReturnStatement(s)||ts.isThrowStatement(s)&&!errorConstruction?[s.expression]:[];
   if(expressions.some(n=>!simple(n))){restore();return opaque(s,state,'ASYNC_EXCEPTION_VALUE_EFFECT_UNKNOWN');}
   const r=statement(s,state);values.push(...r.values);
   if(r.stops){restore();return {...r,values,...(ts.isThrowStatement(s)&&r.asyncRejected?{exceptionThrowAt:s}:{})};}
   if(calls.length||awaited&&state.asyncFrame.summary.unknown){restore();return opaque(s,state,'ASYNC_EXCEPTION_CALL_COMPLETION_UNKNOWN');}
  }
  restore();return {values,stops:false};
 }
 function handle(node,state){
  if(state.exceptionScope||state.exceptionHandler||!shape(node.tryBlock,state,1)
    ||node.catchClause?.variableDeclaration&&!ts.isIdentifier(node.catchClause.variableDeclaration.name)
    ||node.catchClause&&!shape(node.catchClause.block,state,0)||node.finallyBlock&&!shape(node.finallyBlock,state,0))
   return opaque(node,state,'ASYNC_EXCEPTION_FLOW_UNKNOWN');
  const start=copy(state);start.uncertain=true;start.exposureUncertain=true;
  start.exceptionScope={errors:[]};start.asyncFrame.summary.exception=true;
  evidence('ASYNC_TRY_ENTERED',node,start);
  const first=run(node.tryBlock,start),paths=[];
  if(!first.asyncRejected)paths.push({state:start,result:first});
  if(first.asyncRejected&&(!start.asyncRejected||!start.exceptionScope.errors.length)){
   start.exceptionScope.errors.push(copy(start));
   evidence('ASYNC_THROW_CAPTURED',first.exceptionThrowAt??node.tryBlock,start);
  }
  for(const error of start.exceptionScope.errors){
   error.exceptionScope=undefined;error.exceptionHandler=true;error.asyncStop=false;error.asyncRejected=false;error.constructorAbrupt=false;
   error.asyncFrame.summary.rejected=false;error.asyncFrame.summary.unknown=false;
   if(node.catchClause){
    const name=node.catchClause.variableDeclaration?.name.text,old=name&&error.vars.get(name),had=name&&error.vars.has(name);
    if(name)error.vars.set(name,unknown());
    evidence('ASYNC_CATCH_ENTERED',node.catchClause,error);
    const handled=run(node.catchClause.block,error);
    if(name){if(had)error.vars.set(name,old);else error.vars.delete(name);}
    paths.push({state:error,result:handled});
   }else paths.push({state:error,result:stopped(true)});
  }
  for(const p of paths){
   p.state.exceptionScope=undefined;p.state.exceptionHandler=true;
   if(node.finallyBlock&&!p.result.asyncStopped){
    const original=p.result;p.state.asyncStop=false;p.state.asyncRejected=false;p.state.constructorAbrupt=false;
    p.state.asyncFrame.summary.rejected=false;
    evidence('ASYNC_FINALLY_ENTERED',node.finallyBlock,p.state);
    const final=run(node.finallyBlock,p.state);p.result=final.stops?final:original;
   }
   const kind=p.result.asyncStopped?'ASYNC_EXCEPTION_PATH_UNKNOWN':p.result.asyncRejected?'ASYNC_EXCEPTION_PROPAGATED':p.result.stops?'ASYNC_EXCEPTION_PATH_RETURNED':'ASYNC_EXCEPTION_PATH_CONTINUES';
   evidence(kind,node,p.state);
  }
  const continuing=paths.filter(p=>!p.result.stops),all=paths.map(p=>p.state);
  const summary=state.asyncFrame.summary;
  summary.exception=true;summary.awaited||=all.some(b=>b.asyncFrame.summary.awaited);
  summary.io||=all.some(b=>b.asyncFrame.summary.io);summary.unknown||=paths.some(p=>p.result.asyncStopped);
  summary.mayReject||=paths.some(p=>p.result.asyncRejected);
  state.nodeMutations=new Set(all.flatMap(b=>[...(b.asyncFrame.preMutations??b.nodeMutations)]));
  if(continuing.length){mergeVars(state,continuing.map(p=>p.state));state.asyncStop=false;state.asyncRejected=false;}
  const values=paths.flatMap(p=>p.result.values);
  return {values,stops:!continuing.length,...(!continuing.length&&paths.every(p=>p.result.asyncRejected)?{asyncRejected:true}:{}),
   ...(!continuing.length&&paths.some(p=>p.result.asyncStopped)?{asyncStopped:true}:{})};
 }
 function rejection(state,node){
  if(!state.exceptionScope)return;
  const b=copy(state);b.exceptionScope=undefined;
  b.asyncFrame.summary.awaited=true;b.asyncFrame.preMutations=new Set(state.nodeMutations);
  b.asyncFrame.post=true;b.nodeMutations=new Set();b.uncertain=true;b.exposureUncertain=true;
  b.context=Object.assign(Object.create(state.context),{asyncPostAwait:true,unresolved:true});
  state.exceptionScope.errors.push(b);evidence('ASYNC_REJECTION_CAPTURED',node,b);
 }
 return {handle,rejection};
}
