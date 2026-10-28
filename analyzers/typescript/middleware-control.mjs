// Local synchronous route-chain proof only. Never invokes target callbacks.
export function middlewareControl({ts,tick,note,loc,append,result}) {
  const cache=new WeakMap();
  const unwrap=n=>ts.isParenthesizedExpression(n)?unwrap(n.expression):n;
  function summarize(v) {
    if(!v?.target||v.unknown||v.ref?.unknown)return;
    const fn=v.target,{node,mod}=fn;
    if(cache.has(node))return cache.get(node);
    cache.set(node,undefined);
    let work=0;
    const charge=()=>{tick(mod);if(++work>256)throw Error('LOCAL_CONTROL_LIMIT');};
    try {
      if(!node.body||node.asteriskToken||node.modifiers?.some(m=>m.kind===ts.SyntaxKind.AsyncKeyword)
          ||node.parameters.length<2||node.parameters.length>3
          ||node.parameters.some(p=>!ts.isIdentifier(p.name)||p.initializer||p.dotDotDotToken))return;
      const names=node.parameters.map(p=>p.name.text);
      if(new Set(names).size!==names.length||names.includes('this'))return;
      const [req,res,next]=names;
      const data=n=>{
        charge();n=unwrap(n);
        if(ts.isStringLiteral(n)||ts.isNoSubstitutionTemplateLiteral(n)||ts.isNumericLiteral(n)
            ||[ts.SyntaxKind.NullKeyword,ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword].includes(n.kind))return true;
        if(ts.isPrefixUnaryExpression(n)&&[ts.SyntaxKind.PlusToken,ts.SyntaxKind.MinusToken].includes(n.operator))return ts.isNumericLiteral(n.operand);
        if(ts.isArrayLiteralExpression(n))return n.elements.every(data);
        if(ts.isObjectLiteralExpression(n))return n.properties.every(p=>ts.isPropertyAssignment(p)
          &&!ts.isComputedPropertyName(p.name)&&data(p.initializer));
        return false;
      };
      const predicate=n=>{
        charge();n=unwrap(n);
        if([ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword].includes(n.kind))return true;
        if(ts.isPropertyAccessExpression(n)){
          let root=n;while(ts.isPropertyAccessExpression(root)){charge();root=root.expression;}
          return ts.isIdentifier(root)&&root.text===req;
        }
        if(ts.isPrefixUnaryExpression(n)&&n.operator===ts.SyntaxKind.ExclamationToken)return predicate(n.operand);
        if(ts.isBinaryExpression(n)&&[ts.SyntaxKind.EqualsEqualsEqualsToken,ts.SyntaxKind.ExclamationEqualsEqualsToken,
          ts.SyntaxKind.AmpersandAmpersandToken,ts.SyntaxKind.BarBarToken].includes(n.operatorToken.kind))
          return (predicate(n.left)||data(n.left))&&(predicate(n.right)||data(n.right));
        return false;
      };
      const status=n=>ts.isNumericLiteral(n)&&Number(n.text)>=100&&Number(n.text)<=599&&Number.isInteger(Number(n.text));
      const numeric=n=>{n=unwrap(n);return ts.isNumericLiteral(n)||ts.isPrefixUnaryExpression(n)
        &&[ts.SyntaxKind.PlusToken,ts.SyntaxKind.MinusToken].includes(n.operator)&&ts.isNumericLiteral(n.operand);};
      const responseBase=n=>{
        n=unwrap(n);
        if(ts.isIdentifier(n)&&n.text===res)return true;
        return ts.isCallExpression(n)&&ts.isPropertyAccessExpression(n.expression)&&n.expression.name.text==='status'
          &&ts.isIdentifier(n.expression.expression)&&n.expression.expression.text===res&&n.arguments.length===1&&status(n.arguments[0]);
      };
      const action=n=>{
        charge();n=unwrap(n);
        if(!ts.isCallExpression(n))return;
        const callee=unwrap(n.expression);
        if(next&&ts.isIdentifier(callee)&&callee.text===next){
          if(n.arguments.length===0)return 'NEXT';
          if(n.arguments.length===1&&ts.isStringLiteral(n.arguments[0])){
            if(n.arguments[0].text==='route')return 'NEXT_ROUTE';
            if(n.arguments[0].text==='router')return 'NEXT_ROUTER';
          }
          return 'ERROR_OR_VALUE_DISPATCH_UNKNOWN';
        }
        if(!ts.isPropertyAccessExpression(callee)||!responseBase(callee.expression))return;
        const method=callee.name.text;
        if(method==='end'&&n.arguments.length<=1&&n.arguments.every(a=>ts.isStringLiteral(a)||ts.isNoSubstitutionTemplateLiteral(a)))return 'RESPONSE_END';
        if(method==='sendStatus'&&n.arguments.length===1&&status(n.arguments[0]))return 'RESPONSE_END';
        if(['send','json'].includes(method)&&n.arguments.length<=1&&n.arguments.every(data)
            &&!(method==='send'&&n.arguments.some(numeric)))return 'RESPONSE_END';
      };
      function expression(n,state,returns) {
        const kind=action(n);if(!kind)return;
        const at=loc(n,mod,kind,fn);
        append(result.nodeUses,{ruleId:'JS_SERVER_ENTRY_CONTEXT',kind:'MIDDLEWARE_CONTROL_OBSERVATION',operation:kind,
          location:at,trace:[],limitations:['STATIC_CALLBACK_SYNTAX_NOT_RUNTIME_EXECUTION','NOT_A_COMPLETE_CONTROL_OR_AUTHORIZATION_PROOF']},mod);
        if(kind==='RESPONSE_END')return {...state,response:true,stopped:returns,trace:[...state.trace,at]};
        if(state.handoff||state.response||kind==='ERROR_OR_VALUE_DISPATCH_UNKNOWN')return;
        return {...state,handoff:kind,stopped:returns,trace:[...state.trace,at]};
      }
      function statement(n,states) {
        charge();
        if(ts.isBlock(n))return sequence(n.statements,states);
        const out=[];
        for(const s of states){
          if(s.stopped){out.push(s);continue;}
          if(ts.isEmptyStatement(n)){out.push(s);continue;}
          if(ts.isIfStatement(n)&&predicate(n.expression)){
            const branch={...s,trace:[...s.trace,loc(n.expression,mod,'READ_ONLY_BRANCH_CONDITION',fn)]};
            const yes=statement(n.thenStatement,[branch]);
            const no=n.elseStatement?statement(n.elseStatement,[branch]):[branch];
            if(!yes||!no)return;out.push(...yes,...no);
          }else if(ts.isReturnStatement(n)&&!n.expression)out.push({...s,stopped:true});
          else if(ts.isReturnStatement(n)||ts.isExpressionStatement(n)){
            const e=n.expression;
            if(!e)return;
            if(ts.isExpressionStatement(n)&&ts.isStringLiteral(e)){out.push(s);continue;}
            const nextState=expression(e,s,ts.isReturnStatement(n));if(!nextState)return;out.push(nextState);
          }else return;
          if(out.length>8)throw Error('LOCAL_CONTROL_PATH_LIMIT');
        }
        return out;
      }
      function sequence(statements,states) {
        for(const s of statements){states=statement(s,states);if(!states)return;}
        return states;
      }
      const initial={response:false,handoff:undefined,stopped:false,trace:[]};
      const states=ts.isBlock(node.body)?sequence(node.body.statements,[initial]):[expression(node.body,initial,true)];
      if(!states?.length||states.some(s=>!s||(!s.handoff&&!s.response)))return;
      const plan=states.map(s=>({kind:s.handoff??'RESPONSE_END',response:s.response,trace:s.trace}));
      mod.middlewareControlAnalyzed=true;note(mod,'EXPRESS_LOCAL_MIDDLEWARE_CONTROL_ONLY');
      cache.set(node,plan);return plan;
    }catch{note(mod,'EXPRESS_MIDDLEWARE_CONTROL_BUDGET_OR_UNSUPPORTED');return;}
  }
  function proof(callbacks) {
    if(callbacks.some(v=>!v?.target||v.unknown||v.ref?.unknown||v.target.node.parameters.length>3))return;
    const trace=[];const exits=new Set();
    for(const callback of callbacks){
      const plan=summarize(callback);if(!plan)return;
      trace.push(...plan.flatMap(p=>p.trace));
      for(const p of plan)if(p.kind!=='NEXT')exits.add(p.kind);
      if(plan.every(p=>p.kind!=='NEXT')){
        const seen=new Set(),evidence=[];
        for(const chunk of [plan.flatMap(p=>p.trace),trace])for(const p of chunk){
          tick(callback.target.mod);
          const key=JSON.stringify([p.filePath,p.line,p.column,p.kind]);
          if(!seen.has(key)){seen.add(key);if(evidence.length<20)evidence.push(p);}
        }
        return {trace:evidence,exits:[...exits],truncated:seen.size>20};
      }
      if(plan.some(p=>p.kind==='NEXT'&&p.response))return;
    }
  }
  const passive=callbacks=>callbacks.every(v=>{
    const plan=summarize(v);
    return !!plan&&plan.every(p=>!(p.kind==='NEXT'&&p.response));
  });
  return {proof,passive};
}
