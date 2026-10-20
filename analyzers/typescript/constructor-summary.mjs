// Cached plans contain syntax only. Each application uses a fresh symbolic instance.
export function constructorSummaries(api) {
  const {ts,tick,loc,constant,unknown,functionValue,object}=api;
  const cache=new WeakMap();
  const unwrap=n=>{while(n&&ts.isParenthesizedExpression(n))n=n.expression;return n;};
  function plan(fn) {
    if(cache.has(fn.node))return cache.get(fn.node);
    const operations=[];let valid=!!fn.node.body&&ts.isBlock(fn.node.body);
    if(fn.node.parameters.some(p=>!ts.isIdentifier(p.name)||p.initializer||p.dotDotDotToken))valid=false;
    if(valid)for(const s of fn.node.body.statements){
      tick(fn.mod);
      if(ts.isExpressionStatement(s)&&ts.isStringLiteral(s.expression))continue;
      if(ts.isVariableStatement(s)&&s.declarationList.flags&ts.NodeFlags.Const){
        for(const d of s.declarationList.declarations){
          if(!ts.isIdentifier(d.name)||!d.initializer){valid=false;break;}
          operations.push({kind:'local',name:d.name.text,expression:d.initializer,node:d});
        }
      }else if(ts.isExpressionStatement(s)&&ts.isBinaryExpression(s.expression)&&s.expression.operatorToken.kind===ts.SyntaxKind.EqualsToken){
        const left=s.expression.left;
        if(!ts.isPropertyAccessExpression(left)||left.expression.kind!==ts.SyntaxKind.ThisKeyword||['__proto__','prototype','constructor'].includes(left.name.text)){valid=false;break;}
        operations.push({kind:'field',name:left.name.text,expression:s.expression.right,node:s});
      }else if(ts.isIfStatement(s)&&!s.elseStatement){
        let condition=unwrap(s.expression),instance;
        if(ts.isPrefixUnaryExpression(condition)&&condition.operator===ts.SyntaxKind.ExclamationToken)instance=unwrap(condition.operand);
        else if(ts.isBinaryExpression(condition)&&condition.operatorToken.kind===ts.SyntaxKind.EqualsEqualsEqualsToken){
          if(unwrap(condition.left).kind===ts.SyntaxKind.FalseKeyword)instance=unwrap(condition.right);
          else if(unwrap(condition.right).kind===ts.SyntaxKind.FalseKeyword)instance=unwrap(condition.left);
        }
        if(!instance||!ts.isBinaryExpression(instance)||instance.operatorToken.kind!==ts.SyntaxKind.InstanceOfKeyword
          ||unwrap(instance.left).kind!==ts.SyntaxKind.ThisKeyword||!ts.isIdentifier(instance.right)){valid=false;break;}
        operations.push({kind:'selfGuard',name:instance.right.text,node:s});
      }else if(ts.isReturnStatement(s)&&(!s.expression||unwrap(s.expression).kind===ts.SyntaxKind.ThisKeyword)){
        operations.push({kind:'return',node:s});break;
      }else{valid=false;break;}
      if(operations.length>api.limits.maxResults){valid=false;break;}
    }
    const result=valid?operations:null;cache.set(fn.node,result);return result;
  }
  function apply(fn,args,caller) {
    const operations=plan(fn);if(!operations||caller.uncertain)return;
    const instance=object('node-instance');instance.constructorTarget=fn;
    const state={...caller,mod:fn.mod,fn,vars:new Map(fn.closure??[]),thisValue:instance,constructing:true};
    fn.node.parameters.forEach((p,i)=>state.vars.set(p.name.text,args[i]??constant(undefined)));
    let failed=false;
    function read(original){
      const n=unwrap(original);tick(fn.mod);
      if(ts.isIdentifier(n))return state.vars.get(n.text)??(failed=true,unknown());
      if(n.kind===ts.SyntaxKind.ThisKeyword)return instance;
      if(ts.isStringLiteral(n)||ts.isNumericLiteral(n))return constant(ts.isNumericLiteral(n)?Number(n.text):n.text);
      if(n.kind===ts.SyntaxKind.TrueKeyword||n.kind===ts.SyntaxKind.FalseKeyword)return constant(n.kind===ts.SyntaxKind.TrueKeyword);
      if(n.kind===ts.SyntaxKind.NullKeyword)return constant(null);
      if(ts.isArrowFunction(n)||ts.isFunctionExpression(n))return functionValue(n,state);
      if(ts.isPropertyAccessExpression(n)&&!(n.flags&ts.NodeFlags.OptionalChain)){
        const base=read(n.expression);
        if(!base.unknown&&!base.ref?.unknown&&base.ref?.properties.has(n.name.text))return base.ref.properties.get(n.name.text);
      }
      if(ts.isCallExpression(n)&&ts.isPropertyAccessExpression(n.expression)&&n.expression.name.text==='collection'
          &&n.arguments.length===1&&ts.isStringLiteral(n.arguments[0])&&!(n.flags&ts.NodeFlags.OptionalChain)){
        const db=read(n.expression.expression);
        if(db.tag==='mongo-db'&&api.validMongo(db)){
          const c=object('mongo-collection');c.ref.originParent=db.ref;c.ref.driverMajor=db.ref.driverMajor;c.ref.origin=[...(db.ref.origin??[]),loc(n,fn.mod,'MONGODB_COLLECTION_ORIGIN',fn)].slice(-4);return c;
        }
      }
      failed=true;return unknown();
    }
    const evidence=fn.node.parameters.map((p,i)=>loc(p,fn.mod,'SUMMARY_PARAMETER_'+i,fn));
    for(const op of operations){
      tick(fn.mod);
      if(op.kind==='selfGuard'){
        const guard=state.vars.get(op.name);
        if(guard?.target!==fn||guard.unknown||guard.ref?.unknown)return;
      }else if(op.kind==='return')break;
      else{
        const v=read(op.expression);if(failed)return;
        if(op.kind==='local')state.vars.set(op.name,v);else instance.ref.properties.set(op.name,v);
        evidence.push(loc(op.node,fn.mod,op.kind==='local'?'SUMMARY_LOCAL_BINDING':'SUMMARY_FRESH_FIELD_WRITE',fn));
      }
    }
    instance.ref.origin=[loc(fn.node,fn.mod,'CONSTRUCTOR_SUMMARY_MUST',fn)];
    return {instance,evidence:evidence.slice(0,20),truncated:evidence.length>20};
  }
  return {apply};
}
