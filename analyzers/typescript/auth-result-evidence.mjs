// Local syntax evidence only. Never upgrades policy state or establishes authentication.
export function authResultEvidence({ts,charge,binding,escaped,index,location,fnOf}) {
  function observe(mod,call,access,value) {
    const method=call.expression.name.text,session=method==='getSession';
    if(!['getUser','getClaims',...(value?['getSession']:[])].includes(method)||call.arguments.length)return null;
    const expected=method==='getUser'?['data','user']:session?['data','session','user']:['data','claims'];
    const fn=fnOf(access);if(!fn||fnOf(call)!==fn)return null;
    // The shared write index covers assignment expressions, not delete or ++/--.
    let unsupportedMutation=false;
    const mutations=n=>{charge();if(ts.isDeleteExpression(n)||ts.isPostfixUnaryExpression(n)||ts.isPrefixUnaryExpression(n)&&[ts.SyntaxKind.PlusPlusToken,ts.SyntaxKind.MinusMinusToken].includes(n.operator))unsupportedMutation=true;ts.forEachChild(n,mutations);};
    mutations(fn);if(unsupportedMutation)return null;
    const peel=n=>{while(n&&(ts.isParenthesizedExpression(n)||ts.isAsExpression(n)||ts.isNonNullExpression(n)))n=n.expression;return n;};
    function bindingPath(pattern,name,prefix=[],depth=0){
      charge();if(depth>3||!pattern)return null;
      if(ts.isIdentifier(pattern))return pattern.text===name?prefix:null;
      if(!ts.isObjectBindingPattern(pattern))return null;
      for(const element of pattern.elements){
        if(element.dotDotDotToken||element.initializer)return null;
        const key=element.propertyName??element.name;
        if(!ts.isIdentifier(key)&&!ts.isStringLiteral(key))continue;
        const result=bindingPath(element.name,name,[...prefix,key.text],depth+1);if(result)return result;
      }
      return null;
    }
    function origin(original,depth=0,seen=new Set()){
      charge();const n=peel(original);if(!n||depth>6||seen.has(n))return null;seen=new Set([...seen,n]);
      if(n===call)return {fields:[],awaited:false};
      if(ts.isAwaitExpression(n)){const r=origin(n.expression,depth+1,seen);return r?{...r,awaited:true}:null;}
      if(ts.isPropertyAccessExpression(n)){const r=origin(n.expression,depth+1,seen);return r?{...r,fields:[...r.fields,n.name.text]}:null;}
      if(!ts.isIdentifier(n)||index(mod).writes.has(n.text))return null;
      const d=binding(mod,n.text,n);if(!d||fnOf(d)!==fn||escaped(mod,d,n))return null;
      let variable=d,path=[];
      if(ts.isBindingElement(d)){
        while(variable&&!ts.isVariableDeclaration(variable))variable=variable.parent;
        if(!variable)return null;path=bindingPath(variable.name,n.text);if(!path)return null;
      }
      if(!ts.isVariableDeclaration(variable)||!(variable.parent.flags&ts.NodeFlags.Const))return null;
      const r=origin(variable.initializer,depth+1,seen);return r?{...r,fields:[...r.fields,...path]}:null;
    }
    const identity=n=>{const o=origin(n);return o?.awaited&&JSON.stringify(o.fields)===JSON.stringify(expected);};
    const valueOrigin=value&&origin(value),valueIsUserId=!!valueOrigin?.awaited&&JSON.stringify(valueOrigin.fields)===JSON.stringify([...expected,method==='getClaims'?'sub':'id']);
    if(session)return valueIsUserId?{status:'SESSION_READ_UNVERIFIED',valueIsUserId:true}:null;
    function rejectsAbsent(n){
      charge();n=peel(n);
      if(ts.isPrefixUnaryExpression(n)&&n.operator===ts.SyntaxKind.ExclamationToken)return identity(n.operand);
      return ts.isBinaryExpression(n)&&n.operatorToken.kind===ts.SyntaxKind.BarBarToken&&(rejectsAbsent(n.left)||rejectsAbsent(n.right));
    }
    function exits(n){n=peel(n);return ts.isReturnStatement(n)||ts.isThrowStatement(n)||ts.isBlock(n)&&n.statements.length>0&&exits(n.statements.at(-1));}
    let statement=access;while(statement.parent&&!ts.isBlock(statement.parent))statement=statement.parent;
    const block=statement.parent;if(!block||!ts.isBlock(block)||fnOf(block)!==fn&&block!==fn.body)return null;
    const position=block.statements.indexOf(statement);let guard;
    for(const s of block.statements.slice(0,position)){
      charge();
      if(ts.isIfStatement(s)&&!s.elseStatement&&s.pos>call.pos&&rejectsAbsent(s.expression)&&exits(s.thenStatement)){guard=s;continue;}
      // Do not carry this observation across arbitrary calls, loops or mutations.
      if(guard&&!ts.isVariableStatement(s))guard=undefined;
      if(guard&&ts.isVariableStatement(s)){
        const calls=[];const scan=n=>{charge();if(ts.isCallExpression(n)||ts.isNewExpression(n))calls.push(n);ts.forEachChild(n,scan);};scan(s);
        if(calls.length)guard=undefined;
      }
    }
    if(!guard)return null;
    const filters=[];let chain=access;
    while(ts.isPropertyAccessExpression(chain.parent)&&chain.parent.expression===chain&&ts.isCallExpression(chain.parent.parent)){
      charge();chain=chain.parent.parent;
      if(chain.expression.name.text!=='eq'||!ts.isStringLiteral(chain.arguments[0]??{})||filters.length>=4)continue;
      const value=peel(chain.arguments[1]);
      if(value&&ts.isPropertyAccessExpression(value)&&value.name.text===(call.expression.name.text==='getUser'?'id':'sub')&&identity(value.expression))
        filters.push(location(chain,mod,'IDENTITY_RESULT_ID_FILTER_OBSERVED'));
    }
    return {status:'IDENTITY_RESULT_GUARD_OBSERVED',guardLocation:location(guard,mod,'IDENTITY_RESULT_ABSENCE_EXIT'),userIdFilters:filters,...(value?{valueIsUserId}:{}),
      limitations:['LOCAL_SYNTAX_NOT_AUTH_SUCCESS_PROOF','IDENTITY_FIELDS_AND_MIDDLEWARE_NOT_RUNTIME_VERIFIED','APPLICATION_FILTER_NOT_DATABASE_AUTHORIZATION']};
  }
  return {observe};
}
