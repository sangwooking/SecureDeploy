// Registration evidence only: no callback invocation or synthetic HTTP source.
export function entryContracts({ts,modules,tick,note,loc,append,result}) {
  for(const mod of modules.values())try{
    const bindings=new Map(),declarations=new Map(),writes=new Map(),functions=new Map(),owners=new Set();
    const key=node=>node&&(ts.isIdentifier(node)?node.text:ts.isPropertyAccessExpression(node)&&ts.isIdentifier(node.expression)?node.expression.text+'.'+node.name.text:undefined);
    const literal=node=>node&&ts.isStringLiteral(node)?node.text:undefined;
    const imported=node=>{
      if(!node)return;
      if(ts.isCallExpression(node)&&ts.isIdentifier(node.expression)&&node.expression.text==='require'&&node.arguments.length===1)return literal(node.arguments[0]);
      if(ts.isPropertyAccessExpression(node)&&node.name.text==='Strategy'&&imported(node.expression)==='passport-http-bearer')return 'bearer-strategy';
    };
    let hasContract=false;
    for(const statement of mod.ast.statements){
      tick(mod);
      if(ts.isVariableStatement(statement))for(const declaration of statement.declarationList.declarations){
        tick(mod);if(imported(declaration.initializer)==='passport')hasContract=true;
      }
    }
    if(!hasContract)continue;
    const scan=node=>{
      tick(mod);
      if(ts.isIdentifier(node)&&node.parent.name===node&&[ts.isVariableDeclaration,ts.isParameter,ts.isFunctionDeclaration,ts.isClassDeclaration,ts.isImportClause].some(check=>check(node.parent)))
        declarations.set(node.text,(declarations.get(node.text)??0)+1);
      if(ts.isBinaryExpression(node)&&node.operatorToken.kind>=ts.SyntaxKind.FirstAssignment&&node.operatorToken.kind<=ts.SyntaxKind.LastAssignment){
        const left=key(node.left);if(left)writes.set(left,(writes.get(left)??0)+1);
      }
      ts.forEachChild(node,scan);
    };scan(mod.ast);
    if(declarations.has('require'))continue;
    for(const statement of mod.ast.statements){
      tick(mod);
      if(ts.isVariableStatement(statement)&&(statement.declarationList.flags&ts.NodeFlags.Const))for(const declaration of statement.declarationList.declarations){
        if(!ts.isIdentifier(declaration.name)||declarations.get(declaration.name.text)!==1||writes.has(declaration.name.text))continue;
        const name=declaration.name.text,origin=imported(declaration.initializer);
        if(origin&&![...writes.keys()].some(w=>w.startsWith(name+'.')))bindings.set(name,origin);
        if(!declarations.has('module')&&declaration.initializer?.getText(mod.ast)==='module.exports')owners.add(name);
        if(declaration.initializer&&(ts.isFunctionExpression(declaration.initializer)||ts.isArrowFunction(declaration.initializer)))functions.set(name,declaration.initializer);
      }
      if(ts.isFunctionDeclaration(statement)&&statement.name&&!writes.has(statement.name.text))functions.set(statement.name.text,statement);
    }
    for(const statement of mod.ast.statements)if(ts.isExpressionStatement(statement)&&ts.isBinaryExpression(statement.expression)){
      const assignment=statement.expression;
      if(assignment.operatorToken.kind!==ts.SyntaxKind.EqualsToken||!ts.isPropertyAccessExpression(assignment.left)||!owners.has(assignment.left.expression.text))continue;
      const name=key(assignment.left);
      if(writes.get(name)===1&&(ts.isFunctionExpression(assignment.right)||ts.isArrowFunction(assignment.right)))functions.set(name,assignment.right);
    }
    const target=node=>node&&(ts.isFunctionExpression(node)||ts.isArrowFunction(node)?node:functions.get(key(node)));
    const registrations=[],uses=[];
    const visit=node=>{
      tick(mod);
      if(ts.isCallExpression(node)&&ts.isPropertyAccessExpression(node.expression)&&ts.isIdentifier(node.expression.expression)&&bindings.get(node.expression.expression.text)==='passport'){
        const method=node.expression.name.text;
        if(method==='use'){
          const strategy=node.arguments.at(-1),name=node.arguments.length===2?literal(node.arguments[0]):node.arguments.length===1?'bearer':undefined;
          if(name&&strategy&&ts.isNewExpression(strategy)&&[1,2].includes(strategy.arguments?.length)&&ts.isIdentifier(strategy.expression)&&bindings.get(strategy.expression.text)==='bearer-strategy'){
            const callback=target(strategy.arguments?.at(-1)),location=loc(node,mod,'PASSPORT_STRATEGY_REGISTRATION');
            append(result.nodeUses,{ruleId:'JS_SERVER_ENTRY_CONTEXT',kind:callback?'CALLBACK_BOUND':'CALL_TARGET_UNKNOWN',operation:'PASSPORT_BEARER_REGISTRATION',
              location,trace:callback?[loc(callback,mod,'PASSPORT_VERIFY_CALLBACK')]:[],
              limitations:['REGISTRATION_DECLARATION_NOT_HTTP_ENTRY','INITIALIZATION_AND_REQUEST_DISPATCH_NOT_VERIFIED','PASSPORT_LIBRARY_VERSION_NOT_VERIFIED']},mod);
            registrations.push({name,location,callback});note(mod,'PASSPORT_DECLARATION_NOT_HTTP_ENTRY');
          }
        }
        if(method==='authenticate'&&literal(node.arguments[0]))uses.push({name:literal(node.arguments[0]),location:loc(node,mod,'PASSPORT_AUTHENTICATOR_REFERENCE')});
      }
      ts.forEachChild(node,visit);
    };visit(mod.ast);
    for(const use of uses){
      const matching=registrations.filter(r=>r.name===use.name);
      append(result.nodeUses,{ruleId:'JS_SERVER_ENTRY_CONTEXT',kind:matching.length===1&&matching[0].callback?'AUTHENTICATOR_REFERENCED':'EXTERNAL_IMPLEMENTATION_UNKNOWN',
        operation:'PASSPORT_AUTHENTICATE',location:use.location,trace:matching.length===1?[matching[0].location]:[],
        limitations:['SAME_FILE_REGISTRATION_SCOPE_ONLY','INITIALIZATION_AND_REQUEST_DISPATCH_NOT_VERIFIED','NOT_AUTHORIZATION_OR_SIGNATURE_PROOF']},mod);
    }
  }catch{note(mod,'ENTRY_CONTRACT_ANALYSIS_INCOMPLETE');}
}
