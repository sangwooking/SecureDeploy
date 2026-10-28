// Reuse the already bounded parse walk. These are syntax facts, not execution or trust proofs.
export function syntaxIndex() {
  return {declarations:new Map(),bindings:new Set(),nextBindings:new Set(),nextInlineServerClosure:false,writes:new Set(),exportWrites:new Set(),nodes:[],typeOnly:new Set(),dependencies:[],argumentUses:new Map(),argumentReferenceIncomplete:new Set(),aliases:new Map()};
}
export function indexSyntax(ts,n,index) {
  // Same facts as the Next registration walk, charged once by bounded parsing.
  if(n.name&&ts.isIdentifier(n.name)&&(ts.isParameter(n)||ts.isVariableDeclaration(n)||ts.isFunctionDeclaration(n)
      ||ts.isClassDeclaration(n)||ts.isImportClause(n)||ts.isNamespaceImport(n)||ts.isImportEqualsDeclaration(n)||ts.isBindingElement(n)))index.nextBindings.add(n.name.text);
  if(ts.isFunctionLike(n)&&n.body&&ts.isBlock(n.body)&&!ts.isSourceFile(n.parent)&&!ts.isVariableDeclaration(n.parent)){
    for(const s of n.body.statements){
      if(!ts.isExpressionStatement(s)||!ts.isStringLiteral(s.expression))break;
      if(s.expression.text==='use server'){index.nextInlineServerClosure=true;break;}
    }
  }
  if(ts.isDeleteExpression(n)||(ts.isPrefixUnaryExpression(n)||ts.isPostfixUnaryExpression(n))
      &&[ts.SyntaxKind.PlusPlusToken,ts.SyntaxKind.MinusMinusToken].includes(n.operator)){
    let x=n.expression??n.operand;while(ts.isPropertyAccessExpression(x)||ts.isElementAccessExpression(x))x=x.expression;
    if(ts.isIdentifier(x))index.exportWrites.add(x.text);
  }
  if(ts.isVariableDeclaration(n)&&ts.isIdentifier(n.name)&&n.initializer){
    const values=ts.isObjectLiteralExpression(n.initializer)?n.initializer.properties.flatMap(p=>ts.isShorthandPropertyAssignment(p)?[p.name]:ts.isPropertyAssignment(p)?[p.initializer]:[]):[n.initializer];
    for(const value of values)if(ts.isIdentifier(value)){
      const aliases=index.aliases.get(value.text)??[];aliases.push({declaration:n,reference:value});index.aliases.set(value.text,aliases);
    }
  }
  if(ts.isIdentifier(n)&&!(ts.isPropertyAccessExpression(n.parent)&&n.parent.name===n)&&!(ts.isPropertyAssignment(n.parent)&&n.parent.name===n)){
    let child=n,depth=0;
    for(;child.parent&&depth<8;child=child.parent,depth++){
      const parent=child.parent;if(ts.isFunctionLike(parent)||ts.isSourceFile(parent)||ts.isBlock(parent))break;
      if(ts.isCallExpression(parent)||ts.isNewExpression(parent)){
        if((parent.arguments??[]).includes(child)){const uses=index.argumentUses.get(n.text)??[];uses.push({call:parent,node:n});index.argumentUses.set(n.text,uses);}
        break;
      }
    }
    if(depth===8)index.argumentReferenceIncomplete.add(n.text);
  }
  if(n.name&&ts.isIdentifier(n.name)&&[ts.isParameter,ts.isVariableDeclaration,ts.isFunctionDeclaration,ts.isClassDeclaration,ts.isImportClause,ts.isImportSpecifier,ts.isNamespaceImport,ts.isImportEqualsDeclaration,ts.isBindingElement].some(f=>f(n)))index.bindings.add(n.name.text);
  if(ts.isCallExpression(n))index.nodes.push(n);
  if(n.name&&ts.isIdentifier(n.name)&&[ts.isVariableDeclaration,ts.isParameter,ts.isFunctionDeclaration,ts.isClassDeclaration,ts.isBindingElement].some(f=>f(n))){
    const a=index.declarations.get(n.name.text)??[];a.push(n);index.declarations.set(n.name.text,a);
  }
  if(ts.isImportDeclaration(n)){
    if(n.importClause?.isTypeOnly&&n.importClause.name)index.typeOnly.add(n.importClause.name.text);
    for(const e of n.importClause?.namedBindings?.elements??[])if(n.importClause.isTypeOnly||e.isTypeOnly)index.typeOnly.add(e.name.text);
    if(ts.isStringLiteral(n.moduleSpecifier)&&!n.importClause?.isTypeOnly)index.dependencies.push({pos:n.pos,spec:n.moduleSpecifier.text,mode:'import'});
  }
  if(ts.isCallExpression(n)&&ts.isIdentifier(n.expression)&&n.expression.text==='require'&&n.arguments.length===1&&ts.isStringLiteral(n.arguments[0]))
    index.dependencies.push({pos:n.pos,spec:n.arguments[0].text,mode:'require'});
  if(ts.isBinaryExpression(n)&&ts.isAssignmentOperator(n.operatorToken.kind)){
    let x=n.left;while(ts.isPropertyAccessExpression(x)||ts.isElementAccessExpression(x))x=x.expression;
    if(ts.isIdentifier(x))index.writes.add(x.text);
  }
}
