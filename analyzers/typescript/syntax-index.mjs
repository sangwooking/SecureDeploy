// Reuse the already bounded parse walk. These are syntax facts, not execution or trust proofs.
export function syntaxIndex() {
  return {declarations:new Map(),writes:new Set(),nodes:[],typeOnly:new Set(),dependencies:[]};
}
export function indexSyntax(ts,n,index) {
  if(ts.isCallExpression(n))index.nodes.push(n);
  if(n.name&&ts.isIdentifier(n.name)&&[ts.isVariableDeclaration,ts.isParameter,ts.isFunctionDeclaration,ts.isClassDeclaration,ts.isBindingElement].some(f=>f(n))){
    const a=index.declarations.get(n.name.text)??[];a.push(n);index.declarations.set(n.name.text,a);
  }
  if(ts.isImportDeclaration(n)){
    if(n.importClause?.isTypeOnly&&n.importClause.name)index.typeOnly.add(n.importClause.name.text);
    for(const e of n.importClause?.namedBindings?.elements??[])if(n.importClause.isTypeOnly||e.isTypeOnly)index.typeOnly.add(e.name.text);
    if(ts.isStringLiteral(n.moduleSpecifier)&&!n.importClause?.isTypeOnly)index.dependencies.push({pos:n.pos,spec:n.moduleSpecifier.text});
  }
  if(ts.isCallExpression(n)&&ts.isIdentifier(n.expression)&&n.expression.text==='require'&&n.arguments.length===1&&ts.isStringLiteral(n.arguments[0]))
    index.dependencies.push({pos:n.pos,spec:n.arguments[0].text});
  if(ts.isBinaryExpression(n)&&ts.isAssignmentOperator(n.operatorToken.kind)){
    let x=n.left;while(ts.isPropertyAccessExpression(x)||ts.isElementAccessExpression(x))x=x.expression;
    if(ts.isIdentifier(x))index.writes.add(x.text);
  }
}
