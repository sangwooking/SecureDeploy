import ts from 'typescript';
const fail=()=>{throw Error('MANUAL_REVIEW_REQUIRED');};
// Extends the patch validator, never the finding engine. Only direct, statically registered handlers.
export function expressResponsePatch(input,{object,literal}){
 const {source,sink,sources,replacement}=input;
 if(typeof source!=='string'||Buffer.byteLength(source)>65536||!Array.isArray(sources)||!sources.length||sources.length>20)fail();
 const f=ts.createSourceFile('input.ts',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);if(f.parseDiagnostics.length)fail();
 const pos=n=>{const p=f.getLineAndCharacterOfPosition(n.getStart(f));return {line:p.line+1,column:p.character+1};};
 const same=(a,b)=>a.line===b.line&&a.column===b.column;
 const all=[];let count=0;function walk(n){if(++count>20000)fail();all.push(n);ts.forEachChild(n,walk);}walk(f);
 const calls=all.filter(n=>ts.isCallExpression(n)&&ts.isPropertyAccessExpression(n.expression)&&n.expression.name.text==='json'&&same(pos(n),sink));if(calls.length!==1)fail();const call=calls[0];
 if(!ts.isPropertyAccessExpression(call.expression)||call.expression.name.text!=='json'||call.arguments.length!==1||!ts.isReturnStatement(call.parent)||!ts.isObjectLiteralExpression(call.arguments[0]))fail();
 let handler=call.parent;while(handler&&!ts.isArrowFunction(handler)&&!ts.isFunctionExpression(handler))handler=handler.parent;
 if(!handler||handler.parameters.length!==2||handler.parameters.some(p=>!ts.isIdentifier(p.name)||p.dotDotDotToken||p.initializer))fail();
 const response=handler.parameters[1].name.text,registration=handler.parent;
 if(!ts.isCallExpression(registration)||!ts.isPropertyAccessExpression(registration.expression)||!['get','post','put','patch','delete','head','options'].includes(registration.expression.name.text)||registration.arguments.length!==2||registration.arguments[1]!==handler||!ts.isStringLiteral(registration.arguments[0])||!ts.isIdentifier(registration.expression.expression))fail();
 const app=registration.expression.expression.text;
 const bindings=name=>all.filter(n=>(ts.isVariableDeclaration(n)||ts.isParameter(n)||ts.isFunctionDeclaration(n)||ts.isClassDeclaration(n)||ts.isImportClause(n)||ts.isImportSpecifier(n)||ts.isNamespaceImport(n)||ts.isBindingElement(n))&&n.name?.getText(f)===name);
 const appBinding=bindings(app);if(appBinding.length!==1||!ts.isVariableDeclaration(appBinding[0])||!ts.isCallExpression(appBinding[0].initializer)||appBinding[0].initializer.arguments.length||!ts.isIdentifier(appBinding[0].initializer.expression))fail();
 const imported=appBinding[0].initializer.expression.text,imports=bindings(imported);
 if(imports.length!==1||!ts.isImportClause(imports[0])||imports[0].isTypeOnly||imports[0].parent.moduleSpecifier.text!=='express')fail();
 if(bindings('process').length||bindings(response).length!==1)fail();
 const root=n=>{while(ts.isPropertyAccessExpression(n)||ts.isElementAccessExpression(n))n=n.expression;return n;};
 for(const n of all){
  if(ts.isBinaryExpression(n)&&n.operatorToken.kind>=ts.SyntaxKind.FirstAssignment&&n.operatorToken.kind<=ts.SyntaxKind.LastAssignment||ts.isPrefixUnaryExpression(n)||ts.isPostfixUnaryExpression(n)||ts.isDeleteExpression(n)){
   const left=ts.isBinaryExpression(n)?n.left:n.operand??n.expression;const r=root(left);if(ts.isIdentifier(r)&&['process',app,response,imported].includes(r.text))fail();
  }
 }
 let receiver=call.expression.expression;
 if(ts.isCallExpression(receiver)&&ts.isPropertyAccessExpression(receiver.expression)&&receiver.expression.name.text==='status'&&receiver.arguments.length===1&&ts.isNumericLiteral(receiver.arguments[0])&&Number(receiver.arguments[0].text)>=200&&Number(receiver.arguments[0].text)<=599)receiver=receiver.expression.expression;
 if(!ts.isIdentifier(receiver)||receiver.text!==response)fail();
 const target=call.arguments[0],before=target.getText(f),props=object(before),retained=[],removed=[];
 for(let i=0;i<target.properties.length;i++){
  const p=target.properties[i],v=p.initializer;
  if(ts.isPropertyAccessExpression(v)&&ts.isPropertyAccessExpression(v.expression)&&v.expression.expression.getText(f)==='process'&&v.expression.name.text==='env'&&/^[A-Z_][A-Z0-9_]{0,79}$/.test(v.name.text)&&sources.some(s=>same(pos(v),s)))removed.push(p.name.text);
  else{if(!literal(v))fail();retained.push(props[i].getText());}
 }
 if(!removed.length||!retained.length||removed.length!==sources.length)fail();
 const offset=target.getStart(f),line=pos(target).line,suggestedReplacement='{'+retained.join(', ')+'}';
 if(replacement!==undefined){const next=object(replacement);if(next.length!==retained.length||next.some((p,i)=>p.getText()!==retained[i]))fail();const updated=source.slice(0,offset)+replacement+source.slice(target.end);if(ts.createSourceFile('after.ts',updated,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS).parseDiagnostics.length)fail();}
 return {before,offset,line,removed,suggestedReplacement};
}
