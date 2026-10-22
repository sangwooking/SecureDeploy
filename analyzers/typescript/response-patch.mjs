import ts from 'typescript';
import {pathToFileURL} from 'node:url';

const fail=()=>{throw new Error('MANUAL_REVIEW_REQUIRED');};
// Do not send arbitrary application text or identifiers that could contain personal data.
const literal=n=>(ts.isStringLiteral(n)&&['ok','success','error','ready','pending','done'].includes(n.text))
  ||(ts.isNumericLiteral(n)&&Number(n.text)<=100000)||[ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(n.kind);
const dotted=(n,value)=>n?.getText()===value;
function object(text){
  if(typeof text!=='string'||Buffer.byteLength(text)>4096)fail();
  const scanner=ts.createScanner(ts.ScriptTarget.Latest,false,ts.LanguageVariant.Standard,text);
  for(let t=scanner.scan();t!==ts.SyntaxKind.EndOfFileToken;t=scanner.scan())if([ts.SyntaxKind.SingleLineCommentTrivia,ts.SyntaxKind.MultiLineCommentTrivia].includes(t))fail();
  const f=ts.createSourceFile('response.ts','const response='+text,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
  if(f.parseDiagnostics.length||f.statements.length!==1||!ts.isVariableStatement(f.statements[0])||f.statements[0].declarationList.declarations.length!==1)fail();
  const node=f.statements[0].declarationList.declarations[0].initializer;
  if(!ts.isObjectLiteralExpression(node)||node.getText()!==text.trim())fail();
  const properties=node.properties;if(!properties.length||properties.length>20)fail();
  const names=new Set();
  for(const p of properties){
    if(!ts.isPropertyAssignment(p)||!(ts.isIdentifier(p.name)||ts.isStringLiteral(p.name))||names.has(p.name.text)||p.name.text==='__proto__')fail();
    names.add(p.name.text);
  }
  return properties;
}
export function responsePatch(input){
  const {source,sink,sources,replacement}=input;
  if(typeof source!=='string'||Buffer.byteLength(source)>65536||!sink||!Array.isArray(sources)||sources.length<1||sources.length>20)fail();
  const file=ts.createSourceFile('input.ts',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
  if(file.parseDiagnostics.length)fail();
  let nodes=0,call;
  const position=n=>{const p=file.getLineAndCharacterOfPosition(n.getStart(file));return {line:p.line+1,column:p.character+1};};
  const same=(a,b)=>a.line===b.line&&a.column===b.column;
  function visit(n){
    if(++nodes>20000)fail();
    // Shadowed platform globals cannot establish the built-in API contract.
    if((ts.isVariableDeclaration(n)||ts.isBindingElement(n)||ts.isParameter(n)||ts.isFunctionDeclaration(n)||ts.isClassDeclaration(n)||ts.isImportSpecifier(n)||ts.isImportClause(n)||ts.isNamespaceImport(n))
      &&n.name&&['Deno','Response'].includes(n.name.getText(file)))fail();
    if(ts.isBinaryExpression(n)&&n.operatorToken.kind>=ts.SyntaxKind.FirstAssignment&&n.operatorToken.kind<=ts.SyntaxKind.LastAssignment){
      let left=n.left;while(ts.isPropertyAccessExpression(left)||ts.isElementAccessExpression(left))left=left.expression;
      if(ts.isIdentifier(left)&&['Deno','Response'].includes(left.text))fail();
    }
    if(ts.isCallExpression(n)&&same(position(n),sink)&&dotted(n.expression,'Response.json')){if(call)fail();call=n;}
    ts.forEachChild(n,visit);
  }
  visit(file);
  if(!call||call.arguments.length<1||call.arguments.length>2||!ts.isReturnStatement(call.parent)||call.parent.expression!==call||!ts.isObjectLiteralExpression(call.arguments[0]))fail();
  let handler=call.parent;
  while(handler&&!ts.isArrowFunction(handler)&&!ts.isFunctionExpression(handler)&&!ts.isFunctionDeclaration(handler))handler=handler.parent;
  if(!handler||!ts.isCallExpression(handler.parent)||!dotted(handler.parent.expression,'Deno.serve')||handler.parent.arguments[0]!==handler
    ||!ts.isExpressionStatement(handler.parent.parent)||!ts.isSourceFile(handler.parent.parent.parent))fail();
  const target=call.arguments[0],before=target.getText(file),properties=object(before),originals=target.properties;
  const removed=[],retained=[];
  for(let i=0;i<originals.length;i++){
    const p=originals[i],v=p.initializer;
    if(ts.isCallExpression(v)&&dotted(v.expression,'Deno.env.get')&&v.arguments.length===1&&sources.some(s=>same(position(v),s))){
      if(!(ts.isIdentifier(v.arguments[0])||ts.isStringLiteral(v.arguments[0])))fail();
      if(ts.isStringLiteral(v.arguments[0])&&!/^[A-Z_][A-Z0-9_]{0,79}$/.test(v.arguments[0].text))fail();
      removed.push(p.name.text);
    }else{
      // Rich response values may contain side effects, PII or unresolved API contracts.
      if(!literal(v))fail();retained.push(properties[i].getText());
    }
  }
  if(!removed.length||!retained.length||removed.length!==sources.length)fail();
  const offset=target.getStart(file),line=position(target).line;
  if(replacement!==undefined){
    const next=object(replacement);
    if(next.length!==retained.length||next.some((p,i)=>p.getText()!==retained[i]))fail();
    const updated=source.slice(0,offset)+replacement+source.slice(target.end);
    if(ts.createSourceFile('updated.ts',updated,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS).parseDiagnostics.length)fail();
  }
  return {before,offset,line,removed};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try{let chunks=[],size=0;for await(const c of process.stdin){size+=c.length;if(size>150000)fail();chunks.push(c);}
    process.stdout.write(JSON.stringify(responsePatch(JSON.parse(Buffer.concat(chunks).toString('utf8')))));
  }catch{process.stdout.write(JSON.stringify({unsupported:true}));process.exitCode=1;}
}
