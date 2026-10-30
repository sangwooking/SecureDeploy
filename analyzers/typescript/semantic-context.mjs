// Parse-only context selector. Same-file direct helper declarations; no target code execution.
import ts from 'typescript';
import {pathToFileURL} from 'node:url';
export function selectSemanticContext({source,target,unknowns,maxChars=1800}) {
 if(typeof source!=='string'||source.length>100000||!target||!Array.isArray(unknowns)||unknowns.length>100)throw Error('BOUNDED_INPUT_REQUIRED');
 const f=ts.createSourceFile('input.ts',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);if(f.parseDiagnostics.length)throw Error('PARSE_REQUIRED');
 const offset=l=>{if(!Number.isInteger(l.line)||!Number.isInteger(l.column)||l.line<1||l.column<1)return -1;const starts=f.getLineStarts();return l.line>starts.length?-1:starts[l.line-1]+l.column-1;};
 let fn,nodes=0;const all=[],start=offset(target);
 function visit(n){if(++nodes>20000)throw Error('AST_BUDGET');all.push(n);if((ts.isArrowFunction(n)||ts.isFunctionExpression(n)||ts.isFunctionDeclaration(n))&&n.getStart(f)===start)fn=n;ts.forEachChild(n,visit);}visit(f);
 if(!fn?.body)throw Error('HANDLER_TARGET_REQUIRED');
 const selected=[fn],bindings=name=>all.filter(n=>(ts.isFunctionDeclaration(n)||ts.isVariableDeclaration(n)||ts.isParameter(n)||ts.isImportClause(n)||ts.isImportSpecifier(n)||ts.isBindingElement(n))&&n.name?.getText(f)===name);
 // Syntactic linkage only. Calls with duplicate/shadowed bindings, assignments or imported helpers stay unresolved.
 const calls=all.filter(n=>ts.isCallExpression(n)&&n.getStart(f)>=fn.body.getStart(f)&&n.end<=fn.body.end&&ts.isIdentifier(n.expression));
 for(const call of calls){if(selected.length>=3)break;const matches=bindings(call.expression.text);if(matches.length!==1)continue;const h=matches[0];if(!ts.isFunctionDeclaration(h)||!ts.isSourceFile(h.parent)||!h.body)continue;
  if(all.some(n=>ts.isBinaryExpression(n)&&n.left.getText(f)===call.expression.text&&n.operatorToken.kind>=ts.SyntaxKind.FirstAssignment&&n.operatorToken.kind<=ts.SyntaxKind.LastAssignment))continue;
  if(!selected.includes(h))selected.push(h);
 }
 const relevant=unknowns.filter(l=>selected.some(n=>offset(l)>=n.body.getStart(f)&&offset(l)<n.body.end));if(!relevant.length)throw Error('CONNECTED_UNKNOWN_REQUIRED');
 const contexts=[];let budget=0;
 for(const n of selected){const from=n.getStart(f),to=n.end;if(to-from>Math.min(2400,maxChars)||budget+to-from>maxChars)throw Error('WHOLE_CONTEXT_BUDGET');const ranges=[];
  function redact(v){if(ts.isNumericLiteral(v)||v.kind===ts.SyntaxKind.BigIntLiteral||ts.isStringLiteral(v)||ts.isNoSubstitutionTemplateLiteral(v)||ts.isTemplateExpression(v)||v.kind===ts.SyntaxKind.RegularExpressionLiteral){ranges.push([v.getStart(f),v.end]);return;}ts.forEachChild(v,redact);}redact(n);
  const scanner=ts.createScanner(ts.ScriptTarget.Latest,false,ts.LanguageVariant.Standard,source);for(let t=scanner.scan();t!==ts.SyntaxKind.EndOfFileToken;t=scanner.scan())if([ts.SyntaxKind.SingleLineCommentTrivia,ts.SyntaxKind.MultiLineCommentTrivia].includes(t)&&scanner.getTokenPos()>=from&&scanner.getTextPos()<=to)ranges.push([scanner.getTokenPos(),scanner.getTextPos()]);
  ranges.sort((a,b)=>a[0]-b[0]||b[1]-a[1]);let end=from,out='';for(const [a,b]of ranges){if(a<end)continue;out+=source.slice(end,a)+source.slice(a,b).replace(/[^\r\n]/g,' ');end=b;}out+=source.slice(end,to);
  if(/[A-Za-z0-9_]{32,}|[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(out))throw Error('SENSITIVE_IDENTIFIER');
  contexts.push({startLine:f.getLineAndCharacterOfPosition(from).line+1,endLine:f.getLineAndCharacterOfPosition(to-1).line+1,content:out,functionName:n.name?.getText(f)??target.functionName??'handler'});budget+=out.length;
 }
 return {...contexts[0],contexts,unknownLines:relevant.map(l=>l.line),linkage:'SAME_FILE_DIRECT_CALL_SYNTAX_NOT_RUNTIME_PROOF'};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){try{let chunks=[],bytes=0;for await(const c of process.stdin){bytes+=c.length;if(bytes>450000)throw Error('INPUT_LIMIT');chunks.push(c);}process.stdout.write(JSON.stringify(selectSemanticContext(JSON.parse(Buffer.concat(chunks)))));}catch{process.exitCode=1;}}
