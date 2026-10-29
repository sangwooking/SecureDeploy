// Parse-only context selector; no rule findings or application code execution.
import ts from 'typescript';
import {pathToFileURL} from 'node:url';
export function selectSemanticContext({source,target,unknowns,maxChars=1800}) {
 if(typeof source!=='string'||source.length>100000||!target||!Array.isArray(unknowns)||unknowns.length>100)throw Error('BOUNDED_INPUT_REQUIRED');
 const f=ts.createSourceFile('input.ts',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
 if(f.parseDiagnostics.length)throw Error('PARSE_REQUIRED');
 const offset=l=>{if(!Number.isInteger(l.line)||!Number.isInteger(l.column)||l.line<1||l.column<1)return -1;const starts=f.getLineStarts();if(l.line>starts.length)return -1;return starts[l.line-1]+l.column-1;};
 let fn,nodes=0;const start=offset(target);
 function visit(n){if(++nodes>20000)throw Error('AST_BUDGET');if((ts.isArrowFunction(n)||ts.isFunctionExpression(n)||ts.isFunctionDeclaration(n))&&n.getStart(f)===start)fn=n;ts.forEachChild(n,visit);}visit(f);
 if(!fn||!fn.body)throw Error('HANDLER_TARGET_REQUIRED');
 const relevant=unknowns.filter(l=>offset(l)>=fn.body.getStart(f)&&offset(l)<fn.body.end);
 if(!relevant.length)throw Error('CONNECTED_UNKNOWN_REQUIRED');
 const from=fn.getStart(f),to=fn.end;if(to-from>Math.min(2400,maxChars))throw Error('WHOLE_HANDLER_BUDGET');
 const ranges=[];function redact(n){if(n.end<=from||n.getStart(f)>=to)return;
  if(ts.isNumericLiteral(n)||n.kind===ts.SyntaxKind.BigIntLiteral||ts.isStringLiteral(n)||ts.isNoSubstitutionTemplateLiteral(n)||ts.isTemplateExpression(n)||n.kind===ts.SyntaxKind.RegularExpressionLiteral){ranges.push([n.getStart(f),n.end]);return;}ts.forEachChild(n,redact);}
 redact(fn);const scanner=ts.createScanner(ts.ScriptTarget.Latest,false,ts.LanguageVariant.Standard,source);
 for(let t=scanner.scan();t!==ts.SyntaxKind.EndOfFileToken;t=scanner.scan())if([ts.SyntaxKind.SingleLineCommentTrivia,ts.SyntaxKind.MultiLineCommentTrivia].includes(t)&&scanner.getTokenPos()>=from&&scanner.getTextPos()<=to)ranges.push([scanner.getTokenPos(),scanner.getTextPos()]);
 ranges.sort((a,b)=>a[0]-b[0]||b[1]-a[1]);let end=from,out='';for(const [a,b]of ranges){if(a<end)continue;out+=source.slice(end,a)+source.slice(a,b).replace(/[^\r\n]/g,' ');end=b;}out+=source.slice(end,to);
 // Identifiers are not guaranteed to be non-sensitive; abstain rather than forward opaque token-like names.
 if(/[A-Za-z0-9_]{32,}|[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(out))throw Error('SENSITIVE_IDENTIFIER');
 return {startLine:f.getLineAndCharacterOfPosition(from).line+1,endLine:f.getLineAndCharacterOfPosition(to-1).line+1,content:out,unknownLines:relevant.map(l=>l.line)};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){try{let chunks=[],bytes=0;for await(const c of process.stdin){bytes+=c.length;if(bytes>450000)throw Error('INPUT_LIMIT');chunks.push(c);}process.stdout.write(JSON.stringify(selectSemanticContext(JSON.parse(Buffer.concat(chunks)))));}catch{process.exitCode=1;}}
