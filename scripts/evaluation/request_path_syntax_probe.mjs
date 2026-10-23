// Trusted parser on supplied text only: no target host, imports or execution.
import ts from '../../analyzers/typescript/node_modules/typescript/lib/typescript.js';
let bytes=0;const chunks=[];
for await(const chunk of process.stdin){bytes+=chunk.length;if(bytes>1200000)throw Error('INPUT_LIMIT');chunks.push(chunk);}
const {files}=JSON.parse(Buffer.concat(chunks).toString('utf8'));
if(!Array.isArray(files)||files.length>100)throw Error('FILE_LIMIT');
const rows=[];let total=0;
for(const file of files){
 if(typeof file.content!=='string'||file.content.length>100000||(total+=file.content.length)>1000000)throw Error('SOURCE_LIMIT');
 const ast=ts.createSourceFile('supplied.ts',file.content,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
 const scanner=ts.createScanner(ts.ScriptTarget.Latest,true,ts.LanguageVariant.Standard,file.content);
 const first=scanner.scan(),second=scanner.scan();
 const errors=ast.parseDiagnostics.map(d=>({code:d.code,line:ast.getLineAndCharacterOfPosition(d.start??0).line+1}));
 const category=!errors.length?'PARSED_STANDALONE':first===ts.SyntaxKind.Identifier&&second===ts.SyntaxKind.ColonToken?'MEMBER_FRAGMENT'
  :first===ts.SyntaxKind.Identifier&&second===ts.SyntaxKind.OpenParenToken?'METHOD_FRAGMENT'
  :first===ts.SyntaxKind.Identifier&&second===ts.SyntaxKind.DotToken?'CALL_OR_PROPERTY_EXCERPT_SYNTAX_ERROR'
  :first===ts.SyntaxKind.ExportKeyword?'EXPORTED_DECLARATION_WITH_SYNTAX_ERROR'
  :first===ts.SyntaxKind.OpenBraceToken?'BLOCK_EXCERPT_SYNTAX_ERROR'
  :[ts.SyntaxKind.CloseBraceToken,ts.SyntaxKind.CloseParenToken,ts.SyntaxKind.DotToken].includes(first)?'LEADING_CONTEXT_TERMINATOR'
  :[ts.SyntaxKind.ElseKeyword,ts.SyntaxKind.CatchKeyword,ts.SyntaxKind.FinallyKeyword].includes(first)?'CONTROL_CONTINUATION'
  :'INCOMPLETE_OR_INVALID_STANDALONE';
 rows.push({filePath:file.filePath,category,firstTokenKind:ts.SyntaxKind[first],errors:errors.slice(0,20),errorCount:errors.length});
}
process.stdout.write(JSON.stringify({parserVersion:ts.version,targetExecuted:false,files:rows}));
