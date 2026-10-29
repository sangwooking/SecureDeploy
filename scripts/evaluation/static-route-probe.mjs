// Trusted evaluation entry point only; the product worker never imports this file.
import {evaluateStaticRoutes} from '../../analyzers/typescript/analyzer.mjs';
let size=0;const chunks=[];
try{
 for await(const chunk of process.stdin){size+=chunk.length;if(size>1200000)throw Error('INPUT_LIMIT');chunks.push(chunk);}
 const r=evaluateStaticRoutes(JSON.parse(Buffer.concat(chunks).toString('utf8'))),out=JSON.stringify(r);
 if(Buffer.byteLength(out)>1950000)throw Error('OUTPUT_LIMIT');process.stdout.write(out);
}catch{process.stderr.write('STATIC_ROUTE_EVALUATION_INCOMPLETE\n');process.exitCode=1;}
