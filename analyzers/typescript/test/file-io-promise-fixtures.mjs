// Grade B, non-blind controls. Expectations precede the file-I/O model implementation.
const prefix=`const app=require('express')();`;
const promisified=`const fs=require('node:fs');const {promisify}=require('node:util');const write=promisify(fs.writeFile);`;
const direct=`const fs=require('node:fs');`;
const route=body=>`app.post('/',async(req,res)=>{${body}});`;
const c=(id,setup,body,expected)=>({id,expected,files:[{filePath:'entry.cjs',content:prefix+setup+route(body)}]});
export const fileIoCases=[
 c('promisified-write',promisified,`await write('unused.txt','data');eval(req.body.code);`,'CONDITIONAL'),
 c('immutable-alias',promisified+`const saved=write;`,`await saved('unused.txt','data');eval(req.body.code);`,'CONDITIONAL'),
 c('fs-promises',direct,`await fs.promises.writeFile('unused.txt','data');eval(req.body.code);`,'CONDITIONAL'),
 c('promise-module',`const {writeFile:write}=require('node:fs/promises');`,`await write('unused.txt','data');eval(req.body.code);`,'CONDITIONAL'),
 c('two-writes',promisified,`await write('one.txt','a');await write('two.txt','b');eval(req.body.code);`,'CONDITIONAL'),
 c('helper-return',promisified+`async function save(){await write('unused.txt','data');return false;}`,`await save();eval(req.body.code);`,'CONDITIONAL'),
 c('skip-write',promisified,`if(false)await write('unused.txt','data');eval(req.body.code);`,'HIGH'),
 c('conditional-write',promisified,`if(req.body.save)await write('unused.txt','data');eval(req.body.code);`,'CONDITIONAL'),
 c('safe-sink',promisified,`await write('unused.txt','data');eval('1');`,'NO_TARGET'),
 c('fulfilled-value-undefined',promisified,`const result=await write('unused.txt','data');if(result===undefined)eval('1');`,'NO_TARGET'),
 c('early-return',promisified,`await write('unused.txt','data');return;eval(req.body.code);`,'NO_TARGET'),
 c('unhandled-known-rejection',promisified,`await Promise.reject('no');await write('unused.txt','data');eval(req.body.code);`,'NO_TARGET'),
 c('same-name-function',`function write(){return external();}`,`await write('unused.txt','data');eval(req.body.code);`,'UNKNOWN'),
 c('changed-reference',promisified,`write=external;await write('unused.txt','data');eval(req.body.code);`,'UNKNOWN'),
 c('custom-promisify',direct+`const {promisify}=require('util');fs.writeFile[promisify.custom]=external;const write=promisify(fs.writeFile);`,`await write('unused.txt','data');eval(req.body.code);`,'UNKNOWN'),
 c('escaped-function',promisified+`external(write);`,`await write('unused.txt','data');eval(req.body.code);`,'UNKNOWN'),
 c('wrapper-unknown',direct+`const write=external(fs.writeFile);`,`await write('unused.txt','data');eval(req.body.code);`,'UNKNOWN'),
 c('catch-not-modeled',promisified,`try{await write('unused.txt','data');}catch(e){eval(req.body.code);}`,'UNKNOWN'),
 c('rethrow-not-modeled',promisified,`try{await write('unused.txt','data');}catch(e){throw e;}eval(req.body.code);`,'UNKNOWN'),
 c('finally-not-modeled',promisified,`try{await write('unused.txt','data');}finally{eval(req.body.code);}`,'UNKNOWN'),
 c('dynamic-import',``, `const fs=await import('node:fs/promises');await fs.writeFile('unused.txt','data');eval(req.body.code);`,'UNKNOWN'),
 c('wrong-arguments',promisified,`await write();eval(req.body.code);`,'UNKNOWN'),
 c('custom-method-this',`const x={writeFile:external};const {promisify}=require('util');const write=promisify(x.writeFile);`,`await write('unused.txt','data');eval(req.body.code);`,'UNKNOWN'),
];
