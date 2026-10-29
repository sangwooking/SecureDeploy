// Grade B controls frozen before the bounded exception implementation; not blind.
const c=(id,body,expected)=>({id,expected,files:[{filePath:'entry.cjs',content:`const app=require('express')();app.post('/',async(req,res)=>{${body}});`}]});
export const asyncExceptionCases=[
 c('fulfilled-try',`try{await Promise.resolve(0);}catch(e){return;}eval(req.body.code);`,'CONDITIONAL'),
 c('rejected-caught',`try{await Promise.reject('x');}catch(e){const handled=true;}eval(req.body.code);`,'CONDITIONAL'),
 c('catch-return',`try{await Promise.reject('x');}catch(e){return;}eval(req.body.code);`,'NO_TARGET'),
 c('catch-rethrow',`try{await Promise.reject('x');}catch(e){throw e;}eval(req.body.code);`,'NO_TARGET'),
 c('synchronous-throw',`try{throw 'x';}catch(e){}eval(req.body.code);`,'CONDITIONAL'),
 c('normal-finally',`try{await Promise.resolve(0);}finally{const done=true;}eval(req.body.code);`,'CONDITIONAL'),
 c('finally-return',`try{await Promise.resolve(0);}finally{return;}eval(req.body.code);`,'NO_TARGET'),
 c('finally-throw',`try{await Promise.resolve(0);}finally{throw 'x';}eval(req.body.code);`,'NO_TARGET'),
 c('catch-additional-throw',`try{await Promise.reject('x');}catch(e){throw Error('again');}eval(req.body.code);`,'NO_TARGET'),
 c('uncaught-rejection',`try{await Promise.reject('x');}finally{const done=true;}eval(req.body.code);`,'NO_TARGET'),
 c('finally-return-overrides-throw',`try{throw 'x';}finally{return;}eval(req.body.code);`,'NO_TARGET'),
 c('external-promise',`try{await external();}catch(e){}eval(req.body.code);`,'UNKNOWN'),
 c('nested-exception',`try{try{await Promise.resolve(0);}catch(e){}}catch(e){}eval(req.body.code);`,'UNKNOWN'),
 c('conditional-await',`try{if(req.body.run)await Promise.resolve(0);}catch(e){}eval(req.body.code);`,'UNKNOWN'),
 c('catch-unknown-call',`try{await Promise.reject('x');}catch(e){external();}eval(req.body.code);`,'UNKNOWN'),
 c('error-path-only-sink',`try{await Promise.reject('x');}catch(e){eval(req.body.code);}`,'CONDITIONAL'),
 c('unreachable-sink',`try{await Promise.reject('x');eval(req.body.code);}catch(e){return;}`,'NO_TARGET'),
 c('file-write-catch-return',`const {writeFile}=require('fs/promises');try{await writeFile('unused.txt','data');}catch(e){return;}eval(req.body.code);`,'CONDITIONAL'),
 c('file-write-catch-continues',`const {writeFile}=require('fs/promises');try{await writeFile('unused.txt','data');}catch(e){}eval(req.body.code);`,'CONDITIONAL'),
 c('safe-code',`try{await Promise.resolve(0);}catch(e){}eval('1');`,'NO_TARGET'),
];
