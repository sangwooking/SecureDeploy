import{analyze,VERSION}from'../../analyzers/typescript/analyzer.mjs';
export const helperReferenceCases=[
 {id:'direct-before-await',setup:''},
 {id:'short-circuit-before-await',setup:'if(req.query.flag&&external){}'},
 {id:'after-literal-await',setup:'await 0;'},
 {id:'short-circuit-after-await',setup:'await 0;if(req.query.flag&&external){}'},
 {id:'changed-function-reference',setup:'helper=external;'},
];
export function auditHelperReferences(){return helperReferenceCases.map(c=>{
 const binding=c.id==='changed-function-reference'?'let':'const';
 const r=analyze({files:[{filePath:'entry.cjs',content:`const app=require('express')();${binding} helper=require('./helper.cjs');app.post('/',async(req,res)=>{${c.setup}try{await helper(req.body.value);}catch(e){}});`},
 {filePath:'helper.cjs',content:`module.exports=function work(value){eval(value);return 'fixed';};`} ]});
 return{id:c.id,findings:r.findings.map(f=>({ruleId:f.ruleId,confidence:f.confidence,source:f.source,sink:f.sink})),
 states:r.nodeUses.filter(u=>u.operation==='BOUNDED_ASYNC_FLOW'),limitations:r.files.map(f=>({filePath:f.filePath,limitations:f.limitations}))};
});}
if(process.argv[1]?.endsWith('/reference35.mjs'))console.log(JSON.stringify({worker:VERSION,scope:'NON_BLIND_REFERENCE_AUDIT_NOT_PRODUCTION_REFERENCE_RESTORATION',cases:auditHelperReferences()},null,2));
