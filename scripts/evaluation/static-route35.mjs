import{createHash}from'node:crypto';import{analyze,evaluateStaticRoutes,VERSION}from'../../analyzers/typescript/analyzer.mjs';
import{staticRouteCases}from'../../analyzers/typescript/test/static-route-fixtures.mjs';
export function evaluateStaticRouteControls(){return staticRouteCases.map(c=>{
 const p=analyze(c.input),r=evaluateStaticRoutes(c.input);
 return{id:c.id,expectedCategory:c.category,expectedRuleObservations:c.findings,inputSha256:createHash('sha256').update(JSON.stringify(c.input)).digest('hex'),
  productionEntries:p.files.reduce((n,f)=>n+f.entrypoints,0),productionFindings:p.findings.length,
  rows:r.rows.map(row=>({category:row.category,traceStatus:row.traceStatus,source:row.registration,handler:row.handler,findingRefs:row.observationRefs.findings})),
  ruleObservations:r.observations.findings.map(f=>({ruleId:f.ruleId,confidence:f.confidence,source:f.source,sink:f.sink})),
  riskApplied:r.riskApplied,limitations:r.limitations};
});}
if(process.argv[1]?.endsWith('/static-route35.mjs'))console.log(JSON.stringify({engineVersion:VERSION,evaluationVersion:'static-route-v1',grade:'B',independent:false,newRealTP:0,cases:evaluateStaticRouteControls()},null,2));
