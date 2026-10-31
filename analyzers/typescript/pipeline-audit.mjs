// Evaluation sidecar only: bounded observations, never an exhaustive call graph or safety verdict.
export function pipelineAudit() {
  const maps={moduleLinks:new Map(),calls:new Map(),invocations:new Map()};let truncated=false;
  function add(kind,row){const key=JSON.stringify(row);const m=maps[kind];if(m.has(key))return;if(m.size>=1000){truncated=true;return;}m.set(key,row);}
  return {add,report(){return {scope:'OBSERVED_STATIC_LINKS_ONLY',completeDenominator:null,truncated,
    ...Object.fromEntries(Object.entries(maps).map(([key,m])=>[key,[...m.entries()].sort(([a],[b])=>a.localeCompare(b)).map(([,v])=>v)]))};}};
}
