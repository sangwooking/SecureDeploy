import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {analyze} from '../../analyzers/typescript/analyzer.mjs';

const hash=b=>createHash('sha256').update(b).digest('hex');
const files={
  LICENSE:'95a5762890e5c1c9808921cef095661fc482c5e1f0bba31446ac85595df6237c',
  'examples/params/index.js':'f381d9199eace049b8048d03362010765cf17374a72c2c6656e2757236c9b301',
  'examples/route-middleware/index.js':'8bbd84ce25e3be1e943d83d2dfe4a8fddc99358c0b7dc454a4df39b7597c26bb',
};
export function officialExposureProbe(engine,root) {
  const base=fs.realpathSync(root),sources={};
  for(const [name,digest] of Object.entries(files)) {
    const file=path.join(base,name);
    if(fs.lstatSync(file).isSymbolicLink()||!fs.realpathSync(file).startsWith(base+path.sep)||fs.statSync(file).size>100000)throw Error('INVALID_EXTERNAL_ASSET');
    const bytes=fs.readFileSync(file);if(hash(bytes)!==digest)throw Error('EXTERNAL_ASSET_HASH_MISMATCH');sources[name]=bytes.toString('utf8');
  }
  const manifest=[{filePath:'package.json',express:'4.18.0'}];
  const run=content=>engine({files:[{filePath:'server.cjs',content}],nodeManifests:manifest});
  const controlled=sources['examples/route-middleware/index.js'].replace("require('../../lib/express')","require('express')");
  const cases=[
    ['json-secret','RISK',"response.json({value:process.env.API_SECRET});"],
    ['helper-send','RISK',"const make=value=>({value});response.status(202).send(make(process.env.API_SECRET));"],
    ['public-key','NORMAL',"response.json({key:process.env.SUPABASE_PUBLISHABLE_KEY});"],
    ['internal-only','NORMAL',"const key=process.env.API_SECRET;await fetch('https://provider.example.invalid',{headers:{Authorization:key}});response.json({ready:true});"],
    ['unknown-masking','UNKNOWN',"response.json(mask(process.env.API_SECRET));"],
    ['changed-response','UNKNOWN',"response.json=custom;response.json(process.env.API_SECRET);"],
  ];
  const results=cases.map(([id,truth,body])=>{
    const prefix=controlled+"\napp.get('/__controlled_probe',async(request,response)=>{\n";
    const source=prefix+body+'\n});\n',line=prefix.split('\n').length;
    const start=performance.now(),result=run(source),elapsedMs=performance.now()-start;
    const matched=result.findings.filter(f=>f.ruleId==='TS_SENSITIVE_DATA_EXPOSURE'&&f.sink.line===line);
    return {id,truth,grade:'B_CONTROLLED_OFFICIAL_EXAMPLE',sourceHash:hash(source),engine:result.analyzerVersion,
      verdict:truth==='UNKNOWN'?(matched.length?'UNEXPECTED_CANDIDATE':'UNKNOWN'):truth==='RISK'?(matched.length?'TP':'FN'):(matched.length?'FP':'TN'),
      targetFindingCount:matched.length,sinkLine:line,entrypoints:result.files[0].entrypoints,
      parseStatus:result.files[0].parseStatus,limitations:result.files[0].limitations,elapsedMs:Math.round(elapsedMs)};
  });
  const params=run(sources['examples/params/index.js'].replace("require('../../')","require('express')"));
  return {repository:'expressjs/express',sha:'0dee2c52c7c873498f8ed7d8ee4ddd0a04d3ada8',license:'MIT',sourceExecuted:false,
    independentBlindEvaluation:false,transformations:['RELATIVE_FRAMEWORK_IMPORT_TO_DECLARED_PACKAGE','APPEND_SYNTHETIC_ROUTE_KEEP_ORIGINAL_ROUTING'],
    results,uncontrolledParams:{grade:'C',parseStatus:params.files[0].parseStatus,flowStatus:params.files[0].flowStatus,entrypoints:params.files[0].entrypoints,limitations:params.files[0].limitations,verdict:'NOT_INSPECTED_NOT_SAFE'}};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  if(process.argv.length!==3)throw Error('EXPECTED_VERIFIED_LOCAL_EXPRESS_EXAMPLES_DIRECTORY');
  process.stdout.write(JSON.stringify(officialExposureProbe(analyze,process.argv[2]),null,2)+'\n');
}
