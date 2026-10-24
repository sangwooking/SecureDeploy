import path from 'node:path';

// Supplied JSONC only: no config inheritance, compiler host, plugins or filesystem reads.
export function tsPaths({ts,input,modules,charge,note}) {
  const configs=[],inventory=new Set([...(input.nodeSourceInventory??[]),...modules.keys()]);
  const safe=p=>p!== '..'&&!p.startsWith('../')&&!p.startsWith('/')&&!p.split('/').includes('node_modules');
  for(const file of (input.typescriptConfigs??[]).slice(0,32)) {
    const c={filePath:file.filePath,dir:path.posix.dirname(file.filePath),status:'UNKNOWN',paths:[]};configs.push(c);
    if(file.status!=='SELECTED'||typeof file.content!=='string'||file.content.length>64000)continue;
    try {
      const parsed=ts.parseConfigFileTextToJson(file.filePath,file.content);
      if(parsed.error||!parsed.config||typeof parsed.config!=='object'||Array.isArray(parsed.config)||'extends' in parsed.config)continue;
      const ast=ts.parseJsonText(file.filePath,file.content);let duplicate=false;
      const visit=n=>{charge();if(ts.isObjectLiteralExpression(n)){const keys=new Set();for(const p of n.properties){const key=p.name?.text;if(keys.has(key))duplicate=true;keys.add(key);}}ts.forEachChild(n,visit);};visit(ast);
      if(duplicate)continue;
      const options=parsed.config.compilerOptions===undefined?{}:parsed.config.compilerOptions;
      if(!options||typeof options!=='object'||Array.isArray(options))continue;
      const base=options.baseUrl===undefined?'.':options.baseUrl,paths=options.paths===undefined?{}:options.paths;
      if(typeof base!=='string'||base.length>240||/[\\\0]/.test(base)||path.posix.isAbsolute(base)||!paths||typeof paths!=='object'||Array.isArray(paths)||Object.keys(paths).length>100)continue;
      c.base=path.posix.normalize(path.posix.join(c.dir,base));if(!safe(c.base))continue;
      c.status='PARSED';
      for(const [pattern,targets] of Object.entries(paths)){
        const validPattern=pattern.length<=240&&(pattern.match(/\*/g)??[]).length<=1&&!/[\\\0]/.test(pattern);
        if(!validPattern){c.status='UNKNOWN';break;}
        const target=Array.isArray(targets)&&targets.length===1&&typeof targets[0]==='string'?targets[0]:null;
        c.paths.push({pattern,target:target&&target.length<=240&&!/[\\\0]/.test(target)&&!path.posix.isAbsolute(target)&&(target.match(/\*/g)??[]).length<=1&&(!target.includes('*')||pattern.includes('*'))?target:null});
      }
    }catch{c.status='UNKNOWN';}
  }
  const configCache=new Map(),byPath=new Map(configs.map(c=>[c.filePath,c])),enumerated=new Set(input.nodeEnumeratedDirectories??[]);
  function findConfig(mod){
    let dir=path.posix.dirname(mod.filePath);
    for(let depth=0;depth<100;depth++){
      const p=path.posix.join(dir,'tsconfig.json'),c=byPath.get(p);
      if(c)return c;
      if(inventory.has(p))return {status:'UNKNOWN',paths:[]};
      if(input.nodeSourceInventoryComplete===false&&!enumerated.has(dir))return {status:'UNINSPECTED',paths:[]};
      if(dir==='.')return null;dir=path.posix.dirname(dir);
    }
    return {status:'UNKNOWN',paths:[]};
  }
  function config(mod){if(!configCache.has(mod.filePath))configCache.set(mod.filePath,findConfig(mod));return configCache.get(mod.filePath);}
  function matching(c,spec){return c.paths.filter(p=>p.pattern.includes('*')?spec.length>=p.pattern.length-1&&spec.startsWith(p.pattern.split('*')[0])&&spec.endsWith(p.pattern.split('*')[1]):p.pattern===spec)
    .sort((a,b)=>Number(a.pattern.includes('*'))-Number(b.pattern.includes('*'))||b.pattern.split('*')[0].length-a.pattern.split('*')[0].length);}
  function shadows(mod,spec){if(typeof spec!=='string'||spec.length>240)return false;const c=config(mod);return c?.status==='PARSED'&&matching(c,spec).length>0;}
  function target(mod,spec) {
    if(typeof spec!=='string'||spec.length>240)return null;
    const c=config(mod);if(!c)return null;
    if(c.status!=='PARSED'){note(mod,'TS_PATH_CONFIG_UNKNOWN');return null;}
    const matches=matching(c,spec);if(!matches.length)return null;
    if(matches.length>1&&matches[0].pattern.includes('*')&&matches[1].pattern.includes('*')&&matches[0].pattern.split('*')[0].length===matches[1].pattern.split('*')[0].length){note(mod,'TS_PATH_TARGET_AMBIGUOUS');return null;}
    const selected=matches[0];if(!selected.target){note(mod,'TS_PATH_TARGETS_UNSUPPORTED');return null;}
    const [prefix,suffix='']=selected.pattern.split('*'),wild=selected.pattern.includes('*')?spec.slice(prefix.length,spec.length-suffix.length):'';
    const base=path.posix.normalize(path.posix.join(c.base,selected.target.replace('*',wild)));
    if(!safe(base)){note(mod,'TS_PATH_OUTSIDE_INPUT');return null;}
    const candidates=[base,base.replace(/\.js$/,'.ts'),base+'.ts',base+'.tsx',base+'.js',base+'/index.ts',base+'/index.js'];
    const present=[...new Set(candidates.filter(p=>inventory.has(p)))];
    if(present.length!==1){note(mod,present.length?'TS_PATH_TARGET_AMBIGUOUS':'TS_PATH_TARGET_NOT_INSPECTED');return null;}
    const resolved=modules.get(present[0]);if(!resolved){note(mod,'TS_PATH_TARGET_NOT_INSPECTED');return null;}
    note(mod,'TS_STATIC_PATH_ALIAS_LINK');return resolved;
  }
  return {target,shadows,uncertain:mod=>config(mod)?.status==='UNKNOWN'};
}
