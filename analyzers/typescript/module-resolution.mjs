import path from 'node:path';

// Resolve supplied source metadata only. Never consult the host filesystem.
export function moduleResolution({modules,input,tick,note}) {
  const manifests=new Map((input.nodeManifests??[]).slice(0,100).map(m=>[m.filePath,m]));
  const inventory=new Set([...(input.nodeSourceInventory??[]),...modules.keys(),...manifests.keys()]);
  const directories=new Set(['.',...(input.nodeEnumeratedDirectories??[])]);
  for(const p of inventory){let dir=path.posix.dirname(p);while(!directories.has(dir)){directories.add(dir);const parent=path.posix.dirname(dir);if(parent===dir)break;dir=parent;}}
  const safe=p=>p!== '..'&&!p.startsWith('../')&&!path.posix.isAbsolute(p);
  const relative=s=>s==='.'||s==='..'||s.startsWith('./')||s.startsWith('../');
  function packageType(file,mod) {
    let dir=path.posix.dirname(file);
    for(let depth=0;depth<100;depth++) {
      tick(mod);
      const p=path.posix.join(dir,'package.json'), m=manifests.get(p);
      if(m)return !m.resolutionStatus||m.resolutionStatus==='PARSED'?m.moduleType??'commonjs':'unknown';
      if(inventory.has(p))return 'unknown';
      if(dir==='.')return 'commonjs';
      dir=path.posix.dirname(dir);
    }
    return 'unknown';
  }
  function resolve(mod,spec,mode='require') {
    if(typeof spec!=='string'||spec.length>240||!relative(spec))return;
    if(/[\\\0?#%]/.test(spec)){note(mod,'NODE_MODULE_SPECIFIER_NOT_SUPPORTED');return;}
    const base=path.posix.normalize(path.posix.join(path.posix.dirname(mod.filePath),spec));
    if(!safe(base)){note(mod,'NODE_MODULE_PATH_OUTSIDE_INPUT');return;}
    let blocked=false;
    function file(p) {
      tick(mod);p=path.posix.normalize(p);
      if(!safe(p)){blocked=true;note(mod,'NODE_MODULE_PATH_OUTSIDE_INPUT');return;}
      if(directories.has(p))return;
      if(!inventory.has(p))return;
      const target=modules.get(p);
      if(!target){blocked=true;note(mod,'NODE_MODULE_TARGET_NOT_INSPECTED');return;}
      if(mode==='require'&&(!/\.(?:js|cjs)$/.test(p)||p.endsWith('.js')&&packageType(p,mod)!=='commonjs')){
        blocked=true;note(mod,'NODE_REQUIRE_FORMAT_NOT_SUPPORTED');return;
      }
      return target;
    }
    if(mode==='import') {
      const exact=file(base);if(exact||blocked)return exact;
      // Preserve the existing TS source/bundler contract, not Node ESM directory loading.
      const choices=[base.replace(/\.js$/,'.ts'),...['.ts','.js','.mjs','.cjs'].map(e=>base+e)]
        .filter(p=>p!==base&&modules.has(p));
      if(choices.length===1){note(mod,'NODE_IMPORT_SOURCE_MAPPING_NOT_RUNTIME_PROOF');return modules.get(choices[0]);}
      note(mod,choices.length?'CALL_TARGET_UNKNOWN':'NODE_ESM_DIRECTORY_OR_TARGET_NOT_SUPPORTED');return;
    }
    function asFile(p) {
      for(const name of [p,p+'.js',p+'.json',p+'.node']){
        const target=file(name);if(target||blocked)return target;
      }
    }
    function index(dir) {
      for(const ext of ['js','json','node']){
        const target=file(path.posix.join(dir,'index.'+ext));if(target||blocked)return target;
      }
    }
    // A trailing slash requests a directory, not its same-named sibling file.
    const direct=spec.endsWith('/')?undefined:asFile(base);if(direct||blocked)return direct;
    const packagePath=path.posix.join(base,'package.json'), manifest=manifests.get(packagePath);
    if(!inventory.has(packagePath)&&input.nodeSourceInventoryComplete===false&&!(input.nodeEnumeratedDirectories??[]).includes(base)){
      note(mod,'NODE_DIRECTORY_INVENTORY_INCOMPLETE');return;
    }
    if(inventory.has(packagePath)&&(!manifest||manifest.resolutionStatus&&manifest.resolutionStatus!=='PARSED'||manifest.mainStatus==='UNKNOWN')){
      note(mod,'NODE_PACKAGE_CONFIGURATION_UNKNOWN');return;
    }
    if(manifest?.mainStatus==='STATIC') {
      const main=manifest.main;
      if(typeof main!=='string'||main.length>240||!main||/[\\\0?#%]/.test(main)||path.posix.isAbsolute(main)){
        note(mod,'NODE_PACKAGE_CONFIGURATION_UNKNOWN');return;
      }
      const targetPath=path.posix.normalize(path.posix.join(base,main));
      if(!safe(targetPath)){note(mod,'NODE_MODULE_PATH_OUTSIDE_INPUT');return;}
      const target=asFile(targetPath);if(target){note(mod,'NODE_COMMONJS_DIRECTORY_SOURCE_LINK');return target;}if(blocked)return;
      const fallback=index(targetPath);if(fallback){note(mod,'NODE_COMMONJS_DIRECTORY_SOURCE_LINK');return fallback;}if(blocked)return;
    }
    const target=index(base);if(target){note(mod,'NODE_COMMONJS_DIRECTORY_SOURCE_LINK');return target;}if(blocked)return;
    note(mod,'CONTEXT_MISSING');
  }
  return {resolve};
}
