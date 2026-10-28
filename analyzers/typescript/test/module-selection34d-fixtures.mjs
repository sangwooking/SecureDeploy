// Expectations fixed before the resolver/selection implementation; no upstream truth labels.
const config=(options,extra={})=>({filePath:'tsconfig.json',status:'SELECTED',content:JSON.stringify({compilerOptions:{moduleResolution:'bundler',baseUrl:'.',paths:{'@/*':['./src/*']},...options},...extra})});
export const moduleSelectionCases=[
 {id:'file-only',files:['src/lib/item.ts'],inventory:['src/lib/item.ts'],expected:'src/lib/item.ts'},
 {id:'index-only',files:['src/lib/item/index.ts'],inventory:['src/lib/item/index.ts'],expected:'src/lib/item/index.ts'},
 {id:'directory-and-index',files:['src/lib/item/index.ts'],inventory:['src/lib/item','src/lib/item/index.ts'],directories:['src/lib/item'],expected:'src/lib/item/index.ts'},
 {id:'file-before-directory-index',files:['src/lib/item.ts','src/lib/item/index.ts'],inventory:['src/lib/item','src/lib/item.ts','src/lib/item/index.ts'],directories:['src/lib/item'],expected:'src/lib/item.ts'},
 {id:'explicit-js-source-substitution',specifier:'@/lib/item.js',files:['src/lib/item.ts','src/lib/item.js'],inventory:['src/lib/item.ts','src/lib/item.js'],expected:'src/lib/item.ts'},
 {id:'multiple-alias-targets',configs:[config({paths:{'@/*':['./src/*','./other/*']}})],files:['src/lib/item.ts'],inventory:['src/lib/item.ts'],expected:null},
 {id:'conditional-directory-package',files:['src/lib/item/index.ts'],inventory:['src/lib/item','src/lib/item/package.json','src/lib/item/index.ts'],expected:null},
 {id:'nodenext-runtime-unverified',configs:[config({moduleResolution:'nodenext'})],files:['src/lib/item.ts'],inventory:['src/lib/item.ts'],expected:null},
 {id:'nearest-config-not-inspected',configs:[config({}),{filePath:'src/tsconfig.json',status:'LIMIT_EXCEEDED'}],files:['src/lib/item.ts'],inventory:['src/lib/item.ts','src/tsconfig.json'],expected:null},
 {id:'escaping-alias',configs:[config({paths:{'@/*':['../outside/*']}})],files:['src/lib/item.ts'],inventory:['src/lib/item.ts'],expected:null},
 {id:'unselected-preferred-file',files:['src/lib/item.js'],inventory:['src/lib/item.ts','src/lib/item.js'],expected:null},
 {id:'legacy-multiple-files-remain-unknown',configs:[{filePath:'tsconfig.json',status:'SELECTED',content:'{"compilerOptions":{"paths":{"@/*":["./src/*"]}}}'}],files:['src/lib/item.ts','src/lib/item.js'],inventory:['src/lib/item.ts','src/lib/item.js'],expected:null},
];
export const defaultModuleConfig=config({});
