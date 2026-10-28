// Fixed before implementation. Owned Grade B text, not real CVE ground truth.
const pre=`import {toNextJsHandler as adapt} from 'better-auth/next-js';`;
const handler=`async function run(request){return fetch(new URL(request.url).searchParams.get('url'));}`;
const config={filePath:'tsconfig.json',status:'SELECTED',content:'{"compilerOptions":{"moduleResolution":"bundler"}}'};
const packet=(content,extra=[],version='1.7.12')=>({typescriptConfigs:[config],nodeManifests:[{filePath:'package.json',next:'15.2.4','better-auth':version}],files:[{filePath:'app/api/sample/route.ts',content},...extra]});
export const externalHandlerCases=[
 {id:'direct-function',truth:'FLOW',entries:1,input:packet(pre+handler+`export const {GET}=adapt(run);`)},
 {id:'object-handler',truth:'FLOW',entries:2,input:packet(pre+handler+`export const {GET,POST}=adapt({handler:run});`)},
 {id:'result-alias',truth:'FLOW',entries:1,input:packet(pre+handler+`const routes=adapt(run);export const {POST}=routes;`)},
 {id:'module-handler',truth:'FLOW',entries:1,input:packet(pre+`import {run} from './handler';export const {POST}=adapt(run);`,[{filePath:'app/api/sample/handler.ts',content:'export '+handler}])},
 {id:'handler-reexport',truth:'FLOW',entries:1,input:packet(`export {GET} from './generated';`,[{filePath:'app/api/sample/generated.ts',content:pre+handler+`export const {GET}=adapt(run);`}])},
 {id:'fixed-destination',truth:'NORMAL',entries:1,input:packet(pre+`export const {GET}=adapt(async request=>fetch('https://example.invalid/fixed'));`)},
 {id:'literal-guard',truth:'NORMAL',entries:1,input:packet(pre+`export const {GET}=adapt(async request=>{const url=new URL(request.url).searchParams.get('url');if(url!=='https://example.invalid/fixed')return Response.json({ok:false});return fetch(url);});`)},
 {id:'same-name-local',truth:'NORMAL',entries:0,input:packet(`function adapt(x){return {GET:x}}${handler}export const {GET}=adapt(run);`)},
 {id:'different-package',truth:'NORMAL',entries:0,input:packet(`import {toNextJsHandler as adapt} from 'unrelated';${handler}export const {GET}=adapt(run);`)},
 {id:'not-exported',truth:'NORMAL',entries:0,input:packet(pre+handler+`const {GET}=adapt(run);`)},
 {id:'sdk-opaque',truth:'UNKNOWN',entries:2,input:packet(pre+`import {auth} from './sdk';export const {GET,POST}=adapt(auth);`,[{filePath:'app/api/sample/sdk.ts',content:`import {betterAuth} from 'better-auth';export const auth=betterAuth({});`}])},
 {id:'unknown-version',truth:'UNKNOWN',entries:0,input:packet(pre+handler+`export const {GET}=adapt(run);`,[],'2.0.0')},
 {id:'missing-version',truth:'UNKNOWN',entries:0,input:packet(pre+handler+`export const {GET}=adapt(run);`,[],'latest')},
 {id:'mutated-result',truth:'UNKNOWN',entries:0,input:packet(pre+handler+`const routes=adapt(run);routes.GET=other;export const {GET}=routes;`)},
 {id:'escaped-result',truth:'UNKNOWN',entries:0,input:packet(pre+handler+`const routes=adapt(run);change(routes);export const {GET}=routes;`)},
 {id:'dynamic-factory',truth:'UNKNOWN',entries:0,input:packet(pre+handler+`const factory=choose(adapt);export const {GET}=factory(run);`)},
 {id:'dynamic-import',truth:'UNKNOWN',entries:0,input:packet(`const {toNextJsHandler:adapt}=await import('better-auth/next-js');${handler}export const {GET}=adapt(run);`)},
 {id:'sdk-callback-not-http',truth:'UNKNOWN',entries:1,input:packet(pre+`import {betterAuth} from 'better-auth';const auth=betterAuth({callback:async request=>fetch(request.url)});export const {GET}=adapt(auth);`)},
 {id:'unsupported-adapter-method',truth:'UNKNOWN',entries:0,input:packet(pre+handler+`export const {OPTIONS}=adapt(run);`)},
 {id:'object-getter',truth:'UNKNOWN',entries:1,input:packet(pre+handler+`export const {GET}=adapt({get handler(){return run}});`)},
];
