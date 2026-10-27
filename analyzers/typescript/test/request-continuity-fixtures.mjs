// Frozen before implementation. Same-author Grade B, not upstream vulnerabilities.
const file=(filePath,content)=>({filePath,content});
const manifest=[{filePath:'package.json',next:'15.2.4'}];
const wrapper=`export const wrap=(handler)=>async(request)=>handler(request);`;
const url=`new URL(request.url).searchParams.get('url')`;
const risky=`async(request)=>fetch(${url})`;
const safe=`async(request)=>fetch('https://example.invalid/status')`;
const route=code=>file('app/api/task/route.ts',code);
const helper=code=>file('lib/wrap.ts',code);
const setup=(id,truth,code,extra=[],rule='TS_SSRF_INPUT_FLOW')=>({id,truth,rule,input:{nodeManifests:manifest,
 files:[route(code),...extra]}});
export const continuityCases=[
 setup('direct','DANGEROUS',`export const GET=${risky};`),
 setup('local-wrapper','DANGEROUS',`${wrapper}export const GET=wrap(${risky});`),
 setup('imported-wrapper','DANGEROUS',`import {wrap} from '../../../lib/wrap';export const GET=wrap(${risky});`,[helper(wrapper)]),
 setup('two-wrappers','DANGEROUS',`${wrapper}export const GET=wrap(wrap(${risky}));`),
 setup('imported-handler','DANGEROUS',`${wrapper}import {handler} from '../../../lib/handler';export const GET=wrap(handler);`,[file('lib/handler.ts',`export const handler=${risky};`)]),
 setup('reexported-handler','DANGEROUS',`${wrapper}import {handler} from '../../../lib/api';export const GET=wrap(handler);`,[file('lib/api.ts',`export {handler} from './handler';`),file('lib/handler.ts',`const handler=${risky};export {handler};`)]),
 setup('argument-order','DANGEROUS',`const wrap=(first,second)=>async(request)=>second(request);export const GET=wrap(${safe},${risky});`),
 setup('helper-return','DANGEROUS',`${wrapper}function extract(request){return ${url};}export const GET=wrap(async(request)=>fetch(extract(request)));`),
 setup('object-argument','DANGEROUS',`const wrap=(handler)=>async(request)=>handler({request});export const GET=wrap(async({request})=>fetch(${url}));`),
 setup('secret-response','DANGEROUS',`${wrapper}export const GET=wrap(async(request)=>Response.json({ok:true,diagnostic:process.env.SERVICE_ROLE_KEY}));`,[],'TS_SENSITIVE_DATA_EXPOSURE'),
 setup('fixed-fetch','NORMAL',`${wrapper}export const GET=wrap(${safe});`),
 setup('unused-request','NORMAL',`const wrap=(handler)=>async(request)=>handler('https://example.invalid/fixed');export const GET=wrap(async(value)=>fetch(value));`),
 setup('other-handler','NORMAL',`const wrap=(first,second)=>async(request)=>first(request);export const GET=wrap(${safe},${risky});`),
 setup('early-return','NORMAL',`const wrap=(handler)=>async(request)=>{if(true)return Response.json({ok:true});return handler(request);};export const GET=wrap(${risky});`),
 setup('internal-secret','NORMAL',`${wrapper}export const GET=wrap(async(request)=>{const key=process.env.SERVICE_ROLE_KEY;return Response.json({ok:true});});`,[],'TS_SENSITIVE_DATA_EXPOSURE'),
 setup('literal-branch','NORMAL',`const wrap=(handler)=>async(request)=>{if(false)return handler(request);return Response.json({ok:true});};export const GET=wrap(${risky});`),
 setup('numeric-conversion','NORMAL',`${wrapper}export const GET=wrap(async(request)=>Response.json({value:Number(${url})}));`),
 setup('no-source','NORMAL',`${wrapper}export const GET=wrap(async(request)=>Response.json({ok:true}));`),
 setup('unknown-wrapper','UNKNOWN',`import {wrap} from 'uninspected-middleware';export const GET=wrap(${risky});`),
 setup('side-effect-factory','UNKNOWN',`const wrap=(handler)=>{uninspected();return async(request)=>handler(request);};export const GET=wrap(${risky});`),
 setup('async-factory','UNKNOWN',`const wrap=async(handler)=>async(request)=>handler(request);export const GET=wrap(${risky});`),
 setup('multiple-targets','UNKNOWN',`${wrapper}const first=${risky};const second=${safe};export const GET=wrap(external?first:second);`),
 setup('mutable-wrapper','UNKNOWN',`let wrap=(handler)=>async(request)=>handler(request);wrap=external;export const GET=wrap(${risky});`),
 setup('unknown-sanitizer','UNKNOWN',`${wrapper}export const GET=wrap(async(request)=>fetch(sanitize(${url})));`),
 setup('conditional-execution','UNKNOWN',`const wrap=(handler)=>async(request)=>{if(external)return handler(request);return Response.json({ok:true});};export const GET=wrap(${risky});`),
 setup('recursive-handler','UNKNOWN',`${wrapper}function handler(request){return handler(request);}export const GET=wrap(handler);`),
];
