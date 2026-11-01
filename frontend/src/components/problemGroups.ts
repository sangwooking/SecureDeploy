import type {RiskFinding,SecurityReviewResponse,Vulnerability} from '../types/securityReview';
import type {ServerFlowFinding} from '../types/serverAnalysis';
import {allRiskFindings,findingTitle,codeExplanation} from './reviewPresentation';
const indexes=new WeakMap<SecurityReviewResponse,{ids:Map<number,Vulnerability>;paths:Map<string,Vulnerability[]>}>();
function index(result:SecurityReviewResponse){let cached=indexes.get(result);if(!cached){const ids=new Map<number,Vulnerability>(),paths=new Map<string,Vulnerability[]>();for(const v of result.vulnerabilities){if(v.vulnerabilityId!=null)ids.set(v.vulnerabilityId,v);const key=JSON.stringify([v.ruleId,v.filePath]);const matches=paths.get(key);if(matches)matches.push(v);else paths.set(key,[v]);}cached={ids,paths};indexes.set(result,cached);}return cached;}
export type CodeArea='APPLICATION'|'TEST'|'UNKNOWN';
export function codeArea(path:string):{kind:CodeArea;label:string;boundary:string}{
 const p=path.replace(/\\/g,'/');const match=/(^|\/)(tests?|__tests__|fixtures?|__fixtures__|__mocks__)(\/|$)/i.exec(p);
 if(match||/(?:^|\/)[^/]+\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(p))return {kind:'TEST',label:'테스트 경로 · 운영 사용 여부 별도 확인',boundary:match?p.slice(0,match.index+match[0].length):p.replace(/[^/]+$/,'')};
 if(!/(^|\/)(node_modules|vendor|dist|build|generated)\//.test(p)&&/(^|\/)(?:src|app|pages|api|server|lib|components|supabase\/functions)\//.test(p))return {kind:'APPLICATION',label:'애플리케이션 경로 · 운영 실행 미확인',boundary:p};
 return {kind:'UNKNOWN',label:'용도 미확인',boundary:p};
}
export type ProblemItem=RiskFinding|{findingId:string;source:'FLOW';priority:ServerFlowFinding['priority'];sourceFiles:string[];advisoryId?:undefined;flow:ServerFlowFinding};
export function problemItems(result:SecurityReviewResponse):ProblemItem[]{
 const risk=allRiskFindings(result);const represented=new Set(risk.map(f=>itemVulnerability(result,f)).filter(Boolean));
 const missing=result.vulnerabilities.flatMap((v,i)=>represented.has(v)?[]:[{findingId:`legacy:${v.vulnerabilityId??i}`,source:'CODE' as const,findingCategory:'CODE' as const,vulnerabilityId:v.vulnerabilityId??null,ruleId:v.ruleId,ecosystem:null,packageName:null,version:null,advisoryId:null,sourceFiles:[v.filePath],priority:'REVIEW_REQUIRED' as const,reasonCode:'LEGACY_RULE_EVIDENCE',priorityReason:'원본 룰 근거 · 우선순위 별도 확인',dependencyFacts:null}]);
 const flows=[...(result.serverAnalysis?.validatedFindings??[]),...(result.serverAnalysis?.pythonAnalysis?.validatedFindings??[])].map(flow=>({findingId:'flow:'+flow.findingId,source:'FLOW' as const,priority:flow.priority,sourceFiles:[flow.location.filePath],flow}));
 return [...risk,...missing,...flows];
}
export function itemVulnerability(result:SecurityReviewResponse,item:ProblemItem):Vulnerability|undefined{
 if('flow' in item)return undefined;
 if(item.findingId.startsWith('legacy:')&&item.vulnerabilityId==null)return result.vulnerabilities[Number(item.findingId.slice(7))];
 const lookup=index(result);if(item.vulnerabilityId!=null)return lookup.ids.get(item.vulnerabilityId);
 const matches=[...new Set(item.sourceFiles.flatMap(path=>lookup.paths.get(JSON.stringify([item.ruleId,path]))??[]))];return matches.length===1?matches[0]:undefined;
}
export function itemTitle(result:SecurityReviewResponse,item:ProblemItem){const v=itemVulnerability(result,item);return 'flow'in item?item.flow.title:v?.ruleId==='LOCAL_STORAGE_TOKEN'?'인증 토큰 localStorage 사용':v?.ruleId==='INSECURE_API_URL'?'HTTP 주소 사용 검토':v?codeExplanation(v).title:findingTitle(result,item);}
export function itemLocation(result:SecurityReviewResponse,item:ProblemItem){const v=itemVulnerability(result,item);return 'flow'in item?{path:item.flow.location.filePath,line:item.flow.location.line}:v?{path:v.filePath,line:v.line}:{path:item.sourceFiles[0]??'',line:undefined};}
export function dependencyGroupKey(d:{ecosystem:string;packageName:string;installedVersion:string;sourceFiles:string[];fixedVersions:string[]}){
 // Different versions, manifests or fixed-version evidence never imply one safe update action.
 return JSON.stringify([d.ecosystem,d.packageName,d.installedVersion,(Array.isArray(d.sourceFiles)?[...d.sourceFiles]:[]).sort(),(Array.isArray(d.fixedVersions)?[...d.fixedVersions]:[]).sort()]);
}
export interface ProblemGroup {id:string;items:ProblemItem[];title:string;area:ReturnType<typeof codeArea>}
export function groupProblems(result:SecurityReviewResponse,items:ProblemItem[]):ProblemGroup[]{
 const map=new Map<string,ProblemGroup>();
 for(const f of items){const loc=itemLocation(result,f),v=itemVulnerability(result,f),area=codeArea(loc.path);
  const key='flow'in f?JSON.stringify(['FLOW',f.flow.ruleId,loc.path,f.flow.location.functionName,f.flow.location.kind]):f.dependency?dependencyGroupKey(f.dependency):f.source==='CODE'&&v?JSON.stringify(['CODE',v.ruleId,area.kind,area.boundary,f.reasonCode]):f.findingId;
  const found=map.get(key);if(found)found.items.push(f);else map.set(key,{id:f.findingId,items:[f],title:itemTitle(result,f),area});
 }
 const rank={APPLICATION:0,UNKNOWN:1,TEST:2};return [...map.values()].sort((a,b)=>rank[a.area.kind]-rank[b.area.kind]);
}
export function groupCounts(result:SecurityReviewResponse,groups:ProblemGroup[]){const items=groups.flatMap(g=>g.items),locations=new Set<string>();let statusRecorded=0,markedResolved=0;
 for(const item of items){const l=itemLocation(result,item);if(l.path&&l.line&&l.line>0)locations.add(`${l.path}:${l.line}`);const v=itemVulnerability(result,item);if(v?.status&&v.status!=='UNCHECKED')statusRecorded++;if(v?.status==='RESOLVED')markedResolved++;}
 return {groups:groups.length,originalItems:items.length,locations:locations.size,statusRecorded,markedResolved};
}
export interface EditContext {findingId:string;title:string;ruleId:string;path:string;line?:number;locations:{findingId:string;path:string;line?:number}[];vulnerability?:Vulnerability;flow?:ServerFlowFinding;guide:string[]}
export function editContext(result:SecurityReviewResponse,id?:string):EditContext|undefined{
 if(!id)return;const items=problemItems(result),item=items.find(f=>f.findingId===id);if(!item)return;
 const l=itemLocation(result,item),v=itemVulnerability(result,item);if(!l.path)return;
 const group=groupProblems(result,items).find(g=>g.items.some(f=>f.findingId===id));return {findingId:id,title:itemTitle(result,item),ruleId:'flow'in item?item.flow.ruleId:item.ruleId??'',...l,locations:(group?.items??[item]).flatMap(f=>f.source==='DEPENDENCY'?f.sourceFiles.map(path=>({findingId:f.findingId+':'+path,path,line:undefined})):[{findingId:f.findingId,...itemLocation(result,f)},...('flow'in f&&f.flow.ruleId==='HTTP_HTML_INPUT_FLOW'?(f.flow.evidence??[]).flatMap(e=>(e.flow??[]).filter(l=>l.kind==='HTML_FUNCTION_RETURN')).filter((l,i,a)=>!!l.filePath&&l.line>0&&a.findIndex(x=>x.filePath===l.filePath&&x.line===l.line)===i).slice(0,40).map((l,i)=>({findingId:f.findingId+':transfer:'+i,path:l.filePath,line:l.line})):[])]),vulnerability:v,flow:'flow'in item?item.flow:undefined,guide:[]};
}
