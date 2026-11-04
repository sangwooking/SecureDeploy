import {useEffect,useRef,useState} from 'react';
import {prepareNpmTreePlan,generateNpmTreePlan,applyNpmTreePlan} from '../api/editingApi';
import type {EditingWorkspace,NpmTreePlan} from '../api/editingApi';
import {fetchDependencyUpdatePlans,getDependencyAdvice} from '../api/securityReviewApi';
import type {DependencyUpdatePlans} from '../types/dependencyUpdatePlan';
import type {SecurityReviewResponse} from '../types/securityReview';
import {allRiskFindings} from './reviewPresentation';
import {requestProblem} from '../api/requestProblem';
import {PatchDiff} from './PatchDiff';
export function treePlanGroups(plans:DependencyUpdatePlans['plans']) {return plans.flatMap((p,i)=>p.ecosystem==='NPM'&&!plans.slice(0,i).some(q=>q.ecosystem===p.ecosystem&&q.packageName===p.packageName&&q.lockedVersion===p.lockedVersion)?[{index:i,label:`${p.packageName}@${p.lockedVersion}`}]:[]);}
export function selectedTreePlan(result:SecurityReviewResponse,id:string|undefined,plans:DependencyUpdatePlans['plans']) {const selected=allRiskFindings(result).find(f=>f.findingId===id&&f.source==='DEPENDENCY');if(!selected)return '';const index=plans.findIndex(p=>p.ecosystem===selected.ecosystem&&p.packageName===selected.packageName&&p.lockedVersion===selected.version&&[p.advisoryId,...p.aliases].some(a=>a.toUpperCase()===selected.advisoryId?.toUpperCase()));if(index<0)return '';const first=plans.findIndex(p=>p.ecosystem===plans[index].ecosystem&&p.packageName===plans[index].packageName&&p.lockedVersion===plans[index].lockedVersion);return String(first);}
export function NpmTreePlanPanel({workspace,result,findingId,advice,initialAdviceId,disabled,onApplied}:{workspace:EditingWorkspace;result:SecurityReviewResponse;findingId?:string;advice?:{id:string;index:number};initialAdviceId?:string;disabled:boolean;onApplied:(w:EditingWorkspace)=>Promise<void>}) {
 const planIndex=advice?.index;
 const adviceId=advice?.id??initialAdviceId;
 const [plans,setPlans]=useState<DependencyUpdatePlans|null>(null),[selection,setSelection]=useState(''),[proposal,setProposal]=useState<NpmTreePlan|null>(null),[exec,setExec]=useState(false),[approve,setApprove]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState('');const generation=useRef(0);
 useEffect(()=>{
   const current=++generation.current;
   setProposal(null);setExec(false);setApprove(false);setError('');setSelection('');setPlans(null);setBusy(false);
   const reviewId=result.reviewId;
   if(reviewId) void (async()=>{
     try{
       const value=await fetchDependencyUpdatePlans(reviewId);
       let index=planIndex;
       if(adviceId){
         const saved=await getDependencyAdvice(reviewId,adviceId);
         if(saved.reviewId!==reviewId||saved.evidenceHash!==value.evidenceHash
             ||saved.state!=='GENERATED'||saved.output?.decision!=='PROPOSE_UPDATE'
             ||!saved.output.candidateVersion||!value.plans[saved.planIndex]
             ||(index!=null&&index!==saved.planIndex)){
           throw new Error('현재 검사에 사용할 수 있는 검증된 AI 버전 후보가 없습니다.');
         }
         index=saved.planIndex;
       }
       if(current===generation.current){setPlans(value);setSelection(index!=null?String(index):selectedTreePlan(result,findingId,value.plans));}
     }catch(e){
       if(current===generation.current)setError(e instanceof Error?e.message:'AI 제안을 확인할 수 없습니다. 현재 검사에서 다시 제안받으세요.');
     }
   })();
   return()=>{generation.current++;};
 },[workspace.id,workspace.revision,result.reviewId,findingId,adviceId,planIndex]);
 const run=async(action:()=>Promise<void>)=>{if(busy||disabled)return;setBusy(true);setError('');try{await action();}catch(e){setError(requestProblem(e,'의존성 수정안').message);}finally{setBusy(false);}};
 if(workspace.changedFileIds?.length) return <section aria-label="의존성 트리 업데이트 수정안" className="workspace-automation"><p>이미 저장한 변경이 있습니다. 변경 검토·승인에서 Diff를 확인하고 다운로드·재검사를 이어가세요. 새 자동 수정안은 변경 없는 검증된 원본에서만 만들 수 있습니다.</p></section>;
 return <section aria-label="의존성 트리 업데이트 수정안" className="workspace-automation"><h3>업데이트 수정안 만들기</h3><p>{adviceId?'검증된 AI 버전 후보와 일치하는 잠금 파일만 제안합니다. 파일 생성과 안전성 검사는 npm과 서버가 담당합니다.':'AI 없이 확인된 잠금 경로의 상위 패키지를 먼저 검토합니다.'} npm v3·단일 루트·하나의 상위 선언만 지원하며, 미지원 구조는 수동 검토로 남깁니다.</p>
 {!adviceId&&<label>수정할 라이브러리<select value={selection} disabled={disabled||busy||!!proposal} onChange={e=>setSelection(e.target.value)}><option value="">문제를 선택하세요</option>{treePlanGroups(plans?.plans??[]).map(p=><option key={p.index} value={p.index}>{p.label}</option>)}</select></label>}
 {!proposal&&<button type="button" disabled={disabled||busy||selection===''} onClick={()=>void run(async()=>{const g=generation.current;const p=await prepareNpmTreePlan(workspace,Number(selection),adviceId);if(g===generation.current)setProposal(p);})}>업데이트 수정안 만들기</button>}
 {proposal&&<><p role="status">{proposal.message}</p><p>생성 방식: {adviceId?'AI 검토 후보 · npm 파일 생성 및 서버 검증':'결정적 의존성 그래프 · AI 호출 없음'} · 호환성 {proposal.compatibility}</p><p>대상: {proposal.packageName}@{proposal.lockedVersion} · 상위 선언 {proposal.rootPackage??'미확인'} {proposal.fromRootVersion??''}{proposal.candidateVersion?` → ${proposal.candidateVersion}`:''}</p>
 <p>기존 선언 범위: {proposal.declaredRange??'미확인'}{proposal.withinDeclaredRange===false?' · 기존 선언 범위를 변경하는 후보입니다. Diff에서 새 정확 버전을 확인하세요.':''}</p>
 {proposal.state==='EXECUTION_CONSENT_REQUIRED'&&<><p>전송 범위: 공개 패키지명·버전·의존성 메타데이터. 소스 코드·비밀값은 보내지 않습니다. 네트워크가 차단된 비특권 컨테이너에서 설치 스크립트를 차단한 npm 잠금 생성을 실행합니다. 필요한 공개 registry 메타데이터만 서버가 중개하며 호스트 실행으로 대체하지 않습니다.</p><label><input type="checkbox" checked={exec} onChange={e=>setExec(e.target.checked)} disabled={disabled||busy}/>공개 registry·OSV 조회와 스크립트 없는 npm 실행에 동의합니다.</label><button type="button" disabled={disabled||busy||!exec} onClick={()=>void run(async()=>{const g=generation.current;const p=await generateNpmTreePlan(workspace,proposal);if(g===generation.current)setProposal(p);})}>{busy?'의존성 트리 검증 중…':'동의하고 수정안 검증'}</button></>}
 {proposal.state==='PROPOSED'&&<><p>동일 OSV 자료의 공지 매칭: {proposal.beforeAdvisoryItems} → {proposal.afterAdvisoryItems}. 원본 위험 경로 {proposal.affectedPaths.length}곳, 잔존 경로 {proposal.remainingPaths.length}곳. 전체 안전성의 증명은 아닙니다.</p>{proposal.differences.map(d=><div key={d.path}><h4>{d.path}</h4><PatchDiff patch={d.patch}/></div>)}<label><input type="checkbox" checked={approve} onChange={e=>setApprove(e.target.checked)} disabled={disabled||busy}/>두 파일의 Diff와 앱 호환성 미검증 상태를 확인하고 Workspace 적용을 승인합니다.</label><button type="button" disabled={disabled||busy||!approve} onClick={()=>void run(async()=>{const g=generation.current;const next=await applyNpmTreePlan(workspace,proposal);if(g===generation.current)await onApplied(next);})}>승인한 수정안을 Workspace에 적용</button></>}
 {['MANUAL_REVIEW','PARTIAL'].includes(proposal.state)&&<p>원본 파일은 바뀌지 않았습니다. 수정 가이드를 참고해 상위 패키지·peer·optional 조건과 제한 override의 필요성을 수동으로 확인하세요.</p>}
 <details><summary>잠금 경로·후보 검증 근거</summary><ul>{proposal.affectedPaths.map(p=><li key={p}>{p}</li>)}</ul><ul>{proposal.attempts.map((p,i)=><li key={i}>{p.root} {p.version} · {p.outcome}</li>)}</ul><p>npm {proposal.npmVersion??'실행 전'} · Node {proposal.nodeVersion??'미기록'} · 격리 작업 {proposal.executionId??'미기록'} · 근거 해시 {proposal.evidenceHash??'검증 전'}</p></details></>}
 {error&&<p role="alert">{error}</p>}</section>;
}
