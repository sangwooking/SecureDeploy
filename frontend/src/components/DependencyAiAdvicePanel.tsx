import {AiRequestDisclosure} from './AiRequestDisclosure';
import { ApiRequestError, requestProblem } from '../api/requestProblem';
import { useEffect, useRef, useState } from 'react';
import { dependencyAdviceProvider, prepareDependencyAdvice, generateDependencyAdvice, getDependencyAdvice } from '../api/securityReviewApi';
import type { DependencyAdviceView, DependencyAdviceProvider, DependencyUpdatePlans } from '../types/dependencyUpdatePlan';
import { providerOriginLabel, providerSetupLabel } from './EvidenceSupportLayout';

export function DependencyAiAdvicePanel({reviewId,evidence,onEditDependency,selectedIndex}:{reviewId:number;evidence:DependencyUpdatePlans;onEditDependency?:(id:string)=>void;selectedIndex?:number}) {
 const [provider,setProvider]=useState<DependencyAdviceProvider|null>(null),[choice,setChoice]=useState(''),[requestId,setRequestId]=useState('');
 const [view,setView]=useState<DependencyAdviceView|null>(null),[consent,setConsent]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState('');
 const generation=useRef(0);
 useEffect(()=>{const current=++generation.current;setProvider(null);setView(null);setChoice(selectedIndex!=null&&selectedIndex>=0?String(selectedIndex):'');setConsent(false);setError('');setBusy(false);setRequestId('');
  dependencyAdviceProvider(reviewId).then(p=>{if(current===generation.current)setProvider(p);}).catch(()=>{if(current===generation.current)setError('AI Provider 상태를 확인하지 못했습니다. 근거 기반 안내는 계속 사용할 수 있습니다.');});return()=>{generation.current++;};
 },[reviewId,evidence.evidenceHash,selectedIndex]);
 const perform=async(action:()=>Promise<DependencyAdviceView>)=>{
  if(busy)return;const current=generation.current;setBusy(true);setError('');setConsent(false);
  try{const next=await action();if(current===generation.current){if(next.reviewId!==reviewId||next.evidenceHash!==evidence.evidenceHash||(selectedIndex!=null&&next.planIndex!==selectedIndex))throw Error('근거 불일치');setView(next);setRequestId(next.id);}}
  catch(e){if(current===generation.current)setError(e instanceof ApiRequestError?requestProblem(e,'AI 제안').message:'응답의 분석 근거를 확인하지 못했어요. 기존 요청 상태를 확인해 주세요. 자동 재시도하지 않습니다.');}finally{if(current===generation.current)setBusy(false);}
 };
 const eligible=evidence.plans.map((p,index)=>({p,index})).filter(({p,index})=>(selectedIndex==null||index===selectedIndex)&&p.ecosystem==='NPM'&&p.packageManagerEvidence==='NPM_LOCK_OBSERVED_VERSION_UNVERIFIED'&&p.sameMajorCandidates.length&&p.locations.some(l=>l.confirmed));
 const states:Record<string,string>={APPROVAL_REQUIRED:'전송 동의 대기',GENERATING:'응답 생성 중',GENERATED:'응답 검증 통과 · 수정 미적용',NEEDS_REVIEW:'AI도 추가 검토 필요',INVALID:'허용 범위를 벗어난 응답 거부',FAILED:'생성 실패'};
 return <section aria-label="AI 의존성 수정 방향" className="dependency-ai-advice">
  <h3>AI 수정 제안</h3>
  <p className="advice-boundary">분석 결과와 별도의 AI 의견입니다. 제안만으로 파일·위험 평가·안전 판정은 바뀌지 않습니다.</p>
  <p className="provider-origin">{provider?providerSetupLabel(provider.origin,provider.name):'Provider 상태 확인 중'}{provider?.model&&<span> · {provider.model}</span>}</p>
  {provider&&!provider.available&&<p role="note">{provider.unavailableReason==='WORKSPACE_ONLY'
   ?'현재 실제 AI 호출은 승인된 코드 수정에만 허용됩니다. 라이브러리 수정은 아래 공지와 업데이트 근거로 검토하세요.'
   :'AI 제안을 사용할 수 없습니다. 아래 근거 기반 안내를 확인하세요.'}</p>}
  <div className="advice-request-controls"><label>AI 수정 방향을 요청할 공지<select value={choice} disabled={busy||!provider?.available} onChange={e=>{setChoice(e.target.value);setView(null);setConsent(false);}}><option value="">항목 선택</option>{eligible.map(({p,index})=><option key={index} value={index}>{p.packageName}@{p.lockedVersion} · {p.advisoryId}</option>)}</select></label>
   <button type="button" className="secondary-button" disabled={busy||!provider?.available||choice===''||!eligible.some(e=>String(e.index)===choice)} onClick={()=>void perform(()=>prepareDependencyAdvice(reviewId,evidence.evidenceHash,Number(choice)))}>AI 전송 범위 확인</button></div>
  {!eligible.length&&<p>저장된 계획에 정확한 npm 잠금 버전·확인된 선언 경로·동일 major 수정 후보를 모두 연결할 수 있는 항목이 없습니다. AI 요청을 비활성화했습니다. 별도 공식 메타데이터 조회는 원본 계획을 자동 변경하지 않습니다. 원문 공지에 따른 수동 수정 또는 새 기준 검사를 이용하세요.</p>}
  {error&&<p role="alert">{error}</p>}
  {view&&<div className="advice-response">
   <p className="source-label source-label-advice">{providerOriginLabel(view.provider.origin,view.provider.name)}</p>
   <h4>{states[view.state]??'요청 상태 확인 필요'}</h4><p>{view.message}</p>
   {view.provider.origin==='ARCHIVED_OPENAI'&&<p className="review-caution">과거 검증 기록의 재표시입니다. 이번 화면에서 모델 호출·새 수정·재검사를 수행한 결과가 아닙니다.</p>}
   {view.state==='APPROVAL_REQUIRED'&&<><p>전송할 공개 메타데이터입니다. 비공개 프로젝트명·파일 경로·소스는 포함하지 않습니다.</p><pre>{view.transmittedData}</pre><AiRequestDisclosure task="라이브러리 수정 방향 제안" scope="공개 패키지·잠금 버전·보안 공지·서버가 검증한 수정 후보 메타데이터만 전송합니다."/><label className="consent-control"><input type="checkbox" checked={consent} disabled={busy} onChange={e=>setConsent(e.target.checked)}/>이 메타데이터의 외부 전송과 API 비용 발생 가능성에 동의합니다.</label><button type="button" className="primary-button" disabled={busy||!consent||!view.provider.available} onClick={()=>void perform(()=>generateDependencyAdvice(reviewId,view.id,view.evidenceHash))}>동의한 근거로 AI 수정 방향 생성</button></>}
   {busy&&<p role="status">요청을 처리 중입니다. 파일은 변경하지 않습니다.</p>}
   <button type="button" className="text-action" disabled={busy} onClick={()=>void perform(()=>getDependencyAdvice(reviewId,view.id))}>기존 요청 상태 확인</button>
   <DependencyAdviceResult view={view} onEditDependency={onEditDependency} archived={view.provider.origin==='ARCHIVED_OPENAI'}/>
  </div>}
  <details className="restore-advice"><summary>기존 AI 제안 불러오기</summary><p>같은 분석 근거의 유효한 요청 ID만 조회합니다. 새 모델을 호출하지 않습니다. 만료된 요청은 복원되지 않습니다.</p><label>AI 제안 요청 ID<input value={requestId} maxLength={80} disabled={busy} onChange={e=>setRequestId(e.target.value)}/></label><button type="button" className="secondary-button" disabled={busy||!requestId.trim()} onClick={()=>void perform(()=>getDependencyAdvice(reviewId,requestId.trim()))}>저장된 제안 조회</button></details>
 </section>;
}

export function adviceLead(value:string) {
 const boundary=value.search(/[.!?。](?:\s|$)/);return boundary<0?value:value.slice(0,boundary+1);
}
export function DependencyAdviceResult({view,onEditDependency,archived=false}:{view:DependencyAdviceView;onEditDependency?:(id:string)=>void;archived?:boolean}) {
return view.output&&['GENERATED','NEEDS_REVIEW'].includes(view.state)?<div className="dependency-ai-result">
    {archived&&<p className="archive-notice" role="note">과거 OpenAI 검증 기록의 재표시 · 새 모델 호출 없음</p>}
    <h4>검증된 분석 사실</h4><p><strong>{view.output.packageName} {view.output.lockedVersion}</strong></p>
    {view.output.decision==='PROPOSE_UPDATE'&&view.output.candidateVersion?<div className="version-proposal"><span>서버가 허용한 검토 후보</span><strong>{view.output.candidateVersion}</strong><small>공지·버전 근거 검증 · 호환성은 아직 확인하지 않았어요</small></div>:<p>적용 가능한 업데이트 버전은 추가 확인이 필요합니다.</p>}
    <h4>AI 수정 조언 · 사실 여부 미검증</h4><p className="advice-reason">{adviceLead(view.output.explanation)}</p>
    <h4>어떻게 수정하나요?</h4><p>{adviceLead(view.output.recommendedAction)}</p>
    <h4>수정 후 확인할 일</h4><ul>{view.output.verificationSteps.map((s,i)=><li key={i}>{s}</li>)}</ul>
    <details><summary>AI 원문·영향·불확실성과 원본 상태</summary><p>{view.output.explanation}</p><p>{view.output.whyItMatters}</p><p>{view.output.recommendedAction}</p><p>{view.output.possibleImpact}</p><ul>{view.output.uncertainties.map((s,i)=><li key={i}>{s}</li>)}</ul><p>{view.output.advisoryId} · {view.state} · {view.reviewStatus} · {view.compatibility} · 모델 품질 {view.modelQuality}</p><p>검토 상태: REVIEW_REQUIRED · 호환성: NOT_VERIFIED · 실제 적용 Patch 없음</p><p>제안은 15분 동안 임시 보관되며 서버 재시작 시 사라집니다. 원본 분석 이력은 변경하지 않습니다.</p></details>
    <p className="advice-handoff">npm이 파일을 생성하고 사용자가 Diff를 승인합니다. AI가 lockfile을 직접 작성하지 않습니다.</p>
    {view.state==='GENERATED'&&view.output.decision==='PROPOSE_UPDATE'&&!!view.output.candidateVersion&&onEditDependency&&view.provider.origin!=='ARCHIVED_OPENAI'&&<button type="button" className="primary-button" onClick={()=>onEditDependency(view.id)}>Workspace에서 수정 파일 제안 준비</button>}
   </div>:null;
}
