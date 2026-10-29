import { useEffect, useRef, useState } from 'react';
import { dependencyAdviceProvider, prepareDependencyAdvice, generateDependencyAdvice, getDependencyAdvice } from '../api/securityReviewApi';
import type { DependencyAdviceView, DependencyAdviceProvider } from '../types/dependencyUpdatePlan';
import type { DependencyUpdatePlans } from '../types/dependencyUpdatePlan';

export function DependencyAiAdvicePanel({reviewId,evidence,onEditDependency}:{reviewId:number;evidence:DependencyUpdatePlans;onEditDependency?:(id:string)=>void}) {
  const [provider,setProvider]=useState<DependencyAdviceProvider|null>(null),[choice,setChoice]=useState('');
  const [view,setView]=useState<DependencyAdviceView|null>(null),[consent,setConsent]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState('');
  const generation=useRef(0);
  useEffect(()=>{const current=++generation.current;setProvider(null);setView(null);setChoice('');setConsent(false);setError('');setBusy(false);
    dependencyAdviceProvider(reviewId).then(p=>{if(current===generation.current)setProvider(p);}).catch(()=>{if(current===generation.current)setError('AI Provider 상태를 확인하지 못했습니다. 근거 기반 안내는 계속 사용할 수 있습니다.');});
    return()=>{generation.current++;};
  },[reviewId,evidence.evidenceHash]);
  const perform=async(action:()=>Promise<DependencyAdviceView>)=>{
    if(busy)return;const current=generation.current;setBusy(true);setError('');setConsent(false);
    try{const next=await action();if(current===generation.current){if(next.reviewId!==reviewId||next.evidenceHash!==evidence.evidenceHash)throw Error('근거 불일치');setView(next);}}
    catch{if(current===generation.current)setError('AI 요청을 완료하거나 응답을 확인하지 못했습니다. 자동 재시도하지 않습니다. 기존 요청 상태를 먼저 확인하세요.');}
    finally{if(current===generation.current)setBusy(false);}
  };
  const eligible=evidence.plans.map((p,index)=>({p,index})).filter(({p})=>p.ecosystem==='NPM'&&p.packageManagerEvidence==='NPM_LOCK_OBSERVED_VERSION_UNVERIFIED'&&p.sameMajorCandidates.length&&p.locations.some(l=>l.confirmed));
  const states:Record<string,string>={APPROVAL_REQUIRED:'전송 동의 대기',GENERATING:'응답 생성 중',GENERATED:'응답 검증 통과 · 수정 미적용',NEEDS_REVIEW:'AI도 추가 검토 필요',INVALID:'허용 범위를 벗어난 응답 거부',FAILED:'생성 실패'};
  return <section aria-label="AI 의존성 수정 방향" className="dependency-ai-advice">
    <h3>AI에게 수정 방향 물어보기</h3>
    <p>제안은 15분 동안 임시 보관되며 서버 재시작 시 사라집니다. 원본 분석 이력은 변경하지 않습니다.</p>
    <p>아래 검증된 분석 사실을 바꾸지 않는 별도 AI 의견입니다. 후보 버전과 근거를 서버가 대조하며, 원본 수정·lockfile 생성·승인을 자동 수행하지 않습니다.</p>
    {!provider?.available?<p>AI Provider가 비활성화되어 있거나 준비되지 않았습니다. 기존 근거 기반 한국어 안내를 사용할 수 있습니다.</p>:<p>Provider: {provider.name} · 모델: {provider.model} · {provider.origin==='MOCK'?'Mock 통제 응답 · 실제 모델 미검증':provider.origin==='OPENAI'?'OpenAI API 연결 설정 · 요청 시 비용 발생 가능':'Provider 출처 미검증'}</p>}
    <label>AI 수정 방향을 요청할 공지<select value={choice} disabled={busy||!provider?.available} onChange={e=>{setChoice(e.target.value);setView(null);setConsent(false);}}><option value="">항목 선택</option>{eligible.map(({p,index})=><option key={index} value={index}>{p.packageName}@{p.lockedVersion} · {p.advisoryId}</option>)}</select></label>
    {!eligible.length&&<p>정확한 npm 잠금 버전·선언 경로·동일 major 수정 후보를 연결할 수 있는 항목이 없습니다.</p>}
    <button type="button" className="secondary-button" disabled={busy||!provider?.available||choice===''} onClick={()=>void perform(()=>prepareDependencyAdvice(reviewId,evidence.evidenceHash,Number(choice)))}>AI 전송 범위 확인</button>
    {error&&<p role="alert">{error}</p>}
    {view&&<>
      <h4>{states[view.state]??view.state}</h4><p>{view.message}</p>
      <p>검토 상태: REVIEW_REQUIRED · 호환성: NOT_VERIFIED · 실제 적용 Patch 없음</p>
      {view.state==='APPROVAL_REQUIRED'&&<>
        <p>전송할 공개 메타데이터입니다. 비공개 프로젝트명·파일 경로·소스는 포함하지 않습니다.</p><pre>{view.transmittedData}</pre>
        <label><input type="checkbox" checked={consent} disabled={busy} onChange={e=>setConsent(e.target.checked)}/>이 메타데이터의 외부 전송과 API 비용 발생 가능성에 동의합니다.</label>
        <button type="button" className="primary-button" disabled={busy||!consent||!view.provider.available} onClick={()=>void perform(()=>generateDependencyAdvice(reviewId,view.id,view.evidenceHash))}>동의한 근거로 AI 수정 방향 생성</button>
      </>}
      {busy&&<p role="status">요청을 처리 중입니다. 파일은 변경하지 않습니다.</p>}
      <button type="button" className="secondary-button" disabled={busy} onClick={()=>void perform(()=>getDependencyAdvice(reviewId,view.id))}>기존 요청 상태 확인</button>
      {view.output&&<div className="dependency-ai-result">
        <p>{view.provider.origin==='MOCK'?'Mock 생성 의견 · 실제 AI 품질 미검증':view.provider.origin==='OPENAI'?'OpenAI Provider 응답 · 구조·근거 대조 통과 · 품질은 별도 검토':'출처 미검증 Provider 의견'}</p>
        {view.state==='GENERATED'&&onEditDependency&&<button type="button" onClick={()=>onEditDependency(view.id)}>Workspace에서 수정 파일 제안 준비</button>}
        <h4>검증된 분석 사실</h4><p>{view.output.packageName}@{view.output.lockedVersion} · {view.output.advisoryId}</p>
        <p>서버가 허용한 검토 후보: {view.output.candidateVersion||'추가 검토 필요'}</p>
        <h4>무슨 문제인가요? · AI 의견</h4><p>{view.output.explanation}</p>
        <h4>왜 중요한가요? · AI 의견</h4><p>{view.output.whyItMatters}</p>
        <h4>가능한 영향 · 미확인 의견</h4><p>{view.output.possibleImpact}</p>
        <h4>권장 수정 방향 · AI 의견</h4><p>{view.output.recommendedAction}</p>
        <h4>수정 후 확인할 일</h4><ul>{view.output.verificationSteps.map((s,i)=><li key={i}>{s}</li>)}</ul>
        <h4>불확실한 부분</h4><ul>{view.output.uncertainties.map((s,i)=><li key={i}>{s}</li>)}</ul>
        <p>실제 파일 위치는 위의 서버 분석 근거를 따릅니다. 패키지 관리자의 잠금 파일 생성과 Workspace Diff·승인·다운로드·재검사가 별도로 필요합니다. AI 의견만으로 해결 완료를 선언하지 않습니다.</p>
      </div>}
    </>}
  </section>;
}
