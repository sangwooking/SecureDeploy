import { useUiCapabilities } from './useUiCapabilities';
import { requestProblem } from '../api/requestProblem';
import type { DependencyVulnerability } from '../types/securityReview';
import { DependencyAiAdvicePanel } from './DependencyAiAdvicePanel';
import { useEffect, useRef, useState } from 'react';
import { fetchDependencyUpdatePlans } from '../api/securityReviewApi';
import type { DependencyUpdatePlans as Plans } from '../types/dependencyUpdatePlan';

const kind: Record<string,string> = { DIRECT:'직접 의존성', TRANSITIVE:'간접 의존성', MIXED:'직접·간접 경로 혼재', UNKNOWN:'직접·간접 미확인' };
export function sameDependencyAdvisory(dep:DependencyVulnerability,plan:Plans['plans'][number]) {
 if(dep.ecosystem!==plan.ecosystem||dep.packageName!==plan.packageName||dep.installedVersion!==plan.lockedVersion)return false;
 const ids=new Set([dep.osvId,...dep.aliases].map(x=>x.toUpperCase()));return [plan.advisoryId,...plan.aliases].some(x=>ids.has(x.toUpperCase()));
}
export function DependencyUpdatePlans({reviewId,onEditDependency,selectedDependency,onEditFile}: {reviewId?:number|null;selectedDependency?:DependencyVulnerability;onEditDependency?:(id:string)=>void;onEditFile?:(path:string)=>void}) {
  const cap=useUiCapabilities();
  const [problem,setProblem]=useState<ReturnType<typeof requestProblem>|null>(null);
  const [result,setResult]=useState<Plans|null>(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);
  const generation=useRef(0);
  useEffect(()=>{generation.current++;setResult(null);setError('');setBusy(false);return()=>{generation.current++;};},[reviewId]);
  const load=async(force=false)=>{
    if(!reviewId||busy&&!force)return;
    const current=generation.current;setBusy(true);setError('');setProblem(null);
    try {const value=await fetchDependencyUpdatePlans(reviewId);if(current===generation.current&&value.reviewId===reviewId)setResult(value);}
    catch(e) {if(current===generation.current){const p=requestProblem(e,'업데이트 계획');setProblem(p);setError(p.message);}}
    finally {if(current===generation.current)setBusy(false);}
  };
  useEffect(()=>{if(reviewId&&cap.value?.dependencyPlans)void load(true);},[reviewId,cap.value?.dependencyPlans]);
  const matching=result?.plans.flatMap((p,i)=>selectedDependency&&sameDependencyAdvisory(selectedDependency,p)?[i]:[])??[];
  const selectedIndex=matching.length===1?matching[0]:-1;
  const shownPlans=result?.plans.filter((_,i)=>!selectedDependency||i===selectedIndex)??[];
  return <section className="dependency-update-plans" aria-label="근거 기반 의존성 수정 검토">
    <h3>업데이트 방법 확인</h3>
    <p>현재 버전 → 공지의 수정 경계를 대조한 뒤 선언·잠금 파일과 호환성을 확인합니다. 실제 변경 생성은 Workspace에서 지원 계약을 확인한 경우에만 제공합니다. AI 코드 생성이나 적용 완료를 의미하지 않습니다.</p>
    <p className="source-label">근거 기반 안내 · AI 제안과 구분</p>
    {selectedDependency&&selectedDependency.ecosystem==='NPM'&&!selectedDependency.sourceFiles.includes('package-lock.json')&&<p role="note">이 항목은 루트 package-lock.json 계약으로 확인되지 않았습니다. 중첩 프로젝트·다른 잠금 형식의 npm 파일 자동 생성은 지원하지 않으며 실제 선언 위치에서 수동 업데이트를 검토하세요.</p>}
    {selectedDependency&&<><p>{selectedDependency.packageName} {selectedDependency.installedVersion}에 연결된 공지와 상위 의존성을 확인하고, 패키지 관리자로 변경 파일을 생성한 뒤 호환성을 검증하세요.</p><p>공지의 수정 버전은 AI 추천이나 프로젝트 전체의 안전한 버전을 의미하지 않습니다.</p></>}
    {selectedDependency&&onEditFile&&selectedDependency.sourceFiles[0]&&<button type="button" className="primary-button" onClick={()=>onEditFile(selectedDependency.sourceFiles[0])}>{cap.value?.npmTreePlans&&selectedDependency.ecosystem==='NPM'&&selectedDependency.sourceFiles.includes('package-lock.json')?'업데이트 수정안 만들기':'수정 작업으로 이동'}</button>}
    {!reviewId?<p>저장된 검사에서 업데이트 근거를 확인할 수 있어요.</p>:cap.loading||busy?<p role="status">업데이트 계획 지원 확인 중…</p>:!cap.value?.dependencyPlans?<p role="note">{cap.problem?.message??'현재 서버에서 업데이트 계획을 지원하지 않아요.'} 수동으로 수정할 수 있습니다.</p>:null}
    {error&&<p role="alert">{error}</p>}{problem?.retryable&&<button type="button" disabled={busy} onClick={()=>void load()}>업데이트 근거 다시 확인</button>}
    {result&&<>
      <details><summary>근거 기반 계획의 지원 범위</summary><p>기본 계획: 근거 기반 안내 · 호환성: 미검증 · 적용 가능 Patch: 없음</p><p>잠금 파일 재생성과 원본 파일 해시 검증 전까지 검토 필요 상태를 유지합니다.</p></details>
      {reviewId&&cap.value?.dependencyAdvice&&cap.value?.providerAvailable&&<DependencyAiAdvicePanel reviewId={reviewId} evidence={result} onEditDependency={onEditDependency} selectedIndex={selectedDependency?selectedIndex:undefined} />}
      {!result.plans.length&&<p>이 저장 결과에는 업데이트 계획으로 연결할 보안 공지가 없습니다. 전체 안전을 의미하지 않습니다.</p>}
      {selectedDependency&&selectedIndex===-1&&<p role="note">이 공지에 연결된 업데이트 근거가 없거나 여러 계획과 겹칩니다. 다른 공지의 AI 의견을 대신 표시하지 않습니다.</p>}
      {cap.value?.npmIsolation?.state==='UNAVAILABLE'?<p role="note">{cap.value.npmIsolation.message}</p>:!cap.value?.providerAvailable&&!cap.value?.npmTreePlans&&<p>AI Provider 설정이 필요해요. 아래 근거 기반 계획과 수동 수정을 이용할 수 있습니다.</p>}
      {shownPlans.map((p,i)=><details key={`${p.ecosystem}:${p.packageName}:${p.lockedVersion}:${p.advisoryId}:${i}`}>
        <summary>{p.packageName}@{p.lockedVersion} → {p.sameMajorCandidates.join(', ')||'같은 major 후보 미확인'} · {p.advisoryId} · 적용 가능 미확인</summary>
        <h4>확인된 근거</h4><p>{p.explanation}</p>
        <p>{kind[p.dependencyKind]??kind.UNKNOWN} · 버전 근거: {p.sourceFiles.join(', ')||'미확인'}</p>
        <p>이 공지에 기록된 수정 버전: {p.fixedVersionEvidence.join(', ')||'확인되지 않음'}</p>
        <p>동일 major 검토 후보: {p.sameMajorCandidates.join(', ')||'확인되지 않음'} · 호환성 검증 전 추천 버전으로 확정하지 않습니다.</p>
        {p.locations.map((l,j)=><p key={j}><code>{l.file}:{l.line}</code> · {l.section} · {l.parentPackage} {l.declaredVersion} · {l.confirmed?'선언 확인':'선언 미확인'}{l.peer?' · peer 조건 확인 필요':''}</p>)}
        <h4>수정 후 확인할 일</h4><ol>{p.verificationSteps.map((s,j)=><li key={j}>{s}</li>)}</ol>
        <h4>미확인 사항</h4><ul>{p.unknowns.map((s,j)=><li key={j}>{s}</li>)}</ul>
        <p>공지 수정 시각: {p.advisoryModified||'미기록'} · 패키지 관리자 근거: {p.packageManagerEvidence}</p>
      </details>)}
      <details><summary>근거 식별 및 검토 범위</summary><p>원본 SHA: {result.sourceRevision||'저장된 Git SHA 없음'}</p><p>SCA 근거 SHA-256: <code>{result.evidenceHash}</code></p><p>분석 시각: {result.analyzedAt||'미기록'}</p><ul>{result.limitations.map((s,i)=><li key={i}>{s}</li>)}</ul></details>
    </>}
  </section>;
}
