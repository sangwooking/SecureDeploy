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
export function DependencyUpdatePlans({reviewId,onEditDependency,selectedDependency}: {reviewId?:number|null;selectedDependency?:DependencyVulnerability;onEditDependency?:(id:string)=>void}) {
  const [result,setResult]=useState<Plans|null>(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);
  const generation=useRef(0);
  useEffect(()=>{generation.current++;setResult(null);setError('');setBusy(false);return()=>{generation.current++;};},[reviewId]);
  const load=async()=>{
    if(!reviewId||busy)return;
    const current=generation.current;setBusy(true);setError('');
    try {const value=await fetchDependencyUpdatePlans(reviewId);if(current===generation.current&&value.reviewId===reviewId)setResult(value);}
    catch {if(current===generation.current)setError('업데이트 근거를 불러오지 못했습니다. 원본 결과는 변경하지 않았습니다.');}
    finally {if(current===generation.current)setBusy(false);}
  };
  const matching=result?.plans.flatMap((p,i)=>selectedDependency&&sameDependencyAdvisory(selectedDependency,p)?[i]:[])??[];
  const selectedIndex=matching.length===1?matching[0]:-1;
  const shownPlans=result?.plans.filter((_,i)=>!selectedDependency||i===selectedIndex)??[];
  return <section className="dependency-update-plans" aria-label="근거 기반 의존성 수정 검토">
    <h3>프로젝트에 맞는 업데이트 검토</h3>
    <p>저장된 공지·잠금 버전·상위 선언을 연결한 검토 계획입니다. AI 코드 생성이나 적용 완료를 의미하지 않습니다.</p>
    {!reviewId?<p>저장된 분석 이력에서 수정 근거를 확인할 수 있습니다.</p>:<button type="button" className="secondary-button" disabled={busy} onClick={()=>void load()}>{busy?'근거 확인 중':'근거 기반 업데이트 계획 보기'}</button>}
    {error&&<p role="alert">{error}</p>}
    {result&&<>
      <details><summary>근거 기반 계획의 지원 범위</summary><p>기본 계획: 근거 기반 안내 · 호환성: 미검증 · 적용 가능 Patch: 없음</p><p>잠금 파일 재생성과 원본 파일 해시 검증 전까지 검토 필요 상태를 유지합니다.</p></details>
      {reviewId&&<DependencyAiAdvicePanel reviewId={reviewId} evidence={result} onEditDependency={onEditDependency} selectedIndex={selectedDependency?selectedIndex:undefined} />}
      {!result.plans.length&&<p>이 저장 결과에는 업데이트 계획으로 연결할 보안 공지가 없습니다. 전체 안전을 의미하지 않습니다.</p>}
      {selectedDependency&&selectedIndex===-1&&<p role="note">이 공지에 연결된 업데이트 근거가 없거나 여러 계획과 겹칩니다. 다른 공지의 AI 의견을 대신 표시하지 않습니다.</p>}
      {shownPlans.map((p,i)=><details key={`${p.ecosystem}:${p.packageName}:${p.lockedVersion}:${p.advisoryId}:${i}`}>
        <summary>{p.packageName}@{p.lockedVersion} · {p.advisoryId} · 검토 필요</summary>
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
