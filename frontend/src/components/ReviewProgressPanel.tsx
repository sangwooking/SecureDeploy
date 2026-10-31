import {ChangeProvenance} from './ChangeProvenance';
import { changeOriginLabel } from './EvidenceSupportLayout';
import { useState } from 'react';
import type { SecurityReviewResponse } from '../types/securityReview';
import type { ProgressChange, ProgressFinding } from '../types/reviewProgress';
import { codeExplanation, deploymentLabels, priorityLabels } from './reviewPresentation';
import { FindingRemediation } from './FindingRemediation';
import { inspectionLabel, securityTerms } from './uiLanguage';
import { GitHubCommitComparison } from './GitHubSourceInfo';

const labels: Record<ProgressChange, string> = {
  RESOLVED: '해결된 문제', REMAINING: '아직 남아 있는 문제', NEW: '새로 발견된 문제',
  CHANGED: '상태가 달라진 문제', UNAVAILABLE: '비교 확인 불가',
};
function title(finding: ProgressFinding) {
  return finding.code ? codeExplanation(finding.code).title : `${finding.risk.packageName ?? '라이브러리'} 업데이트 검토`;
}
export function hasComparableReview(snapshot?:SecurityReviewResponse['comparison']){return !!snapshot&&snapshot.baselineReviewId!=null&&!!snapshot.basis&&(['COMPLETE','PARTIAL'].includes(snapshot.status)||!!snapshot.basis?.flowChanges.length);}
export function ReviewProgressPanel({ result, compact = false }: { compact?:boolean; result: Pick<SecurityReviewResponse, 'comparison' | 'remediation'> & Partial<Pick<SecurityReviewResponse,'projectId'|'reviewId'>> }) {
  const [filter, setFilter] = useState<ProgressChange>(()=>(['RESOLVED','REMAINING','NEW','CHANGED','UNAVAILABLE'] as ProgressChange[]).find(k=>(result.comparison?.counts[k]??0)>0)??'RESOLVED');
  const snapshot = result.comparison;
  if (!snapshot || !hasComparableReview(snapshot)) return <section className="comparison-empty" aria-label="비교 불가"><h2>{snapshot&&snapshot.baselineReviewId!=null&&!snapshot.basis?'과거 비교의 코드·엔진 근거가 부족해요.':snapshot?.status==='UNAVAILABLE'?'이전 검사와 비교할 수 없어요.':'비교할 이전 검사가 없어요.'}</h2><p>현재 검사 결과는 저장됐지만, 비교 가능한 원본 검사가 없어 변경 사항을 판단할 수 없습니다.</p>{result.projectId&&result.reviewId&&<a href={`#/projects/${result.projectId}/findings?review=${result.reviewId}`}>현재 검사 결과 보기</a>}<details><summary>비교 상태의 기술 정보</summary><p>{snapshot?.status??'NOT_RECORDED'} · 비교 불가 · NOT_COMPARED</p><p>NOT_COMPARED는 RESOLVED가 아닙니다.</p>{snapshot&&<><p>{snapshot.message}</p>{!snapshot.basis&&<><p>원본 비교 기록은 보존하지만 과거 해결·신규 수를 현재 검증 결과로 확정하지 않습니다.</p><pre>{JSON.stringify({archivedCounts:snapshot.counts,archivedFindings:snapshot.findings},null,2)}</pre></>}{snapshot.notices.map((n,i)=><p key={i}>{n}</p>)}</>}</details></section>;
  const before = snapshot.assessmentBefore, after = snapshot.assessmentAfter;
  return <section className="security-progress" aria-label="보안 상태 변화">
    <h2>보안 상태 변화</h2>
    {snapshot.basis&&<div className="comparison-basis" aria-label="코드와 엔진 비교 근거">
      <p>{snapshot.basis.message}</p>
      <p>코드: {({SAME_ANALYZED_INPUT:'수집한 분석 입력 내용 동일',CHANGED_ANALYZED_INPUT:'수집한 분석 입력 내용 변경',SAME_VERIFIED_WORKSPACE:'검증된 원본과 수정 파일 내용 동일',CHANGED_VERIFIED_WORKSPACE:'검증된 원본의 수정 파일 변경',SAME_GIT_REVISION:'같은 Git 원본 버전',INPUT_SELECTION_CHANGED:'분석 입력 파일 구성이 달라짐',UNKNOWN:'동일성 확인 불가'} as Record<string,string>)[snapshot.basis.sourceState]??'확인 불가'}</p>
      <p>파일 해시는 수집한 분석 입력 기준이며 저장소 전체나 실제 실행 범위의 보증은 아닙니다.</p>
      <p>분석 엔진: {snapshot.basis.engineState==='SAME'?'동일':snapshot.basis.engineState==='CHANGED'?'변경됨':'전체 동일성 확인 불가'}</p>
      <details><summary>엔진·코드 비교의 기술 근거</summary><pre>{JSON.stringify({sourceState:snapshot.basis.sourceState,before:snapshot.basis.enginesBefore,after:snapshot.basis.enginesAfter,inputFiles:snapshot.basis.inputFiles,limitations:snapshot.basis.limitations},null,2)}</pre></details>
      {!!snapshot.basis.flowChanges.length&&<p>흐름 비교 기록(해결·신규 집계와 별도): {Object.entries(snapshot.basis.flowChanges.reduce((counts,e)=>({...counts,[e.status]:(counts[e.status]??0)+1}),{} as Record<string,number>)).map(([status,count])=>`${({OBSERVED_BOTH:'같은 근거 관찰',ENGINE_EVIDENCE_ADDED:'새 엔진의 추가 근거',NOT_REOBSERVED_AFTER_EDIT:'수정 후 미관찰 · 확정 해결 아님',UNAVAILABLE:'비교 확인 불가'} as Record<string,string>)[status]??'비교 확인 불가'} ${count}건`).join(' · ')}</p>}
      {!!snapshot.basis.flowChanges.length&&<details className="flow-comparison"><summary>서버 코드 흐름 근거 비교 ({snapshot.basis.flowChanges.length})</summary>
        <p>원본 Finding ID를 보존한 별도 비교입니다. 아래 관찰은 기존 해결·신규 건수나 Risk/Score를 변경하지 않습니다.</p>
        {snapshot.basis.flowChanges.map((e,i)=><article key={i}><h3>{({OBSERVED_BOTH:'두 검사에서 같은 코드 근거 관찰',ENGINE_EVIDENCE_ADDED:'새 엔진이 추가 연결한 분석 근거',NOT_REOBSERVED_AFTER_EDIT:'수정 후 기존 흐름 미관찰 · 확정 해결 아님',UNAVAILABLE:'흐름 비교 확인 불가'} as Record<string,string>)[e.status]??'흐름 비교 확인 불가'}</h3><p>{e.ruleId} · {(e.after??e.before)?.location.filePath}</p><p>{e.note}</p><details><summary>원본 ID·Source/Sink 근거</summary><pre>{JSON.stringify(e,null,2)}</pre></details></article>)}
      </details>}
    </div>}
    {!snapshot.basis&&<p>과거에 저장된 비교입니다. 코드 해시와 실제 Worker 전체 동일성은 이 기록에서 확인하지 못했습니다.</p>}
    <p className="comparison-policy">저장된 정책 판단: {before ? deploymentLabels[before.deploymentAssessment] : '평가 정보 없음'} → {after ? deploymentLabels[after.deploymentAssessment] : '평가 정보 없음'}</p>
    <details><summary>규칙 기반 참고 점수 · 전체 안전 점수와 구분</summary><div className="comparison-score" aria-label="규칙 기반 참고 점수 변화"><span>규칙 기반 참고 점수</span><strong>{before?.referenceSecurityScore ?? '정보 없음'} → {after?.referenceSecurityScore ?? '정보 없음'}</strong><small>구조 후보·미검사 영역을 포함한 전체 안전 점수가 아닙니다.</small></div></details>
    <nav className="progress-filters" aria-label="변화 분류">{(Object.keys(labels) as ProgressChange[]).filter(change=>(snapshot.counts[change]??0)>0).map(change =>
      <button type="button" key={change} aria-pressed={filter === change} onClick={() => setFilter(change)}>
        {labels[change]} {!compact&&<strong>{snapshot.counts[change]}</strong>}</button>)}</nav>
    {!Object.values(snapshot.counts).some(n=>n>0)&&<p>정책 항목에서 확정한 변화가 없습니다. 코드 흐름과 비교하지 못한 범위를 함께 확인하세요.</p>}
    <p className="review-caution">확인한 범위에서만 비교했어요. 코드 검토 후보를 비교하지 못했거나 검사 버전이 다르면 해결된 것으로 처리하지 않아요.</p>
    <p>{inspectionLabel(snapshot.status)} · 변화 건수는 비교한 보안 문제 기준이며, 영향받는 패키지 수나 수정 작업 수가 아닙니다.</p>
    <details className="comparison-status"><summary>비교 상태의 기술 정보</summary><p>{snapshot.status} · {securityTerms.notCompared} (NOT_COMPARED)는 RESOLVED가 아닙니다.</p></details>
    {snapshot.workspaceScan&&<p>수정본은 새 GitHub commit이 아닙니다. 원본 버전과 수정 revision·입력 해시로 구분합니다.</p>}
    {snapshot.workspaceScan&&!snapshot.workspaceScan.baselineVerified&&<p role="note">원본 동일성 미확인: 과거 Review와 자동 해결 비교를 하지 않습니다.</p>}
    <p>{snapshot.message}</p>
    <details className="comparison-limitations"><summary>변화 건수의 의미와 추가 비교 제한 ({snapshot.notices.length}건)</summary>
      <p>해결된 문제(RESOLVED)는 비교 가능한 현재 검사에서 해당 경고가 재탐지되지 않았다는 뜻입니다. 실제 취약점 해결이나 전체 안전성의 증명이 아닙니다. 새로 발견된 문제도 코드 변경으로 새로 생겼다는 뜻은 아닙니다.</p>
      {snapshot.notices.map((note, index) => <p key={index}>{note}</p>)}
    </details>
    <details className="comparison-context"><summary>비교한 분석·정책·파일 근거</summary>
    {snapshot.workspaceScan && <div className="workspace-scan-provenance"><p>수정본 revision {snapshot.workspaceScan.revision} · 원본 Review {snapshot.workspaceScan.originalReviewId} · GitHub 반영 안 함</p>
      <p>RESOLVED는 비교 가능한 검사에서 해당 경고가 재탐지되지 않았다는 뜻입니다. 실제 취약점 해결이나 전체 안전성의 증명이 아닙니다.</p>
      <details><summary>수정본 파일·해시 근거</summary><p className="source-revision">원본: {snapshot.workspaceScan.sourceRevision}<br />입력: {snapshot.workspaceScan.inputHash}</p>
        <p className="source-revision">분석기: {snapshot.workspaceScan.analyzerVersion}</p>
        {snapshot.workspaceScan.analysisRoot && <p>분석 위치는 ZIP의 {snapshot.workspaceScan.analysisRoot}/ 폴더 기준입니다. 아래 변경 파일·해시는 전체 원본 경로 기준입니다.</p>}
        <ul>{snapshot.workspaceScan.files.filter(f => f.changed).map(f => <li key={f.fileId}>{f.path} · <ChangeProvenance origin={f.changeOrigin} events={f.provenance}/><br />
          <span className="source-revision">{f.originalHash} → {f.currentHash}</span></li>)}</ul></details></div>}
    {!!snapshot.workspaceScan?.exports?.length&&<details><summary>다운로드 승인 기록</summary><ul>{snapshot.workspaceScan.exports.map((e,i)=><li key={i}>r{e.revision} · {e.format} · 사용자 {e.userId} · {e.at}<p>출처 manifest SHA-256: {e.provenanceHash}</p></li>)}</ul></details>}
    {!snapshot.workspaceScan&&<GitHubCommitComparison before={snapshot.sourceBefore} after={snapshot.sourceAfter} />}
    <div className="progress-assessments">
      {[{ label: '이전', value: before, id: snapshot.baselineReviewId, date: snapshot.baselineAnalyzedAt },
        { label: '현재', value: after, id: snapshot.currentReviewId, date: snapshot.currentAnalyzedAt }].map(item =>
        <div key={item.label}><h3>{item.label}{item.id != null && ` · 분석 #${item.id}`}</h3>
          <strong>{item.value ? deploymentLabels[item.value.deploymentAssessment] : '평가 정보 없음'}</strong>
          {item.date && <p><time dateTime={item.date}>{new Date(item.date).toLocaleString('ko-KR')}</time></p>}
        </div>)}
    </div>
    <dl className="progress-metrics">{(['BLOCKING', 'REVIEW_REQUIRED', 'SHOULD_FIX'] as const).map(priority =>
      <div key={priority}><dt>{priorityLabels[priority]}</dt><dd>{before?.prioritySummary[priority] ?? '미평가'} → {after?.prioritySummary[priority] ?? '미평가'}</dd></div>)}
    </dl>
    <p>배포 판단은 각 분석 당시의 평가입니다. 분석하지 못한 항목과 AI 후보는 해결 수에 포함하지 않습니다.</p>
    </details>
    <h3>{labels[filter]}</h3>
    <div className="vulnerability-list">{snapshot.findings.filter(entry => entry.status === filter).map((entry, index) => {
      const finding = entry.after ?? entry.before;
      if (!finding) return null;
      return <article className="vulnerability-item action-finding" key={`${entry.fingerprint}-${index}`}>
        <span className={`risk-badge risk-${finding.risk.priority.toLowerCase()}`}>{priorityLabels[finding.risk.priority]} · {entry.after ? '현재' : '이전'}</span>
        <h3>{title(finding)}</h3><p>{entry.note}</p>
        <p>우선순위: {entry.before ? priorityLabels[entry.before.risk.priority] : '이전 Finding 없음'} → {entry.after ? priorityLabels[entry.after.risk.priority] : '현재 Finding 없음'}</p>
        {entry.before && <p className="finding-location">이전 위치: {entry.before.risk.sourceFiles.join(', ')}{entry.before.code && ` · ${entry.before.code.line}행`}</p>}
        {entry.after && <p className="finding-location">현재 위치: {entry.after.risk.sourceFiles.join(', ')}{entry.after.code && ` · ${entry.after.code.line}행`}</p>}
        {finding.risk.source === 'DEPENDENCY' && <>
          <p>이전 Finding 버전: {entry.before?.risk.version ?? '정보 없음'} / 현재 Finding 버전: {entry.after?.risk.version ?? '정보 없음'}</p>
          <p>현재 의존성 선언에서 관찰한 버전: {entry.currentVersions.join(', ') || '확인 불가'}. 범위·미확정 값이 포함될 수 있으며 실제 설치 버전이나 안전한 버전이라는 뜻은 아닙니다.</p>
        </>}
        {entry.after && <>
          {entry.after.code && <p>{entry.after.code.recommendation}</p>}
          <FindingRemediation finding={entry.after.risk} snapshot={result.remediation} />
        </>}
        <details className="technical-details"><summary>{entry.status === 'RESOLVED' ? '이전 기술 정보 보기' : '기술 정보 보기'}</summary>
          <pre>{JSON.stringify({ fingerprint: entry.fingerprint, before: entry.before, after: entry.after }, null, 2)}</pre>
        </details>
      </article>;
    })}</div>
    {!snapshot.findings.some(e => e.status === filter) && <p>이 분류에 저장된 변화가 없습니다. 확인 불가 범위도 함께 확인하세요.</p>}
    <details className="coverage-details"><summary>추가 확인 항목 변화 · AI ({snapshot.aiChanges.length})</summary>
      <p>AI가 다시 제안하지 않았다는 사실만으로 해결되었다고 판단하지 않습니다.</p>
      {snapshot.aiChanges.map((entry, index) => <article className="vulnerability-item" key={`${entry.fingerprint}-${index}`}>
        <h3>{entry.status === 'NOT_REOBSERVED' ? '이번 AI 검토에서 다시 관찰되지 않음' : entry.status === 'NEW' ? '새 추가 확인 후보' : entry.status === 'REMAINING' ? '계속 확인할 후보' : 'AI 비교 확인 불가'}</h3>
        <p>{(entry.after ?? entry.before)?.reason}</p><p>{entry.note}</p>
        <details><summary>AI 근거 보기</summary><pre>{JSON.stringify(entry, null, 2)}</pre></details>
      </article>)}
    </details>
    <details className="technical-details"><summary>비교 범위와 참고 점수</summary>
      <p>룰 기반 참고 점수: {before?.referenceSecurityScore ?? '정보 없음'} → {after?.referenceSecurityScore ?? '정보 없음'}</p>
      <p>비교 상태: {snapshot.status} · 비교 버전: {snapshot.comparisonSchemaVersion}</p>
    </details>
  </section>;
}
