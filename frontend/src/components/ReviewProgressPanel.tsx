import { useState } from 'react';
import type { SecurityReviewResponse } from '../types/securityReview';
import type { ProgressChange, ProgressFinding } from '../types/reviewProgress';
import { codeExplanation, deploymentLabels, priorityLabels } from './reviewPresentation';
import { FindingRemediation } from './FindingRemediation';
import { GitHubCommitComparison } from './GitHubSourceInfo';

const labels: Record<ProgressChange, string> = {
  RESOLVED: '해결된 문제', REMAINING: '아직 남아 있는 문제', NEW: '새로 발견된 문제',
  CHANGED: '상태가 달라진 문제', UNAVAILABLE: '비교 확인 불가',
};
function title(finding: ProgressFinding) {
  return finding.code ? codeExplanation(finding.code).title : `${finding.risk.packageName ?? '라이브러리'} 업데이트 검토`;
}
export function ReviewProgressPanel({ result }: { result: Pick<SecurityReviewResponse, 'comparison' | 'remediation'> }) {
  const [filter, setFilter] = useState<ProgressChange>('RESOLVED');
  const snapshot = result.comparison;
  if (!snapshot) return <section><h2>보안 상태 변화</h2><p>이 분석에는 저장된 비교 결과가 없습니다. 같은 프로젝트에서 다시 검사하면 이후 변화가 기록됩니다.</p></section>;
  const before = snapshot.assessmentBefore, after = snapshot.assessmentAfter;
  return <section className="security-progress" aria-label="보안 상태 변화">
    <h2>보안 상태 변화</h2>
    {snapshot.workspaceScan && <div className="workspace-scan-provenance"><p>수정본 revision {snapshot.workspaceScan.revision} · 원본 Review {snapshot.workspaceScan.originalReviewId} · GitHub 반영 안 함</p>
      <p>RESOLVED는 비교 가능한 검사에서 해당 경고가 재탐지되지 않았다는 뜻입니다. 실제 취약점 해결이나 전체 안전성의 증명이 아닙니다.</p>
      {!snapshot.workspaceScan.baselineVerified && <p>원본 동일성 미확인: 과거 Review와 자동 해결 비교를 하지 않습니다.</p>}
      <details><summary>수정본 파일·해시 근거</summary><p className="source-revision">원본: {snapshot.workspaceScan.sourceRevision}<br />입력: {snapshot.workspaceScan.inputHash}</p>
        <p className="source-revision">분석기: {snapshot.workspaceScan.analyzerVersion}</p>
        {snapshot.workspaceScan.analysisRoot && <p>분석 위치는 ZIP의 {snapshot.workspaceScan.analysisRoot}/ 폴더 기준입니다. 아래 변경 파일·해시는 전체 원본 경로 기준입니다.</p>}
        <ul>{snapshot.workspaceScan.files.filter(f => f.changed).map(f => <li key={f.fileId}>{f.path} · {f.changeOrigin === 'AI_APPROVED' ? '승인된 AI 수정' : f.changeOrigin === 'MANUAL_AFTER_AI' ? 'AI 적용 후 수동 변경' : '수동 수정'}<br />
          <span className="source-revision">{f.originalHash} → {f.currentHash}</span></li>)}</ul></details></div>}
    <p className="review-caution">비교는 저장된 분석 계약과 확인한 범위에 한정됩니다. 구조 분석 후보의 NOT_COMPARED와 미검사·버전 차이로 인한 확인 불가는 RESOLVED가 아닙니다.</p>
    <p>{snapshot.message}</p>
    {snapshot.workspaceScan
      ? <p>수정본은 새 GitHub commit이 아닙니다. 원본 버전과 수정 revision·입력 해시로 구분합니다.</p>
      : <GitHubCommitComparison before={snapshot.sourceBefore} after={snapshot.sourceAfter} />}
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
    <nav className="progress-filters" aria-label="변화 분류">{(Object.keys(labels) as ProgressChange[]).map(change =>
      <button type="button" key={change} aria-pressed={filter === change} onClick={() => setFilter(change)}>
        {labels[change]} {snapshot.counts[change]}</button>)}</nav>
    <h3>{labels[filter]}</h3>
    <div className="vulnerability-list">{snapshot.findings.filter(entry => entry.status === filter).map((entry, index) => {
      const finding = entry.after ?? entry.before;
      if (!finding) return null;
      return <article className="vulnerability-item action-finding" key={`${entry.fingerprint}-${index}`}>
        <span className={`risk-badge risk-${finding.risk.priority.toLowerCase()}`}>{priorityLabels[finding.risk.priority]} · {entry.after ? '현재' : '이전'}</span>
        <h3>{title(finding)}</h3><p>{entry.note}</p>
        {entry.before && <p className="finding-location">이전 위치: {entry.before.risk.sourceFiles.join(', ')}{entry.before.code && ` · ${entry.before.code.line}행`}</p>}
        {entry.after && <p className="finding-location">현재 위치: {entry.after.risk.sourceFiles.join(', ')}{entry.after.code && ` · ${entry.after.code.line}행`}</p>}
        {finding.risk.source === 'DEPENDENCY' && <p>이전 버전: {entry.before?.risk.version ?? '정보 없음'} / 현재 확인 버전: {entry.currentVersions.join(', ') || '확인 불가'}</p>}
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
      {snapshot.notices.map(note => <p key={note}>{note}</p>)}
      <p>룰 기반 참고 점수: {before?.referenceSecurityScore ?? '정보 없음'} → {after?.referenceSecurityScore ?? '정보 없음'}</p>
      <p>비교 상태: {snapshot.status} · 비교 버전: {snapshot.comparisonSchemaVersion}</p>
    </details>
  </section>;
}
