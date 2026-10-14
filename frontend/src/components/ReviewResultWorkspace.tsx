import { useEffect, useRef, useState, type ReactNode } from 'react';
import type { RiskFinding, SecurityReviewResponse, Severity } from '../types/securityReview';
import { CodeFindingCard, type FindingStatusActions } from './CodeFindingCard';
import { DependencyFindingCard } from './DependencyFindingCard';
import { DependencySecuritySection, ScaAssessmentNotice } from './DependencySecuritySection';
import { FindingRemediation, RemediationNotice } from './FindingRemediation';
import { RiskAssessmentSection } from './RiskAssessmentSection';
import { SemanticReviewSection } from './SemanticReviewSection';
import { ReviewProgressPanel } from './ReviewProgressPanel';
import { allRiskFindings, deploymentLabels, findingTitle, priorityLabels, resultViews, reviewCounts,
  semanticStatusText, vulnerabilityForFinding, type ResultView } from './reviewPresentation';

const severityOrder: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

interface Props {
  result: SecurityReviewResponse;
  view: ResultView;
  onViewChange: (view: ResultView) => void;
  statusActions: FindingStatusActions;
  reportActions: ReactNode;
  progress: ReactNode;
  aiPanel: ReactNode;
  rescanActions?: ReactNode;
}

export function ReviewResultWorkspace({ result, view, onViewChange, statusActions, reportActions, progress, aiPanel, rescanActions }: Props) {
  const panel = useRef<HTMLDivElement>(null);
  const root = useRef<HTMLElement>(null);
  useEffect(() => { root.current?.scrollIntoView({ block: 'start' }); }, []);
  const assessment = result.riskAssessment;
  const findings = allRiskFindings(result);
  const counts = reviewCounts(result);
  const navigate = (next: ResultView) => {
    onViewChange(next);
    requestAnimationFrame(() => { panel.current?.focus({ preventScroll: true }); panel.current?.scrollIntoView({ block: 'start' }); });
  };
  return <section ref={root} className="result-area result-workspace" aria-label="프로젝트 분석 결과">
    <header className="result-workspace-header">
      <div><p className="eyebrow">프로젝트 보안 상태</p><h2>{result.projectName}</h2>
        <p>{result.reviewId ? `분석 #${result.reviewId}` : '현재 분석'} · {result.scannedFileCount}개 파일 검사</p></div>
      <details className="report-menu"><summary>리포트 다운로드</summary><div className="result-actions">{reportActions}</div></details>
    </header>
    {rescanActions}
    <nav className="result-navigation" aria-label="분석 결과 메뉴">
      {resultViews.map(item => <button key={item.id} type="button" aria-current={view === item.id ? 'page' : undefined}
        aria-controls="result-content" onClick={() => navigate(item.id)}>{item.label}</button>)}
    </nav>
    <div id="result-content" className="result-content" tabIndex={-1} ref={panel}>
      <p className="result-breadcrumb">분석 결과 / {resultViews.find(item => item.id === view)?.label}</p>
      {view === 'SUMMARY' && <>
        <section className={`readiness-band assessment-${assessment?.prioritizedDeploymentAssessment.toLowerCase() ?? 'unknown'}`} aria-label="지금 배포해도 될까요?">
          <p>지금 배포해도 될까요?</p>
          <h2>{assessment ? deploymentLabels[assessment.prioritizedDeploymentAssessment] : '재분석 후 배포 여부를 확인하세요'}</h2>
          <p>{assessment ? '코드·라이브러리 위험과 분석 완성도를 고려한 결과입니다.' : '이 이력에는 위험 기반 배포 평가가 없습니다. 기존 점수만으로 배포 가능 여부를 판단하지 않습니다.'}</p>
          <div className="decision-counts">
            <button type="button" onClick={() => navigate('BLOCKING')}><span>반드시 처리</span><strong>{counts.blocking ?? '미평가'}</strong></button>
            <button type="button" onClick={() => navigate('REVIEW_REQUIRED')}><span>확인 필요</span>
              <strong>{counts.review === null ? '미평가' : counts.review + counts.candidates}</strong>
              <small>{counts.review === null ? `AI 추가 후보 ${counts.candidates}건은 별도 확인` : `분석 확인 ${counts.review} + AI 추가 후보 ${counts.candidates}`}</small></button>
            <button type="button" onClick={() => navigate('SHOULD_FIX')}><span>수정 권장</span><strong>{counts.recommended ?? '미평가'}</strong></button>
          </div>
          <p className="decision-disclaimer">분석 당시의 판단입니다. 미발견이 완전한 안전을 뜻하지 않으며, AI 추가 후보는 배포 판단에 합산하지 않습니다.</p>
        </section>
        <section className="next-actions"><h3>가장 먼저 해야 할 일</h3>
          {assessment ? <>
            <ol>{(['BLOCKING', 'REVIEW_REQUIRED', 'SHOULD_FIX'] as const).filter(priority => assessment.prioritySummary[priority] > 0).map(priority => {
              const first = findings.find(f => f.priority === priority);
              return <li key={priority}><div><strong>{priorityLabels[priority]} {assessment.prioritySummary[priority]}건</strong>
                <p>{first ? findingTitle(result, first) : '저장된 분석 항목을 확인하세요.'}</p></div>
                <button className="secondary-button" type="button" onClick={() => navigate(priority)}>왜 문제인지 확인</button></li>;
            })}</ol>
            {assessment.prioritySummary.BLOCKING === 0 && assessment.prioritySummary.REVIEW_REQUIRED === 0 && assessment.prioritySummary.SHOULD_FIX === 0 && <p>분석된 범위에서 필수 처리 또는 수정 권장 문제가 보고되지 않았습니다. 분석 범위와 추가 확인 사항을 함께 확인하세요.</p>}
            {counts.candidates > 0 && <p>AI가 제안한 {counts.candidates}개 확인 항목은 ‘확인 필요’에서 검토하세요.</p>}
            {assessment.prioritySummary.INFORMATIONAL > 0 && <p>참고 사항 {assessment.prioritySummary.INFORMATIONAL}건은 ‘수정 권장’에서 별도로 확인할 수 있습니다.</p>}
          </> : <button className="secondary-button" type="button" onClick={() => navigate('REVIEW_REQUIRED')}>저장된 문제 확인</button>}
        </section>
        <section className="analysis-coverage-brief"><h3>추가 코드 검토</h3>
          <p>{semanticStatusText(result.semanticReview, result.scanMode)}</p>
          {result.semanticReview && <p>검토한 코드 영역 {result.semanticReview.semanticSlicesAnalyzed}개 · 추가 확인 후보 {counts.candidates}개</p>}
          <ScaAssessmentNotice sca={result.sca} />
          <button type="button" className="secondary-button" onClick={() => navigate('REVIEW_REQUIRED')}>확인할 내용 보기</button>
        </section>
      </>}
      {(view === 'BLOCKING' || view === 'REVIEW_REQUIRED' || view === 'SHOULD_FIX') && <>
        <h2>{priorityLabels[view]}</h2>
        <p>{view === 'BLOCKING' ? '저장된 위험 평가에서 배포 전 처리가 필요하다고 판단한 문제입니다.'
          : view === 'REVIEW_REQUIRED' ? '추가 정보나 주변 코드에 따라 판단이 달라질 수 있습니다. 먼저 이 부분을 확인하세요.'
          : '저장된 위험 평가에서 수정을 권장하는 문제입니다.'}</p>
        {assessment ? <FindingCollection key={view} result={result} findings={findings.filter(f => f.priority === view)} statusActions={statusActions} />
          : <p className="review-caution">이전 이력에는 우선순위 평가가 없습니다. 심각도만으로 필수 처리 여부를 정하지 않습니다.</p>}
        {view === 'REVIEW_REQUIRED' && <>
          {!assessment && <details open><summary>우선순위가 저장되지 않은 코드 문제</summary>
            <LegacyCodeList result={result} statusActions={statusActions} />
          </details>}
          <details className="coverage-details"><summary>라이브러리 조회와 분석 범위 확인</summary>
            <DependencySecuritySection sca={result.sca} riskAssessment={assessment} remediation={result.remediation} />
          </details>
          <SemanticReviewSection snapshot={result.semanticReview} />
        </>}
        {view === 'SHOULD_FIX' && assessment && <details className="coverage-details"><summary>참고 사항 ({assessment.prioritySummary.INFORMATIONAL}건)</summary>
          <FindingCollection result={result} findings={findings.filter(f => f.priority === 'INFORMATIONAL')} statusActions={statusActions} />
        </details>}
      </>}
      {view === 'PROGRESS' && <ReviewProgressPanel result={result} />}
      {view === 'GUIDANCE' && <>
        <h2>해결 방법</h2><p>저장된 문제별 수정 제안입니다. 적용 전 프로젝트의 사용 방식과 호환성을 확인하세요.</p>
        <Guidance result={result} findings={findings} />
        {progress}
        <details className="optional-ai"><summary>AI와 더 자세히 검토하기</summary>
          <p>추가 설명과 종합 의견입니다. AI 의견은 저장된 배포 판단을 변경하지 않습니다.</p>{aiPanel}
        </details>
      </>}
      {view === 'TECHNICAL' && <>
        <h2>기술 정보</h2>
        <dl className="reference-score"><div><dt>보안 점수 · 룰 기반 참고값</dt><dd>{result.securityScore} / 100</dd></div>
          <div><dt>기존 판정 · 참고용</dt><dd>{result.deploymentStatus}</dd></div>
          <div><dt>원본 룰 탐지 수</dt><dd>{result.vulnerabilityCount}</dd></div></dl>
        <p>참고 점수는 배포 허가가 아닙니다. 배포 여부는 ‘결과 요약’의 판단을 우선 확인하세요.</p>
        <details><summary>저장된 배포 평가와 분석 범위</summary><RiskAssessmentSection assessment={assessment} /></details>
        <details><summary>코드에서 발견된 문제 · 원본과 판단 근거</summary><LegacyCodeList result={result} statusActions={statusActions} /></details>
        <details><summary>사용 중인 라이브러리 문제 · 보안 공지와 악용 정보</summary><DependencySecuritySection sca={result.sca} riskAssessment={assessment} remediation={result.remediation} /></details>
        <details><summary>AI 추가 검토 기록</summary><SemanticReviewSection snapshot={result.semanticReview} /></details>
        <RemediationNotice snapshot={result.remediation} />
      </>}
    </div>
  </section>;
}

function FindingCollection({ result, findings, statusActions }: {
  result: SecurityReviewResponse; findings: RiskFinding[]; statusActions: FindingStatusActions;
}) {
  const [severity, setSeverity] = useState<Severity | 'ALL'>('ALL');
  const [page, setPage] = useState(0);
  const level = (f: RiskFinding) => f.dependency?.severity ?? vulnerabilityForFinding(result, f)?.severity;
  const sorted = findings.filter(f => severity === 'ALL' || level(f) === severity).sort((a, b) =>
    (severityOrder[level(a) as Severity] ?? 4) - (severityOrder[level(b) as Severity] ?? 4));
  const currentPage = Math.min(page, Math.max(0, Math.ceil(sorted.length / 6) - 1));
  return <>
    <label className="finding-filter">심각도 <select value={severity} onChange={event => { setSeverity(event.target.value as Severity | 'ALL'); setPage(0); }}>
      <option value="ALL">전체</option>{Object.keys(severityOrder).map(value => <option key={value}>{value}</option>)}
    </select><span>{sorted.length}건</span></label>
    {!sorted.length && <p className="result-empty">{findings.length ? '선택한 심각도에 해당하는 문제가 없습니다.' : '이 분류에 저장된 문제가 없습니다.'}</p>}
    <div className="vulnerability-list">{sorted.slice(currentPage * 6, currentPage * 6 + 6).map(finding => {
      const vulnerability = vulnerabilityForFinding(result, finding);
      if (finding.source === 'CODE' && vulnerability) return <CodeFindingCard key={finding.findingId} vulnerability={vulnerability}
        finding={finding} remediation={result.remediation} statusActions={statusActions} />;
      if (finding.dependency) return <DependencyFindingCard key={finding.findingId} dependency={finding.dependency}
        finding={finding} remediation={result.remediation} intelligence={result.riskAssessment?.threatIntelligence} />;
      return <article className="vulnerability-item action-finding" key={finding.findingId}>
        <span className={`risk-badge risk-${finding.priority.toLowerCase()}`}>{priorityLabels[finding.priority]}</span>
        <h3>{findingTitle(result, finding)}</h3><h4>내가 확인할 일</h4><p>{finding.priorityReason}</p>
        <p className="finding-location">{finding.sourceFiles.join(', ')}</p>
        <details className="technical-details"><summary>기술 정보 보기</summary><p>{finding.findingId} · {finding.reasonCode}</p></details>
      </article>;
    })}</div>
    {sorted.length > 6 && <nav className="finding-pagination" aria-label="문제 목록 페이지">
      <button type="button" className="secondary-button" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>이전</button>
      <span>{currentPage + 1} / {Math.ceil(sorted.length / 6)}</span>
      <button type="button" className="secondary-button" disabled={(currentPage + 1) * 6 >= sorted.length} onClick={() => setPage(currentPage + 1)}>다음</button>
    </nav>}
  </>;
}

function LegacyCodeList({ result, statusActions }: { result: SecurityReviewResponse; statusActions: FindingStatusActions }) {
  const [severity, setSeverity] = useState<Severity | 'ALL'>('ALL');
  const list = [...result.vulnerabilities].filter(v => severity === 'ALL' || v.severity === severity)
    .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  return <>
    <label className="finding-filter">심각도 <select value={severity} onChange={event => setSeverity(event.target.value as Severity | 'ALL')}>
      <option value="ALL">전체</option>{Object.keys(severityOrder).map(value => <option key={value}>{value}</option>)}
    </select></label>
    <div className="vulnerability-list">{list.map((v, index) => <CodeFindingCard key={v.vulnerabilityId ?? index} vulnerability={v}
      finding={result.riskAssessment?.codeFindings.find(f => v.vulnerabilityId != null && f.vulnerabilityId === v.vulnerabilityId)}
      remediation={result.remediation} statusActions={statusActions} />)}</div>
    {!list.length && <p>표시할 코드 문제가 없습니다.</p>}
  </>;
}

function Guidance({ result, findings }: { result: SecurityReviewResponse; findings: RiskFinding[] }) {
  const [selected, setSelected] = useState('');
  const order = { BLOCKING: 0, REVIEW_REQUIRED: 1, SHOULD_FIX: 2, INFORMATIONAL: 3 };
  const ordered = [...findings].sort((a, b) => order[a.priority] - order[b.priority]);
  const finding = ordered.find(f => f.findingId === selected) ?? ordered[0];
  const vulnerability = finding && vulnerabilityForFinding(result, finding);
  return <section className="guidance-section">
    {finding ? <>
      <label htmlFor="guidance-finding">해결할 문제 선택</label>
      <select id="guidance-finding" value={finding.findingId} onChange={event => setSelected(event.target.value)}>
        {ordered.map(item => <option key={item.findingId} value={item.findingId}>{priorityLabels[item.priority]} · {findingTitle(result, item)}</option>)}
      </select>
      <h3>{findingTitle(result, finding)}</h3>
      {vulnerability && <p>{vulnerability.recommendation}</p>}
      {finding.dependency && <DependencyFindingCard dependency={finding.dependency} finding={finding}
        remediation={result.remediation} intelligence={result.riskAssessment?.threatIntelligence} />}
      {!finding.dependency && <FindingRemediation finding={finding} snapshot={result.remediation} />}
      {!result.remediation?.findings.some(item => item.findingId === finding.findingId && item.advice) && <p>이 문제에는 저장된 추가 수정안이 없습니다. 문제의 권장 조치와 분석 근거를 먼저 확인하세요.</p>}
    </> : <p>문제별 해결 방법을 연결할 우선순위 평가가 없습니다. 저장된 원본 결과를 참고하거나 재분석하세요.</p>}
    <RemediationNotice snapshot={result.remediation} />
  </section>;
}
