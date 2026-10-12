import type { SemanticSnapshot, SemanticCandidate } from '../types/securityReview';

const statuses: Record<SemanticSnapshot['semanticReviewStatus'], string> = {
  NOT_REQUESTED: '미실행', UNAVAILABLE: '분석 불가', NO_SUPPORTED_CONTEXT: '지원 코드 문맥 없음',
  COMPLETED: '선택된 문맥 검토 완료', PARTIAL: '일부 후보 검증 실패', FAILED: '생성 실패', REJECTED: '후보 근거 검증 실패',
};

export function SemanticReviewSection({ snapshot }: { snapshot?: SemanticSnapshot | null }) {
  return <section className="semantic-review" aria-label="AI 보안 추가 검토">
    <div className="section-heading"><h2>AI 보안 추가 검토</h2>
      {snapshot && <span className="status-pill">{statuses[snapshot.semanticReviewStatus]}</span>}
    </div>
    {!snapshot ? <p>이 분석 이력에는 저장된 Semantic Review가 없습니다.</p> : <>
      <p className="semantic-disclaimer">AI 보조 분석 후보이며 확정 취약점이 아닙니다. 기존 위험 기반 배포 판단과 취약점 수에는 합산하지 않습니다.</p>
      {snapshot.candidates.length > 0 ? <>
        <strong>{snapshot.candidates.length}개 항목 확인 필요 · REVIEW REQUIRED</strong>
        {snapshot.candidates.map(candidate => <Candidate key={candidate.candidateId} candidate={candidate} />)}
      </> : <p>표시할 추가 검토 후보가 없습니다. 미실행·실패 또는 후보 0건은 안전을 의미하지 않습니다.</p>}
      {snapshot.existingFindingEvidence.length > 0 && <details>
        <summary>기존 탐지의 추가 근거 ({snapshot.existingFindingEvidence.length}건 · 별도 후보 수 제외)</summary>
        {snapshot.existingFindingEvidence.map(candidate => <Candidate key={candidate.candidateId} candidate={candidate} />)}
      </details>}
      <details className="semantic-metadata">
        <summary>분석 범위와 검증 기록</summary>
        <p>{snapshot.scanMode} · Slice {snapshot.semanticSlicesAnalyzed}개 · 생략 {snapshot.omittedSlices}개 · 요청 {snapshot.requestCount}회</p>
        <p>거부 후보 {snapshot.rejectedCandidates}개 · 중복 제거 {snapshot.deduplicatedCandidates}개</p>
        <p>{snapshot.provider}{snapshot.model ? ` / ${snapshot.model}` : ''} · {snapshot.promptVersion}</p>
        {snapshot.usage && <p>{snapshot.usage.totalTokens} tokens · 비용 추정 미산정</p>}
        <time dateTime={snapshot.generatedAt}>{new Date(snapshot.generatedAt).toLocaleString('ko-KR')}</time>
        {snapshot.slices.map(slice => <div key={slice.sliceId}>
          <h4>{slice.httpMethod} {slice.endpoint}</h4>
          <ul>{slice.locations.map((location, index) => <li key={index}>{location.filePath}:{location.startLine}-{location.endLine} · {location.functionName}</li>)}</ul>
          <ul>{slice.limitations.map((note, index) => <li key={index}>{note}</li>)}</ul>
        </div>)}
        <ul>{snapshot.notices.map((note, index) => <li key={index}>{note}</li>)}</ul>
      </details>
    </>}
  </section>;
}

function Candidate({ candidate }: { candidate: SemanticCandidate }) {
  return <article className="semantic-candidate">
    <div className="section-heading"><h3>{candidate.title}</h3><span className="risk-badge risk-review_required">추가 검토 필요</span></div>
    <p>{candidate.candidateType} · 의미 분석 신뢰도: {candidate.semanticAnalysisConfidence} (기존 탐지 신뢰도와 별개)</p>
    <h4>의심 근거</h4><p>{candidate.reason}</p>
    <h4>관련 위치</h4>
    <ul>{candidate.evidence.map((evidence, index) => <li key={index}>
      <code>{evidence.filePath}:{evidence.startLine}-{evidence.endLine}</code>
      <p>{evidence.functionName}</p><p>{evidence.evidenceDescription}</p>
    </li>)}</ul>
    <h4>확인할 내용</h4><ul>{candidate.verificationSteps.map((step, index) => <li key={index}>{step}</li>)}</ul>
    {candidate.relatedExistingFindingIds.length > 0 && <p>연결된 기존 Finding: {candidate.relatedExistingFindingIds.join(', ')}</p>}
  </article>;
}
