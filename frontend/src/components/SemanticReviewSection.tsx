import type { SemanticSnapshot, SemanticCandidate } from '../types/securityReview';
import { semanticStatusText } from './reviewPresentation';

const statuses: Record<SemanticSnapshot['semanticReviewStatus'], string> = {
  NOT_REQUESTED: '미실행', UNAVAILABLE: '분석 불가', NO_SUPPORTED_CONTEXT: '지원 코드 문맥 없음',
  COMPLETED: '선택된 문맥 검토 완료', PARTIAL: '일부 후보 검증 실패', FAILED: '생성 실패', REJECTED: '후보 근거 검증 실패',
};

const candidateLabels: Record<string, string> = {
  AUTHORIZATION_BYPASS: '권한 확인을 건너뛸 수 있는지 확인해 주세요.',
  IDOR: '다른 사용자의 정보에 접근할 수 있는지 확인해 주세요.',
  MISSING_AUTHENTICATION: '로그인 확인이 적용되는지 확인해 주세요.',
  BROKEN_ACCESS_CONTROL: '요청한 사용자에게 접근 권한이 있는지 확인해 주세요.',
  BUSINESS_LOGIC_BYPASS: '필수 처리 절차를 건너뛸 수 있는지 확인해 주세요.',
  UNSAFE_FILE_ACCESS: '허용된 파일에만 접근할 수 있는지 확인해 주세요.',
  PATH_TRAVERSAL_CANDIDATE: '파일 경로가 허용된 범위를 벗어날 수 있는지 확인해 주세요.',
  SSRF_CANDIDATE: '서버가 요청할 수 있는 외부 주소를 확인해 주세요.',
  COMMAND_INJECTION_CANDIDATE: '사용자 입력이 시스템 명령에 사용되는지 확인해 주세요.',
  UNSAFE_DESERIALIZATION: '외부 데이터를 객체로 변환하는 과정을 확인해 주세요.',
  SENSITIVE_DATA_EXPOSURE: '민감한 정보가 불필요하게 공개되는지 확인해 주세요.',
  CRYPTO_MISUSE: '암호화 적용 방식을 확인해 주세요.',
  SESSION_SECURITY: '로그인 상태 관리 방식을 확인해 주세요.',
  OTHER_SECURITY_CONCERN: '추가 보안 검토가 필요한 코드입니다.',
};

export function SemanticReviewSection({ snapshot }: { snapshot?: SemanticSnapshot | null }) {
  return <section className="semantic-review" aria-label="추가 확인이 필요한 부분">
    <div className="section-heading"><h2>추가 확인이 필요한 부분</h2>
      {snapshot && <span className="status-pill">{statuses[snapshot.semanticReviewStatus]}</span>}
    </div>
    <p>{semanticStatusText(snapshot)}</p>
    {!snapshot ? <p>이 분석 이력에는 저장된 추가 검토 결과가 없습니다.</p> : <>
      <p className="semantic-disclaimer">AI 보조 분석 후보이며 확정 취약점이 아닙니다. 기존 위험 기반 배포 판단과 취약점 수에는 합산하지 않습니다.</p>
      {snapshot.candidates.length > 0 ? <>
        <strong>{snapshot.candidates.length}개 항목 확인 필요</strong>
        {snapshot.candidates.map(candidate => <Candidate key={candidate.candidateId} candidate={candidate} />)}
      </> : <p>표시할 추가 검토 후보가 없습니다. 미실행·실패 또는 후보 0건은 안전을 의미하지 않습니다.</p>}
      {snapshot.existingFindingEvidence.length > 0 && <details>
        <summary>기존 탐지의 추가 근거 ({snapshot.existingFindingEvidence.length}건 · 별도 후보 수 제외)</summary>
        {snapshot.existingFindingEvidence.map(candidate => <Candidate key={candidate.candidateId} candidate={candidate} />)}
      </details>}
      <details className="semantic-metadata">
        <summary>기술 정보 보기 · 분석 범위와 검증 기록</summary>
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
    <div className="section-heading"><h3>{candidateLabels[candidate.candidateType] ?? '추가 보안 검토가 필요한 코드입니다.'}</h3><span className="risk-badge risk-review_required">추가 검토 필요</span></div>
    <p>이것이 반드시 취약점이라는 뜻은 아닙니다. 다른 코드 계층의 보호 조치도 함께 확인하세요.</p>
    <h4>왜 확인해야 하나요?</h4><p>{candidate.reason}</p>
    <h4>확인할 것</h4><ul>{candidate.verificationSteps.map((step, index) => <li key={index}>{step}</li>)}</ul>
    <details className="action-details"><summary>관련 코드 위치와 근거 보기</summary>
    <ul>{candidate.evidence.map((evidence, index) => <li key={index}>
      <code>{evidence.filePath}:{evidence.startLine}-{evidence.endLine}</code>
      <p>{evidence.functionName}</p><p>{evidence.evidenceDescription}</p>
    </li>)}</ul>
    </details>
    <details className="technical-details"><summary>기술 정보 보기</summary>
    <p>AI 원본 제목: {candidate.title}</p>
    <p>{candidate.candidateType} · 의미 분석 신뢰도: {candidate.semanticAnalysisConfidence} (기존 탐지 신뢰도와 별개)</p>
    <p>{candidate.findingType} · {candidate.reviewStatus}</p>
    <p>{candidate.provider} · {candidate.model ?? '모델 정보 없음'} · {candidate.promptVersion}</p>
    {candidate.relatedExistingFindingIds.length > 0 && <p>연결된 기존 Finding: {candidate.relatedExistingFindingIds.join(', ')}</p>}
    </details>
  </article>;
}
