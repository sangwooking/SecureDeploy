import type { RemediationSnapshot, RiskFinding, RemediationGenerationStatus, Vulnerability } from '../types/securityReview';
import { findingGuidance, needsVerification } from './findingGuidance';
import { priorityLabels } from './reviewPresentation';
import { incompleteDependency } from './dependencyGuidance';
import { DependencyVerificationDetails } from './IncompleteDependencyCard';

const labels: Record<RemediationGenerationStatus, string> = {
  GENERATED: 'AI 생성', TEMPLATE: '템플릿 가이드', UNAVAILABLE: '생성 불가', FAILED: '생성 실패', NOT_REQUESTED: '생성 대상 아님',
};

export function RemediationNotice({ snapshot }: { snapshot?: RemediationSnapshot | null }) {
  if (!snapshot) return <p className="remediation-notice">이 분석 이력에는 저장된 해결 방법이 없습니다. 각 문제의 권장 조치를 참고하거나 재분석하세요.</p>;
  return <div className="remediation-notice" role="status">
    {snapshot.omittedFindingCount > 0 && <p>생성 한도로 {snapshot.omittedFindingCount}개 문제의 해결 방법이 생략되었습니다. 위험 평가에는 그대로 포함됩니다.</p>}
    <details><summary>해결 방법 생성 기록</summary>
      {snapshot.notices.map((notice, index) => <p key={index}>{notice}</p>)}
      {snapshot.usage && <p>{snapshot.usage.provider} · {snapshot.usage.totalTokens} tokens · 비용 추정 미산정</p>}
    </details>
  </div>;
}

export function FindingRemediation({ finding, snapshot, vulnerability, expanded = false }: {
  finding?: RiskFinding; snapshot?: RemediationSnapshot | null; vulnerability?: Vulnerability; expanded?: boolean;
}) {
  if (!finding) return null;
  if (incompleteDependency(finding)) return <details className="finding-remediation" open={expanded || undefined}>
    <summary>수정·확인 가이드 <span>정보 확인 안내</span></summary>
    <DependencyVerificationDetails finding={finding} />
  </details>;
  const item = snapshot?.findings.find(entry => entry.findingId === finding?.findingId);
  const advice = item?.advice;
  const manual = findingGuidance(finding, vulnerability);
  const review = needsVerification(finding, vulnerability);
  return <details className="finding-remediation" open={expanded || undefined}>
    <summary>수정·확인 가이드 <span>{item ? labels[item.generationStatus] : '기본 안내'}</span></summary>
    <h4>{advice ? item?.generationStatus==='GENERATED' ? 'AI 해결 가이드' : '저장된 템플릿 가이드' : '기본 확인 안내 · 저장된 수정안 없음'}</h4>
    <p className="remediation-notice">{review ? '배포 전 직접 확인할 부분입니다. 실제 문제인지 확인한 뒤 수정하세요.' : '저장된 근거를 바탕으로 한 수정 제안입니다. 실제 영향은 사용 방식에 따라 달라집니다.'}
      {' '}탐지 신뢰도·우선순위·배포 판단은 변경하지 않습니다.</p>
    <h4>이게 어떤 문제인가요?</h4><p>{manual.summary}</p>
    <dl>
      <div><dt>왜 위험한가요?</dt><dd>{manual.risk}</dd></div>
      <div><dt>어떤 일이 생길 수 있나요? · 가능한 예시</dt><dd>
        {manual.impactSteps ? <ol>{manual.impactSteps.map(step => <li key={step}>{step}</li>)}</ol>
          : <p>{manual.risk} 현재 프로젝트에서 실제 발생한 일이라는 뜻은 아닙니다.</p>}
      </dd></div>
      <div><dt>먼저 직접 확인할 일</dt><dd><ol>{manual.steps.map(step => <li key={step}>{step}</li>)}</ol></dd></div>
      <div><dt>{review ? '문제가 확인되면 무엇을 수정하나요?' : '무엇을 수정해야 하나요?'}</dt><dd>{advice?.recommendedAction ?? manual.action}</dd></div>
      {advice && <div><dt>저장된 해결 가이드</dt><dd>{advice.summary}<p>{advice.whyItMatters}</p></dd></div>}
      {advice?.codeExample && <div><dt>코드 예시</dt><dd><pre><code>{advice.codeExample}</code></pre></dd></div>}
      {advice?.configurationExample && <div><dt>설정 예시</dt><dd><pre><code>{advice.configurationExample}</code></pre></dd></div>}
      <div><dt>수정 후 무엇을 확인하나요?</dt><dd>
        {advice && <ul>{advice.verificationSteps.map((step, index) => <li key={index}>{step}</li>)}</ul>}
        <p>관련 기능을 테스트한 뒤 같은 프로젝트로 다시 검사하세요. 이전 분석과 비교하여 해결된 문제와 남은 문제를 확인하세요.</p>
      </dd></div>
      {advice?.caution && <div><dt>주의사항</dt><dd>{advice.caution}</dd></div>}
    </dl>
    <p>처리 순서: {priorityLabels[finding.priority]} · 저장된 서버 위험 평가를 따릅니다.</p>
    <details className="technical-details"><summary>기술 정보 보기 · 수정 위치와 생성 기록</summary>
      <p>위치: {finding.sourceFiles?.join(', ') || '저장된 위치 없음'}{vulnerability ? ` · ${vulnerability.line}행` : ''}</p>
      <p>{finding.ruleId ?? finding.advisoryId} · {finding.reasonCode}</p><p>{finding.priorityReason}</p>
      {item && <p className="remediation-notice">{advice && `수정안 신뢰도: ${advice.remediationConfidence} (탐지 신뢰도와 별개) · `}
        {item.provider}{item.model ? ` / ${item.model}` : ''}{' · '}{item.promptVersion}
        {' · '}<time dateTime={item.generatedAt}>{new Date(item.generatedAt).toLocaleString('ko-KR')}</time></p>}
    </details>
  </details>;
}
