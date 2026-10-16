import { useId, useRef, useState, type FormEvent } from 'react';
import type { RiskFinding } from '../types/securityReview';
import type { SupplementalDependencyResponse } from '../types/dependencyGuidance';
import { dependencyGuidance, dependencyText, knownDependencyValue, unconfirmed } from './dependencyGuidance';
import { lookupSupplementalDependency } from '../api/securityReviewApi';

export function DependencyVerificationDetails({ finding }: { finding: RiskFinding }) {
  const guide = dependencyGuidance(finding);
  return <>
    <h4>왜 이 정보가 필요한가요?</h4>
    <p>보안 문제는 라이브러리 이름과 정확한 사용 버전으로 조회합니다. 현재 정보로는 취약 여부·정확한 수정 버전·해당 보안 공지를 확정할 수 없습니다.</p>
    <h4>어디서 어떤 값을 찾나요?</h4><p>{guide.places}</p>
    <ol>{guide.steps.map(step => <li key={step}>{step}</li>)}</ol>
    <p>이 안내는 저장된 분석 정보에 기반합니다. 라이브러리나 수정 버전을 AI가 추측하지 않습니다.</p>
  </>;
}

export function SupplementalDependencyResult({ result }: { result: SupplementalDependencyResponse }) {
  const complete = result.status === 'COMPLETE';
  return <section className="supplemental-result" aria-label="추가 정보 조회 결과" aria-live="polite">
    <h4>추가 정보 조회 결과</h4>
    <p><strong>사용자가 직접 입력한 정보로 확인한 결과입니다.</strong></p>
    <p>{dependencyText(result.packageName)} · {dependencyText(result.version)}</p>
    {!complete && <p className="review-caution">{result.status === 'DISABLED' ? '현재 라이브러리 조회가 비활성화되어 ' : '조회가 완료되지 않아 '}알려진 보안 문제를 끝까지 확인하지 못했습니다. 안전하다는 뜻이 아닙니다.</p>}
    {result.findings.length > 0 ? <>
      <p>입력한 정보 기준으로 알려진 보안 문제가 확인되었습니다.{!complete && ' 아래는 일부 확인된 결과입니다.'}</p>
      <ul>{result.findings.map((finding, index) => <li key={index}>
        <p>{dependencyText(finding.summary)}</p>
        <p>수정이 확인된 버전: {finding.fixedVersions.map(knownDependencyValue).filter(Boolean).join(', ') || unconfirmed}</p>
        <details><summary>기술 정보 · 보안 공지</summary><p>{dependencyText(finding.osvId)}</p>
          <p>{dependencyText(finding.aliases.join(', '))}</p></details>
      </li>)}</ul>
      <p>수정 버전은 해당 보안 문제에 대한 정보이며 모든 문제 해결이나 호환성을 보장하지 않습니다.</p>
    </> : complete && <p>입력한 이름과 버전에서 알려진 보안 문제가 반환되지 않았습니다. 실제 사용 버전이나 프로젝트 전체의 안전을 보장하지 않습니다.</p>}
    <p>기존 분석 결과·점수·배포 판단은 변경되지 않습니다. 실제 프로젝트를 수정하고 빌드·기능 테스트 후 다시 검사해야 정식으로 반영됩니다.</p>
  </section>;
}

export function IncompleteDependencyCard({ finding, reviewId }: { finding: RiskFinding; reviewId?: number | null }) {
  const guide = dependencyGuidance(finding);
  const id = useId();
  const busy = useRef(false);
  const [name, setName] = useState(guide.name ?? '');
  const [version, setVersion] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<SupplementalDependencyResponse | null>(null);
  function changed() { setError(''); setResult(null); }
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy.current || reviewId == null) return;
    const packageName = name.trim(), currentVersion = version.trim();
    const namePattern = finding.ecosystem === 'MAVEN' ? /^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+$/ : /^(?:@[A-Za-z0-9_.-]+\/)?[A-Za-z0-9_.-]+$/;
    if (!namePattern.test(packageName) || packageName.length > 256 || !/^[0-9][0-9A-Za-z._+-]*$/.test(currentVersion) || currentVersion.length > 128) {
      setResult(null); setError('라이브러리 이름과 정확한 버전을 확인해 주세요. 주소·스크립트·버전 범위는 사용할 수 없습니다.'); return;
    }
    busy.current = true; setLoading(true); setError(''); setResult(null);
    try {
      setResult(await lookupSupplementalDependency(reviewId, { findingId: finding.findingId, packageName, version: currentVersion }));
    } catch (e) { setError(e instanceof Error ? e.message : '추가 정보를 확인하지 못했습니다. 잠시 후 다시 시도해 주세요.'); }
    finally { busy.current = false; setLoading(false); }
  }
  return <article className="vulnerability-item action-finding incomplete-dependency">
    <span className="risk-badge risk-review_required">배포 전 직접 확인할 부분</span>
    <h3>{guide.title}</h3><p>{guide.reason}</p>
    <p>현재 정보만으로는 취약한지 안전한지 판단할 수 없습니다.</p>
    <dl className="dependency-versions">
      <div><dt>라이브러리</dt><dd>{guide.name ?? unconfirmed}</dd></div>
      <div><dt>현재 버전</dt><dd>{unconfirmed}</dd></div>
      <div><dt>확인할 파일</dt><dd className="finding-location">{guide.location}</dd></div>
    </dl>
    <p>{guide.name ? '정확한 버전을 알아야 알려진 보안 문제가 있는지 확인할 수 있습니다.' : '이 파일에서 사용 중인 라이브러리 이름과 버전을 확인해 주세요.'}</p>
    <details className="action-details"><summary>어디서 확인하는지 알려주세요</summary>
      <DependencyVerificationDetails finding={finding} />
    </details>
    {reviewId != null && <details className="action-details"><summary>{guide.name ? '버전을 알고 있어요' : '추가 정보로 확인하기'}</summary>
      <form className="dependency-lookup-form" onSubmit={submit}>
        <fieldset disabled={loading}>
          <legend>추가 정보로 확인하기</legend>
          <label htmlFor={`${id}-name`}>라이브러리 이름</label>
          <input id={`${id}-name`} value={name} readOnly={!!guide.name} required maxLength={256}
            onChange={e => { setName(e.target.value); changed(); }} aria-describedby={`${id}-name-hint`} />
          <p id={`${id}-name-hint`}>{guide.name ? '소스에서 확인된 이름입니다. 현재 사용 버전만 입력해 주세요.' : guide.nameHint}</p>
          <label htmlFor={`${id}-version`}>현재 사용 버전</label>
          <input id={`${id}-version`} value={version} required maxLength={128} onChange={e => { setVersion(e.target.value); changed(); }} />
          <p>입력한 이름과 버전을 외부 보안 정보 서비스로 조회합니다. 비밀번호·토큰·개인정보는 입력하지 마세요.</p>
          <button type="submit" className="secondary-button" disabled={loading}>{loading ? '확인 중...' : '이 정보로 확인'}</button>
        </fieldset>
      </form>
      {error && <p role="alert" className="error-message">{error}</p>}
      {result && <SupplementalDependencyResult result={result} />}
    </details>}
    <details className="technical-details"><summary>기술 정보 보기</summary>
      <p>라이브러리 유형: {dependencyText(finding.ecosystem)}</p>
      <p>선언된 버전 값: {guide.declaration ?? unconfirmed}</p>
      <p>미확인 사유: {dependencyText(finding.priorityReason)}</p>
    </details>
  </article>;
}
