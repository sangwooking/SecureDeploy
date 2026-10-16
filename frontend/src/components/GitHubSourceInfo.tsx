import type { GitHubSourceMetadata } from '../types/githubSource';
import { dateLabel } from './WorkspaceSummary';

export function GitHubSourceInfo({ source, compact = false }: { source?: GitHubSourceMetadata | null; compact?: boolean }) {
  if (!source) return <p className="github-source">이 분석에는 저장된 branch / commit 정보가 없습니다.</p>;
  return <section className="github-source" aria-label="분석한 GitHub 버전">
    {source.accessMethod === 'GITHUB_APP' && <p>{source.privateRepository ? '비공개' : '공개'} 저장소 · GitHub App 읽기 전용 · 분석 시점 기준</p>}
    {compact ? <p>Branch <strong>{source.analyzedBranch}</strong> · Commit <code>{source.shortCommitSha}</code></p> : <>
      <h3>분석한 GitHub 버전</h3>
      <dl className="technical-grid">
        <div><dt>Repository</dt><dd>{source.owner}/{source.repository}</dd></div>
        <div><dt>Branch</dt><dd>{source.analyzedBranch}</dd></div>
        <div><dt>분석한 Commit</dt><dd><code>{source.shortCommitSha}</code></dd></div>
        <div><dt>분석 시각</dt><dd>{dateLabel(source.analyzedAt)}</dd></div>
      </dl>
      <p>이 분석은 GitHub의 {source.shortCommitSha} 버전을 기준으로 수행되었습니다.</p>
      <details className="technical-details"><summary>소스 기술 정보 보기</summary>
        <dl className="technical-grid">
          <div><dt>Repository URL</dt><dd>{source.canonicalRepositoryUrl}</dd></div>
          <div><dt>전체 Commit SHA</dt><dd><code>{source.commitSha}</code></dd></div>
          <div><dt>Commit 시각</dt><dd>{dateLabel(source.commitTimestamp)}</dd></div>
          <div><dt>수집 완료</dt><dd>{dateLabel(source.clonedAt)}</dd></div>
          <div><dt>수집 깊이</dt><dd>{source.cloneDepth}</dd></div>
        </dl>
      </details>
    </>}
    {source.limitations.length > 0 && <div className="review-caution" role="note">
      <strong>분석에서 제외된 소스가 있습니다.</strong>
      {source.limitations.map(note => <p key={note}>{note}</p>)}
      <p>배포 판단은 수집된 소스 범위에 한정됩니다. 제외된 코드의 안전을 보장하지 않습니다.</p>
    </div>}
  </section>;
}

export function GitHubCommitComparison({ before, after }: { before?: GitHubSourceMetadata | null; after?: GitHubSourceMetadata | null }) {
  if (!before && !after) return null;
  const same = before && after && before.canonicalRepositoryUrl === after.canonicalRepositoryUrl && before.commitSha === after.commitSha;
  return <section className="github-source" aria-label="GitHub 버전 변화">
    <h3>분석한 버전 변화</h3>
    <p><code>{before?.shortCommitSha ?? '이전 commit 정보 없음'}</code> → <code>{after?.shortCommitSha ?? '현재 commit 정보 없음'}</code></p>
    {same ? <p>이전 검사와 동일한 commit입니다.</p> : <p>{before && after ? '서로 다른 commit을 분석했습니다.' : '저장된 commit 정보가 부족하여 버전 변경 여부를 확인할 수 없습니다.'}</p>}
    <p>검사 결과는 매번 새로 계산합니다. Commit 변경 여부만으로 보안 개선을 판단하지 않습니다.</p>
  </section>;
}
