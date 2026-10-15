// Synthetic public source metadata. No credentials or network calls.
module.exports = (sha = 'a'.repeat(40)) => ({
  owner: 'fixture', repository: 'monorepo', canonicalRepositoryUrl: 'https://github.com/fixture/monorepo',
  analyzedBranch: 'develop', commitSha: sha, shortCommitSha: sha.slice(0, 7),
  commitTimestamp: '2026-10-14T10:00:00Z', cloneStartedAt: '2026-10-15T10:00:00Z',
  clonedAt: '2026-10-15T10:00:01Z', analyzedAt: '2026-10-15T10:00:02Z', cloneDepth: 1,
  submoduleCount: 1, lfsPointerCount: 1, symlinkCount: 0,
  limitations: ['Submodule은 이번 분석에 포함되지 않았습니다.', 'Git LFS 실제 내용은 분석에서 제외했습니다.'],
});
