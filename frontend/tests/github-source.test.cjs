const { test } = require('node:test');
const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const load = require('./load-component.cjs');
const source = require('./github-source-fixture.cjs');
const progress = require('./progress-fixture.cjs');
const { GitHubSourceInfo, GitHubCommitComparison } = load('GitHubSourceInfo');
const { ReviewProgressPanel } = load('ReviewProgressPanel');
const render = (component, props) => renderToStaticMarkup(React.createElement(component, props));

test('source metadata shows non-main branch, full SHA, acquisition time and excluded scopes', () => {
  const html = render(GitHubSourceInfo, { source: source() });
  for (const text of ['fixture/monorepo', 'develop', 'a'.repeat(40), '수집 완료', 'Submodule', 'Git LFS', '안전을 보장하지 않습니다']) assert.ok(html.includes(text));
  assert.ok(render(GitHubSourceInfo, {}).includes('저장된 branch / commit 정보가 없습니다'));
});
test('repository metadata is escaped, never treated as HTML', () => {
  const html = render(GitHubSourceInfo, { source: { ...source(), analyzedBranch: '<img src=x onerror=alert(1)>' } });
  assert.ok(!html.includes('<img')); assert.ok(html.includes('&lt;img'));
});
test('same commit requires exact full SHA and repository identity', () => {
  const before = source();
  assert.ok(render(GitHubCommitComparison, { before, after: source() }).includes('이전 검사와 동일한 commit입니다.'));
  const after = source('a'.repeat(7) + 'b'.repeat(33));
  assert.ok(render(GitHubCommitComparison, { before, after }).includes('서로 다른 commit'));
  assert.ok(!render(GitHubCommitComparison, { before, after: { ...before, canonicalRepositoryUrl: 'https://github.com/fixture/other' } }).includes('동일한 commit'));
  assert.ok(render(GitHubCommitComparison, { before }).includes('변경 여부를 확인할 수 없습니다'));
});
test('commit comparison preserves deterministic progress assessment and immutable result', () => {
  const result = progress(); result.comparison.sourceBefore = source(); result.comparison.sourceAfter = source('b'.repeat(40));
  const saved = JSON.stringify(result), html = render(ReviewProgressPanel, { result });
  assert.ok(html.includes('aaaaaaa')); assert.ok(html.includes('bbbbbbb'));
  assert.ok(html.includes('Commit 변경 여부만으로 보안 개선을 판단하지 않습니다'));
  assert.ok(html.includes('해결된 문제 1')); assert.equal(JSON.stringify(result), saved);
});
