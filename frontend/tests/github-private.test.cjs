const { test } = require('node:test');
const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const load = require('./load-component.cjs');
const { GitHubSourceInfo } = load('GitHubSourceInfo');
const { NewProjectAnalysis } = load('NewProjectAnalysis');
const { ProjectList } = load('WorkspaceSummary');
const render = (component, props) => renderToStaticMarkup(React.createElement(component, props));

test('connected source metadata distinguishes private read-only access and preserves commit identity', () => {
  const source = { owner: '<script>owner</script>', repository: 'private-fixture', analyzedBranch: 'develop',
    shortCommitSha: 'a'.repeat(7), commitSha: 'a'.repeat(40), limitations: [], accessMethod: 'GITHUB_APP', privateRepository: true };
  const html = render(GitHubSourceInfo, { source });
  assert.ok(html.includes('비공개 저장소')); assert.ok(html.includes('읽기 전용'));
  assert.ok(html.includes('develop')); assert.ok(html.includes('a'.repeat(40)));
  assert.ok(!html.includes('<script>'));
});
test('new analysis preserves ZIP/public URL and offers connected repositories with external-data disclosure', () => {
  const html = render(NewProjectAnalysis, { policy: null, policyError: '', retryPolicy() {}, onComplete() {} });
  for (const text of ['ZIP 업로드', 'GitHub URL 입력', '연결된 GitHub 저장소', '패키지 이름', 'OSV', '비공개 패키지']) assert.ok(html.includes(text));
  assert.ok(!html.includes('checked=""'));
});
test('compact project list does not infer safety from missing analysis or expose source metadata', () => {
  const project = { projectId: 1, name: 'private-fixture', sourceType: 'GITHUB', githubRepositoryId: 20,
    privateRepository: true, latestReview: null, latestProgress: null, reviewCount: 0 };
  const html = render(ProjectList, { projects: [project] });
  assert.ok(!html.includes('비공개'));assert.ok(html.includes('private-fixture'));
  assert.equal((html.match(/<dd>미평가<\/dd>/g)||[]).length,3);
  assert.ok(!html.includes('배포 가능'));
});
