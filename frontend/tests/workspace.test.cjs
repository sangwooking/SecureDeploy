const { test } = require('node:test');
const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const load = require('./load-component.cjs');
const { parseWorkspaceRoute, projectLink } = load('workspaceRoute');
const { WorkspaceSummary, ProjectList, PriorityCounts, ProgressBrief, reviewStatus } = load('WorkspaceSummary');
const render = (Component, props) => renderToStaticMarkup(React.createElement(Component, props));
const result = require('./result-fixture.cjs')();
const riskSummary = { deploymentAssessment: 'BLOCKED', prioritySummary: result.riskAssessment.prioritySummary, semanticCandidateCount: 1, referenceSecurityScore: 100 };
const project = { projectId: 7, name: '<script>private</script>', sourceType: 'ZIP', repositoryUrl: null,
  reviewCount: 3, createdAt: '2026-10-14T00:00:00Z', updatedAt: '2026-10-14T01:00:00Z',
  latestReview: { ...result, createdAt: '2026-10-14T01:00:00Z', riskSummary }, latestProgress: null };

test('workspace routes default to dashboard and preserve project/review/view identity', () => {
  assert.deepEqual(parseWorkspaceRoute(''), { page: 'dashboard' });
  assert.deepEqual(parseWorkspaceRoute(projectLink(7, 'findings', 101, 'PROGRESS')),
    { page: 'project', projectId: 7, tab: 'findings', reviewId: 101, view: 'PROGRESS' });
  assert.equal(parseWorkspaceRoute('#/projects/7/overview?review=101').reviewId, undefined);
  for (const hash of ['#/projects/0', '#/projects/1?review=-1', '#/projects/1?review=oops', '#/projects/9007199254740992', '#/unknown']) assert.equal(parseWorkspaceRoute(hash).page, 'not-found');
});
test('dashboard counts and project assessment are backend values, not derived from legacy score', () => {
  const data = { projectCount: 10, blockedProjectCount: 4, reviewRequiredProjectCount: 2, analyzedProjectCount: 8, unassessedProjectCount: 2, projects: [project] };
  const before = JSON.stringify(data), html = render(WorkspaceSummary, { data, name: 'Fixture' });
  assert.match(html, /관리 중인 프로젝트<\/dt><dd>10<\/dd>/);
  assert.match(html, /배포 전 수정 필요<\/dt><dd>4<\/dd>/);
  assert.ok(html.includes('배포 전 수정 필요'));
  assert.ok(!html.includes('100'));
  assert.equal(JSON.stringify(data), before);
  assert.ok(!html.includes('<script>'));
});
test('missing reviews or assessment never become READY or zero assessed risk', () => {
  assert.equal(reviewStatus(null), '분석 결과 없음');
  assert.equal(reviewStatus({ ...project.latestReview, riskSummary: null }), '위험 평가 미저장');
  assert.ok(render(PriorityCounts, {}).includes('미평가'));
  assert.ok(render(ProjectList, { projects: [] }).includes('새 프로젝트 분석'));
});
test('project list contains only linked names and compact saved counts, never duplicate open links or history',()=>{
  const saved=JSON.stringify(project),html=render(ProjectList,{projects:[project]});
  assert.equal((html.match(/<a /g)||[]).length,1);
  assert.ok(html.includes('href="#/projects/7/overview"'));
  assert.ok(html.includes('&lt;script&gt;private&lt;/script&gt;'));
  for(const [label,key] of [['반드시 처리','BLOCKING'],['배포 전 확인','REVIEW_REQUIRED'],['수정 권장','SHOULD_FIX']])
    assert.ok(html.includes(`<dt>${label}</dt><dd>${riskSummary.prioritySummary[key]}</dd>`));
  for(const removed of ['프로젝트 열기','최근 분석:','총 분석:','배포 전 수정 필요','비교할 이전 분석','참고 점수'])assert.ok(!html.includes(removed),removed);
  assert.equal(JSON.stringify(project),saved);
});
test('compact project counts distinguish zero from absent reviews, absent assessment and partial counts',()=>{
  for(const latestReview of [null,{...project.latestReview,riskSummary:null}]){
    const html=render(ProjectList,{projects:[{...project,latestReview}]});
    assert.equal((html.match(/<dd>미평가<\/dd>/g)||[]).length,3);assert.ok(!html.includes('<dd>0</dd>'));
  }
  const html=render(PriorityCounts,{compact:true,assessment:{...riskSummary,prioritySummary:{BLOCKING:0}}});
  assert.ok(html.includes('<dd>0</dd>'));assert.equal((html.match(/<dd>미평가<\/dd>/g)||[]).length,2);
  assert.ok(render(PriorityCounts,{assessment:riskSummary}).includes('배포 전 직접 확인'));
});
test('progress respects all five saved states and unavailable never masquerades as resolved', () => {
  const counts = { RESOLVED: 3, REMAINING: 2, NEW: 1, CHANGED: 4, UNAVAILABLE: 5 };
  const html = render(ProgressBrief, { progress: { status: 'PARTIAL', baselineReviewId: 1, counts, message: 'fixture' } });
  for (const text of ['해결됨 3', '남아 있음 2', '새로 발견 1', '변경됨 4', '확인 불가 5', '해결로 처리하지 않습니다']) assert.ok(html.includes(text));
  const unknown = render(ProgressBrief, { progress: { status: 'UNAVAILABLE', counts, message: '근거 부족' } });
  assert.ok(unknown.includes('변화 확인 불가')); assert.ok(!unknown.includes('해결됨 3'));
});
