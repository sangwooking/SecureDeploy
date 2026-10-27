const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const { RecentProjects, ProjectList } = require('./load-component.cjs')('WorkspaceSummary');

function luminance(hex) {
  const c = hex.match(/[a-f\d]{2}/gi).map(v => parseInt(v, 16) / 255).map(v => v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4);
  return c[0] * 0.2126 + c[1] * 0.7152 + c[2] * 0.0722;
}
test('shared text, action and status token pairs meet normal-text AA contrast', () => {
  const css = fs.readFileSync('src/renovation.css', 'utf8');
  const token = name => css.match(new RegExp(`--${name}: (#[a-f\\d]{6})`, 'i'))[1];
  const pairs = [[token('ink'), token('canvas')], [token('muted'), token('canvas')],
    [token('accent'), '#ffffff'], ['#ffffff', token('accent')], ['#991b1b', '#fff1f2'],
    ['#854d0e', '#fffbeb'], ['#16604e', '#f0f9f4'], ['#78350f', '#fffbeb']];
  for (const [foreground, background] of pairs) {
    const a = luminance(foreground), b = luminance(background);
    assert.ok((Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05) >= 4.5, `${foreground} on ${background}`);
  }
});
test('dashboard rows show saved policy while coverage is fetched only in the result', () => {
  const project = { projectId: 1, name: '<img src=x onerror=alert(1)>', latestReview: {
    createdAt: '2026-10-28T00:00:00Z', riskSummary: { deploymentAssessment: 'READY', prioritySummary: { BLOCKING: 0, REVIEW_REQUIRED: 2, SHOULD_FIX: 3 } },
  } };
  const before = JSON.stringify(project);
  const html = renderToStaticMarkup(React.createElement(RecentProjects, { projects: [project] }));
  assert.ok(html.includes('결과에서 확인')); assert.ok(html.includes('policy-ready'));
  assert.ok(!html.includes('<img')); assert.ok(!html.includes('PARTIAL'));
  assert.equal(JSON.stringify(project), before);
  const compact = renderToStaticMarkup(React.createElement(ProjectList, { projects: [project] }));
  assert.ok(!compact.includes('policy-ready')); assert.ok(compact.includes('project-menu-trigger'));
});
test('missing dashboard review stays unassessed without fabricated score or coverage', () => {
  const html = renderToStaticMarkup(React.createElement(RecentProjects, { projects: [{ projectId: 1, name: 'Empty', latestReview: null }] }));
  assert.ok(html.includes('분석 결과 없음')); assert.equal((html.match(/<dd>미평가<\/dd>/g) || []).length, 3);
  assert.ok(!html.includes('100')); assert.ok(!html.includes('policy-ready'));
});
