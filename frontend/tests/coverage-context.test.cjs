const { test } = require('node:test');
const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const load = require('./load-component.cjs');
const { AnalysisCoverageSection } = load('AnalysisCoverageSection');
const { DependencyContextDetails, dependencyActionGroups } = load('DependencyContextDetails');
const render = (component, props) => renderToStaticMarkup(React.createElement(component, props));
const path = { declarationFile: 'package.json', declarationLine: 8, declarationSection: 'devDependencies',
  declaredPackage: 'fixture-tool', declaredVersion: '^1.0.0', declarationConfirmed: true, optional: false, peer: false,
  chain: [{ packageName: 'fixture-tool', version: '1.0.0' }, { packageName: 'fixture-leaf', version: '2.0.0' }] };
const component = { ecosystem: 'NPM', packageName: 'fixture-leaf', version: '2.0.0', sourceFile: 'package-lock.json', direct: false,
  context: { schemaVersion: 1, environment: 'DEVELOPMENT', runtimeReachability: 'NOT_ANALYZED', pathsComplete: true,
    installedPath: 'node_modules/fixture-leaf', lockLine: 22, paths: [path], limitations: [], lockFlags: ['dev'] } };

test('coverage differentiates unsupported, excluded, parse errors and not-requested AI from safety', () => {
  const html = render(AnalysisCoverageSection, { coverage: { schemaVersion: 1, status: 'PARTIAL',
    discoveredFiles: 4, selectedFiles: 1, unsupportedFiles: 2, excludedFiles: 1, failedFiles: 0,
    inventoryComplete: false, omittedEntries: 12, analyzers: [{ analyzer: 'RULE_ENGINE', status: 'COMPLETE', scope: '패턴만 검사' }],
    entries: [{ filePath: 'server.py', kind: 'FILE', status: 'UNSUPPORTED', reason: 'NO_SUPPORTED_ANALYZER' },
      { filePath: '<script>.txt', kind: 'FILE', status: 'UNSUPPORTED', reason: 'NO_SUPPORTED_ANALYZER' }] },
    semantic: { semanticReviewStatus: 'NOT_REQUESTED' }, sca: { manifests: [{ filePath: 'package.json', status: 'FAILED', reason: 'UNSUPPORTED_OR_INVALID_MANIFEST' }] } });
  for (const value of ['미지원 2개', '제외 1개', '안전 여부는 별도 확인', '미지원 형식', '실행하지 않음', '12건은 생략']) assert.ok(html.includes(value), value);
  assert.ok(html.includes('&lt;script&gt;'));
  assert.ok(!html.includes('<script>'));
});
test('legacy coverage is unknown, not backfilled with zero counts', () => {
  const html = render(AnalysisCoverageSection, { coverage: null });
  assert.ok(html.includes('범위 기록이 없습니다'));
  assert.ok(!html.includes('미지원 0개'));
});
test('dependency context shows parent edit location and uncertainty, not runtime guarantees', () => {
  for (const env of ['DEVELOPMENT', 'PRODUCTION', 'SHARED', 'UNKNOWN']) {
    const html = render(DependencyContextDetails, { locations: [{ ...component, context: { ...component.context, environment: env } }] });
    for (const value of ['package.json:8', 'package-lock.json:22', 'fixture-tool@1.0.0', '운영 실행 여부나 공격 가능성을 확인한 것은 아닙니다', '권장 버전은 현재 확인하지 못했습니다']) assert.ok(html.includes(value), value);
  }
  assert.ok(render(DependencyContextDetails, { locations: [] }).includes('경로가 없습니다'));
});
test('advisories are grouped by editable parent without being discarded or counting as independent actions', () => {
  const sca = { components: [component], dependencyVulnerabilities: ['FIXTURE-1', 'FIXTURE-2'].map(osvId => ({
    ecosystem: 'NPM', packageName: 'fixture-leaf', installedVersion: '2.0.0', osvId })) };
  const before = JSON.stringify(sca);
  const groups = dependencyActionGroups(sca);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].advisories.size, 2);
  assert.equal(groups[0].label, 'fixture-tool');
  assert.equal(JSON.stringify(sca), before);
});
