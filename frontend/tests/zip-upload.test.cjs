const test = require('node:test');
const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const load = require('./load-component.cjs');
const policy = require('./upload-policy-fixture.cjs');
const { validateZipUpload } = load('zipUploadValidation');
const { ZipUploadGuidance } = load('ZipUploadGuidance');
const { RescanForm } = load('RescanForm');

test('ZIP size boundaries use the server policy for new scans and rescans', () => {
  assert.equal(validateZipUpload({ name: 'ok.ZIP', size: policy.maxZipBytes }, policy), '');
  assert.equal(validateZipUpload({ name: 'ok.zip', size: policy.maxZipBytes - 1 }, policy), '');
  assert.match(validateZipUpload({ name: 'large.zip', size: policy.maxZipBytes + 1 }, policy), /최대 200MB/);
  assert.match(validateZipUpload({ name: 'large.zip', size: 3 }, { ...policy, maxZipBytes: 2, maxZipLabel: '2B' }), /최대 2B/);
});
test('missing policy never invents a size and invalid inputs are rejected', () => {
  assert.match(validateZipUpload({ name: 'ok.zip', size: 1 }, null), /제한을 확인하지 못/);
  assert.match(validateZipUpload(null, policy), /선택/);
  assert.match(validateZipUpload({ name: 'source.jar', size: 1 }, policy), /ZIP 형식/);
  assert.match(validateZipUpload({ name: 'empty.zip', size: 0 }, policy), /비어/);
  const html = renderToStaticMarkup(React.createElement(ZipUploadGuidance, { policy: null, error: '조회 실패', onRetry() {} }));
  assert.ok(html.includes('role="alert"'));
  assert.ok(html.includes('제한 정보 다시 확인'));
  assert.ok(!html.includes('200MB'));
});
test('shared guidance and rescan expose server limits and folder hint', () => {
  const props = { result: { projectName: 'Fixture', sourceType: 'ZIP' }, onScan() {}, onCancel() {}, uploadPolicy: policy };
  const html = renderToStaticMarkup(React.createElement(RescanForm, props));
  assert.ok(html.includes('ZIP 파일 최대 200MB'));
  assert.ok(html.includes('node_modules, .git, build, dist, target'));
  const unavailable = renderToStaticMarkup(React.createElement(RescanForm, { ...props, uploadPolicy: null }));
  assert.ok(unavailable.includes('disabled=""'));
  const github = renderToStaticMarkup(React.createElement(RescanForm, { ...props, result: { ...props.result, sourceType: 'GITHUB' }, uploadPolicy: null }));
  assert.ok(!github.includes('disabled=""'));
});
