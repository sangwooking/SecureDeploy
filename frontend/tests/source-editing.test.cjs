const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const React=require('react');
const {renderToStaticMarkup}=require('react-dom/server');
const {SourceEditingWorkspace}=require('./load-component.cjs')('SourceEditingWorkspace');
test('ZIP acquisition is explicit and legacy source identity is never assumed',()=>{
  const result={...require('./result-fixture.cjs')(),sourceType:'ZIP',reviewId:4,projectName:'<script>fixture</script>'};
  const html=renderToStaticMarkup(React.createElement(SourceEditingWorkspace,{result,onBack(){}}));
  assert.ok(html.includes('과거 ZIP과 일치하는지 검증할 기록이 없습니다'));
  assert.ok(html.includes('원본 확보 후 작업 공간 시작'));assert.ok(html.includes('disabled'));
  assert.ok(!html.includes('<script>'));assert.ok(html.includes('&lt;script&gt;'));
});
test('GitHub acquisition is exact-revision and source is never rendered or executed',()=>{
  const result={...require('./result-fixture.cjs')(),sourceType:'GITHUB',reviewId:4};
  const html=renderToStaticMarkup(React.createElement(SourceEditingWorkspace,{result,onBack(){}}));
  assert.ok(html.includes('분석 당시 commit만'));assert.ok(!html.includes('type="file"'));
  const source=fs.readFileSync('src/components/SourceEditingWorkspace.tsx','utf8');
  for(const denied of ['dangerouslySetInnerHTML','iframe','eval(','srcDoc'])assert.ok(!source.includes(denied));
  assert.ok(source.includes('loadEditingDiff'));assert.ok(source.includes('value.revision !== workspace.revision'));
  assert.ok(source.includes('UNVERIFIED_REUPLOAD'));assert.ok(source.includes('EXACT_GIT_COMMIT'));
});
test('editing uses owned IDs and explicit revision-bound export approval; source is not browser-persisted',()=>{
  const api=fs.readFileSync('src/api/editingApi.ts','utf8');
  assert.ok(api.includes('originalHash: file.originalHash'));assert.ok(api.includes('revision: workspace.revision'));
  assert.ok(api.includes('changedFileIds: workspace.changedFileIds'));assert.ok(api.includes('approved: true'));
  const source=fs.readFileSync('src/components/SourceEditingWorkspace.tsx','utf8');
  assert.ok(!source.includes('localStorage'));assert.ok(source.includes('sessionStorage.setItem(key, value.id)'));
  assert.ok(!source.includes('sessionStorage.setItem(key, text)'));assert.ok(source.includes('편집 후 줄 위치는 달라질 수 있습니다'));
});
