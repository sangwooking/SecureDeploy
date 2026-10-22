const {test}=require('node:test');
const assert=require('node:assert/strict');
const React=require('react');
const {renderToStaticMarkup}=require('react-dom/server');
const load=require('./load-component.cjs');
const {ReviewResultWorkspace}=load('ReviewResultWorkspace');
const {ReviewSummaryPanel}=load('ReviewSummaryPanel');
for(const scenario of require('./summary-fixture.cjs')())test(`summary: ${scenario.id}`,()=>{
  const before=JSON.stringify(scenario.result);
  const html=renderToStaticMarkup(React.createElement(ReviewResultWorkspace,{result:scenario.result,view:scenario.view,
    onViewChange(){},statusActions:{updatingId:null,comments:{},onComment(){},onStatus(){}},reportActions:null,progress:null}));
  for(const text of scenario.expected)assert.ok(html.includes(text),text);
  assert.ok(!html.includes('<img src=x'));
  assert.ok(!html.includes('지금 배포해도 될까요?'));
  assert.equal(JSON.stringify(scenario.result),before);
});
test('unsupported summary schema remains historical absence and cannot override BLOCKED',()=>{
  const r=require('./result-fixture.cjs')();r.resultSummary={schemaVersion:999,title:'SAFE'};
  const html=renderToStaticMarkup(React.createElement(ReviewSummaryPanel,{result:r}));
  assert.ok(html.includes('반드시 처리할 문제부터'));assert.ok(!html.includes('SAFE'));
  assert.ok(html.includes('미기록'));
});
