const {test}=require('node:test');const assert=require('node:assert/strict');const React=require('react');
const {renderToStaticMarkup}=require('react-dom/server');const {ServerAnalysisSection}=require('./load-component.cjs')('ServerAnalysisSection');
const fixture=require('./server-analysis-fixture.cjs');const resources=require('./resource-fixture.cjs');
test('file and restoration findings retain separate actions and explain filesystem uncertainty',()=>{
  const root=fixture(),py=fixture();root.pythonAnalysis=py;py.validatedFindings=resources();py.findings=py.validatedFindings.flatMap(f=>f.evidence);
  py.resourceUses=py.validatedFindings.map(f=>({ruleId:f.ruleId,kind:f.ruleId.includes('FILE_PATH')?'INPUT_IN_FILE_PATH':'INPUT_TO_UNSAFE_DESERIALIZATION',location:f.location,trace:f.evidence[0].flow,defenses:[],limitations:f.evidence[0].limitations,executionObserved:true}));
  const html=renderToStaticMarkup(React.createElement(ServerAnalysisSection,{snapshot:root}));
  for(const s of ['파일에 접근할 가능성','위험한 방식으로 복원','app/views.py:7','app/views.py:8','YAML SafeLoader','심볼릭 링크','NOT_COMPARED','Java·일반 Node.js 파일 흐름은 이번 범위에 포함되지 않습니다'])assert.ok(html.includes(s),s);
  assert.equal((html.match(/py-flow:synthetic-resource-/g)||[]).length,2);
});
test('unknown resource candidates use the correct title; legacy records are not backfilled',()=>{
  const root=fixture(),py=fixture();root.pythonAnalysis=py;py.validatedFindings=[];py.findings=resources().flatMap(f=>f.evidence);py.findings.forEach(f=>f.confidence='MEDIUM');
  const html=renderToStaticMarkup(React.createElement(ServerAnalysisSection,{snapshot:root}));
  for(const s of ['입력된 파일 경로의 제한','외부 데이터의 복원 방식','파일 접근·데이터 복원 추적 기록이 없습니다'])assert.ok(html.includes(s),s);
});
