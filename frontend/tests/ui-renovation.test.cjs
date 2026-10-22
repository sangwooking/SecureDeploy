const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),React=require('react');
const {renderToStaticMarkup}=require('react-dom/server'),load=require('./load-component.cjs');
test('default project results open summary without changing explicitly linked priority views',()=>{
 const {parseWorkspaceRoute}=load('workspaceRoute');assert.equal(parseWorkspaceRoute('#/projects/1/findings').view,'SUMMARY');
 assert.equal(parseWorkspaceRoute('#/projects/1/findings?view=BLOCKING').view,'BLOCKING');
});
test('editor stages retain mounted scan and proposal state while separating visible surfaces',()=>{
 const s=fs.readFileSync('src/components/SourceEditingWorkspace.tsx','utf8');
 for(const text of ["hidden={stage!=='scan'}","hidden={stage!=='diff'}","hidden={stage!=='edit'}",'securedeploy:before-navigate','beforeunload','initialPath'])assert.ok(s.includes(text),text);
 assert.ok(!s.includes("stage==='scan' && <WorkspaceScanPanel"));
 const shell=fs.readFileSync('src/components/Workspace.tsx','utf8');assert.ok(shell.includes('event.defaultPrevented'));assert.ok(shell.includes('history.replaceState'));
});
test('scope and failed inspections remain visible outside collapsed technical details',()=>{
 const {ReviewSummaryPanel}=load('ReviewSummaryPanel');const result=require('./result-fixture.cjs')();
 result.resultSummary={schemaVersion:1,title:'확인 필요',reason:'부분 검사',coverageStatus:'PARTIAL',analyzers:[{analyzer:'synthetic',observations:{AST_PARSE_FAILED:2}}]};
 const html=renderToStaticMarkup(React.createElement(ReviewSummaryPanel,{result}));
 assert.ok(html.indexOf('완료하지 못한 검사')<html.indexOf('class="summary-detail"'));assert.ok(html.includes('구문 파싱 실패 2개'));assert.ok(html.includes('전체 안전 점수가 아닙니다'));
});
test('common surfaces have responsive spacing, focus and minimum interaction sizes',()=>{
 const css=fs.readFileSync('src/renovation.css','utf8');
 for(const text of ['--space-lg: 24px','--space-md: 16px',':focus-visible','min-height: 44px','[hidden]','max-width: 800px','prefers-reduced-motion'])assert.ok(css.includes(text),text);
 assert.ok(!css.includes('vw;'));assert.ok(!css.includes('linear-gradient'));
});
