const {test}=require('node:test'),assert=require('node:assert/strict'),React=require('react'),{renderToStaticMarkup}=require('react-dom/server'),load=require('./load-component.cjs');
const {WorkspaceComparisonOverview,WorkspaceDiffReview}=load('WorkspaceOutcome'),{DependencyAdviceResult}=load('DependencyAiAdvicePanel'),{providerOriginLabel,changeOriginLabel}=load('EvidenceSupportLayout');
const render=(C,p)=>renderToStaticMarkup(React.createElement(C,p));
test('comparison shows saved advisory items without deriving safety or mutating risk',()=>{
 const before={reviewId:10,sca:{status:'COMPLETE',dependencyVulnerabilities:[1,2,3,4]}};const after={reviewId:11,sca:{status:'COMPLETE',dependencyVulnerabilities:[1]},workspaceScan:{baselineVerified:true,originalReviewId:10},comparison:{status:'PARTIAL'},coverage:{status:'PARTIAL'}};
 const original=JSON.stringify([before,after]),html=render(WorkspaceComparisonOverview,{original:before,modified:after});assert.match(html,/<strong>4<\/strong>/);assert.match(html,/<strong>1<\/strong>/);assert.ok(html.includes('NOT_VERIFIED'));assert.ok(html.includes('전체 웹사이트 안전성도 미검증'));assert.equal(JSON.stringify([before,after]),original);
 for(const patch of [{workspaceScan:{baselineVerified:false,originalReviewId:10}},{comparison:{status:'UNAVAILABLE'}},{comparison:null},{sca:{status:'PARTIAL',dependencyVulnerabilities:[]}}])assert.ok(!render(WorkspaceComparisonOverview,{original:before,modified:{...after,...patch}}).includes('comparison-pair'));
});
test('missing model output is never replaced with an invented recommendation',()=>{
 const view={state:'GENERATED',provider:{origin:'OPENAI'},output:null};assert.equal(render(DependencyAdviceResult,{view}),'');
 const output={packageName:'<script>library</script>',lockedVersion:'1.0.0',candidateVersion:'1.0.1',decision:'NEEDS_REVIEW',explanation:'미확인',whyItMatters:'조건 확인',recommendedAction:'검토',verificationSteps:[],uncertainties:[]};const html=render(DependencyAdviceResult,{view:{...view,output}});assert.ok(!html.includes('version-proposal'));assert.ok(html.includes('&lt;script&gt;library&lt;/script&gt;'));assert.ok(!html.includes('AI 추천 버전'));assert.equal(render(DependencyAdviceResult,{view:{...view,state:'FAILED',output}}),'');
});
test('recorded OpenAI, Mock, unknown origin and package-manager edits are explicit',()=>{
 assert.ok(providerOriginLabel('ARCHIVED_OPENAI').includes('새 호출 없음'));assert.ok(providerOriginLabel('MOCK').includes('실제 모델 미검증'));assert.ok(providerOriginLabel('invented').includes('미확인'));
 const html=render(WorkspaceDiffReview,{files:[{path:'package-lock.json',patch:'- "version": "1.0.0"\n+ "version": "1.0.1"',origin:'PACKAGE_MANAGER_APPROVED'}]});assert.ok(html.includes('패키지 관리자 생성 · 사용자 승인'));assert.ok(!html.includes('승인된 AI 코드 수정'));assert.equal(changeOriginLabel('unknown'),'수정 출처 미기록');
});
test('project ordering uses saved policy without changing the original list',()=>{
 const {importantProjects}=load('WorkspaceSummary');const rows=[{projectId:1,latestReview:{createdAt:'2026-01-01',riskSummary:{deploymentAssessment:'READY'}}},{projectId:2,latestReview:{createdAt:'2025-01-01',riskSummary:{deploymentAssessment:'BLOCKED'}}},{projectId:3,latestReview:null}];const prior=JSON.stringify(rows);assert.deepEqual(importantProjects(rows).map(p=>p.projectId),[2,1,3]);assert.equal(JSON.stringify(rows),prior);
});
test('canonical CVE and source GHSA aliases link only within the same package and version',()=>{
 const {sameDependencyAdvisory}=load('DependencyUpdatePlans');const dep={ecosystem:'NPM',packageName:'library',installedVersion:'1.0.0',osvId:'CVE-2026-11111',aliases:['GHSA-ABCD-1234-TEST']};const plan={ecosystem:'NPM',packageName:'library',lockedVersion:'1.0.0',advisoryId:'GHSA-abcd-1234-test',aliases:[]};
 assert.equal(sameDependencyAdvisory(dep,plan),true);assert.equal(sameDependencyAdvisory(dep,{...plan,packageName:'other'}),false);assert.equal(sameDependencyAdvisory(dep,{...plan,lockedVersion:'2.0.0'}),false);assert.equal(sameDependencyAdvisory(dep,{...plan,advisoryId:'GHSA-other'}),false);
});
test('short model lead preserves version decimals and keeps the full statement when no boundary exists',()=>{const {adviceLead}=load('DependencyAiAdvicePanel');assert.equal(adviceLead('1.2.3 버전을 검토하세요. 호환성은 미확인입니다.'),'1.2.3 버전을 검토하세요.');assert.equal(adviceLead('검토 필요'),'검토 필요');});
test('the reusable advisory badge is a server item count, not a vulnerability claim',()=>{const {AdvisoryItemCount}=load('EvidenceSupportLayout');const html=render(AdvisoryItemCount,{count:12});assert.match(html,/<strong>12<\/strong>/);assert.ok(html.includes('공지 항목'));assert.ok(!html.includes('취약점'));});
