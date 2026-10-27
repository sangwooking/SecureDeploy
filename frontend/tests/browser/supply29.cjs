// Real React UI with synthetic API data. Never connects to GitHub or a user database.
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
const fixture=require('../server-analysis-fixture.cjs');
const workspace=require('./workspace-fixture.cjs');
const url=process.env.FRONTEND_URL;if(!url)throw Error('ISOLATED_FRONTEND_URL_REQUIRED');
(async()=>{
 const browser=await chromium.launch({headless:true});
 try{for(const width of [1440,390,320]){
  const page=await browser.newPage({viewport:{width,height:1000}}),errors=[],blocked=[];
  const result=require('../result-fixture.cjs')();result.serverAnalysis=fixture();
  const data=require('../deployment-fixture.cjs')();data.analyzerVersion='deployment-v2';
  data.findings[0]={...data.findings[0],ruleId:'CI_UNTRUSTED_PR_EXECUTION',filePath:'.github/workflows/check.yml',title:'외부 PR 코드 실행 검토',reason:'CWE-829 · 실제 token·secret·승인은 미검증'};
  data.files[0].format='GITHUB_ACTIONS';data.files[0].limitations=['WORKFLOW_DECLARATIONS_NOT_RUNNER_OR_ATTACK_PROOF','ORGANIZATION_TOKEN_SECRETS_AND_ENVIRONMENT_APPROVAL_UNKNOWN'];
  result.serverAnalysis.deploymentAnalysis=data;
  await page.addInitScript(()=>{localStorage.setItem('securedeploy.accessToken','synthetic-supply29-not-authentication');localStorage.setItem('securedeploy.authUser',JSON.stringify({id:1,name:'Local fixture',email:'local@example.invalid'}));});
  page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/*',route=>{const target=new URL(route.request().url());
   if(!target.pathname.startsWith('/api/')){
    if(target.origin===new URL(url).origin)return route.continue();
    blocked.push(target.origin);return route.abort();
   }
   const body=target.pathname==='/api/reviews/101'?result:workspace(target.pathname,result);
   return route.fulfill({status:body?200:404,contentType:'application/json',body:JSON.stringify(body??{})});});
  await page.goto(url+'/#/projects/7/findings');
  await page.getByRole('navigation',{name:'분석 결과 메뉴'}).getByRole('button',{name:'문제 목록',exact:true}).click();
  await page.getByRole('navigation',{name:'문제 우선순위'}).getByRole('button',{name:/배포 전 직접 확인할 부분/}).click();
  const section=page.getByRole('region',{name:'서버·배포 설정 검사',exact:true});
  await section.getByRole('heading',{name:'외부 PR 코드 실행 검토',exact:true}).waitFor();
  await section.getByText('설정 근거와 한계',{exact:true}).click();
  await section.getByText('설정 파일별 검사 범위 (1)',{exact:true}).click();
  await section.getByText(/compose.yaml · GITHUB_ACTIONS/).click();
  const text=await section.innerText();
  for(const s of ['NOT_COMPARED','Actions·shell을 실행하거나','조직 권한·실제 token','점수·배포 판단·반드시 처리 건수에 합산하지 않습니다'])assert.ok(text.includes(s),s);
  assert.ok(!text.includes('자동 수정안 만들기'));assert.ok(!text.includes('AI 수정안 만들기'));
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
  assert.deepEqual(errors,[]);assert.deepEqual(blocked,[]);
  console.log(JSON.stringify({width,deploymentEvidence:'PASS',automaticPatches:0,externalRequests:0}));await page.close();
 }}finally{await browser.close();}
})().catch(e=>{console.error('Owned UI check failed:',e.message);process.exitCode=1;});
