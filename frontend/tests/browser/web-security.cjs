// Synthetic API data, real React UI. No GitHub, provider or user database requests.
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
const fixture=require('../server-analysis-fixture.cjs');
const workspace=require('./workspace-fixture.cjs');
const url=process.env.FRONTEND_URL;if(!url)throw Error('ISOLATED_FRONTEND_URL_REQUIRED');
(async()=>{
 const browser=await chromium.launch({headless:true});
 try{for(const width of [1440,390,320]){
  const page=await browser.newPage({viewport:{width,height:1000}}),errors=[],blocked=[];
  const result=require('../result-fixture.cjs')();const data=fixture();result.serverAnalysis=data;
  const template=data.validatedFindings[0],evidence=data.findings[0];
  data.validatedFindings=[['JS_RATE_LIMIT_BYPASS_REVIEW','요청 제한을 건너뛰고 서버 작업으로 이어지는 설정을 확인해 주세요'],['JS_CORS_CREDENTIAL_REFLECTION','민감 응답에 적용된 CORS 출처 설정을 확인해 주세요'],
   ['JS_SESSION_COOKIE_ATTRIBUTE_REVIEW','세션 쿠키의 HttpOnly 해제 설정을 확인해 주세요']].map(([ruleId,title],i)=>({
    ...template,findingId:'ts-flow:web27-'+i,ruleId,title,
    riskExplanation:'저장소 선언 근거이며 실제 인증 성공·브라우저 열람·운영 적용은 미검증입니다.',
    recommendedAction:'소유한 로컬 환경에서 허용·비허용 요청과 정상 동작을 확인하세요.',
    evidence:[{...evidence,ruleId,limitations:['DECLARED_POLICY_NOT_BROWSER_OR_AUTHENTICATION_PROOF','PROXY_TLS_AND_DEPLOYMENT_UNKNOWN']}]}));
  data.findings=data.validatedFindings.flatMap(f=>f.evidence);
  data.nodeUses=[{ruleId:'JS_WEB_SECURITY_CONTEXT',kind:'CSRF_CONTEXT_UNVERIFIED',operation:'WEB_RESPONSE_POLICY',location:evidence.sink,trace:[],limitations:['COOKIE_AUTHENTICATION_NOT_PROVEN','CSRF_DEFENSE_UNKNOWN']}];
  await page.addInitScript(()=>{localStorage.setItem('securedeploy.accessToken','synthetic-web27-not-authentication');localStorage.setItem('securedeploy.authUser',JSON.stringify({id:1,name:'Local fixture',email:'local@example.invalid'}));});
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
  const section=page.getByRole('region',{name:'서버 코드 흐름 검사',exact:true});
  for(const f of data.validatedFindings)await section.getByRole('heading',{name:f.title,exact:true}).waitFor();
  for(const d of await section.getByText('Finding 기술 근거와 한계',{exact:true}).all())await d.click();
  await section.getByText('Express 코드 실행·데이터 접근 근거 (1)',{exact:true}).click();
  const text=await section.innerText();
  for(const s of ['NOT_COMPARED','인증 방식·상태 변경·CSRF 보호를 추가 확인','실제 인증 성공·브라우저 열람·운영 적용은 미검증'])assert.ok(text.includes(s),s);
  assert.ok(!text.includes('자동 수정안 만들기'));assert.ok(!text.includes('AI 수정안 만들기'));
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
  assert.deepEqual(errors,[]);assert.deepEqual(blocked,[]);
  console.log(JSON.stringify({width,webPolicyEvidence:'PASS',automaticPatches:0,externalRequests:0}));await page.close();
 }}finally{await browser.close();}
})().catch(e=>{console.error('Owned UI check failed:',e.message);process.exitCode=1;});
