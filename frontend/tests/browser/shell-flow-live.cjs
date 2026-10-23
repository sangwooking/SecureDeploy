// Actual isolated H2 API + React, synthetic source only. No target execution.
const {chromium,request}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict'),{execFileSync}=require('node:child_process');
const {resultView}=require('./editor-navigation.cjs');
const origin=process.env.FRONTEND_ORIGIN||'http://127.0.0.1:5174',api='http://127.0.0.1:8085';
const sql=process.env.FLOW_KIND==='sequelize';
(async()=>{const browser=await chromium.launch(),http=await request.newContext({baseURL:api});
try{
 const signup=await http.post('/api/auth/signup',{data:{email:`shell-${Date.now()}@example.invalid`,name:'synthetic',password:'Synthetic-Local-813!'}});
 assert.equal(signup.status(),200);const user=await signup.json(),headers={Authorization:`Bearer ${user.accessToken}`};
 const reports=[];
 const cases=sql?[['input',"db.query('SELECT value FROM records WHERE id='+req.body.value)",1],['binding',"db.query('SELECT value FROM records WHERE id=$1',{bind:[req.body.value]})",0]]
   :[['input',"cp.exec('fixed '+req.body.value)",1],['argv',"cp.execFile('fixed',['arg',req.body.value])",0]];
 for(const [name,body,count]of cases){
  const files={'package.json':JSON.stringify({dependencies:{express:'4.21.2',...(sql?{sequelize:'4.13.10'}:{})}}),'server.cjs':`const express=require('express');const app=express();${sql?"const db=require('./store').sequelize;":"const cp=require('node:child_process');"}app.set('port',process.env.PORT||3001);app.post('/work',(req,res)=>{${body};});app.get('env');`};
  if(sql){
   files['store/index.js']="const fs=require('fs');const path=require('path');const E=require('sequelize');const connection=new E('unused');const db={};fs.readdirSync(__dirname).filter(function(file){return(file.indexOf('.')!==0)&&(file!=='index.js');}).forEach(function(file){var model=connection.import(path.join(__dirname,file));db[model.name]=model;});db.sequelize=connection;module.exports=db;";
   files['store/item.js']="module.exports=function(c,T){return c.define('Item',{id:{type:T.INTEGER}});};";
  }
  const zip=execFileSync('python3',['-c',"import io,sys,json,zipfile\nb=io.BytesIO()\nwith zipfile.ZipFile(b,'w',zipfile.ZIP_DEFLATED) as z:\n for p,s in json.load(sys.stdin).items(): z.writestr(p,s)\nsys.stdout.buffer.write(b.getvalue())"],{input:JSON.stringify(files)});
  const response=await http.post('/api/reviews/upload',{headers,multipart:{scanMode:'STANDARD',file:{name:'synthetic.zip',mimeType:'application/zip',buffer:zip}}});
  assert.equal(response.status(),200);const review=await response.json();
  assert.equal(review.serverAnalysis.validatedFindings.length,count);assert.equal(review.securityScore,100);
  if(!count){assert.ok(review.serverAnalysis.nodeUses.some(u=>u.kind===(sql?'STATIC_OR_DATA_ONLY':'ARGV_WITHOUT_SHELL_DECLARED')));continue;}
  const finding=review.serverAnalysis.validatedFindings[0];
  assert.equal(finding.ruleId,sql?'JS_SEQUELIZE_SQL_INPUT_FLOW':'JS_SHELL_COMMAND_INPUT_FLOW');assert.equal(finding.comparisonPolicy,'NOT_COMPARED');
  if(sql)assert.ok(review.serverAnalysis.nodeUses.some(u=>u.kind==='INITIALIZATION_SUMMARY_MUST'));
  for(const width of [1440,390,320]){
   const page=await browser.newPage({viewport:{width,height:1000}}),errors=[],outbound=[];
   page.on('pageerror',e=>errors.push(e.message));
   await page.addInitScript(auth=>{localStorage.setItem('securedeploy.accessToken',auth.accessToken);localStorage.setItem('securedeploy.authUser',JSON.stringify(auth.user));},user);
   // Test-only transport proxy: production CORS remains restricted to localhost:5173.
   await page.route('**/*',async r=>{const u=new URL(r.request().url());if(u.pathname.startsWith('/api/')){
    const response=await r.fetch({url:api+u.pathname+u.search,headers:{...r.request().headers(),origin:'http://localhost:5173'}});
    return r.fulfill({response,headers:{...response.headers(),'access-control-allow-origin':origin}});
   }if(u.origin===origin)return r.continue();outbound.push(u.origin);return r.abort();});
   await page.goto(`${origin}/#/projects/${review.projectId}/findings?review=${review.reviewId}&view=SUMMARY`);await resultView(page,'배포 전 직접 확인할 부분');
   const section=page.getByLabel('서버 코드 흐름 검사',{exact:true});await section.waitFor();
   assert.ok((await section.innerText()).includes(sql?'실행 문자열':'명령 문자열'));assert.ok((await section.innerText()).includes('server.cjs:1'));
   const details=section.locator('.flow-action-details > summary').first();await details.focus();await page.keyboard.press('Enter');
   assert.ok(await section.getByLabel('기록된 코드 전달 경로').first().isVisible());
   assert.ok((await section.innerText()).includes('요청 본문'));assert.ok((await section.innerText()).includes(sql?'CWE-89':'CWE-78'));
   assert.ok(await section.getByRole('button',{name:'이 파일 수정하기',exact:true}).isVisible());
   assert.equal(await page.getByRole('button',{name:'자동 수정안 만들기',exact:true}).count(),0);
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));assert.deepEqual(errors,[]);assert.deepEqual(outbound,[]);
   await page.screenshot({path:`/private/tmp/securedeploy-${sql?'sequelize':'shell'}-flow-${width}.png`,fullPage:true});await page.close();reports.push({width,candidates:count,score:review.securityScore,coverage:review.coverage.status});
  }
 }
 console.log(JSON.stringify({passed:true,backend:'ACTUAL_H2',targetExecuted:false,providerCalls:0,reports}));
}finally{await browser.close();await http.dispose();}})().catch(e=>{console.error(e.stack);process.exitCode=1;});
