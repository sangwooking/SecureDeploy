// Synthetic text is scanned, never built or executed. Actual H2 API and React UI.
const {chromium,request}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict'),{execFileSync}=require('node:child_process');
const {resultView}=require('./editor-navigation.cjs');
const origin='http://127.0.0.1:5174',api='http://127.0.0.1:8085';
(async()=>{const browser=await chromium.launch(),http=await request.newContext({baseURL:api});
try{
 const signup=await http.post('/api/auth/signup',{data:{email:`modern-${Date.now()}@example.invalid`,name:'synthetic',password:'Synthetic-Local-813!'}});
 assert.equal(signup.status(),200);const user=await signup.json(),headers={Authorization:`Bearer ${user.accessToken}`},reports=[];
 for(const layout of ['root','src']){
  const prefix=layout==='src'?'src/':'',files={
   'package.json':JSON.stringify({dependencies:{next:'15.2.0'}}),
   'tsconfig.json':JSON.stringify({compilerOptions:{baseUrl:prefix||'.',paths:{'~/*':['*']}}}),
   [prefix+'lib/client.ts']:"import {createServerClient} from '@supabase/ssr';export function make(){const jar=cookies();return createServerClient('https://example.invalid',process.env.PUBLIC_ANON_KEY,{cookies:{getAll(){return jar.getAll();}}});}",
   [prefix+'app/api/items/route.ts']:"import {make} from '~/lib/client';export async function POST(){const db=await make();const {data:{user}}=await db.auth.getUser();if(!user)throw new Error('missing');return Response.json(await db.from('items').update({}).eq('user_id',user.id));}",
   'supabase/migrations/20260101000000_items.sql':"CREATE TABLE public.items(user_id uuid);ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;GRANT UPDATE ON public.items TO authenticated;CREATE POLICY p ON public.items FOR UPDATE TO authenticated USING(true) WITH CHECK(true);"};
  const zip=execFileSync('python3',['-c',"import io,sys,json,zipfile\nb=io.BytesIO()\nwith zipfile.ZipFile(b,'w',zipfile.ZIP_DEFLATED) as z:\n for p,s in json.load(sys.stdin).items(): z.writestr(p,s)\nsys.stdout.buffer.write(b.getvalue())"],{input:JSON.stringify(files)});
  const response=await http.post('/api/reviews/upload',{headers,multipart:{scanMode:'STANDARD',file:{name:'synthetic.zip',mimeType:'application/zip',buffer:zip}}});
  assert.equal(response.status(),200);const review=await response.json(),s=review.serverAnalysis.supabaseAnalysis,e=s.accesses[0].authorizationEvidence;
  assert.equal(e.state,'BROAD_ACCESS_REVIEW');assert.equal(e.effectiveRole,'UNKNOWN');assert.equal(e.authChecks[0].resultEvidence.userIdFilters.length,1);
  assert.equal(s.findings[0].comparisonPolicy,'NOT_COMPARED');assert.equal(review.securityScore,100);
  for(const width of [1440,390,320]){
   const page=await browser.newPage({viewport:{width,height:1000}}),errors=[],outbound=[];page.on('pageerror',e=>errors.push(e.message));
   await page.addInitScript(auth=>{localStorage.setItem('securedeploy.accessToken',auth.accessToken);localStorage.setItem('securedeploy.authUser',JSON.stringify(auth.user));},user);
   await page.route('**/*',async r=>{const u=new URL(r.request().url());if(u.pathname.startsWith('/api/')){
    const response=await r.fetch({url:api+u.pathname+u.search,headers:{...r.request().headers(),origin:'http://localhost:5173'}});
    return r.fulfill({response,headers:{...response.headers(),'access-control-allow-origin':origin}});
   }if(u.origin===origin)return r.continue();outbound.push(u.origin);return r.abort();});
   await page.goto(`${origin}/#/projects/${review.projectId}/findings?review=${review.reviewId}&view=SUMMARY`);await resultView(page,'배포 전 직접 확인할 부분');
   const section=page.getByLabel('Supabase 데이터 접근 검사',{exact:true});await section.waitFor();
   await section.locator('details').evaluateAll(elements=>elements.forEach(e=>e.open=true));
   const text=await section.innerText();for(const value of ['인증 성공 보장 아님','실제 호출 여부는 미확인','DB 소유권 검증 보장 아님',prefix+'app/api/items/route.ts'])assert.ok(text.includes(value),value);
   assert.equal(await page.getByRole('button',{name:'자동 수정안 만들기',exact:true}).count(),0);
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));assert.deepEqual(errors,[]);assert.deepEqual(outbound,[]);
   await page.screenshot({path:`/private/tmp/securedeploy-modern7-${layout}-${width}.png`,fullPage:true});await page.close();reports.push({layout,width,passed:true});
  }
 }
 console.log(JSON.stringify({passed:true,backend:'ACTUAL_H2',github:'NOT_LIVE',targetExecuted:false,providerCalls:0,reports}));
}finally{await browser.close();await http.dispose();}})().catch(e=>{console.error(e.stack);process.exitCode=1;});
