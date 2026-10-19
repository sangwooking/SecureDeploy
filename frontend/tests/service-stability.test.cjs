const {test}=require('node:test');const assert=require('node:assert/strict');const React=require('react');const {renderToStaticMarkup}=require('react-dom/server');
const {ServiceStabilityDetails}=require('./load-component.cjs')('ServiceStabilityDetails');
const render=uses=>renderToStaticMarkup(React.createElement(ServiceStabilityDetails,{uses}));
const use={kind:'REQUESTS',status:'EXPLICIT_TIMEOUT_DISABLED',location:{filePath:'api.py',line:7,functionName:'endpoint'},trace:[],limitations:['STATIC_CALL_NOT_SERVICE_FAILURE_PROOF']};
test('timeout and platform uncertainty provide local actions, not an outage claim',()=>{const h=render([use]);for(const s of ['명시적으로 해제','api.py:7','운영 장애는 미확인','지연 Mock','전체 요청 기한'])assert.ok(h.includes(s),s);});
test('httpx defaults, dynamic configuration, empty and historical evidence remain distinct',()=>{assert.ok(render([{...use,status:'HTTPX_DEFAULT_INACTIVITY_TIMEOUT'}]).includes('비활동 제한'));assert.ok(render([{...use,status:'TIMEOUT_SETTING_UNRESOLVED'}]).includes('동적·미지원'));assert.ok(render(null).includes('과거 결과를 추측하지'));assert.ok(render([]).includes('충분하다는 의미는 아닙니다'));});
test('service locations are escaped',()=>{assert.ok(!render([{...use,location:{...use.location,filePath:'<img src=x>'}}]).includes('<img'));});
