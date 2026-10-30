exports.stage=async(page,name)=>page.getByRole('navigation',{name:'수정 단계',exact:true}).getByRole('button',{name:({'코드 편집':'코드 수정','변경 검토 · 다운로드':'변경 검토·승인','재검사 · 비교':'재검사'})[name]??name,exact:true}).click();
exports.pane=async(page,name)=>{
 const nav=page.getByRole('navigation',{name:'편집 화면',exact:true});
 if(await nav.isVisible())await nav.getByRole('button',{name:name==='수정 근거 · AI'?'수정 근거':name,exact:true}).click();
 else if(name==='수정 근거 · AI'){
  const open=page.getByRole('button',{name:'수정 근거 열기',exact:true});if(await open.isVisible())await open.click();
 }else if(name==='코드'){
  const close=page.getByRole('button',{name:'수정 근거 접기',exact:true});if(await close.isVisible())await close.click();
 }
};
exports.resultView=async(page,name)=>{
 const nav=page.getByRole('navigation',{name:'분석 결과 메뉴',exact:true});
 if(['해결 방법','기술 정보','변화 보기'].includes(name)){await page.locator('.report-menu > summary').click();await page.getByRole('button',{name:({'해결 방법':'저장된 수정 가이드','변화 보기':'검사 변화 보기'})[name]??name,exact:true}).click();}
 else if(['반드시 처리','배포 전 직접 확인할 부분','수정 권장'].includes(name)){
  await nav.getByRole('button',{name:'문제 목록',exact:true}).click();await page.getByLabel('검토 우선순위',{exact:true}).selectOption(({'반드시 처리':'BLOCKING','배포 전 직접 확인할 부분':'REVIEW_REQUIRED','수정 권장':'SHOULD_FIX'})[name]);
  const row=page.locator('.problem-row').first();if(await row.count())await row.click();
 }else await nav.getByRole('button',{name:name==='결과 요약'?'문제 목록':name,exact:true}).click();
};
