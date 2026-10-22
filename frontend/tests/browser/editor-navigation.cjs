exports.stage=async(page,name)=>page.getByRole('navigation',{name:'수정 단계',exact:true}).getByRole('button',{name,exact:true}).click();
exports.pane=async(page,name)=>{
 const nav=page.getByRole('navigation',{name:'편집 화면',exact:true});
 if(await nav.isVisible())await nav.getByRole('button',{name,exact:true}).click();
 else if(name==='수정 근거 · AI'){
  const open=page.getByRole('button',{name:'수정 근거 열기',exact:true});if(await open.isVisible())await open.click();
 }else if(name==='코드'){
  const close=page.getByRole('button',{name:'수정 근거 접기',exact:true});if(await close.isVisible())await close.click();
 }
};
exports.resultView=async(page,name)=>{
 const nav=page.getByRole('navigation',{name:'분석 결과 메뉴',exact:true});
 if(['해결 방법','기술 정보'].includes(name)){await nav.locator('summary').click();await nav.getByRole('button',{name,exact:true}).click();}
 else if(['반드시 처리','배포 전 직접 확인할 부분','수정 권장'].includes(name)){
  await nav.getByRole('button',{name:'문제 목록',exact:true}).click();await page.getByRole('navigation',{name:'문제 우선순위'}).getByRole('button',{name:new RegExp('^'+name+' ')}).click();
 }else await nav.getByRole('button',{name,exact:true}).click();
};
