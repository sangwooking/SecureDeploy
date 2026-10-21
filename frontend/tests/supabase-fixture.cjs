module.exports=()=>{
 const location={filePath:'supabase/migrations/20260101000000_policy.sql',line:5,column:1,functionName:'',kind:'RLS_DECLARATION'};
 return {schemaVersion:1,analyzerVersion:'supabase-rls-v1',status:'PARTIAL',files:[{filePath:location.filePath,status:'PARTIAL',statements:4,limitations:['OTHER_SQL_NOT_INTERPRETED']}],
  tables:[{scope:'',table:'public.entries',rls:'ENABLED',force:'UNKNOWN',location,grantLocations:[location],limitations:[],
   policies:[{name:'shared',command:'UPDATE',mode:'PERMISSIVE',roles:['authenticated'],using:{kind:'ALLOW',columns:[]},check:{kind:'ALLOW',columns:[]},location}],
   operations:[{role:'authenticated',operation:'UPDATE',grant:'EXPLICIT_GRANT',using:'ALLOW',check:'ALLOW',columns:[],state:'ALLOW',candidate:true,policyLocations:[location]}]}],
  clients:[],accesses:[{location:{...location,filePath:'src/action.ts',line:8},table:'public.entries',operation:'UPDATE',clientStatus:'CLIENT_ORIGIN_UNKNOWN',clientLocation:null,keySource:'SERVER_KEY_NAME_HINT',policyStatus:'TABLE_DECLARATION_FOUND',policyLocation:location,limitations:[]}],
  findings:[{findingId:'supabase-rls:fixture',ruleId:'SUPABASE_BROAD_WRITE_DECLARATION',priority:'REVIEW_REQUIRED',comparisonPolicy:'NOT_COMPARED',table:'public.entries',location,roles:['authenticated'],operations:['UPDATE'],evidenceLocations:[location],
   title:'사용자별 수정 권한이 넓게 선언되어 있습니다',reason:'명시적 쓰기 권한과 행 제한 없는 선언을 확인했습니다. 실제 적용과 공유 의도는 미확인입니다.',
   recommendation:'사용자 전용 데이터라면 USING과 WITH CHECK에서 소유자 컬럼을 확인하세요.',verificationSteps:['사용자 A·B의 수정·삭제 차단을 격리 환경에서 확인하고 재검사하세요.'],limitations:[]}],limitations:['DECLARATIONS_NOT_LIVE_DATABASE']};
};
