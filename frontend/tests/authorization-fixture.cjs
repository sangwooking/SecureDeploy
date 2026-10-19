module.exports=()=>{
  const location=(line,kind)=>({filePath:'app/views.py',line,column:2,functionName:'erase',kind});
  const source=location(4,'QUERY_PARAMETER'),lookup=location(5,'RESOURCE_LOOKUP'),guard=location(6,'INVERTED_OWNER_REJECTION'),sink=location(8,'RESOURCE_DELETE');
  const evidence={ruleId:'PY_AUTHORIZATION_INVERTED_OWNER_GUARD',kind:'CWE-863',confidence:'HIGH',disposition:'REVIEW_REQUIRED',source,sink,flow:[source,lookup,guard,sink],defenses:[guard],
    limitations:['AUTH_LOGIC_CANDIDATE_NOT_EXPLOIT_PROOF','AUTH_MIDDLEWARE_AND_RUNTIME_NOT_VERIFIED'],message:'소유자 일치 시 차단한 뒤 다른 분기에서 객체를 변경합니다.',recommendation:'비교 방향과 거부 분기를 확인하고 두 사용자 계정으로 허용·거부를 테스트하세요.'};
  const access={operation:'DELETE',location:sink,resourceLocation:lookup,identifierInputs:[source],checks:[guard],conclusion:'INVERTED_OWNER_REJECTION_CANDIDATE',limitations:['AUTH_MIDDLEWARE_AND_RUNTIME_NOT_VERIFIED']};
  return {details:{authenticationStatus:'DECLARED_LOGIN_REQUIRED',objectAuthorizationStatus:'RISK_LOGIC_CANDIDATE',permissionSource:'VIEW_DECORATOR',
    permissionDeclarations:[{source:'VIEW_DECORATOR',permissions:['IsAuthenticated'],location:location(2,'VIEW_PERMISSION_DECLARATION')}],principalReferences:[location(6,'REQUEST_PRINCIPAL_REFERENCE')],ownershipComparisons:[guard],accesses:[access],limitations:['AUTHENTICATION_IS_NOT_OBJECT_AUTHORIZATION','AUTH_MIDDLEWARE_AND_RUNTIME_NOT_VERIFIED']},evidence,
    finding:{findingId:'py-flow:synthetic-auth',sourceType:'PYTHON_DATA_FLOW',analyzerVersion:'py-django-v4',ruleId:evidence.ruleId,priority:'REVIEW_REQUIRED',comparisonPolicy:'NOT_COMPARED',location:sink,evidence:[evidence],executionLocations:[sink],title:'사용자를 비교한 뒤 다른 분기에서 정보를 변경하는 조건을 확인해 주세요',riskExplanation:'정적 비교·차단 흐름의 검토 후보입니다. 실제 권한 우회 성공은 확인하지 않았습니다.',recommendedAction:evidence.recommendation,verificationSteps:['로컬 사용자 A/B와 소유·비소유 객체를 준비하세요.','의도한 허용·거부를 검증한 뒤 다시 검사하세요.']}};
};
