module.exports = () => {
  return ['PY_FILE_PATH_INPUT_FLOW','PY_UNSAFE_DESERIALIZATION_INPUT_FLOW'].map((ruleId,index)=>{
    const source={filePath:'app/views.py',line:3+index,column:2,functionName:'download',kind:index?'REQUEST_BODY':'QUERY_PARAMETER'};
    const sink={...source,line:7+index,kind:index?'DESERIALIZATION_CALL':'FILE_ACCESS_CALL'};
    const evidence={ruleId,kind:index?'CWE-502':'CWE-22',confidence:'HIGH',disposition:'REVIEW_REQUIRED',source,sink,flow:[source],defenses:[],
      limitations:[index?'LIBRARY_VERSION_AND_EXPLOITABILITY_NOT_VERIFIED':'SYMLINKS_PERMISSIONS_AND_RUNTIME_NOT_VERIFIED'],
      message:'외부 입력의 사용 위치와 방어 처리를 확인하세요.',recommendation:index?'외부 입력의 pickle 복원을 피하고 JSON 스키마 검증 또는 YAML SafeLoader를 검토하세요.':'고정된 파일 식별자를 사용하거나 기준 디렉터리와 경계를 검증하세요.'};
    return {findingId:'py-flow:synthetic-resource-'+index,sourceType:'PYTHON_DATA_FLOW',analyzerVersion:'py-django-v3',ruleId,priority:'REVIEW_REQUIRED',comparisonPolicy:'NOT_COMPARED',
      location:sink,evidence:[evidence],executionLocations:[sink],title:index?'외부에서 받은 데이터를 위험한 방식으로 복원할 가능성이 있습니다':'사용자가 입력한 경로로 서버가 다른 파일에 접근할 가능성이 있습니다',
      riskExplanation:index?'요청 데이터가 객체 복원 호출에 전달됩니다. 실제 공격 성공은 검증하지 않았습니다.':'요청 값이 파일 경로에 전달됩니다. 실제 파일 유출을 확인한 것은 아닙니다.',
      recommendedAction:evidence.recommendation,verificationSteps:['임시 디렉터리 또는 로컬 Mock에서 정상·거부 동작을 확인하세요.','변경 후 다시 검사하세요.']};
  });
};
