module.exports = () => ({schemaVersion:1,analyzerVersion:'deployment-v1',status:'PARTIAL',
  files:[{filePath:'compose.yaml',format:'COMPOSE',status:'PARSED',limitations:['DECLARATIONS_ONLY_RUNTIME_AND_OVERRIDES_UNKNOWN'],observations:[
    {line:3,scope:'service:web',setting:'user',valueStatus:'UNKNOWN',valueSummary:'not resolved',ruleId:''}]}],
  findings:[{findingId:'config:synthetic',sourceType:'DEPLOYMENT_CONFIGURATION',priority:'REVIEW_REQUIRED',comparisonPolicy:'NOT_COMPARED',
    filePath:'compose.yaml',line:4,scope:'service:web',setting:'volumes[0]',ruleId:'COMPOSE_SOCKET',valueSummary:'Docker socket bind',
    title:'컨테이너에 Docker 제어 소켓을 연결합니다',reason:'호스트 제어 가능성이 있어 실제 적용 구성을 확인해야 합니다.',
    recommendation:'소켓 연결을 제거하거나 제한된 중계 서비스를 검토하세요.',verificationSteps:['실제 배포 구성을 확인하세요.','변경 후 기능 테스트와 재검사를 수행하세요.']}],
  limitations:['DECLARATIONS_ONLY_RUNTIME_AND_OVERRIDES_UNKNOWN','SUPPLEMENTAL_REVIEW_NOT_RISK_OR_SCORE']});
