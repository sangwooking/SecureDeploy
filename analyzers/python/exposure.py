"""Static provenance only: no credential values are serialized or validated externally."""
import re


def credential_shape(value):
    return isinstance(value, str) and bool(re.fullmatch(r'(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{24,}|AKIA[A-Z0-9]{16})', value))


class ExposureEvidence:
    def __init__(self, analyzer, value):
        self.a, self.V = analyzer, value
        self.uses = []
        self.uncertain = False

    def call(self, node, function, base, name, args, keywords):
        if function.unknown:
            return None
        if function.symbol == 'logging.getLogger':
            return self.V(tag='exposure-logger')
        if function.symbol in {'django.http.JsonResponse', 'django.http.response.JsonResponse', 'rest_framework.response.Response', 'django.http.HttpResponse', 'django.http.response.HttpResponse'}:
            incoming = self.combined(args[:1] or [keywords.get('data', keywords.get('content', self.V(unknown=True)))])
            return self.V(exposures=incoming.exposures, unknown=incoming.unknown or self.a.partial or self.uncertain or any(k in keywords for k in {'encoder','json_dumps_params'}), tag='exposure-response',
                          response_locations=(self.a.loc(node,'HTTP_RESPONSE'),), exposure_trail=incoming.exposure_trail)
        if (base and base.tag == 'exposure-logger' and name in {'debug','info','warning','error','exception','critical'}) or function.symbol in {
                'logging.debug','logging.info','logging.warning','logging.error','logging.exception','logging.critical','builtins.print'}:
            self.observe(self.combined([*args,*keywords.values()]), self.a.loc(node,'LOG_ARGUMENT'), 'LOG_ARGUMENT')
            return self.V(literal=None)
        return None

    def combined(self, values):
        origins = tuple(dict.fromkeys(tuple(sorted(o.items())) for v in values for o in v.exposures))[:20]
        trail = tuple(dict.fromkeys(tuple(sorted(o.items())) for v in values for o in v.exposure_trail))[:10]
        return self.V(exposures=tuple(dict(o) for o in origins), unknown=any(v.unknown for v in values), exposure_trail=tuple(dict(o) for o in trail))

    def observe(self, value, location, kind):
        if not value.exposures:
            return
        if len(self.uses) >= 200:
            self.a.note('EXPOSURE_RESULT_LIMIT')
            return
        sources = list(value.exposures)[:20]
        strong = [s for s in sources if s['kind'] in {'CREDENTIAL_SHAPED_LITERAL','FRAMEWORK_SECRET_SETTING','AUTHENTICATION_HEADER'}]
        error = [s for s in sources if s['kind']=='INTERNAL_ERROR_DETAIL'] if kind=='HTTP_RESPONSE_RETURN' else []
        status = 'FLOW_UNRESOLVED' if value.unknown or self.a.partial or self.uncertain else 'SENSITIVE_FLOW_CANDIDATE' if strong or error else 'SENSITIVITY_UNVERIFIED'
        if kind=='LOG_ARGUMENT' and any(s['kind'] in {'INTERNAL_ERROR_DETAIL','ERROR_DETAIL_CONTEXT_UNKNOWN'} for s in sources) and not strong:status='INTERNAL_DIAGNOSTIC_LOG_ONLY'
        limits = ['STATIC_EXPOSURE_NOT_RUNTIME_LEAK_PROOF','MASKING_LOG_ACCESS_AND_DEPLOYMENT_UNKNOWN']
        trace = [*sources,*value.exposure_trail][:20]
        record = dict(kind=kind,status=status,location=location,trace=trace,limitations=limits)
        if record not in self.uses:
            self.uses.append(record)
        if status != 'SENSITIVE_FLOW_CANDIDATE' or len(self.a.findings) >= 200:
            return
        finding = dict(ruleId='PY_ERROR_DETAIL_EXPOSURE' if error else 'PY_SENSITIVE_DATA_EXPOSURE',kind='CWE-209' if error else 'CWE-200',confidence='HIGH',disposition='REVIEW_REQUIRED',
                       source=(error or strong)[0],sink=location,flow=[*trace,location],defenses=[],limitations=limits,
                       message='서버 내부 오류 정보가 사용자에게 전달될 가능성이 있습니다.' if error else '보호해야 할 정보 후보가 서버 응답 또는 로그에 전달되는 경로를 확인해 주세요.',
                       recommendation='응답·로그에서 해당 값을 제거하거나 목적에 맞게 마스킹하세요. 실제 노출이 확인됐다면 자격증명 교체를 검토하고 로컬 테스트와 재검사로 확인하세요. 클라이언트 공개 환경변수로 옮기는 것은 해결이 아닙니다.')
        if error: finding['recommendation']='사용자 응답에는 일반 오류 메시지와 추적 ID만 반환하고 상세 스택은 접근이 제한된 내부 로그로 분리하세요. 디버그·렌더러 설정과 로컬 오류 응답 테스트를 확인한 뒤 재검사하세요.'
        if finding not in self.a.findings:
            self.a.findings.append(finding)
