"""Bounded API-shape observations; never makes HTTP calls or stores URLs/error contents."""
import ast


class ServiceEvidence:
    def __init__(self, analyzer, value):
        self.a, self.V = analyzer, value
        self.uses = []
        self.active_exception = False

    def call(self, node, function, args, keywords):
        if function.unknown:
            return None
        if function.symbol in {'traceback.format_exc','traceback.format_stack'}:
            if any(p=='traceback.py' or p.endswith('/traceback.py') or p.startswith('traceback/') for p in self.a.modules):
                self.a.note('TRACEBACK_MODULE_UNRESOLVED');return self.V(unknown=True)
            known = (function.symbol == 'traceback.format_stack' or self.active_exception) and not args and not keywords
            return self.V(unknown=not known, exposures=(self.a.loc(node,'INTERNAL_ERROR_DETAIL' if known else 'ERROR_DETAIL_CONTEXT_UNKNOWN'),))
        parts=function.symbol.split('.')
        if len(parts)!=2 or parts[0] not in {'requests','httpx'} or parts[1] not in {'get','post','put','patch','delete','head','options','request'}:
            return None
        if any(p == parts[0]+'.py' or p.endswith('/'+parts[0]+'.py') or p.startswith(parts[0]+'/') or '/'+parts[0]+'/' in p for p in self.a.modules):
            self.a.note('HTTP_LIBRARY_LOCAL_SHADOW');return self.V(unknown=True)
        target=args[1 if parts[1]=='request' else 0] if len(args)>(1 if parts[1]=='request' else 0) else keywords.get('url',self.V(unknown=True))
        timeout=keywords.get('timeout')
        if timeout is None:
            status='REQUESTS_DEFAULT_WITHOUT_TIMEOUT' if parts[0]=='requests' else 'HTTPX_DEFAULT_INACTIVITY_TIMEOUT'
        elif not timeout.unknown and timeout.literal is None:
            status='EXPLICIT_TIMEOUT_DISABLED'
        elif not timeout.unknown and type(timeout.literal) in {int,float} and timeout.literal>0:
            status='POSITIVE_TIMEOUT_NOT_TOTAL_DEADLINE'
        elif parts[0]=='requests' and timeout.elements and len(timeout.elements)==2 and all(not v.unknown and type(v.literal) in {int,float} and v.literal>0 for v in timeout.elements):
            status='POSITIVE_TIMEOUT_NOT_TOTAL_DEADLINE'
        else:
            status='TIMEOUT_SETTING_UNRESOLVED'
        if self.a.partial or self.a.exposure.uncertain:
            status='HTTP_CALL_PATH_UNRESOLVED'
        location=self.a.loc(node,'HTTP_CLIENT_CALL')
        limits=['HTTP_LIBRARY_VERSION_AND_PATCHES_UNVERIFIED','PROXY_PLATFORM_AND_TOTAL_DEADLINE_UNKNOWN','STATIC_CALL_NOT_SERVICE_FAILURE_PROOF']
        record=dict(kind=parts[0].upper(),status=status,location=location,trace=list(target.trace)[:20],limitations=limits)
        if len(self.uses)>=200:
            self.a.note('SERVICE_RESULT_LIMIT');return self.V(unknown=True)
        if record not in self.uses:self.uses.append(record)
        if status in {'REQUESTS_DEFAULT_WITHOUT_TIMEOUT','EXPLICIT_TIMEOUT_DISABLED'} and len(self.a.findings)<200:
            finding=dict(ruleId='PY_HTTP_TIMEOUT_REVIEW',kind='CWE-400',confidence='HIGH',disposition='REVIEW_REQUIRED',source=location,sink=location,
                         flow=[*record['trace'],location],defenses=[],limitations=limits,
                         message='외부 서비스의 응답을 기다리는 동안 서버 요청이 장시간 점유될 가능성이 있습니다.',
                         recommendation='사용 라이브러리의 연결·읽기 타임아웃과 전체 요청 기한을 설정하세요. 프록시·플랫폼 제한을 함께 확인하고 지연 응답 Mock으로 로컬 검증 후 재검사하세요.')
            if finding not in self.a.findings:self.a.findings.append(finding)
        return self.V(unknown=True)

    def known_exception_handler(self, node, env):
        if node.orelse or node.finalbody or len(node.body)!=1 or len(node.handlers)!=1:return None
        raised=node.body[0]
        if not isinstance(raised,ast.Raise) or not isinstance(raised.exc,ast.Call) or raised.cause is not None:return None
        call=raised.exc
        names={'Exception','ValueError','RuntimeError'}
        if not isinstance(call.func,ast.Name) or call.func.id not in names or call.func.id in env:return None
        if call.keywords or len(call.args)>1 or any(not isinstance(a,ast.Constant) for a in call.args):return None
        handler=node.handlers[0]
        if not handler.body or not isinstance(handler.body[-1],ast.Return):return None
        if not isinstance(handler.type,ast.Name) or handler.type.id in env or handler.type.id not in {call.func.id,'Exception','BaseException'}:return None
        return handler
