import type {Vulnerability} from '../types/securityReview';
import {findingGuidance} from './findingGuidance';
export function repairGuide(rule:string,v?:Vulnerability){
 if(rule==='HTTP_HTML_INPUT_FLOW')return {summary:'요청값이 HTML 텍스트 또는 지원하는 따옴표 속성에 인코딩 없이 전달되는 정적 경로입니다. 실제 공격 성공은 미검증입니다.',steps:['표시된 요청 Source·전달 함수·HTML 응답 Sink와 Content-Type을 확인하세요.','일반 텍스트는 HTML 텍스트 인코딩이나 text/plain 응답을 검토하세요. 따옴표로 둘러싼 title·alt·aria-label은 따옴표를 유지하고 &, <, >, 양쪽 따옴표의 인코딩을 확인하세요.','기존 정상 응답·상태·API 사용처를 보존하고 실제 Diff를 검토해 승인하세요. 누락·빈 값·반복 파라미터에서도 기존 문자열 변환과 오류 응답이 유지되는지 확인하세요.','무해한 HTML 마커가 DOM 요소가 아닌 텍스트로 표시되는지 확인하고 같은 파일·진입점으로 재검사하세요.'],limit:'HTML 텍스트와 지원하는 따옴표 속성(title·alt·aria-label)의 정적 흐름입니다. JS·URL·CSS·srcdoc·다른 속성에 같은 수정을 일반화하지 않으며 자동/AI Patch를 지원하지 않습니다.'};
 if(rule==='NPM_DEPENDENCY_UPDATE')return {summary:'잠금 파일의 라이브러리 버전에 보안 공지가 연결됐습니다.',steps:['현재 버전과 모든 설치 경로, 직접·상위 의존성 선언을 확인하세요.','지원되는 원본에서는 AI 없이 상위 업데이트 수정안을 검증할 수 있습니다. 상위 업데이트가 불가능할 때만 제한 override를 수동 검토하세요.','생성된 두 파일의 Diff·남은 위험과 호환성 미검증 상태를 확인하고 승인하세요.','수정본을 재검사하고 실제 설치·빌드·정상 기능을 별도로 검증하세요.'],limit:'npm v3 단일 루트 등 서버 지원 계약을 충족해야 합니다. 자동 선정이 불가능하면 수동 가이드를 이용하며 전체 안전성은 미검증입니다.'};
 if(v?.filePath.endsWith('.properties')&&['DEBUG_ENABLED','STACKTRACE_EXPOSURE','INSECURE_COOKIE'].includes(rule))return {summary:rule==='DEBUG_ENABLED'?'저장된 설정에서 디버그 모드 활성화 근거가 발견됐습니다. 실제 운영에서 읽는 설정인지는 별도 확인해야 합니다.':rule==='STACKTRACE_EXPOSURE'?'오류 응답의 stacktrace 포함 설정을 확인해야 합니다.':'세션 쿠키 보안 플래그와 HTTPS 전송 조건을 확인해야 합니다.',steps:[rule==='DEBUG_ENABLED'?'표시된 debug=true 행을 debug=false로 바꾸는 최소 변경을 검토하세요.':rule==='STACKTRACE_EXPOSURE'?'표시된 server.error.include-stacktrace=always 행을 never로 바꾸는 최소 변경을 검토하세요.':'표시된 session.cookie.secure 또는 session.cookie.http-only의 false 값을 확인하고 true 변경을 검토하세요.','중복 키·profile·환경변수·실행 인자가 설정을 덮어쓰는지 확인하세요.','Diff와 기능 영향을 검토해 승인한 뒤 실제 설정 로딩·로그·쿠키/오류 응답과 재검사를 확인하세요.'],limit:'단순 상수 한 줄의 원본·Revision·해시 검증 후에만 수정안 적용을 지원합니다. 운영 적용·정상 기능은 별도 확인이 필요합니다.'};
 if(rule==='TS_SENSITIVE_DATA_EXPOSURE')return {summary:'서버 환경값에서 HTTP 응답으로 연결된 필드가 기록됐습니다. 실제 비밀값·운영 권한·API 사용처는 별도 확인해야 합니다.',steps:['등록된 Handler의 응답 객체에서 Source 환경값을 직접 읽는 필드를 확인하세요.','서버 내부의 환경값 사용과 일반 응답 필드·순서·HTTP 상태를 보존하고 노출 필드만 제거하는 변경을 검토하세요.','클라이언트가 제거될 필드를 사용하는지 확인한 뒤 실제 Diff와 호환성 경고를 검토하고 승인하세요.','같은 파일·HTTP 진입점으로 재검사하고 정상 응답·로그인·오류 처리 회귀를 확인하세요.'],limit:'제한된 inline JSON 구조만 자동/AI Patch 검토를 지원합니다. 원본과 AST·해시 검증 전에는 적용할 수 없습니다.'};
 if(rule==='LOCAL_STORAGE_TOKEN')return {summary:'인증 토큰이 브라우저 저장소에서 읽히거나 저장됩니다. 스크립트 실행 권한이 탈취되면 접근될 수 있어 인증 구조를 함께 확인해야 합니다.',steps:['표시된 저장·조회 위치와 공통 인증 유틸리티를 모두 확인하세요.','서버 로그인·인증 유지 계약을 확인하고 HttpOnly·Secure·SameSite 쿠키 도입 가능성을 검토하세요.','클라이언트 요청의 인증 전달·credentials, 로그아웃·만료·갱신 처리를 함께 변경하세요.','쿠키 방식 변경 시 CSRF 방어·동일 출처 정책을 검토하고 정상 로그인·API 호출·로그아웃 회귀를 수행하세요.'],limit:'인증 서버 계약을 확인하지 못해 자동/AI Patch를 지원하지 않습니다. 한 줄 치환이나 확정 대체 코드는 제공하지 않습니다.'};
 if(/HTTP.*URL|INSECURE_HTTP|INSECURE_API_URL/.test(rule))return {summary:'HTTP 주소 문자열이 기록됐습니다. 실제 운영 통신인지 테스트 예시인지와 전달되는 정보는 별도 확인해야 합니다.',steps:['저장된 주소가 요청·리다이렉트 등에 사용되는지 호출 위치를 확인하세요.','실제 서버의 HTTPS 제공·인증서·리다이렉트·혼합 콘텐츠 조건을 확인하세요.','운영 통신이라면 설정과 호출자를 함께 변경하고, 테스트 문자열이라면 테스트 의도와 운영 경로를 구분해 기록하세요.'],limit:'주소 문자열만으로 실제 통신이나 노출을 확정하지 않습니다. 자동 문자열 치환은 지원하지 않습니다.'};
 const g=findingGuidance(undefined,v);return {summary:g.risk,steps:g.steps,limit:['DEBUG_ENABLED','STACKTRACE_EXPOSURE','INSECURE_COOKIE','TS_SENSITIVE_DATA_EXPOSURE'].includes(rule)?'작업 공간에서 원본·Finding·AST·파일 해시를 확인한 뒤 지원되는 수정안만 생성할 수 있습니다.':'이 유형은 기본 가이드와 수동 수정 경로를 제공합니다. AI Patch 지원을 의미하지 않습니다.'};
}
const examples: Record<string, {before:string; after:string; check:string}> = {
  HARDCODED_FRONTEND_SECRET: {
    before: "const secret = 'server-secret-placeholder';",
    after: "// Browser: request an authenticated server endpoint.\nconst response = await fetch('/api/example');",
    check: '예시 주소입니다. 테스트 더미인지 먼저 확인하세요. 실제 비밀이면 서버에만 보관하고 기존 값을 회전하세요. 브라우저 번들과 API 응답에 값이 없는지 확인하세요.',
  },
  LOCAL_STORAGE_TOKEN: {
    before: "localStorage.setItem('token', token);",
    after: "// After the server issues an HttpOnly session cookie:\nconst response = await fetch('/api/me', { credentials: 'same-origin' });",
    check: '서버의 쿠키 발급과 CSRF 방어가 전제입니다. 로그인·갱신·로그아웃 및 교차 출처 요구사항을 확인하세요.',
  },
  DANGEROUS_SQL: {
    before: 'await db.query("SELECT * FROM users WHERE id = " + id);',
    after: 'await db.query("SELECT * FROM users WHERE id = $1", [id]);',
    check: 'PostgreSQL 스타일 예시입니다. 실제 드라이버의 바인딩 문법과 권한 검사를 확인하세요.',
  },
  HTTP_HTML_INPUT_FLOW: {
    before: 'element.innerHTML = input;',
    after: 'element.textContent = input;',
    check: '브라우저에서 평문을 표시할 때의 예시입니다. 서버 응답은 HTML 문맥에 맞게 인코딩하고 정상 출력도 확인하세요.',
  },
  REACT_DANGEROUS_HTML: {
    before: '<div dangerouslySetInnerHTML={{ __html: input }} />',
    after: '<div>{input}</div>',
    check: '입력을 텍스트로 표시하는 예시입니다. HTML 렌더링이 기능 요구사항이면 별도 정화와 정책 검증이 필요합니다.',
  },
  TS_SENSITIVE_DATA_EXPOSURE: {
    before: 'res.json({ status, token: process.env.SERVICE_TOKEN });',
    after: 'res.json({ status });',
    check: '예시 필드입니다. 실제 응답 계약과 클라이언트 호환성을 확인하세요.',
  },
  DEBUG_ENABLED: {
    before: 'debug=true',
    after: 'debug=false',
    check: '설정 오버라이드와 실제 디버그 로그를 확인하세요.',
  },
};

export function ProblemRepairGuide({rule,v}:{rule:string;v?:Vulnerability}) {
  const guide=repairGuide(rule,v);
  const example=examples[rule];
  return <section className="repair-guide" aria-label="기본 수정 가이드">
    <p className="source-label">기본 수정 가이드 · Rule/Evidence 기반 · AI 요청 없음</p>
    <h4>어떻게 수정하나요?</h4>
    <ol>{guide.steps.map((step,i)=><li key={i}>{step}</li>)}</ol>
    {example&&<details><summary>참고용 수정 전후 예시</summary>
      <p>규칙 기반 예시입니다. 현재 파일에 적용하거나 검증한 변경은 없습니다.</p>
      <h5>수정 전</h5><pre><code>{example.before}</code></pre>
      <h5>수정 후</h5><pre><code>{example.after}</code></pre>
      <p>{example.check}</p>
    </details>}
    <p role="note">{guide.limit}</p>
  </section>;
}
