import type { RiskFinding, Vulnerability } from '../types/securityReview';

export interface ManualGuidance {
  summary: string;
  risk: string;
  steps: string[];
  action: string;
  impactSteps?: string[];
}

export function needsVerification(finding?: RiskFinding, vulnerability?: Vulnerability): boolean {
  return !finding || finding.priority === 'REVIEW_REQUIRED'
    || vulnerability?.confidence === 'LOW' || vulnerability?.falsePositiveRisk === 'HIGH';
}

export function findingGuidance(finding?: RiskFinding, vulnerability?: Vulnerability): ManualGuidance {
  const rule = vulnerability?.ruleId ?? finding?.ruleId ?? '';
  if (finding?.source === 'ANALYSIS') {
    const version = finding.reasonCode === 'UNRESOLVED_VERSION';
    const intelligence = finding.reasonCode === 'INCOMPLETE_THREAT_INTELLIGENCE';
    return {
      summary: version ? '이 라이브러리의 정확한 버전을 확인해 주세요.'
        : intelligence ? '보안 공지의 실제 악용 정보를 끝까지 확인하지 못했습니다.'
        : '라이브러리의 버전이나 취약 여부를 끝까지 확인하지 못했습니다.',
      risk: '정보가 부족한 상태는 안전하다는 뜻이 아닙니다. 확인이 끝나기 전에는 위험이 남아 있을 수 있습니다.',
      steps: intelligence ? ['원문 보안 공지와 실제 악용 정보의 조회 상태를 확인하세요.', '조회 실패라면 연결 상태를 확인하고 다시 검사하세요.']
        : ['pom.xml, build.gradle 또는 package-lock.json 등에서 실제 사용 버전을 확인하세요.',
          '버전이 고정되어 있는지, 잠금 파일이 함께 포함됐는지 확인하세요.',
          '외부 조회 실패라면 연결 상태를 확인한 뒤 같은 프로젝트를 다시 검사하세요.'],
      action: '누락된 버전이나 조회 상태를 확인한 뒤 SecureDeploy로 재검사하세요. 확인 전에는 안전으로 간주하지 마세요.',
    };
  }
  if (finding?.source === 'DEPENDENCY') return {
    summary: `${finding.packageName ?? '사용 중인 라이브러리'}의 보안 업데이트를 검토하세요.`,
    risk: '알려진 문제가 있는 기능을 서비스에서 사용한다면 정보 노출이나 서비스 장애로 이어질 수 있습니다. 실제 도달 가능성은 별도 확인이 필요합니다.',
    steps: ['실제 설치 버전과 해당 보안 공지의 영향 범위를 확인하세요.', '호환되는 수정 버전으로 갱신하고 잠금 파일도 반영하세요.', '관련 기능 테스트 후 SecureDeploy로 다시 검사하세요.'],
    action: '기술 정보의 보안 공지와 수정 버전을 참고하세요. 표시된 버전이 모든 보안 문제의 해결을 보장하지는 않습니다.',
  };
  if (/HARDCODED_.*(?:SECRET|PASSWORD)|DOCKER_SECRET_ENV|K8S_SECRET_PLAIN_TEXT|WEAK_JWT_SECRET/.test(rule)) return {
    summary: needsVerification(finding, vulnerability)
      ? '이 값이 실제 비밀번호나 API Key인지 확인해 주세요.'
      : '보호해야 할 인증정보가 코드나 설정에 들어 있는지 확인하고 분리하세요.',
    risk: '코드가 공개되면 포함된 인증정보를 다른 사람이 사용할 수 있습니다. 실제로 유효한 값인지나 권한 범위는 이 탐지만으로 확인되지 않습니다.',
    impactSteps: ['코드나 설정이 외부에 노출됩니다.', '포함된 값이 실제 인증정보라면 다른 사람이 발견해 사용할 수 있습니다.', '그 값에 부여된 권한에 따라 데이터 접근이나 비용 발생으로 이어질 수 있습니다.'],
    steps: ['예제·테스트용 값인지, 실제 서비스에서 사용하는 값인지 확인하세요. 값을 다른 곳에 붙여넣거나 공유하지 마세요.', '실제 값이면 먼저 폐기·교체한 뒤 코드와 배포 설정에서 제거하세요.', '환경변수 또는 비밀정보 저장소로 옮기고 기존 값이 더 이상 동작하지 않는지 확인하세요.', '로그인 등 관련 기능을 테스트한 뒤 다시 검사하세요.'],
    action: vulnerability?.recommendation ?? '실제 인증정보는 교체하고 코드 밖의 환경변수 또는 비밀정보 저장소에서 관리하세요.',
  };
  return {
    summary: vulnerability?.message ?? '이 문제의 사용 방식과 영향을 확인해 주세요.',
    risk: '이 설정이나 기능이 외부에 노출되고 필요한 보호 조치가 없다면 정보 접근이나 서비스 동작에 영향을 줄 수 있습니다. 실제 영향은 사용 방식에 따라 달라집니다.',
    steps: ['이 기능이 실제 서비스에서 사용되는지 확인하세요.', '권장 조치를 프로젝트에 맞게 적용하고 정상 사용과 거부돼야 할 요청을 함께 테스트하세요.', '수정 후 같은 프로젝트를 다시 검사해 남은 문제를 비교하세요.'],
    action: vulnerability?.recommendation ?? '저장된 근거와 권장 조치를 확인하고, 판단이 어려우면 담당 개발자와 함께 검토하세요.',
  };
}

export function semanticGuidance(type: string): ManualGuidance {
  if (['IDOR', 'AUTHORIZATION_BYPASS', 'BROKEN_ACCESS_CONTROL'].includes(type)) return {
    summary: '일부 코드에서 접근 권한 확인이 충분하지 않을 가능성이 제안됐습니다. 다른 부분에서 보호하고 있을 수도 있어 직접 확인해야 합니다.',
    risk: '접근 제한이 없다면 다른 사용자의 정보를 보거나 변경할 수 있습니다.',
    steps: ['본인이 관리하는 테스트 계정 A와 B를 준비하고 A로 로그인하세요.', '요청 주소나 값의 사용자 번호를 테스트 계정 B의 번호로 바꿔 보세요.', 'B의 정보가 보이지 않고 접근이 거부되는지 확인하세요.'],
    action: '다른 사람의 정보에 접근된다면 사용자가 자신의 데이터에만 접근하도록 권한 확인을 추가하세요.',
  };
  if (['UNSAFE_FILE_ACCESS', 'PATH_TRAVERSAL_CANDIDATE'].includes(type)) return {
    summary: '허용된 파일만 열 수 있도록 제한하는지 추가 확인이 필요합니다.',
    risk: '파일 접근 범위가 제한되지 않으면 공개하면 안 되는 파일이 보일 수 있습니다.',
    steps: ['허용된 폴더 안팎에 민감정보 없는 테스트 파일을 각각 준비하세요.', '허용되지 않은 테스트 파일을 요청했을 때 거부되는지 확인하세요.', '파일 이름을 바꿔도 허용 범위 밖에는 접근할 수 없는지 담당 개발자와 확인하세요.'],
    action: '허용된 위치와 파일만 열도록 제한하고, 요청한 사용자가 그 파일을 볼 수 있는지도 확인하세요.',
  };
  if (['MISSING_AUTHENTICATION', 'SESSION_SECURITY'].includes(type)) return {
    summary: '로그인한 사람만 사용할 수 있어야 하는 기능인지 확인해 주세요.',
    risk: '로그인 확인이 빠지면 원하지 않는 사람이 보호된 기능을 사용할 수 있습니다.',
    steps: ['테스트 환경에서 로그아웃한 상태로 보호된 화면과 기능에 접근해 보세요.', '로그인이 필요하다는 응답이 오는지 확인하세요.', '로그인 만료 후에도 보호된 정보가 보이지 않는지 확인하세요.'],
    action: '보호가 필요한 기능에는 서버에서 로그인과 접근 권한을 함께 확인하도록 하세요.',
  };
  return {
    summary: '선택된 코드 일부에서 추가 검토 의견이 나왔습니다. 실제 문제인지 확정된 상태는 아닙니다.',
    risk: '현재 확인한 코드만으로 실제 영향을 판단하기 어렵습니다.',
    steps: ['기술 정보의 관련 위치에서 이 기능이 언제, 누구에게 제공되는지 확인하세요.', '정상적인 입력과 거부해야 할 입력을 테스트 환경에서 비교하세요.', '확신하기 어렵다면 담당 개발자와 원본 검토 의견을 함께 확인하세요.'],
    action: '문제가 확인된 경우에만 프로젝트에 맞는 보호 조치를 적용하고 재검사하세요.',
  };
}
