package com.securedeploy.analysis.typescript;

import com.securedeploy.risk.model.RiskPriority;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** Supplemental findings: never input to the legacy score, risk verdict or resolved-count comparison. */
public record ServerFlowFinding(String findingId, String sourceType, String analyzerVersion, String ruleId,
        RiskPriority priority, String comparisonPolicy, ServerAnalysisSnapshot.Location location,
        List<ServerAnalysisSnapshot.Finding> evidence, List<ServerAnalysisSnapshot.Location> executionLocations, String title, String riskExplanation,
        String recommendedAction, List<String> verificationSteps) {

    public static List<ServerFlowFinding> connect(ServerAnalysisSnapshot snapshot) {
        var findings = new ArrayList<>(connectSql(snapshot));
        findings.addAll(connectResources(snapshot));
        findings.addAll(connectAuthorization(snapshot));
        findings.addAll(connectTokens(snapshot));
        findings.addAll(connectExposure(snapshot));
        findings.addAll(connectService(snapshot));
        findings.addAll(connectNode(snapshot));
        if (snapshot.httpUses() == null) return List.copyOf(findings);
        Map<ServerAnalysisSnapshot.Location, List<ServerAnalysisSnapshot.Finding>> groups = new LinkedHashMap<>();
        for (var candidate : snapshot.findings()) {
            if (!"TS_SSRF_INPUT_FLOW".equals(candidate.ruleId()) || !"HIGH".equals(candidate.confidence())
                    || candidate.limitations().contains("DESTINATION_FLOW_UNRESOLVED")
                    || candidate.limitations().contains("TRACE_DETAILS_TRUNCATED")) continue;
            boolean observed = snapshot.httpUses().stream().anyMatch(http -> "INPUT_IN_DESTINATION".equals(http.kind())
                    && !http.limitations().contains("DESTINATION_FLOW_UNRESOLVED")
                    && http.location().equals(candidate.sink()) && http.trace().equals(candidate.flow()));
            if (observed) {
                var evidence = groups.computeIfAbsent(candidate.sink(), ignored -> new ArrayList<>());
                if (!evidence.contains(candidate)) evidence.add(candidate);
            }
        }
        groups.forEach((location, evidence) -> findings.add(new ServerFlowFinding(
                identity(snapshot.analyzerVersion(), "TS_SSRF_INPUT_FLOW", location), "TYPESCRIPT_DATA_FLOW", snapshot.analyzerVersion(),
                "TS_SSRF_INPUT_FLOW", RiskPriority.REVIEW_REQUIRED, "NOT_COMPARED", location, List.copyOf(evidence), List.of(location),
                "사용자가 입력한 주소로 서버가 요청을 보낼 수 있습니다",
                "외부 입력이 요청 목적지 또는 호스트에 전달되는 정적 경로를 확인했습니다. 의도하지 않은 서비스로 요청할 가능성이 있으나 내부망 접근이나 공격 성공을 확인한 것은 아닙니다.",
                "사용자에게 전체 URL을 받기보다 서버의 고정된 목적지를 선택하게 하세요. URL이 필요하면 파싱한 프로토콜·호스트를 정확한 허용 목록으로 검사하고 리다이렉트 및 DNS·네트워크 접근 제한을 별도로 확인하세요.",
                List.of("입력 위치부터 HTTP 요청 호출까지의 경로와 실제 허용 목적지를 확인하세요.",
                        "로컬 Mock HTTP 테스트로 허용되지 않은 호스트·프로토콜·리다이렉트가 거부되는지 검증하세요. 운영 서버에 SSRF 요청을 보내지 마세요.",
                        "같은 프로젝트를 재검사하여 흐름 근거를 확인하세요. 이 항목은 기존 점수·배포 판정·해결 건수에 자동 합산되지 않습니다."))));
        return List.copyOf(findings);
    }

    private static List<ServerFlowFinding> connectNode(ServerAnalysisSnapshot snapshot) {
        if(snapshot.nodeUses()==null)return List.of();
        var groups=new LinkedHashMap<ServerAnalysisSnapshot.Location,List<ServerAnalysisSnapshot.Finding>>();
        for(var finding:snapshot.findings()) {
            if(!Set.of("JS_SHELL_COMMAND_INPUT_FLOW","JS_EVAL_INPUT_FLOW","JS_MONGO_WHERE_INPUT_FLOW").contains(finding.ruleId())||!finding.confidence().equals("HIGH")
                    ||finding.limitations().contains("NODE_FLOW_UNRESOLVED")||finding.limitations().contains("TRACE_DETAILS_TRUNCATED"))continue;
            if(snapshot.nodeUses().stream().anyMatch(use->use.ruleId().equals(finding.ruleId())&&use.kind().equals("INPUT_TO_EXECUTION")
                    &&use.location().equals(finding.sink())&&use.trace().equals(finding.flow())))groups.computeIfAbsent(finding.sink(),ignored->new ArrayList<>()).add(finding);
        }
        return groups.entrySet().stream().map(group->{
            var first=group.getValue().get(0);boolean eval=first.ruleId().equals("JS_EVAL_INPUT_FLOW"),shell=first.ruleId().equals("JS_SHELL_COMMAND_INPUT_FLOW");
            return new ServerFlowFinding(identity(snapshot.analyzerVersion(),first.ruleId(),group.getKey()),"TYPESCRIPT_DATA_FLOW",snapshot.analyzerVersion(),
                    first.ruleId(),RiskPriority.REVIEW_REQUIRED,"NOT_COMPARED",group.getKey(),List.copyOf(group.getValue()),List.of(group.getKey()),
                    shell?"사용자가 보낸 값이 서버의 명령 문자열에 전달됩니다":eval?"사용자가 보낸 값이 서버에서 코드로 실행될 수 있습니다":"사용자가 보낸 값이 데이터베이스의 실행 문자열에 들어갈 수 있습니다",
                    "정적으로 연결된 Express 요청 입력과 "+(shell?"Node.js shell 명령 호출(CWE-78)":eval?"eval 호출(CWE-95)":"MongoDB $where 쿼리 호출(CWE-943)")+" 사이의 전달 근거입니다. 미들웨어 검증·실제 라이브러리 설치·운영 실행·공격 성공은 확인하지 않았습니다.",
                    first.recommendation(),List.of("입력 위치부터 전달·실행 위치까지 확인하고 앞단의 검증·인증 미들웨어를 함께 검토하세요.",
                            shell?"로컬 Mock으로 고정 실행 파일·shell 미사용·입력 허용 목록·인자 배열을 검증하세요. execFile 사용만으로 임의 실행 파일·인자 주입·플랫폼 위험까지 안전해지는 것은 아닙니다.":eval?"eval 대신 필요한 숫자 변환과 스키마 검증을 사용하고 로컬 Mock으로 코드 실행 호출이 사라졌는지 확인하세요.":"$where 문자열 결합을 일반 값 비교 쿼리로 바꾸고 타입 검증·드라이버 및 서버 버전·JavaScript 실행 설정을 로컬에서 확인하세요.",
                            "수정 후 같은 프로젝트를 재검사하세요. 운영 서버 공격은 하지 마세요. 이 항목은 기존 점수·배포 판단·해결 건수와 별도입니다."));
        }).toList();
    }

    private static List<ServerFlowFinding> connectSql(ServerAnalysisSnapshot snapshot) {
        boolean python = snapshot.analyzerVersion().startsWith("py-django-");
        String ruleId = python ? "PY_SQL_INPUT_FLOW" : "TS_SQL_INPUT_FLOW";
        Map<ServerAnalysisSnapshot.Location, List<ServerAnalysisSnapshot.Finding>> groups = new LinkedHashMap<>();
        for (var candidate : snapshot.findings()) {
            if (!"HIGH".equals(candidate.confidence()) || !ruleId.equals(candidate.ruleId())
                    || candidate.limitations().contains("QUERY_HAS_UNRESOLVED_VALUES")
                    || candidate.limitations().contains("TRACE_DETAILS_TRUNCATED")) continue;
            boolean executed = snapshot.sqlUses().stream().anyMatch(sql -> sql.executionObserved()
                    && sql.executionLocations() != null && !sql.executionLocations().isEmpty()
                    && "INPUT_IN_QUERY".equals(sql.kind()) && sql.limitations().isEmpty()
                    && sql.location().equals(candidate.sink()) && sql.trace().equals(candidate.flow()));
            if (!executed) continue;
            var evidence = groups.computeIfAbsent(candidate.sink(), ignored -> new ArrayList<>());
            if (!evidence.contains(candidate)) evidence.add(candidate);
        }
        return groups.entrySet().stream().map(group -> new ServerFlowFinding(
                identity(snapshot.analyzerVersion(), ruleId, group.getKey()), python ? "PYTHON_DATA_FLOW" : "TYPESCRIPT_DATA_FLOW", snapshot.analyzerVersion(),
                ruleId, RiskPriority.REVIEW_REQUIRED, "NOT_COMPARED", group.getKey(), List.copyOf(group.getValue()),
                snapshot.sqlUses().stream().filter(sql -> sql.location().equals(group.getKey()) && sql.executionLocations() != null)
                        .flatMap(sql -> sql.executionLocations().stream()).distinct().toList(),
                "요청 값이 SQL 문자열과 실행 호출까지 전달됩니다",
                "사용자가 보낸 값이 데이터 값이 아닌 쿼리 문법으로 해석될 수 있습니다(CWE-89). 정적 전달 근거이며 실제 공격 성공이나 운영 DB 연결을 검증한 것은 아닙니다.",
                python ? "SQL 구조를 고정하고 값은 execute(sql, params)로 분리하거나 Django ORM의 값 매개변수를 사용하세요. 테이블·열 이름은 서버의 고정된 허용 목록에서 선택하세요."
                : "SQL 구조를 고정하고 값은 prepare(...).bind(...)로 전달하세요. 테이블·열 이름은 바인딩 대신 서버의 고정된 허용 목록에서 선택하세요.",
                List.of("표시된 입력·쿼리 구성·실행 경로와 앞단의 입력 검사를 확인하세요.",
                        "정상 값과 따옴표 등이 포함된 테스트 입력으로 값 바인딩을 검증하세요. 실제 운영 서버에서 공격 테스트를 하지 마세요.",
                        "수정 후 같은 프로젝트를 재검사하여 해당 위치의 흐름 근거를 다시 확인하세요. 이 항목은 기존 해결 건수에 자동 합산되지 않습니다.")))
                .toList();
    }

    private static List<ServerFlowFinding> connectResources(ServerAnalysisSnapshot snapshot) {
        if (snapshot.resourceUses() == null) return List.of();
        var groups = new LinkedHashMap<String, List<ServerAnalysisSnapshot.Finding>>();
        for (var candidate : snapshot.findings()) {
            if (!Set.of("PY_FILE_PATH_INPUT_FLOW", "PY_UNSAFE_DESERIALIZATION_INPUT_FLOW").contains(candidate.ruleId())
                    || !"HIGH".equals(candidate.confidence()) || candidate.limitations().contains("RESOURCE_FLOW_UNRESOLVED")) continue;
            boolean observed = snapshot.resourceUses().stream().anyMatch(use -> use.executionObserved()
                    && Set.of("INPUT_IN_FILE_PATH", "INPUT_TO_UNSAFE_DESERIALIZATION").contains(use.kind())
                    && use.ruleId().equals(candidate.ruleId()) && use.location().equals(candidate.sink())
                    && use.trace().equals(candidate.flow()) && !use.limitations().contains("RESOURCE_FLOW_UNRESOLVED"));
            if (!observed) continue;
            String id = identity(snapshot.analyzerVersion(), candidate.ruleId(), candidate.sink());
            var evidence = groups.computeIfAbsent(id, ignored -> new ArrayList<>());
            if (!evidence.contains(candidate)) evidence.add(candidate);
        }
        return groups.entrySet().stream().map(group -> {
            var first = group.getValue().get(0);
            boolean path = first.ruleId().equals("PY_FILE_PATH_INPUT_FLOW");
            return new ServerFlowFinding(group.getKey(), "PYTHON_DATA_FLOW", snapshot.analyzerVersion(), first.ruleId(),
                    RiskPriority.REVIEW_REQUIRED, "NOT_COMPARED", first.sink(), List.copyOf(group.getValue()), List.of(first.sink()),
                    path ? "사용자가 입력한 경로로 서버가 다른 파일에 접근할 가능성이 있습니다" : "외부에서 받은 데이터를 위험한 방식으로 복원할 가능성이 있습니다",
                    path ? "요청 값이 파일 접근 경로에 전달되는 정적 근거입니다(CWE-22). 허용 디렉터리 밖 접근이나 실제 파일 유출을 확인한 것은 아닙니다."
                    : "요청 데이터가 pickle 또는 확인된 unsafe YAML 복원 호출에 전달됩니다(CWE-502). 실제 코드 실행이나 공격 성공은 검증하지 않았습니다.",
                    first.recommendation(), List.of(
                        path ? "입력·파일 접근 위치와 실제 기준 디렉터리, 정규화 후 경계 검사, 심볼릭 링크·접근 권한을 확인하세요."
                        : "입력 출처와 로더를 확인하고 외부 데이터의 객체 복원을 피하세요. JSON 스키마 검증 또는 YAML SafeLoader 사용 시 기능 호환성도 확인하세요.",
                        path ? "임시 테스트 디렉터리에서 정상 파일명·상위 경로·절대 경로·심볼릭 링크가 정책대로 처리되는지 검증하세요."
                        : "로컬 Mock에서 정상 데이터·잘못된 형식·크기 제한과 거부 동작을 검증하세요. 실제 악성 객체를 실행하지 마세요.",
                        "변경 후 같은 프로젝트를 재검사하세요. 이 검토 항목은 기존 점수·배포 판단·해결 건수와 별도입니다."));
        }).toList();
    }

    private static String identity(String version, String ruleId, ServerAnalysisSnapshot.Location location) {
        try {
            String key = version + "\n" + ruleId + "\n" + location.filePath() + "\n" + location.line() + ":" + location.column();
            return (ruleId.startsWith("PY_") ? "py-flow:" : "ts-flow:") + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private static List<ServerFlowFinding> connectExposure(ServerAnalysisSnapshot snapshot) {
        if (snapshot.exposureUses() == null) return List.of();
        var groups = new LinkedHashMap<ServerAnalysisSnapshot.Location, List<ServerAnalysisSnapshot.Finding>>();
        for (var candidate : snapshot.findings()) {
            if (!List.of("TS_SENSITIVE_DATA_EXPOSURE", "PY_SENSITIVE_DATA_EXPOSURE", "TS_ERROR_DETAIL_EXPOSURE", "PY_ERROR_DETAIL_EXPOSURE").contains(candidate.ruleId()) || !"HIGH".equals(candidate.confidence())) continue;
            boolean observed = snapshot.exposureUses().stream().anyMatch(u -> u.location().equals(candidate.sink()) && u.trace().contains(candidate.source()) && "SENSITIVE_FLOW_CANDIDATE".equals(u.status()));
            if (observed) {
                var evidence = groups.computeIfAbsent(candidate.sink(), ignored -> new ArrayList<>());
                if (!evidence.contains(candidate)) evidence.add(candidate);
            }
        }
        return groups.entrySet().stream().map(g -> {
            var f=g.getValue().get(0);
            return new ServerFlowFinding(identity(snapshot.analyzerVersion(),f.ruleId(),g.getKey()),f.ruleId().startsWith("PY_") ? "PYTHON_DATA_FLOW" : "TYPESCRIPT_DATA_FLOW",
                    snapshot.analyzerVersion(),f.ruleId(),RiskPriority.REVIEW_REQUIRED,"NOT_COMPARED",g.getKey(),List.copyOf(g.getValue()),List.of(g.getKey()),f.message(),
                    f.ruleId().contains("ERROR_DETAIL") ? "내부 스택 정보가 반환 응답에 전달되는 정적 흐름입니다. 실제 오류 발생·외부 노출·운영 렌더러 보호는 미검증이며 기존 점수에 합산하지 않습니다." : "자격증명 형식·인증 헤더·서버 비밀 설정에서 응답 또는 로그로의 정적 전달 근거입니다. 실제 비밀값의 유효성·운영 노출·접근 권한은 확인하지 않았으며 기존 위험 건수와 점수에는 합산하지 않습니다.",
                    f.recommendation(),f.ruleId().contains("ERROR_DETAIL") ? List.of("응답 생성·반환 위치와 디버그·미들웨어 설정을 확인하세요.","로컬 오류 테스트에서 경로·스택 대신 일반 메시지와 추적 ID만 반환하는지 확인하세요.","상세 오류는 접근 제한된 내부 로그로 분리하고 재검사하세요.") : List.of("표시된 출처와 전달·노출 위치에서 실제로 필요한 공개 정보인지 확인하세요.","원문 대신 필요한 필드만 반환하고 로컬 로그·응답 테스트에서 비밀값이 제외되는지 확인하세요.","실제 유출이 확인됐다면 해당 자격증명 교체·접근 기록 검토 후 재검사하세요."));
        }).toList();
    }

    private static List<ServerFlowFinding> connectService(ServerAnalysisSnapshot snapshot) {
        if(snapshot.serviceUses()==null)return List.of();
        return snapshot.findings().stream().filter(f->f.ruleId().equals("PY_HTTP_TIMEOUT_REVIEW") && f.confidence().equals("HIGH"))
                .filter(f->snapshot.serviceUses().stream().anyMatch(u->u.location().equals(f.sink()) && List.of("REQUESTS_DEFAULT_WITHOUT_TIMEOUT","EXPLICIT_TIMEOUT_DISABLED").contains(u.status())))
                .collect(java.util.stream.Collectors.toMap(ServerAnalysisSnapshot.Finding::sink,f->f,(a,b)->a,LinkedHashMap::new)).values().stream()
                .map(f->new ServerFlowFinding(identity(snapshot.analyzerVersion(),f.ruleId(),f.sink()),"PYTHON_DATA_FLOW",snapshot.analyzerVersion(),f.ruleId(),RiskPriority.REVIEW_REQUIRED,"NOT_COMPARED",f.sink(),List.of(f),List.of(f.sink()),f.message(),
                        "지원 HTTP API의 타임아웃 누락·해제 형태를 확인했습니다. 실제 라이브러리·프록시·플랫폼의 제한과 운영 장애는 미확인이며 기존 배포 판단을 변경하지 않습니다.",f.recommendation(),List.of("호출 위치에서 설치 라이브러리와 연결·읽기·전체 요청 기한을 확인하세요.","실제 외부 서비스 대신 지연 Mock으로 취소·오류·자원 반환을 로컬 테스트하고 재검사하세요."))).toList();
    }

    private static List<ServerFlowFinding> connectTokens(ServerAnalysisSnapshot snapshot) {
        if (snapshot.tokenUses() == null) return List.of();
        var groups = new LinkedHashMap<ServerAnalysisSnapshot.Location, List<ServerAnalysisSnapshot.Finding>>();
        for (var candidate : snapshot.findings()) {
            boolean signing = candidate.ruleId().equals("PY_JWT_FIXED_SIGNING_KEY");
            if (!signing && !candidate.ruleId().equals("PY_JWT_UNVERIFIED_ACCESS_DECISION")) continue;
            boolean observed = snapshot.tokenUses().stream().anyMatch(t -> signing
                    ? t.operation().equals("SIGN") && t.signatureStatus().equals("HMAC_SIGN_CALL") && t.keySource().equals("FIXED_LITERAL") && t.location().equals(candidate.source())
                    : t.signatureStatus().equals("EXPLICITLY_DISABLED") && t.usageStatus().equals("ACCESS_REJECTION_BRANCH")
                        && t.trace().contains(candidate.source()) && t.trace().stream().anyMatch(l -> l.filePath().equals(candidate.sink().filePath()) && l.line() == candidate.sink().line()));
            if (observed && candidate.confidence().equals("HIGH")) {
                var evidence = groups.computeIfAbsent(candidate.sink(), ignored -> new ArrayList<>());
                if (!evidence.contains(candidate)) evidence.add(candidate);
            }
        }
        return groups.entrySet().stream().map(g -> {
            var first = g.getValue().get(0);
            return new ServerFlowFinding(identity(snapshot.analyzerVersion(), first.ruleId(), g.getKey()), "PYTHON_DATA_FLOW", snapshot.analyzerVersion(),
                    first.ruleId(), RiskPriority.REVIEW_REQUIRED, "NOT_COMPARED", g.getKey(), List.copyOf(g.getValue()), List.of(g.getKey()), first.message(),
                    "지원하는 PyJWT API 형태와 정적 사용 경로를 확인했습니다. 실제 라이브러리 버전·외부 검증·공격 성공은 확인하지 않았습니다. 기존 점수·배포 판단에는 합산하지 않습니다.",
                    first.recommendation(), List.of("표시한 호출·사용 위치와 실제 설치한 JWT 라이브러리·버전을 확인하세요.",
                    "로컬 테스트에서 변조 서명·잘못된 키·만료 토큰이 거부되는지 확인하세요. 단순 표시용 디코딩과 인증 판단을 분리하세요.",
                    "키를 화면·로그에 출력하지 말고 설정 변경 및 키 교체 후 재검사하세요."));
        }).toList();
    }

    private static List<ServerFlowFinding> connectAuthorization(ServerAnalysisSnapshot snapshot) {
        var groups = new LinkedHashMap<ServerAnalysisSnapshot.Location, List<ServerAnalysisSnapshot.Finding>>();
        for (var candidate : snapshot.findings()) {
            if (!candidate.ruleId().equals("PY_AUTHORIZATION_INVERTED_OWNER_GUARD") || !candidate.confidence().equals("HIGH")) continue;
            boolean observed = snapshot.authorizationContexts().stream().filter(c -> c.details() != null)
                    .flatMap(c -> c.details().accesses().stream()).anyMatch(a -> a.location().equals(candidate.sink())
                        && a.conclusion().equals("INVERTED_OWNER_REJECTION_CANDIDATE")
                        && a.identifierInputs().contains(candidate.source()) && List.of("WRITE", "DELETE").contains(a.operation()));
            if (observed) {
                var evidence = groups.computeIfAbsent(candidate.sink(), ignored -> new ArrayList<>());
                if (!evidence.contains(candidate)) evidence.add(candidate);
            }
        }
        return groups.entrySet().stream().map(group -> new ServerFlowFinding(
                identity(snapshot.analyzerVersion(), "PY_AUTHORIZATION_INVERTED_OWNER_GUARD", group.getKey()),
                "PYTHON_DATA_FLOW", snapshot.analyzerVersion(), "PY_AUTHORIZATION_INVERTED_OWNER_GUARD", RiskPriority.REVIEW_REQUIRED,
                "NOT_COMPARED", group.getKey(), List.copyOf(group.getValue()), List.of(group.getKey()),
                "사용자를 비교한 뒤 다른 분기에서 정보를 변경하는 조건을 확인해 주세요",
                "사용자와 리소스 소유자가 일치하면 차단하고, 다른 경로에서 요청한 객체를 변경하는 정적 흐름입니다(CWE-863 검토 후보). 의도된 업무 규칙일 수 있으며 다른 권한 계층이나 실제 우회 성공은 확인하지 않았습니다.",
                group.getValue().get(0).recommendation(), List.of("표시한 사용자·리소스 조회·비교·변경 위치와 별도 관리자·미들웨어 보호를 확인하세요.",
                        "로컬 테스트에서 사용자 A/B, 소유/비소유 객체, 익명/관리자 계정의 허용·거부 행렬을 검증하세요. 운영 서비스 공격은 하지 마세요.",
                        "의도한 정책과 다르면 비교 방향과 차단 분기를 수정한 뒤 재검사하세요. 기존 점수·배포 판단·해결 건수에는 합산하지 않습니다."))).toList();
    }
}
