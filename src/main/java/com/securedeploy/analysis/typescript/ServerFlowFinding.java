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

    static List<ServerFlowFinding> connect(ServerAnalysisSnapshot snapshot) {
        var findings = new ArrayList<>(connectSql(snapshot));
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

    private static List<ServerFlowFinding> connectSql(ServerAnalysisSnapshot snapshot) {
        Map<ServerAnalysisSnapshot.Location, List<ServerAnalysisSnapshot.Finding>> groups = new LinkedHashMap<>();
        for (var candidate : snapshot.findings()) {
            if (!"HIGH".equals(candidate.confidence()) || !"TS_SQL_INPUT_FLOW".equals(candidate.ruleId())
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
                identity(snapshot.analyzerVersion(), "TS_SQL_INPUT_FLOW", group.getKey()), "TYPESCRIPT_DATA_FLOW", snapshot.analyzerVersion(),
                "TS_SQL_INPUT_FLOW", RiskPriority.REVIEW_REQUIRED, "NOT_COMPARED", group.getKey(), List.copyOf(group.getValue()),
                snapshot.sqlUses().stream().filter(sql -> sql.location().equals(group.getKey()) && sql.executionLocations() != null)
                        .flatMap(sql -> sql.executionLocations().stream()).distinct().toList(),
                "요청 값이 SQL 문자열과 실행 호출까지 전달됩니다",
                "사용자가 보낸 값이 데이터 값이 아닌 쿼리 문법으로 해석될 수 있습니다. 정적 전달 근거이며 실제 공격 성공이나 배포 환경의 D1 연결을 검증한 것은 아닙니다.",
                "SQL 구조를 고정하고 값은 prepare(...).bind(...)로 전달하세요. 테이블·열 이름은 바인딩 대신 서버의 고정된 허용 목록에서 선택하세요.",
                List.of("표시된 입력·쿼리 구성·실행 경로와 앞단의 입력 검사를 확인하세요.",
                        "정상 값과 따옴표 등이 포함된 테스트 입력으로 값 바인딩을 검증하세요. 실제 운영 서버에서 공격 테스트를 하지 마세요.",
                        "수정 후 같은 프로젝트를 재검사하여 해당 위치의 흐름 근거를 다시 확인하세요. 이 항목은 기존 해결 건수에 자동 합산되지 않습니다.")))
                .toList();
    }

    private static String identity(String version, String ruleId, ServerAnalysisSnapshot.Location location) {
        try {
            String key = version + "\n" + ruleId + "\n" + location.filePath() + "\n" + location.line() + ":" + location.column();
            return "ts-flow:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
}
