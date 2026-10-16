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
                identity(snapshot.analyzerVersion(), group.getKey()), "TYPESCRIPT_DATA_FLOW", snapshot.analyzerVersion(),
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

    private static String identity(String version, ServerAnalysisSnapshot.Location location) {
        try {
            String key = version + "\nTS_SQL_INPUT_FLOW\n" + location.filePath() + "\n" + location.line() + ":" + location.column();
            return "ts-flow:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
}
