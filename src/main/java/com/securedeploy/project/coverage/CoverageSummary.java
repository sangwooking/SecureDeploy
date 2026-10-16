package com.securedeploy.project.coverage;

import com.securedeploy.sca.model.ScaResult;
import com.securedeploy.threatintel.model.ThreatIntelligenceSnapshot;
import java.util.*;

public final class CoverageSummary {
    private CoverageSummary() { }
    public static CoverageLedger merge(CoverageLedger scanned, CoverageLedger source) {
        var recorder = new CoverageRecorder();
        recorder.merge(source); recorder.merge(scanned);
        return recorder.snapshot();
    }
    public static CoverageLedger failure(CoverageLedger scanned, CoverageLedger source, String stage) {
        var ledger = merge(scanned, source);
        return new CoverageLedger(ledger.schemaVersion(), ledger.policyVersion(), "FAILED", ledger.discoveredFiles(),
                ledger.selectedFiles(), ledger.unsupportedFiles(), ledger.excludedFiles(), ledger.failedFiles(),
                ledger.inventoryComplete(), ledger.omittedEntries(), ledger.entries(), List.of(
                    new CoverageLedger.Analyzer(stage, "FAILED", "분석 중단. 완료된 Review로 저장하지 않았습니다.", Map.of())));
    }
    public static CoverageLedger complete(CoverageLedger scanned, CoverageLedger source, ScaResult sca,
            ThreatIntelligenceSnapshot intelligence) {
        var ledger = merge(scanned, source);
        Map<String, Integer> manifests = new LinkedHashMap<>();
        if (sca.manifests() != null) sca.manifests().forEach(m -> manifests.merge(m.status(), 1, Integer::sum));
        return ledger.withAnalyzers(List.of(
                new CoverageLedger.Analyzer("RULE_ENGINE", "COMPLETE", "지원 파일의 문자열/설정 패턴 검사. 언어 전체 의미, 인증 흐름, 런타임 도달성은 미검증.", Map.of("SELECTED", ledger.selectedFiles())),
                new CoverageLedger.Analyzer("FALSE_POSITIVE", "COMPLETE", "선택된 룰 결과의 문맥 기반 후처리. 제외 파일을 검사한 것은 아님.", Map.of()),
                new CoverageLedger.Analyzer("SCA", sca.status().name(), "Maven/Gradle/npm 정적 선언 및 지원 lockfile의 정확 버전 조회. 설치/빌드 미실행.", manifests),
                new CoverageLedger.Analyzer("THREAT_INTELLIGENCE", intelligence == null ? "UNAVAILABLE" : intelligence.status().name(), "확인된 CVE의 EPSS/KEV 조회. 실제 공격 가능성 검증 아님.", Map.of())));
    }
}
