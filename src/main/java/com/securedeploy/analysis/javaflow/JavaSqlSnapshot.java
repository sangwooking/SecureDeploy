package com.securedeploy.analysis.javaflow;

import com.securedeploy.project.coverage.CoverageLedger;
import java.util.*;

/** Optional historical snapshot. No literal SQL, credentials or source excerpts. */
public record JavaSqlSnapshot(JavaSqlWorker.Result analysis, List<Candidate> findings,
                              int suppressedLegacyCount, List<LegacyEvidence> legacyEvidence) {
    public record Candidate(String findingId, String ruleId, String priority, String comparisonPolicy,
                            JavaSqlWorker.Location location, List<JavaSqlWorker.Location> trace,
                            String title, String explanation, String recommendation, List<String> verificationSteps) { }
    public record LegacyEvidence(String filePath, int line, List<JavaSqlWorker.Location> executions) { }
    public CoverageLedger attachCoverage(CoverageLedger ledger) {
        var counts=new LinkedHashMap<String,Integer>();
        analysis.files().forEach(f->{
            counts.merge("AST_"+f.parseStatus(),1,Integer::sum);counts.merge("ENTRYPOINTS",f.entrypoints(),Integer::sum);
            counts.merge("FUNCTIONS_TRACED",f.functions(),Integer::sum);counts.merge("SQL_CALLS",f.sqlCallSites(),Integer::sum);
            counts.merge("SQL_CALLS_TRACED",f.tracedCallSites(),Integer::sum);
            f.limitations().forEach(l->counts.merge(l,1,Integer::sum));
        });
        counts.put("CONFIRMED_SAFE_LEGACY_SIGNALS_REMOVED",suppressedLegacyCount);
        var analyzers=new ArrayList<>(ledger.analyzers());
        analyzers.add(new CoverageLedger.Analyzer("JAVA_SQL_FLOW",analysis.status(),
                "Spring/Servlet의 지원 진입점·JDBC/JdbcTemplate API 형태를 제한 추적합니다. 타입 해석·실제 실행·외부 검증·JPA 및 전체 Java는 미검증. 새 독립 후보는 점수·Risk·해결 수와 분리됩니다.",counts));
        return new CoverageLedger(ledger.schemaVersion(),ledger.policyVersion(),"FAILED".equals(ledger.status())?"FAILED":analysis.files().isEmpty()?ledger.status():"PARTIAL",
                ledger.discoveredFiles(),ledger.selectedFiles(),ledger.unsupportedFiles(),ledger.excludedFiles(),ledger.failedFiles(),ledger.inventoryComplete(),ledger.omittedEntries(),ledger.entries(),analyzers,ledger.inspectionScope());
    }
}
