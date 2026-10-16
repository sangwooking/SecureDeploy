package com.securedeploy.analysis.typescript;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
import static com.securedeploy.analysis.typescript.TypeScriptServerAnalyzerTest.*;

class ServerFlowFindingTest {
    final TypeScriptServerAnalyzer analyzer = new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties());

    @Test void knownInputQueryAndExecutionBecomeOneSupplementalFinding() {
        var result = analyzer.analyze(project(UNSAFE));
        var finding = result.validatedFindings().get(0);
        assertThat(result.validatedFindings()).hasSize(1);
        assertThat(finding.findingId()).startsWith("ts-flow:");
        assertThat(finding.priority().name()).isEqualTo("REVIEW_REQUIRED");
        assertThat(finding.sourceType()).isEqualTo("TYPESCRIPT_DATA_FLOW");
        assertThat(finding.comparisonPolicy()).isEqualTo("NOT_COMPARED");
        assertThat(finding.evidence().get(0).flow()).anyMatch(l -> l.kind().equals("SQL_STRING_CONSTRUCTION"));
        assertThat(finding.executionLocations()).isNotEmpty();
        assertThat(finding.verificationSteps()).hasSize(3);
        assertThat(analyzer.analyze(project(UNSAFE)).validatedFindings().get(0).findingId()).isEqualTo(finding.findingId());
    }
    @Test void unknownTransformNoExecutionAndSafeBindingAreNotPromoted() {
        for (String code : new String[] {SAFE, UNSAFE.replace(".all()", ""),
                UNSAFE.replace("+ id", "+ escapeSql(id)"),
                UNSAFE.replace("return env.DB", "if(!['id','title'].includes(id)) return; return env.DB")}) {
            assertThat(analyzer.analyze(project(code)).validatedFindings()).isEmpty();
        }
        var bindAfterConcat = analyzer.analyze(project(UNSAFE.replace(".all()", ".bind(1).all()")));
        assertThat(bindAfterConcat.validatedFindings()).hasSize(1);
        assertThat(bindAfterConcat.validatedFindings().get(0).evidence().get(0).limitations()).contains("BIND_DOES_NOT_REWRITE_QUERY");
    }
    @Test void multipleInputsToOneSinkAreGroupedWithoutDiscardingTheirPaths() {
        String code = """
                export default {fetch(request, env) {
                  const url = new URL(request.url);
                  query(env.DB,url.searchParams.get('a'));
                  return query(env.DB,url.searchParams.get('b'));
                }};
                function query(db, id) { return db.prepare('SELECT * FROM t WHERE id=' + id).all(); }
                """;
        var snapshot = analyzer.analyze(project(code));
        assertThat(snapshot.findings()).hasSize(2);
        assertThat(snapshot.validatedFindings()).hasSize(1);
        assertThat(snapshot.validatedFindings().get(0).evidence()).hasSize(2);
    }
    @Test void snapshotsRoundTripAndLegacyIsNotReinterpreted() throws Exception {
        var converter = new ServerAnalysisConverter();
        var snapshot = analyzer.analyze(project(UNSAFE));
        String encoded = converter.convertToDatabaseColumn(snapshot);
        assertThat(encoded).doesNotContain("SELECT *", "WHERE id=");
        assertThat(converter.convertToEntityAttribute(encoded)).isEqualTo(snapshot);
        var old = new ObjectMapper().readTree(encoded);
        ((com.fasterxml.jackson.databind.node.ObjectNode) old).remove("validatedFindings");
        ((com.fasterxml.jackson.databind.node.ObjectNode) old).put("analyzerVersion", "ts-server-v1");
        for (var sql : old.path("sqlUses")) ((com.fasterxml.jackson.databind.node.ObjectNode) sql).remove("executionLocations");
        var restored = converter.convertToEntityAttribute(old.toString());
        assertThat(restored.validatedFindings()).isNull();
        assertThat(restored.analyzerVersion()).isEqualTo("ts-server-v1");
        assertThat(restored.findings()).isEqualTo(snapshot.findings());
    }
    @Test void partialExecutionAndUnresolvedGuardsRemainCandidates() {
        for (String body : new String[] {
                "const statement = env.DB.prepare(id); for(let i=0;i<2;i++) { statement.all(); }",
                "if(!isValid(id)) return; return env.DB.prepare(id).all();",
                "const allowed=['id','title']; if(!allowed.includes(id)) return; return env.DB.prepare(id).all();"}) {
            var snapshot = analyzer.analyze(project("export default {fetch(request,env){ const id = new URL(request.url).searchParams.get('id'); " + body + "}}"));
            assertThat(snapshot.findings()).isNotEmpty();
            assertThat(snapshot.validatedFindings()).isEmpty();
        }
    }
}
