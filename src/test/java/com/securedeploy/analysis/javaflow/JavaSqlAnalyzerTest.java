package com.securedeploy.analysis.javaflow;

import com.securedeploy.project.model.*;
import com.securedeploy.rule.rules.DangerousSqlRule;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class JavaSqlAnalyzerTest {
    final JavaSqlAnalyzer analyzer=new JavaSqlAnalyzer();
    static String controller(String body) {
        return "package fixture;\nimport org.springframework.web.bind.annotation.*;\nimport java.sql.Connection;\n"
                +"@RestController class Endpoint { Connection connection;\n@GetMapping(\"/items\") String inspect(@RequestParam String input) {\n"+body+"\n}\n}";
    }
    static ProjectStructure project(String content) {return project(Map.of("Endpoint.java",content));}
    static ProjectStructure project(Map<String,String> sources) {
        return new ProjectStructure(Path.of("."),sources.entrySet().stream().map(e->new ProjectFile(Path.of(e.getKey()),e.getKey(),ProjectFileType.JAVA,e.getValue().lines().toList())).toList());
    }
    JavaSqlWorker.Result run(String body) {
        var r=analyzer.analyze(project(controller(body)));
        assertThat(r.status()).as(r.limitations().toString()).isEqualTo("PARTIAL");
        assertThat(r.files().get(0).parseStatus()).isEqualTo("PARSED");return r;
    }
    @Test void directSplitCallableAndBindingTooLateRetainDangerousSql() {
        for(String body:List.of(
                "String value=input; if(7*42-106>200) value=\"fixed\";\nconnection.prepareStatement(\"SELECT \"+value).execute();",
                "String sql=\"SELECT id FROM items WHERE name=\"+input;\nconnection.prepareStatement(sql).executeQuery();",
                "String sql=\"SELECT id FROM items WHERE name=\";\nsql += input;\nconnection.prepareStatement(sql).execute();",
                "String sql=\"{call \"+input+\"}\";\nconnection.prepareCall(sql).execute();",
                "var statement=connection.prepareStatement(\"SELECT id FROM items WHERE name=\"+input);\nstatement.setString(1,input);\nstatement.execute();")) {
            var r=run(body);assertThat(r.uses()).hasSize(1);assertThat(r.uses().get(0).kind()).isEqualTo("INPUT_IN_QUERY");
        }
    }
    @Test void constantOverwriteAndActualValueBindingAreSafeForThisSqlCondition() {
        for(String body:List.of(
                "String value=input;\nif(7*42-86>200) value=\"fixed\";\nString sql=\"SELECT \"+value;\nconnection.prepareStatement(sql).execute();",
                "var statement=connection.createStatement();\nstatement.executeQuery(\"SELECT \"+\"1\");",
                "var statement=connection.prepareStatement(\"SELECT id FROM items WHERE name=?\");\nstatement.setString(1,input);\nstatement.execute();",
                "var statement=connection.prepareCall(\"{call constant(?)}\");\nstatement.setString(1,input);\nstatement.execute();")) {
            var r=run(body);assertThat(r.uses()).hasSize(1);assertThat(r.uses().get(0).kind()).isIn("STATIC_QUERY","PARAMETERIZED_QUERY");
            assertThat(r.methods()).anyMatch(JavaSqlWorker.MethodResult::safeForLegacy);
        }
    }
    @Test void importedHelperAndArgumentEvaluationPreserveInput() {
        var p=project(Map.of("Endpoint.java",controller("return Repository.lookup(connection,input);"),
                "Repository.java","package fixture; import java.sql.Connection; class Repository {static String lookup(Connection c,String x){c.prepareStatement(\"SELECT \"+x).execute();return null;}}"));
        var r=analyzer.analyze(p);assertThat(r.uses()).hasSize(1);assertThat(r.uses().get(0).kind()).isEqualTo("INPUT_IN_QUERY");
        assertThat(r.uses().get(0).trace()).anyMatch(l->l.kind().equals("FUNCTION_ARGUMENT"));
    }
    @Test void uncertaintyAndMissingEntryNeverCertifySafe() {
        var r=run("String value=unverified(input);\nconnection.prepareStatement(\"SELECT \"+value).execute();");
        assertThat(r.uses()).hasSize(1);assertThat(r.uses().get(0).kind()).isEqualTo("UNRESOLVED_QUERY");
        assertThat(r.methods()).noneMatch(JavaSqlWorker.MethodResult::safeForLegacy);
        var noEntry=analyzer.analyze(project("class Endpoint { void arbitrary(String input){ } }"));
        assertThat(noEntry.files().get(0).entrypoints()).isZero();
    }
    @Test void shortCircuitAndIntegerOverflowDoNotInventSafeBranches() {
        var shortCircuit=run("String value=input; boolean condition=unknown && ((value=\"fixed\")!=null);\nconnection.prepareStatement(\"SELECT \"+value).execute();");
        assertThat(shortCircuit.uses().get(0).kind()).isEqualTo("INPUT_IN_QUERY");
        var overflow=run("String value=input;\nif(2147483647+1>0) value=\"fixed\";\nconnection.prepareStatement(\"SELECT \"+value).execute();");
        assertThat(overflow.uses().get(0).kind()).isEqualTo("INPUT_IN_QUERY");
    }
    @Test void jdbcTemplateQueriesDistinguishTextAndValueArguments() {
        String prefix="import org.springframework.web.bind.annotation.*; import org.springframework.jdbc.core.JdbcTemplate; @RestController class Endpoint {JdbcTemplate jdbc; @GetMapping(\"/\") void get(@RequestParam String input){";
        var safe=analyzer.analyze(project(prefix+"jdbc.update(\"DELETE FROM items WHERE name=?\",input);}}"));
        var risk=analyzer.analyze(project(prefix+"jdbc.queryForList(\"SELECT * FROM items WHERE name=\"+input);}}"));
        assertThat(safe.uses().get(0).kind()).isEqualTo("PARAMETERIZED_QUERY");assertThat(risk.uses().get(0).kind()).isEqualTo("INPUT_IN_QUERY");
    }
    @Test void reconcileSuppressesOnlyKnownSafeAndKeepsUnknownLegacySignals() {
        var p=project(controller("java.sql.Statement statement=connection.createStatement();\nstatement.executeQuery(\"SELECT 1\");"));
        var raw=p.analysisFiles().stream().flatMap(f->new DangerousSqlRule().evaluate(f).stream()).toList();
        assertThat(raw).hasSize(1);var outcome=analyzer.reconcile(raw,analyzer.analyze(p));
        assertThat(outcome.matches()).isEmpty();assertThat(outcome.snapshot().suppressedLegacyCount()).isEqualTo(1);
        var failure=new JavaSqlWorker.Result(JavaSqlWorker.VERSION,"TIMEOUT",List.of(),List.of(),List.of(),List.of("JAVA_PARSER_TIMEOUT"));
        assertThat(analyzer.reconcile(raw,failure).matches()).isEqualTo(raw);
    }
    @Test void newCallRiskIsReviewOnlyAndHasNoLiteralSourceContent() throws Exception {
        var p=project(controller("connection.prepareCall(\"{call \"+input+\"}\").execute();"));
        var r=analyzer.reconcile(List.of(),analyzer.analyze(p));assertThat(r.snapshot().findings()).hasSize(1);
        var finding=r.snapshot().findings().get(0);assertThat(finding.priority()).isEqualTo("REVIEW_REQUIRED");
        assertThat(finding.comparisonPolicy()).isEqualTo("NOT_COMPARED");
        String json=new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(r.snapshot());assertThat(json).doesNotContain("{call ","@RestController");
    }
    @Test void parserFailureAndSourceSizeLimitAreExplicit() {
        var invalid=analyzer.analyze(project("class Endpoint { void broken( {"));
        assertThat(invalid.files().get(0).parseStatus()).isEqualTo("PARSE_FAILED");
        var oversized=analyzer.analyze(project("x".repeat(100_001)));
        assertThat(oversized.status()).isEqualTo("UNAVAILABLE");
        assertThat(oversized.files().get(0).parseStatus()).isEqualTo("LIMIT_EXCEEDED");
        assertThat(oversized.methods()).isEmpty();
    }
    @Test void leftToRightAssignmentAndArgumentSideEffectsAreNotReversed() {
        assertThat(run("connection.prepareStatement(\"SELECT \"+input+(input=\"fixed\")).execute();").uses().get(0).kind()).isEqualTo("INPUT_IN_QUERY");
        assertThat(run("connection.prepareStatement(\"SELECT \"+(input=\"fixed\")+input).execute();").uses().get(0).kind()).isEqualTo("STATIC_QUERY");
        assertThat(run("connection.prepareStatement(\"SELECT \"+input, ((input=\"fixed\")!=null)?1:0).execute();").uses().get(0).kind()).isEqualTo("INPUT_IN_QUERY");
    }
    @Test void unsupportedCastsIncrementsAndShadowedParsersCannotProveSafety() {
        for(String statement:List.of(
                "int n=256; if((byte)n!=0) input=\"fixed\";",
                "int n=0; n++; if(n==0) input=\"fixed\";",
                "Object Integer=unknownParser; input=Integer.parseInt(input);")) {
            var r=run(statement+"\nconnection.prepareStatement(\"SELECT \"+input).execute();");
            assertThat(r.uses().get(0).kind()).isIn("INPUT_IN_QUERY","UNRESOLVED_QUERY");
            assertThat(r.methods()).noneMatch(JavaSqlWorker.MethodResult::safeForLegacy);
        }
    }
    @Test void exactStringAllowlistAndUnknownValidationRemainDistinct() {
        assertThat(run("if(!input.equals(\"name\")) return null;\nconnection.prepareStatement(\"SELECT \"+input).execute();").uses().get(0).kind()).isEqualTo("STATIC_QUERY");
        assertThat(run("if(!validate(input)) return null;\nconnection.prepareStatement(\"SELECT \"+input).execute();").uses().get(0).kind()).isEqualTo("UNRESOLVED_QUERY");
    }
    @Test void sharedHelperDoesNotSuppressRiskInAnotherCallContext() {
        var p=project(controller("lookup(connection,\"fixed\");lookup(connection,input);return null;")
                .replace("\n}\n}","\n}\nstatic void lookup(Connection c,String value){\nString sql=\"SELECT \"+value;\nc.prepareStatement(sql).execute();\n}\n}"));
        var raw=p.analysisFiles().stream().flatMap(f->new DangerousSqlRule().evaluate(f).stream()).toList();
        var result=analyzer.analyze(p);
        assertThat(result.uses()).anyMatch(u->u.kind().equals("INPUT_IN_QUERY"));
        assertThat(raw).isNotEmpty();assertThat(analyzer.reconcile(raw,result).matches()).isNotEmpty();
    }
    @Test void statementBatchAndPreparedAliasesKeepSqlTextEvidence() {
        assertThat(run("var statement=connection.createStatement();statement.addBatch(\"SELECT \"+input);statement.executeBatch();").uses().get(0).kind()).isEqualTo("INPUT_IN_QUERY");
        assertThat(run("var statement=connection.prepareStatement(\"SELECT ?\");var alias=statement;alias.setString(1,input);statement.execute();").uses().get(0).kind()).isEqualTo("PARAMETERIZED_QUERY");
    }
    @Test void unexecutedPreparationAndUnsupportedLoopAreNotConfirmedRisks() {
        assertThat(run("connection.prepareStatement(\"SELECT \"+input);").uses()).isEmpty();
        var result=run("String sql=\"SELECT 1\";while(unknown)sql=input;connection.prepareStatement(sql).execute();");
        assertThat(result.uses().get(0).kind()).isEqualTo("UNRESOLVED_QUERY");
        assertThat(result.methods()).noneMatch(JavaSqlWorker.MethodResult::safeForLegacy);
    }
    @Test void sourceSelectionPrefersVerifiedEntryHintsAndKeepsOmittedFilesVisible() {
        var sources=new LinkedHashMap<String,String>();
        for(int i=0;i<101;i++)sources.put(String.format("types/Type%03d.java",i),"class Type"+i+" {}");
        sources.put("z/Endpoint.java",controller("connection.prepareCall(\"{call \"+input+\"}\").execute();"));
        var result=analyzer.analyze(project(sources));
        assertThat(result.uses()).anyMatch(u->u.kind().equals("INPUT_IN_QUERY"));
        assertThat(result.files()).hasSize(102);
        assertThat(result.files().stream().filter(f->f.parseStatus().equals("LIMIT_EXCEEDED"))).hasSize(2);
        assertThat(result.limitations()).contains("SOURCE_SELECTION_LIMIT");
    }
    @Test void callDepthLimitIsUncertainNotSafe() {
        String source=controller("String sql=stage1(input);connection.prepareStatement(sql).execute();")
                .replace("\n}\n}","\n}\nstatic String stage1(String x){return stage2(x);}\nstatic String stage2(String x){return stage3(x);}\nstatic String stage3(String x){return stage4(x);}\nstatic String stage4(String x){return x;}\n}");
        var result=analyzer.analyze(project(source));
        assertThat(result.uses().get(0).kind()).isEqualTo("UNRESOLVED_QUERY");
        assertThat(result.methods()).noneMatch(JavaSqlWorker.MethodResult::safeForLegacy);
    }
    @Test void safeExecutionCannotEraseUntracedOrUnexecutedLegacyWarnings() {
        for(String prior:List.of(
                "connection.prepareStatement(\"SELECT \"+input);",
                "Object deferred=new Object(){void run(){entity.createNativeQuery(\"SELECT \"+input);}};")) {
            var p=project(controller(prior+"\nconnection.prepareStatement(\"SELECT 1\").execute();"));
            var raw=p.analysisFiles().stream().flatMap(f->new DangerousSqlRule().evaluate(f).stream()).toList();
            assertThat(raw).isNotEmpty();
            assertThat(analyzer.reconcile(raw,analyzer.analyze(p)).matches()).isEqualTo(raw);
        }
    }
    @Test void manyRetainedMethodsShareParserContextWithoutDroppingCrossFileFlow() {
        var sources=new LinkedHashMap<String,String>();
        for(int i=0;i<78;i++)sources.put("models/Record"+i+".java","package fixture; class Record"+i+" {String copy(String value){return value;}}");
        sources.put("Endpoint.java",controller("Repository.lookup(connection,input); return null;"));
        sources.put("Repository.java","package fixture; import java.sql.Connection; class Repository {static void lookup(Connection c,String value){c.prepareStatement(\"SELECT \"+value).execute();}}");
        for(int repeat=0;repeat<2;repeat++) {
            var result=analyzer.analyze(project(sources));
            assertThat(result.status()).as(result.limitations().toString()).isEqualTo("PARTIAL");
            assertThat(result.files()).hasSize(80).allMatch(f->f.parseStatus().equals("PARSED"));
            assertThat(result.uses()).anyMatch(u->u.kind().equals("INPUT_IN_QUERY")&&u.location().filePath().equals("Repository.java"));
        }
    }
    @Test void brokenUnitDoesNotPoisonValidUnitAndGlobalBudgetNeverCertifiesSafety() {
        var mixed=analyzer.analyze(project(Map.of("Broken.java","class Broken { void broken( {", "Endpoint.java",controller("connection.prepareStatement(\"SELECT \"+input).execute();"))));
        assertThat(mixed.files()).anyMatch(f->f.parseStatus().equals("PARSE_FAILED"));
        assertThat(mixed.uses()).anyMatch(u->u.kind().equals("INPUT_IN_QUERY"));
        var sources=new LinkedHashMap<String,String>();
        for(int i=0;i<20;i++) {
            var text=new StringBuilder("class Many"+i+" {void inspect(){");
            for(int j=0;j<800;j++)text.append("int value").append(j).append("=0;");
            sources.put("Many"+i+".java",text.append("}}").toString());
        }
        var limited=analyzer.analyze(project(sources));
        assertThat(limited.files()).hasSize(20).anyMatch(f->f.parseStatus().equals("LIMIT_EXCEEDED"));
        assertThat(limited.methods()).noneMatch(JavaSqlWorker.MethodResult::safeForLegacy);
    }
}
