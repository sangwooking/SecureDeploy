package com.securedeploy.analysis.javaflow;

import com.securedeploy.rule.rules.DangerousSqlRule;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class JavaSqlCastEvidenceTest {
    private final JavaSqlAnalyzer analyzer=new JavaSqlAnalyzer();
    private JavaSqlAnalyzer.Outcome inspect(String body) {
        var project=JavaSqlAnalyzerTest.project(JavaSqlAnalyzerTest.controller(body));
        var raw=project.analysisFiles().stream().flatMap(f->new DangerousSqlRule().evaluate(f).stream()).toList();
        return analyzer.reconcile(raw,analyzer.analyze(project));
    }
    private static final String COPY="Object stored=input; String copied=(String)stored;\n";

    @Test void identityStringCastDoesNotPoisonLaterProvenStaticStatement() {
        var outcome=inspect(COPY+"copied=\"fixed\";\njava.sql.Statement statement=connection.createStatement();\nstatement.executeQuery(\"SELECT \"+copied);");
        assertThat(outcome.snapshot().analysis().uses()).singleElement().satisfies(u->assertThat(u.kind()).isEqualTo("STATIC_QUERY"));
        assertThat(outcome.matches()).isEmpty();
    }

    @Test void castingStringInputIsNotASanitizer() {
        var outcome=inspect(COPY+"java.sql.Statement statement=connection.createStatement();\nstatement.executeQuery(\"SELECT \"+copied);");
        assertThat(outcome.snapshot().analysis().uses()).singleElement().satisfies(u->assertThat(u.kind()).isEqualTo("INPUT_IN_QUERY"));
        assertThat(outcome.matches()).isNotEmpty();
    }

    @Test void unknownTransformsAndNonStringValuesRemainUnresolved() {
        for(String expression:List.of("unknown(input)","new Object()","42","unknownFlag?input:42","(new int[1])[0]")) {
            var outcome=inspect("Object stored="+expression+";String copied=(String)stored;\n"
                    +"java.sql.Statement statement=connection.createStatement();\nstatement.executeQuery(\"SELECT \"+copied);");
            assertThat(outcome.matches()).isNotEmpty();
            assertThat(outcome.snapshot().analysis().uses()).singleElement().satisfies(u->assertThat(u.kind()).isEqualTo("UNRESOLVED_QUERY"));
        }
    }

    @Test void separateOrReusedStatementCannotHideAnotherDangerousExecution() {
        for(String next:List.of("statement","connection.createStatement()")) {
            var outcome=inspect(COPY+"java.sql.Statement statement=connection.createStatement();\nstatement.executeQuery(\"SELECT 1\");\n"
                    +next+".executeQuery(\"SELECT \"+copied);");
            assertThat(outcome.matches()).isNotEmpty();
            assertThat(outcome.snapshot().analysis().uses()).anyMatch(u->u.kind().equals("INPUT_IN_QUERY"));
        }
    }

    @Test void actualBindingRemainsDistinctFromAlreadyConstructedSql() {
        var safe=inspect(COPY+"var statement=connection.prepareStatement(\"SELECT ?\");\nstatement.setString(1,copied);statement.execute();");
        assertThat(safe.matches()).isEmpty();
        assertThat(safe.snapshot().analysis().uses()).singleElement().satisfies(u->assertThat(u.kind()).isEqualTo("PARAMETERIZED_QUERY"));
        var unsafe=inspect(COPY+"var statement=connection.prepareStatement(\"SELECT \"+copied);\nstatement.setString(1,copied);statement.execute();");
        assertThat(unsafe.matches()).isNotEmpty();
    }

    @Test void nullIdentityCastCannotTurnIntoAnUnknownCall() {
        var outcome=inspect("Object stored=null;String ignored=(String)stored;\njava.sql.Statement statement=connection.createStatement();\nstatement.executeQuery(\"SELECT 1\");");
        assertThat(outcome.matches()).isEmpty();
    }

    @Test void incompleteFlowStillRetainsDeclarationWarnings() {
        var outcome=inspect(COPY+"java.sql.Statement statement=connection.createStatement();\nunknown(statement);\nstatement.executeQuery(\"SELECT 1\");");
        assertThat(outcome.matches()).isNotEmpty();
    }

    @Test void primitiveArrayDefaultsDoNotInventIntegerOverflowForFloatingValues() {
        var outcome=inspect("double[] values=new double[1];String sql=input;\n"
                +"if(values[0]+2147483647+1<0)sql=\"fixed\";\n"
                +"java.sql.Statement statement=connection.createStatement();\nstatement.executeQuery(\"SELECT \"+sql);");
        assertThat(outcome.matches()).isNotEmpty();
        assertThat(outcome.snapshot().analysis().uses()).singleElement().satisfies(u->assertThat(u.kind()).isEqualTo("INPUT_IN_QUERY"));
    }

    @Test void servletCookieStringThroughMapCastCanBeDiscardedSafely() {
        String source="import javax.servlet.http.*;import java.sql.*;class Endpoint extends HttpServlet {Connection connection;\n"
                +"public void doPost(HttpServletRequest request,HttpServletResponse response){\n"
                +"String input=\"fallback\";for(Cookie cookie:request.getCookies())input=cookie.getValue();\n"
                +"var values=new java.util.HashMap<String,Object>();values.put(\"input\",input);values.put(\"constant\",\"fixed\");\n"
                +"String value=(String)values.get(\"input\");value=(String)values.get(\"constant\");\n"
                +"Statement statement=connection.createStatement();\nstatement.executeQuery(\"SELECT \"+value);\n}}";
        var project=JavaSqlAnalyzerTest.project(source);
        var raw=project.analysisFiles().stream().flatMap(f->new DangerousSqlRule().evaluate(f).stream()).toList();
        assertThat(raw).isNotEmpty();
        assertThat(analyzer.reconcile(raw,analyzer.analyze(project)).matches()).isEmpty();
    }
}
