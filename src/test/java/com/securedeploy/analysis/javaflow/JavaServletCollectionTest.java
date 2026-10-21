package com.securedeploy.analysis.javaflow;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

/** Synthetic contracts, not copied application or benchmark sources. */
class JavaServletCollectionTest {
    private JavaSqlWorker.Result inspect(String body) {
        String source = "import javax.servlet.http.*; import java.sql.*; import java.util.*;\n"
                + "class CollectionEndpoint extends HttpServlet { Connection connection;\n"
                + "public void doPost(HttpServletRequest request,HttpServletResponse response){\n"
                + body + "\n}}";
        return new JavaSqlAnalyzer().analyze(JavaSqlAnalyzerTest.project(source));
    }

    private void expect(String body, String kind) {
        var result = inspect(body);
        assertThat(result.files()).allMatch(f -> f.parseStatus().equals("PARSED"));
        assertThat(result.uses()).hasSize(1);
        assertThat(result.uses().get(0).kind()).isEqualTo(kind);
    }

    private String execute(String value) {
        return "connection.prepareStatement(\"SELECT * FROM records WHERE label=\"+" + value + ").execute();";
    }

    @Test void servletArrayElementPreservesRequestOrigin() {
        expect("String[] values=request.getParameterValues(\"label\");" + execute("values[0]"), "INPUT_IN_QUERY");
    }

    @Test void servletMapSelectionPreservesNestedArrayOrigin() {
        expect("Map<String,String[]> params=request.getParameterMap();"
                + "String[] values=params.get(\"label\");" + execute("values[0]"), "INPUT_IN_QUERY");
    }

    @Test void requestEnumerationIsNotAnArbitraryEnumeration() {
        expect("Enumeration<String> values=request.getHeaders(\"X-Label\");"
                + "String label=\"fixed\"; if(values.hasMoreElements()) label=values.nextElement();"
                + execute("label"), "INPUT_IN_QUERY");
    }

    @Test void selectedMapSlotNotEveryInsertedValueDeterminesSql() {
        expect("Map<String,String> values=new HashMap<>();"
                + "values.put(\"selected\",\"fixed\"); values.put(\"other\",request.getParameter(\"label\"));"
                + execute("values.get(\"selected\")"), "STATIC_QUERY");
    }

    @Test void aliasOverwriteUpdatesOriginalWithoutTouchingOtherKeys() {
        expect("Map<String,String> values=new HashMap<>();"
                + "values.put(\"selected\",request.getParameter(\"label\"));"
                + "Map<String,String> alias=values; alias.put(\"selected\",\"fixed\");"
                + execute("values.get(\"selected\")"), "STATIC_QUERY");
    }

    @Test void laterInputOverwriteRemainsDangerous() {
        expect("Map<String,String> values=new HashMap<>(); values.put(\"selected\",\"fixed\");"
                + "values.put(\"selected\",request.getParameter(\"label\"));"
                + execute("values.get(\"selected\")"), "INPUT_IN_QUERY");
    }

    @Test void listMutationAndArrayMutationSelectIndividualSlots() {
        expect("List<String> values=new ArrayList<>(); values.add(request.getParameter(\"label\"));"
                + "values.add(\"fixed\"); values.set(0,\"constant\");" + execute("values.get(0)"), "STATIC_QUERY");
        expect("String[] values={request.getParameter(\"label\"),\"fixed\"};"
                + "values[0]=\"constant\";" + execute("values[1]"), "STATIC_QUERY");
    }

    @Test void collectionInputAsActualBindingDoesNotTaintQueryText() {
        expect("String[] values=request.getParameterValues(\"label\");"
                + "PreparedStatement statement=connection.prepareStatement(\"SELECT * FROM records WHERE label=?\");"
                + "statement.setString(1,values[0]);statement.execute();", "PARAMETERIZED_QUERY");
    }

    @Test void unknownMutationCannotCertifyPreviouslySafeCollection() {
        expect("Map<String,String> values=new HashMap<>(); values.put(\"selected\",\"fixed\");"
                + "unverified(values);" + execute("values.get(\"selected\")"), "UNRESOLVED_QUERY");
    }

    @Test void unknownKeyWriteCannotPreserveSafeSelectedKey() {
        expect("Map<String,String> values=new HashMap<>(); values.put(\"selected\",\"fixed\");"
                + "values.put(request.getParameter(\"key\"),request.getParameter(\"label\"));"
                + execute("values.get(\"selected\")"), "UNRESOLVED_QUERY");
    }

    @Test void branchCopiesDoNotLeakOverwriteIntoUntakenBranch() {
        expect("Map<String,String> values=new HashMap<>();values.put(\"selected\",request.getParameter(\"label\"));"
                + "if(request.getParameter(\"mode\")==null) values.put(\"selected\",\"fixed\");"
                + execute("values.get(\"selected\")"), "INPUT_IN_QUERY");
        expect("Map<String,String> values=new HashMap<>();values.put(\"selected\",request.getParameter(\"label\"));"
                + "if(request.getParameter(\"mode\")==null) values.put(\"selected\",\"fixed\");"
                + "else values.put(\"selected\",\"other\");" + execute("values.get(\"selected\")"), "STATIC_QUERY");
    }

    @Test void ambiguousAliasCannotMutateOneHeapObjectAsIfCertain() {
        expect("Map<String,String> a=new HashMap<>();Map<String,String> b=new HashMap<>();"
                + "a.put(\"selected\",\"fixed\");b.put(\"selected\",\"fixed\");"
                + "Map<String,String> alias=request.getParameter(\"mode\")==null?a:b;"
                + "alias.put(\"selected\",request.getParameter(\"label\"));"
                + execute("a.get(\"selected\")"), "UNRESOLVED_QUERY");
    }

    @Test void helperMutationUsesCallerHeapAndReturnedAlias() {
        String source = "import javax.servlet.http.*;import java.sql.*;import java.util.*;"
                + "class CollectionEndpoint extends HttpServlet {Connection connection;"
                + "public void doPost(HttpServletRequest request,HttpServletResponse response){"
                + "Map<String,String> values=new HashMap<>();values.put(\"selected\",request.getParameter(\"label\"));"
                + "Map<String,String> alias=replace(values);"+execute("alias.get(\"selected\")")+"}"
                + "static Map<String,String> replace(Map<String,String> target){target.put(\"selected\",\"fixed\");return target;}}";
        var result=new JavaSqlAnalyzer().analyze(JavaSqlAnalyzerTest.project(source));
        assertThat(result.uses()).singleElement().satisfies(u->assertThat(u.kind()).isEqualTo("STATIC_QUERY"));
    }

    @Test void arrayAssignmentEvaluatesBaseAndIndexBeforeValue() {
        expect("String[] values={request.getParameter(\"label\"),\"fixed\"};int i=0;"
                + "values[i]=(i=1)+\"constant\";"+execute("values[0]"), "STATIC_QUERY");
        expect("String[] values={request.getParameter(\"label\"),\"fixed\"};"
                + "values[1]+=values[0];"+execute("values[1]"), "INPUT_IN_QUERY");
    }

    @Test void unknownNestedMutationInvalidatesReachableArrayAlias() {
        expect("Map<String,String[]> values=new HashMap<>();String[] labels={\"fixed\"};"
                + "values.put(\"selected\",labels);unverified(values);"+execute("labels[0]"), "UNRESOLVED_QUERY");
    }

    @Test void unknownArrayAliasWritesDoNotLeaveOriginalTrusted() {
        expect("String[] a={\"fixed\"};String[] b={\"fixed\"};"
                + "String[] alias=request.getParameter(\"mode\")==null?a:b;"
                + "alias[0]=request.getParameter(\"label\");"+execute("a[0]"), "UNRESOLVED_QUERY");
    }

    @Test void arbitraryTypesAndUnsupportedOperationsAreNotJdkContracts() {
        expect("Object values=unverified();"+execute("values.get(\"selected\")"), "UNRESOLVED_QUERY");
        expect("Map<String,String> values=new HashMap<>();values.put(\"selected\",\"fixed\");"
                + "values.compute(\"selected\",(key,old)->request.getParameter(\"label\"));"
                + execute("values.get(\"selected\")"), "UNRESOLVED_QUERY");
    }

    @Test void collectionObjectsAreNotTheirSymbolicNumericIds() {
        expect("Map<String,String> values=new HashMap<>();values.put(\"selected\",request.getParameter(\"label\"));"
                + execute("values"), "UNRESOLVED_QUERY");
        expect("Map<Object,String> values=new HashMap<>();Map<String,String> key=new HashMap<>();"
                + "values.put(1,\"fixed\");values.put(key,request.getParameter(\"label\"));"
                + execute("values.get(1)"), "UNRESOLVED_QUERY");
        expect("Map<String,String> a=new HashMap<>();Map<String,String> b=new HashMap<>();"
                + "String label=request.getParameter(\"label\");if(!a.equals(b))label=\"fixed\";"
                + execute("label"), "INPUT_IN_QUERY");
    }

    @Test void collectionBudgetIsExplicitAndNeverCertifiesSafety() {
        StringBuilder code=new StringBuilder("Map<String,String> values=new HashMap<>();");
        for(int i=0;i<65;i++)code.append("values.put(\"k").append(i).append("\",\"fixed\");");
        var result=inspect(code+execute("values.get(\"k0\")"));
        assertThat(result.limitations()).contains("COLLECTION_STATE_LIMIT");
        assertThat(result.uses()).singleElement().satisfies(u->assertThat(u.kind()).isEqualTo("UNRESOLVED_QUERY"));
        assertThat(result.methods()).noneMatch(JavaSqlWorker.MethodResult::safeForLegacy);
    }

    @Test void unsupportedLoopsAndEscapedAliasesNeverLeaveTrustedSlots() {
        expect("Map<String,String> values=new HashMap<>();values.put(\"selected\",\"fixed\");"
                + "while(request.getParameter(\"mode\")!=null)values.put(\"selected\",request.getParameter(\"label\"));"
                + execute("values.get(\"selected\")"), "UNRESOLVED_QUERY");
        expect("Map<String,String> values=new HashMap<>();values.put(\"selected\",\"fixed\");"
                + "external.shared=values;external.change();"+execute("values.get(\"selected\")"), "UNRESOLVED_QUERY");
    }
}
