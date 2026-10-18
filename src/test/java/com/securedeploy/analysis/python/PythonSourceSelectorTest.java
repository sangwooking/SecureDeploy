package com.securedeploy.analysis.python;

import com.securedeploy.project.model.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class PythonSourceSelectorTest {
    private ProjectFile file(String path, String source) {
        return new ProjectFile(Path.of("/not-executed").resolve(path), path, ProjectFileType.PYTHON, source.lines().toList());
    }
    @Test void routingAndBoundedImportsPrecedeUnrelatedFilesIndependentOfOrder() {
        var files = new ArrayList<ProjectFile>();
        for (int i=0;i<110;i++) files.add(file("a/data"+i+".py", "data=1"));
        files.add(file("z/routes.py", "from django.urls import path\nfrom .controller import endpoint\nurlpatterns=[path('',endpoint)]"));
        files.add(file("z/controller.py", "from .logic import write\ndef endpoint(request):\n    write(request.GET['q'])"));
        files.add(file("z/logic.py", "from django.db import connection\ndef write(value):\n    with connection.cursor() as c:\n        c.execute('select '+value)"));
        var analyzer = new PythonServerAnalyzer(new PythonAnalysisProperties());
        var a = analyzer.analyze(new ProjectStructure(Path.of("/not-executed"), files));
        Collections.shuffle(files, new Random(19));
        var b = analyzer.analyze(new ProjectStructure(Path.of("/not-executed"), files));
        assertThat(a).isEqualTo(b);
        assertThat(a.validatedFindings()).hasSize(1);
        assertThat(a.files().stream().filter(f -> f.parseStatus().equals("PARSED"))).hasSize(100);
        assertThat(a.files().stream().filter(f -> f.limitations().contains("FILE_COUNT_LIMIT"))).hasSize(13);
        assertThat(a.files().stream().filter(f -> f.filePath().equals("z/logic.py")).findFirst().orElseThrow().selectionReason())
                .isEqualTo("RELATED_IMPORT_HINT");
    }
    @Test void schedulingHintsNeverProveAnEntrypointOrBypassSourceLimits() {
        var analyzer = new PythonServerAnalyzer(new PythonAnalysisProperties());
        var result = analyzer.analyze(new ProjectStructure(Path.of("/none"), List.of(
                file("x.py", "from django.urls import path\nnot_a_route=path('fake', unknown)"),
                file("y.py", "from rest_framework.decorators import api_view\n"+"#".repeat(100_000)))));
        assertThat(result.findings()).isEmpty();
        assertThat(result.files().stream().mapToInt(f -> f.entrypoints()).sum()).isZero();
        assertThat(result.files().stream().filter(f -> f.filePath().equals("y.py")).findFirst().orElseThrow().limitations())
                .contains("FILE_CHARACTER_LIMIT");
    }
    @Test void noFrameworkFallsBackDeterministicallyAndRelativeImportCannotEscapeRoot() {
        var result=PythonSourceSelector.order(List.of(file("z.py","from ....hidden import code"),file("a.py","x=1")));
        assertThat(result).extracting(c -> c.file().relativePath()).containsExactly("a.py","z.py");
        assertThat(result).allMatch(c -> c.reason().equals("DETERMINISTIC_FALLBACK"));
    }
    @Test void totalTextAndOmittedDetailCountsRemainBoundedAndHonest() {
        var analyzer=new PythonServerAnalyzer(new PythonAnalysisProperties());
        var large=new ArrayList<ProjectFile>();
        for(int i=0;i<12;i++) large.add(file("text"+i+".py","#"+"a".repeat(89_999)));
        var result=analyzer.analyze(new ProjectStructure(Path.of("/none"),large));
        assertThat(result.selectionCoverage().submittedCharacters()).isLessThanOrEqualTo(1_000_000);
        assertThat(result.selectionCoverage().omissionReasons()).containsEntry("TOTAL_CHARACTER_LIMIT",1);
        var many=new ArrayList<ProjectFile>();
        for(int i=0;i<205;i++) many.add(file("file"+i+".py","value=1"));
        var capped=analyzer.analyze(new ProjectStructure(Path.of("/none"),many));
        assertThat(capped.selectionCoverage().discoveredFiles()).isEqualTo(205);
        assertThat(capped.selectionCoverage().submittedFiles()).isEqualTo(100);
        assertThat(capped.selectionCoverage().omittedFiles()).isEqualTo(105);
        assertThat(capped.selectionCoverage().omittedDetails()).isEqualTo(5);
        assertThat(capped.files()).hasSize(200);
        assertThat(capped.limitations()).contains("OMITTED_FILE_DETAILS_TRUNCATED");
    }
    @Test void hintInspectionIsBoundedAndPermutationDoesNotChangeItsBudget() {
        var files=new ArrayList<ProjectFile>();
        for(int i=0;i<1002;i++) files.add(file(String.format("f%04d.py",i),"value=1"));
        var first=PythonSourceSelector.order(files);
        Collections.shuffle(files,new Random(27));
        assertThat(PythonSourceSelector.order(files)).isEqualTo(first);
        assertThat(first.stream().filter(c -> c.reason().equals("SELECTION_HINT_LIMIT"))).hasSize(2);
    }
}
