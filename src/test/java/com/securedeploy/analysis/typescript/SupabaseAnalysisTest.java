package com.securedeploy.analysis.typescript;

import com.securedeploy.project.model.*;
import com.securedeploy.project.service.ProjectFileCollector;
import com.securedeploy.project.coverage.CoverageLedger;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class SupabaseAnalysisTest {
    private ProjectStructure project(String sql){
        String path="supabase/migrations/20260101000000_policy.sql";
        return new ProjectStructure(Path.of("/not-executed"),List.of(new ProjectFile(Path.of(path),path,ProjectFileType.SUPABASE_SQL,sql.lines().toList())));
    }
    private final String broad="CREATE TABLE public.records(user_id uuid);ALTER TABLE public.records ENABLE ROW LEVEL SECURITY;GRANT UPDATE ON public.records TO authenticated;CREATE POLICY shared ON public.records FOR UPDATE TO authenticated USING(true) WITH CHECK(true);";
    @Test void sqlOnlyProjectPersistsBoundedEvidenceWithoutSqlTextAndPreservesLegacyConstructors(){
        var result=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(project(broad));
        assertThat(result.supabaseAnalysis()).isNotNull();assertThat(result.supabaseAnalysis().tables()).hasSize(1);
        assertThat(result.supabaseAnalysis().findings()).hasSize(1);
        assertThat(result.supabaseAnalysis().findings().get(0).priority()).isEqualTo("REVIEW_REQUIRED");
        assertThat(result.validatedFindings()).isEmpty();
        var converter=new ServerAnalysisConverter();String json=converter.convertToDatabaseColumn(result);
        assertThat(json).doesNotContain("CREATE POLICY","WITH CHECK(true)");
        assertThat(converter.convertToEntityAttribute(json)).isEqualTo(result);
        assertThat(result.withPythonAnalysis(null).withJavaAnalysis(null).withNodeUses(List.of()).supabaseAnalysis()).isEqualTo(result.supabaseAnalysis());
        assertThat(result.attachCoverage(new com.securedeploy.project.coverage.CoverageRecorder().snapshot()).analyzers()).anyMatch(a->a.analyzer().equals("SUPABASE_RLS"));
    }
    @Test void disabledOrOmittedSqlIsNotAnEmptySuccessfulCheck(){
        var properties=new TypeScriptAnalysisProperties();properties.setEnabled(false);
        var result=new TypeScriptServerAnalyzer(properties).analyze(project(broad));
        assertThat(result.supabaseAnalysis().status()).isEqualTo("PARTIAL");
        assertThat(result.supabaseAnalysis().files().get(0).status()).isEqualTo("NOT_RUN");
    }
    @Test void collectorRecognizesOnlyScopedPolicySources(){
        var collector=new ProjectFileCollector();
        assertThat(collector.resolveAnalysisFileType(Path.of("nested/supabase/migrations/20260101000000_rls.sql"))).contains(ProjectFileType.SUPABASE_SQL);
        assertThat(collector.resolveAnalysisFileType(Path.of("schema.sql"))).contains(ProjectFileType.SUPABASE_SQL);
        assertThat(collector.resolveAnalysisFileType(Path.of("arbitrary.sql"))).isEmpty();
    }
}
