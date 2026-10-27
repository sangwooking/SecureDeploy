package com.securedeploy.analysis.typescript;

import com.securedeploy.project.model.*;
import com.securedeploy.project.service.ProjectFileCollector;
import com.securedeploy.project.coverage.CoverageLedger;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class SupabaseAnalysisTest {
    @Test void columnOnlyBroadWritePersistsWithoutInventingWholeTablePermissionOrResolvedHistory(){
        var result=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(project(
            broad.replace("CREATE TABLE public.records(user_id uuid)","CREATE TABLE public.records(user_id uuid, body text)")
                .replace("GRANT UPDATE ON","GRANT UPDATE(body) ON")));
        var s=result.supabaseAnalysis();assertThat(s.analyzerVersion()).isEqualTo("supabase-rls-v4");
        assertThat(s.findings()).hasSize(1);assertThat(s.findings().get(0).comparisonPolicy()).isEqualTo("NOT_COMPARED");
        assertThat(s.tables().get(0).updatePrivileges().get(1).tableGrant()).isEqualTo("NOT_ESTABLISHED");
        assertThat(s.tables().get(0).updatePrivileges().get(1).columns()).containsExactly("body");
        var converter=new ServerAnalysisConverter();String json=converter.convertToDatabaseColumn(result);
        assertThat(json).doesNotContain("CREATE TABLE","GRANT UPDATE(body)");
        assertThat(converter.convertToEntityAttribute(json)).isEqualTo(result);
        String old=json.replace("ts-server-v38","ts-server-v33").replace("supabase-rls-v4","supabase-rls-v3");
        assertThat(converter.convertToDatabaseColumn(converter.convertToEntityAttribute(old))).isEqualTo(old);
    }
    @Test void localIdentityAliasesAndMatchPersistAsEvidenceNotAuthorizationOrNewFindings(){
        for(String filter:List.of("eq('user_id',identity)","match({user_id:identity})")){
            String path="app/api/records/route.ts",code="import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.invalid',process.env.ANON_KEY);export async function GET(req){const {data:{user}}=await db.auth.getUser();if(!user)return;const identity=user.id;return db.from('records').select()."+filter+";}";
            var files=List.of(new ProjectFile(Path.of(path),path,ProjectFileType.TYPESCRIPT,code.lines().toList()),
                    new ProjectFile(Path.of("package.json"),"package.json",ProjectFileType.PACKAGE_JSON,List.of("{\"dependencies\":{\"next\":\"15.2.0\"}}")));
            var result=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(new ProjectStructure(Path.of("/not-executed"),files));
            var e=result.supabaseAnalysis().accesses().get(0).authorizationEvidence();
            assertThat(e.requestEntry()).isNotNull();assertThat(e.effectiveRole()).isEqualTo("UNKNOWN");
            assertThat(e.state()).isEqualTo("UNKNOWN");
            assertThat(e.authChecks().get(0).resultEvidence().userIdFilters()).hasSize(1);
            assertThat(result.validatedFindings()).isEmpty();assertThat(result.supabaseAnalysis().findings()).isEmpty();
            var converter=new ServerAnalysisConverter();String saved=converter.convertToDatabaseColumn(result);
            assertThat(saved).doesNotContain(code);assertThat(converter.convertToEntityAttribute(saved)).isEqualTo(result);
            assertThat(result.attachCoverage(new com.securedeploy.project.coverage.CoverageRecorder().snapshot()).analyzers())
                    .anyMatch(a->a.analyzer().equals("SUPABASE_RLS")&&a.fileStatuses().get("IDENTITY_ID_FILTERS_OBSERVED")==1);
        }
    }
    @Test void localWriteOriginsPersistWithoutValuesAndLegacySnapshotsStayUnrecorded() throws Exception {
        String path="app/api/records/route.ts",code="import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.invalid',process.env.ANON_KEY);export async function POST(req){const body=await req.json();return db.from('records').update({title:body.title,fixed:'private-placeholder'}).eq('id',body.id);}";
        var files=new ArrayList<>(project(broad).analysisFiles());
        files.add(new ProjectFile(Path.of(path),path,ProjectFileType.TYPESCRIPT,code.lines().toList()));
        files.add(new ProjectFile(Path.of("package.json"),"package.json",ProjectFileType.PACKAGE_JSON,List.of("{\"dependencies\":{\"next\":\"15.2.0\"}}")));
        var result=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(new ProjectStructure(Path.of("/not-executed"),files));
        var w=result.supabaseAnalysis().accesses().get(0).writeEvidence();assertThat(w).isNotNull();
        assertThat(w.columnUpdate()).isNotNull();assertThat(w.columnUpdate().roles()).hasSize(2);
        assertThat(w.columnUpdate().roles().get(1).fields()).extracting(SupabaseSnapshot.ColumnField::grant).containsOnly("TABLE_GRANT");
        assertThat(w.dataFields()).extracting(SupabaseSnapshot.WriteValue::source).containsExactly("REQUEST_CONTROLLED","SERVER_CONTROLLED");
        assertThat(w.filters()).extracting(SupabaseSnapshot.WriteValue::source).containsExactly("REQUEST_CONTROLLED");
        var converter=new ServerAnalysisConverter();String json=converter.convertToDatabaseColumn(result);
        assertThat(json).doesNotContain(code,"private-placeholder");assertThat(converter.convertToEntityAttribute(json)).isEqualTo(result);
        var tree=(com.fasterxml.jackson.databind.node.ObjectNode)new com.fasterxml.jackson.databind.ObjectMapper().readTree(json);
        tree.put("analyzerVersion","ts-server-v25");
        var write=(com.fasterxml.jackson.databind.node.ObjectNode)tree.path("supabaseAnalysis").path("accesses").get(0).path("writeEvidence");write.remove("columnUpdate");
        ((com.fasterxml.jackson.databind.node.ObjectNode)tree.path("supabaseAnalysis").path("tables").get(0)).remove("updatePrivileges");
        assertThat(converter.convertToEntityAttribute(tree.toString()).supabaseAnalysis().accesses().get(0).writeEvidence().columnUpdate()).isNull();
        assertThat(converter.convertToEntityAttribute(tree.toString()).supabaseAnalysis().tables().get(0).updatePrivileges()).isNull();
        ((com.fasterxml.jackson.databind.node.ObjectNode)tree.path("supabaseAnalysis").path("accesses").get(0)).remove("writeEvidence");
        assertThat(converter.convertToEntityAttribute(tree.toString()).supabaseAnalysis().accesses().get(0).writeEvidence()).isNull();
        assertThat(result.attachCoverage(new com.securedeploy.project.coverage.CoverageRecorder().snapshot()).analyzers())
                .anyMatch(a->a.analyzer().equals("SUPABASE_RLS")&&a.fileStatuses().get("WRITE_ORIGIN_RECORDED")==1);
    }
    @Test void linkedOperationEvidenceSurvivesSnapshotsButOldEvidenceIsNotInvented() throws Exception {
        var files=new ArrayList<>(project(broad.replace("USING(true) WITH CHECK(true)","USING(auth.uid()=user_id) WITH CHECK(auth.uid()=user_id)")).analysisFiles());
        String path="src/data.ts",code="import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.invalid',process.env.ANON_KEY);db.from('records').update({});";
        files.add(new ProjectFile(Path.of(path),path,ProjectFileType.TYPESCRIPT,code.lines().toList()));
        var result=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(new ProjectStructure(Path.of("/not-executed"),files));
        var access=result.supabaseAnalysis().accesses().get(0);
        assertThat(access.authorizationEvidence().state()).isEqualTo("CONFIRMED_POLICY_EVIDENCE");
        assertThat(access.authorizationEvidence().effectiveRole()).isEqualTo("UNKNOWN");
        assertThat(result.supabaseAnalysis().findings()).isEmpty();
        var converter=new ServerAnalysisConverter();String json=converter.convertToDatabaseColumn(result);
        assertThat(converter.convertToEntityAttribute(json)).isEqualTo(result);
        assertThat(json).doesNotContain(code,"auth.uid()=user_id");
        var old=(com.fasterxml.jackson.databind.node.ObjectNode)new com.fasterxml.jackson.databind.ObjectMapper().readTree(json);
        ((com.fasterxml.jackson.databind.node.ObjectNode)old.path("supabaseAnalysis").path("accesses").get(0)).remove("authorizationEvidence");
        assertThat(converter.convertToEntityAttribute(old.toString()).supabaseAnalysis().accesses().get(0).authorizationEvidence()).isNull();
    }
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
