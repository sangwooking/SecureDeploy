package com.securedeploy.analysis.typescript;

import com.securedeploy.global.config.FileStorageProperties;
import com.securedeploy.project.coverage.CoverageRecorder;
import com.securedeploy.project.model.*;
import com.securedeploy.project.service.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.assertj.core.api.Assertions.*;

class PolicySourceCoverageTest {
    @TempDir Path temp;
    private final String sql="CREATE TABLE public.items(user_id uuid);ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;GRANT UPDATE ON public.items TO authenticated;CREATE POLICY p ON public.items FOR UPDATE TO authenticated USING(auth.uid()=user_id) WITH CHECK(auth.uid()=user_id);";
    private ProjectStructure project(String root,boolean action) throws Exception {
        Path folder=temp.resolve(root);Files.createDirectories(folder);
        String file=action?"src/app/actions.ts":"app/api/items/route.ts";
        Path code=folder.resolve(file);Files.createDirectories(code.getParent());
        Files.writeString(code,(action?"'use server';":"")+"import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.invalid',process.env.ANON_KEY);export async function "+(action?"save(body)":"POST(body)")+"{return db.from('items').update({payload:'fixed'});}");
        Files.writeString(folder.resolve("package.json"),"{\"dependencies\":{\"next\":\"15.2.0\"}}");
        Path migration=folder.resolve("supabase/migrations/20260101000000_owner.sql");Files.createDirectories(migration.getParent());Files.writeString(migration,sql);
        return new ProjectScanner(new ProjectFileCollector(),new FileStorageProperties()).scan(folder);
    }
    @Test void realLfsPolicyOmissionDoesNotBecomeConfirmedProtectionInEitherNextLayout() throws Exception {
        for(boolean action:List.of(false,true)){
            var initial=project(action?"action":"route",action);Path missing=initial.projectRoot().resolve("supabase/migrations/20260102000000_next.sql");
            Files.writeString(missing,"version https://git-lfs.github.com/spec/v1\noid sha256:"+"1".repeat(64)+"\nsize 123\n");
            var scanned=new ProjectScanner(new ProjectFileCollector(),new FileStorageProperties()).scan(initial.projectRoot());
            var result=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(scanned);
            assertThat(result.supabaseAnalysis().accesses().get(0).authorizationEvidence().state()).isEqualTo("UNKNOWN");
            assertThat(result.supabaseAnalysis().files()).anyMatch(f->f.filePath().endsWith("_next.sql")&&f.status().equals("NOT_RUN"));
        }
    }
    @Test void acquisitionNullTypesUseTheSamePathContractAndUnrelatedOmissionsDoNotInvalidatePolicies() throws Exception {
        var p=project("acquisition",false);var recorder=new CoverageRecorder();
        recorder.record("images/large.png","FILE",null,"EXCLUDED","BINARY_ASSET_NOT_ANALYZED");
        recorder.record("node_modules/pkg/schema.sql","FILE",null,"EXCLUDED","DIRECTORY_POLICY");
        var scanner=new ProjectScanner(new ProjectFileCollector(),new FileStorageProperties());var analyzer=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties());
        assertThat(analyzer.analyze(scanner.scan(p.projectRoot(),recorder.snapshot())).supabaseAnalysis().accesses().get(0).authorizationEvidence().state()).isEqualTo("CONFIRMED_POLICY_EVIDENCE");
        recorder.record("supabase/migrations/20260102000000_external.sql","FILE",null,"EXCLUDED","LFS_POINTER");
        assertThat(analyzer.analyze(scanner.scan(p.projectRoot(),recorder.snapshot())).supabaseAnalysis().accesses().get(0).authorizationEvidence().state()).isEqualTo("UNKNOWN");
    }
    @Test void knownMigrationOmissionsStayWithinTheirScopeAndNoContentIsRequiredForMissingOnlyProjects() throws Exception {
        var files=new ArrayList<ProjectFile>();var ledger=new CoverageRecorder();
        for(String prefix:List.of("alpha/","beta/"))for(var f:project(prefix,false).analysisFiles()){
            String name=prefix+(f.type()==ProjectFileType.TYPESCRIPT?"src/":"")+f.relativePath();
            files.add(new ProjectFile(f.absolutePath(),name,f.type(),f.lines()));ledger.record(name,"FILE",f.type().name(),"SELECTED","PATTERN_ANALYSIS_INPUT");
        }
        ledger.record("alpha/supabase/migrations/20260102000000_missing.sql","FILE",null,"EXCLUDED","LFS_POINTER");
        var result=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(new ProjectStructure(temp,files,ledger.snapshot()));
        assertThat(result.supabaseAnalysis().accesses()).anyMatch(a->a.location().filePath().startsWith("alpha/")&&a.authorizationEvidence().state().equals("UNKNOWN"));
        assertThat(result.supabaseAnalysis().accesses()).anyMatch(a->a.location().filePath().startsWith("beta/")&&a.authorizationEvidence().state().equals("CONFIRMED_POLICY_EVIDENCE"));
        var only=new CoverageRecorder();only.record("supabase/migrations/20260102000000_missing.sql","FILE",null,"EXCLUDED","LFS_POINTER");
        var missing=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(new ProjectStructure(temp,List.of(),only.snapshot()));
        assertThat(missing.supabaseAnalysis().status()).isEqualTo("PARTIAL");assertThat(missing.supabaseAnalysis().files()).hasSize(1);
    }
    @Test void ledgerTruncationNeverEstablishesACompletePolicyInventory() throws Exception {
        var p=project("bounded",false);var ledger=new CoverageRecorder();
        for(int i=0;i<=CoverageRecorder.MAX_ENTRIES;i++)ledger.record("images/"+i+".png","FILE",null,"EXCLUDED","BINARY_ASSET_NOT_ANALYZED");
        var result=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(new ProjectStructure(p.projectRoot(),p.analysisFiles(),ledger.snapshot()));
        assertThat(result.supabaseAnalysis().accesses().get(0).authorizationEvidence().state()).isEqualTo("UNKNOWN");
        assertThat(result.supabaseAnalysis().files().size()).isLessThanOrEqualTo(100);
    }
    @Test void descriptorOverflowAndRedactedSqlDoNotRestoreProtection() throws Exception {
        var p=project("metadata",false);var analyzer=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties());
        var ledger=new CoverageRecorder();
        for(int i=0;i<120;i++)ledger.record("supabase/migrations/"+String.format("%014d",i)+"_missing.sql","FILE",null,"EXCLUDED","LFS_POINTER");
        var capped=analyzer.analyze(new ProjectStructure(p.projectRoot(),p.analysisFiles(),ledger.snapshot()));
        assertThat(capped.supabaseAnalysis().files()).hasSize(100);
        assertThat(capped.supabaseAnalysis().accesses().get(0).authorizationEvidence().state()).isEqualTo("UNKNOWN");
        var redacted=new CoverageRecorder();redacted.record("secret=fixture/schema.sql","FILE","SUPABASE_SQL","EXCLUDED","LFS_POINTER");
        var hidden=analyzer.analyze(new ProjectStructure(p.projectRoot(),p.analysisFiles(),redacted.snapshot()));
        assertThat(hidden.supabaseAnalysis().accesses().get(0).authorizationEvidence().state()).isEqualTo("UNKNOWN");
    }
}
