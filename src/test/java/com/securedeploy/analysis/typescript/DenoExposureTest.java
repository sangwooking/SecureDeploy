package com.securedeploy.analysis.typescript;

import com.securedeploy.project.model.*;
import com.securedeploy.project.service.ProjectFileCollector;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class DenoExposureTest {
    private ServerAnalysisSnapshot analyze(String body,String config) {
        String path="supabase/functions/inspect/index.ts";
        var source=new ProjectFile(Path.of(path),path,ProjectFileType.TYPESCRIPT,
                ("Deno.serve(async request=>{"+body+"});").lines().toList());
        var settings=new ProjectFile(Path.of("supabase/config.toml"),"supabase/config.toml",ProjectFileType.SUPABASE_CONFIG,config.lines().toList());
        return new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(new ProjectStructure(Path.of("/unreadable-target"),List.of(source,settings)));
    }
    @Test void metadataContainsDeclarationsNotSecretsOrAuthorizationGuarantees() {
        for(String flag:List.of("true","false")) {
            var r=analyze("return Response.json(Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'));","[functions.inspect]\nverify_jwt="+flag);
            assertThat(r.files().get(0).limitations()).contains("SUPABASE_VERIFY_JWT_DECLARED_"+flag.toUpperCase(Locale.ROOT),"SUPABASE_LIVE_AUTHORIZATION_AND_RLS_NOT_VERIFIED");
            assertThat(r.validatedFindings()).hasSize(1);
            assertThat(r.validatedFindings().get(0).priority().name()).isEqualTo("REVIEW_REQUIRED");
            String json=new ServerAnalysisConverter().convertToDatabaseColumn(r);
            assertThat(json).doesNotContain("SUPABASE_SERVICE_ROLE_KEY");
            assertThat(new ServerAnalysisConverter().convertToEntityAttribute(json)).isEqualTo(r);
        }
    }
    @Test void unknownConfigAndBooleanResponseDoNotCertifyDeployment() {
        var r=analyze("return Response.json({configured:!!Deno.env.get('API_SECRET')});","not valid toml");
        assertThat(r.validatedFindings()).isEmpty();
        assertThat(r.files().get(0).limitations()).contains("SUPABASE_VERIFY_JWT_DECLARATION_UNKNOWN");
        assertThat(new ProjectFileCollector().resolveAnalysisFileType(Path.of("nested/supabase/config.toml"))).contains(ProjectFileType.SUPABASE_CONFIG);
        assertThat(new ProjectFileCollector().resolveAnalysisFileType(Path.of("unrelated/config.toml"))).isEmpty();
    }
}
