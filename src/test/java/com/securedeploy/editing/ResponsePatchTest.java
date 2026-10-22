package com.securedeploy.editing;

import com.securedeploy.analysis.typescript.*;
import com.securedeploy.project.model.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ResponsePatchTest {
    @Test void realParserAndAnalyzerAgreeOnSourceSinkAndDoNotRunTheSource() {
        String path="supabase/functions/inspect/index.ts";
        for(String expression:List.of("'SUPABASE_SERVICE_ROLE_KEY'","new URL(request.url).searchParams.get('field')")) {
            String setup=expression.startsWith("new")?"const name="+expression+";":"";
            String value=setup.isEmpty()?expression:"name";
            String code="Deno.serve(request=>{"+setup+"return Response.json({status: 'ok', diagnostic: Deno.env.get("+value+")});});";
            var analysis=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(new ProjectStructure(Path.of("/no-target-execution"),List.of(
                    new ProjectFile(Path.of(path),path,ProjectFileType.TYPESCRIPT,code.lines().toList()))));
            var finding=analysis.validatedFindings().stream().filter(f->f.ruleId().equals("TS_SENSITIVE_DATA_EXPOSURE")).findFirst().orElseThrow();
            var contract=new ResponsePatchValidator.Contract(code,finding.location(),finding.evidence().stream().map(e->e.source()).distinct().toList());
            var validator=new ResponsePatchValidator(new TypeScriptAnalysisProperties());
            var target=validator.check(contract,null);assertTrue(target.before().contains("diagnostic"));
            assertDoesNotThrow(()->validator.check(contract,"{status: 'ok'}"));
            assertThrows(IllegalArgumentException.class,()->validator.check(contract,"{status: 'changed'}"));
            assertThrows(IllegalArgumentException.class,()->validator.check(contract,"{}"));
        }
    }
}
