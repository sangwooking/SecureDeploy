package com.securedeploy.analysis.typescript;

import com.securedeploy.project.model.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class SecretObjectFlowTest {
    ServerAnalysisSnapshot run(String body){
        String path="app/api/check/route.ts",code="export async function GET(){"+body+"}";
        var files=List.of(new ProjectFile(Path.of(path),path,ProjectFileType.TYPESCRIPT,code.lines().toList()),
            new ProjectFile(Path.of("package.json"),"package.json",ProjectFileType.PACKAGE_JSON,List.of("{\"dependencies\":{\"next\":\"15.3.0\"}}")));
        return new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(new ProjectStructure(Path.of("/not-executed"),files));
    }
    @Test void mutationAndSpreadReachExistingUserFindingWithoutValuesOrNewRepairContract(){
        var r=run("const internal={};internal.value=process.env.UNIQUE22_PRIVATE_API_KEY;const output={status:'ok',...internal};return Response.json(output);");
        assertThat(r.validatedFindings()).hasSize(1);
        var f=r.validatedFindings().get(0);
        assertThat(f.ruleId()).isEqualTo("TS_SENSITIVE_DATA_EXPOSURE");
        assertThat(f.priority().name()).isEqualTo("REVIEW_REQUIRED");assertThat(f.comparisonPolicy()).isEqualTo("NOT_COMPARED");
        assertThat(f.evidence().get(0).flow()).anyMatch(l->l.kind().equals("OBJECT_DATA_PROPERTY_WRITE"));
        assertThat(f.evidence().get(0).flow()).anyMatch(l->l.kind().equals("OBJECT_DATA_SPREAD"));
        assertThat(f.recommendedAction()).contains("정상 응답 필드는 유지","anon","폐기·교체","canary");
        var converter=new ServerAnalysisConverter();String json=converter.convertToDatabaseColumn(r);
        assertThat(json).doesNotContain("UNIQUE22_PRIVATE_API_KEY","process.env");assertThat(converter.convertToEntityAttribute(json)).isEqualTo(r);
    }
    @Test void deleteAndFieldSelectionDoNotLeakButDynamicDeletionAndHooksAreUnknown(){
        for(String body:List.of("const output={value:process.env.SERVER_SECRET,status:'ok'};delete output.value;return Response.json(output);",
            "const output={value:process.env.SERVER_SECRET,status:'ok'};return Response.json({status:output.status});"))assertThat(run(body).validatedFindings()).isEmpty();
        for(String body:List.of("const output={value:process.env.SERVER_SECRET};delete output[externalKey()];return Response.json(output);",
            "const output={__proto__:{value:process.env.SERVER_SECRET}};return Response.json(output);")){
            var r=run(body);assertThat(r.validatedFindings()).isEmpty();
            assertThat(r.exposureUses()).anyMatch(u->u.status().equals("FLOW_UNRESOLVED"));
        }
    }
}
