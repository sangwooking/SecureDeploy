package com.securedeploy.analysis.typescript;

import com.securedeploy.project.model.*;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
import static com.securedeploy.analysis.typescript.TypeScriptServerAnalyzerTest.project;

class FileAccessFlowTest {
    final TypeScriptServerAnalyzer analyzer=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties());
    @Test void requestToFsHasCorroboratedFindingWithoutChangingPolicy() {
        var result=analyzer.analyze(project("const app=require('express')();const fs=require('node:fs');const path=require('node:path');app.post('/',(req,res)=>fs.readFileSync(path.join('/srv/data',req.body.name)));"));
        assertThat(result.analyzerVersion()).isEqualTo("ts-server-v49");
        assertThat(result.resourceUses()).hasSize(1);
        assertThat(result.resourceUses().get(0).kind()).isEqualTo("INPUT_IN_FILE_PATH");
        assertThat(result.validatedFindings()).hasSize(1);
        var f=result.validatedFindings().get(0);
        assertThat(f.ruleId()).isEqualTo("JS_FILE_PATH_INPUT_FLOW");
        assertThat(f.sourceType()).isEqualTo("TYPESCRIPT_DATA_FLOW");
        assertThat(f.priority().name()).isEqualTo("REVIEW_REQUIRED");
        assertThat(f.comparisonPolicy()).isEqualTo("NOT_COMPARED");
        assertThat(f.title()).contains("파일");
        assertThat(f.evidence().get(0).source().kind()).isEqualTo("EXPRESS_BODY");
        assertThat(f.evidence().get(0).limitations()).contains("SYMLINKS_PERMISSIONS_AND_RUNTIME_NOT_VERIFIED");
        var converter=new ServerAnalysisConverter();
        assertThat(converter.convertToEntityAttribute(converter.convertToDatabaseColumn(result))).isEqualTo(result);
    }
    @Test void dataArgumentsAndUnknownUploadedNamesNeverBecomeConfirmedPathFindings() {
        for(String body:List.of("fs.writeFileSync('/srv/fixed',req.body.content);","fs.readFileSync(clean(req.body.name));",
                "fs.writeFileSync('/srv/'+req.file.originalname,'fixed');")) {
            var r=analyzer.analyze(project("const app=require('express')();const fs=require('node:fs');app.post('/',(req,res)=>{"+body+"});"));
            assertThat(r.validatedFindings()).isEmpty();
            assertThat(r.resourceUses()).hasSize(1);
        }
    }
    @Test void nextFormFieldReachesPromisesWriteButFileTypeRemainsUnverified() {
        String code="import {writeFile} from 'node:fs/promises';export async function POST(request){const f=await request.formData();await writeFile(f.get('name'),'fixed');return Response.json({ok:true})}";
        var p=new ProjectStructure(Path.of("/unreadable"),List.of(new ProjectFile(Path.of("/unreadable/app/api/files/route.ts"),"app/api/files/route.ts",ProjectFileType.TYPESCRIPT,code.lines().toList()),
                new ProjectFile(Path.of("/unreadable/package.json"),"package.json",ProjectFileType.PACKAGE_JSON,List.of("{\"dependencies\":{\"next\":\"15.3.0\"}}"))));
        var r=analyzer.analyze(p);
        assertThat(r.validatedFindings()).hasSize(1);
        assertThat(r.validatedFindings().get(0).evidence().get(0).source().kind()).isEqualTo("REQUEST_BODY");
    }
}
