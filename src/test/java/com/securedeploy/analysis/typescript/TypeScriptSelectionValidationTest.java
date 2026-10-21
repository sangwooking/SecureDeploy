package com.securedeploy.analysis.typescript;

import com.securedeploy.project.model.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

/** Later-authored internal controls; not independent external or blind evaluation. */
class TypeScriptSelectionValidationTest {
    ProjectFile file(String p,String c){return new ProjectFile(Path.of("/no-target-read").resolve(p),p,ProjectFileType.TYPESCRIPT,c.lines().toList());}
    @Test void shuffledInputAndRenamedRoutingFoldersRetainDenoHelperSinkButNotASafeReturn(){
        var analyzer=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties());
        for(String folder:List.of("gateway","renamedEndpoint"))for(boolean dangerous:List.of(false,true)) {
            var files=new ArrayList<ProjectFile>();
            for(int i=0;i<130;i++)files.add(file("aaa/ui/Part"+i+".tsx","export const Part=()=>null;"));
            files.add(file("supabase/functions/"+folder+"/index.ts","import {respond} from './logic';Deno.serve(async(req)=>respond(req));"));
            files.add(file("supabase/functions/"+folder+"/logic.ts",dangerous
                    ?"export function respond(req){return Response.json(Deno.env.get('SYNTHETIC_PRIVATE_KEY'));}"
                    :"export function respond(req){return Response.json({ok:true});}"));
            var original=analyzer.analyze(new ProjectStructure(Path.of("/no-target-read"),files));
            Collections.shuffle(files,new Random(37));
            var shuffled=analyzer.analyze(new ProjectStructure(Path.of("/no-target-read"),files));
            assertThat(shuffled).isEqualTo(original);
            assertThat(original.authorizationContexts()).hasSize(1);
            assertThat(original.validatedFindings()).hasSize(dangerous?1:0);
        }
    }
    @Test void lexicalHintsNeverPromoteCommentsToActualRequestsAndOldMetadataRemainsAbsent() throws Exception {
        var analyzer=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties());
        var result=analyzer.analyze(new ProjectStructure(Path.of("/no-target-read"),List.of(file("notes.ts","// Deno.serve(request => fetch(request.url));\nexport const value=1;"))));
        assertThat(result.authorizationContexts()).isEmpty();assertThat(result.validatedFindings()).isEmpty();
        var converter=new ServerAnalysisConverter();
        var old=(com.fasterxml.jackson.databind.node.ObjectNode)new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(converter.convertToDatabaseColumn(result));old.remove("selectionCoverage");
        assertThat(converter.convertToEntityAttribute(old.toString()).selectionCoverage()).isNull();
    }
}
