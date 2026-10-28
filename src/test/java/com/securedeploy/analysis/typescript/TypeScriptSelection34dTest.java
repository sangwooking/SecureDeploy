package com.securedeploy.analysis.typescript;

import com.securedeploy.project.model.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class TypeScriptSelection34dTest {
    ProjectFile file(String p,String text){return new ProjectFile(Path.of("/not-readable").resolve(p),p,ProjectFileType.TYPESCRIPT,text.lines().toList());}
    List<ProjectFile> inputs(){
        var files=new ArrayList<ProjectFile>();
        for(int i=0;i<180;i++)files.add(file("aaa/View%03d.tsx".formatted(i),"export const label=1;"));
        files.add(file("tsconfig.json","{/*JSONC*/\"compilerOptions\":{\"moduleResolution\":\"bundler\",\"paths\":{\"@/*\":[\"./src/*\"]}},}"));
        files.add(file("src/app/api/save/route.ts","import {save} from '@/lib/gateway';export async function POST(request){return save(request);}"));
        files.add(file("src/lib/gateway/index.ts","export {save} from '@/domain/operation';"));
        files.add(file("src/domain/operation.ts","export function save(request){return fetch(request.url);}"));
        return files;
    }
    @Test void staticAliasGraphProtectsTheActualHelperAndServiceUnderTheExistingCaps(){
        var files=inputs();var plan=TypeScriptSourceSelector.select(files);
        assertThat(plan.selected()).hasSize(100);
        assertThat(plan.selected()).extracting(c->c.file().relativePath())
                .contains("src/app/api/save/route.ts","src/lib/gateway/index.ts","src/domain/operation.ts");
        assertThat(plan.coverage().submittedCharacters()).isLessThanOrEqualTo(1_000_000);
        Collections.shuffle(files,new Random(3404));assertThat(TypeScriptSourceSelector.select(files)).isEqualTo(plan);
    }
    @Test void nearestUninspectedOrAmbiguousConfigCannotScheduleAnotherProjectsHelper(){
        for(String config:List.of("{\"extends\":\"./external\",\"compilerOptions\":{\"paths\":{\"@/*\":[\"./src/*\"]}}}",
                "{\"compilerOptions\":{\"paths\":{\"@/*\":[\"./src/*\",\"./other/*\"]}}}",
                "{\"compilerOptions\":{\"paths\":{\"@/*\":[\"../escape/*\"]}}}",
                "{\"compilerOptions\":{\"paths\":{\"@/*\":[\"./src/*\"]},\"paths\":{\"@/*\":[\"./other/*\"]}}}")){
            var files=inputs();files.removeIf(f->f.relativePath().equals("tsconfig.json"));files.add(file("tsconfig.json",config));
            assertThat(TypeScriptSourceSelector.select(files).selected()).extracting(c->c.file().relativePath()).doesNotContain("src/lib/gateway/index.ts");
        }
    }
    @Test void filePreferenceIsASelectionHintNotRuntimeOrEntryProof(){
        var files=inputs();files.add(file("src/lib/gateway.ts","export function save(request){return 'fixed';}"));
        var plan=TypeScriptSourceSelector.select(files);
        assertThat(plan.selected()).extracting(c->c.file().relativePath()).contains("src/lib/gateway.ts").doesNotContain("src/lib/gateway/index.ts");
    }
    @Test void nestedConfigScopeDoesNotBorrowARootMapping(){
        var files=inputs();files.add(file("src/tsconfig.json","{\"extends\":\"./uninspected\"}"));
        assertThat(TypeScriptSourceSelector.select(files).selected()).extracting(c->c.file().relativePath()).doesNotContain("src/lib/gateway/index.ts");
    }
    @Test void destructuredAndForwardedRouteExportsAreSchedulingHintsUnderPressure(){
        for(String content:List.of("import {adapt} from './bridge';export const { GET, POST } = adapt(handler);",
                "export { GET, POST } from './bridge';")){
            var files=inputs();files.removeIf(f->f.relativePath().equals("src/app/api/save/route.ts"));
            files.add(file("src/app/api/save/route.ts",content));
            files.add(file("src/app/api/save/bridge.ts","export const marker=1;"));
            var plan=TypeScriptSourceSelector.select(files);
            assertThat(plan.selected()).extracting(c->c.file().relativePath()).contains("src/app/api/save/route.ts","src/app/api/save/bridge.ts");
            assertThat(plan.selected()).hasSize(100);
        }
    }
}
