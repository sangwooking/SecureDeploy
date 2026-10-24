package com.securedeploy.analysis.typescript;

import com.securedeploy.project.model.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class TypeScriptSourceSelectorTest {
    @Test void staticConfigMetadataIsBoundedAndDeterministicWithoutReadingDisk(){
        var files=new ArrayList<ProjectFile>();
        files.add(js("tsconfig.json","{\"compilerOptions\":{\"paths\":{\"@/*\":[\"./*\"]}}}"));
        files.add(js("nested/tsconfig.json","x".repeat(64_001)));
        files.add(js("tsconfig.extra.json","{}"));
        var metadata=TypeScriptConfigMetadata.read(files);
        assertThat(metadata).hasSize(2);
        assertThat(metadata.get(0)).containsEntry("status","LIMIT_EXCEEDED").doesNotContainKey("content");
        assertThat(metadata.get(1)).containsEntry("status","SELECTED").containsKey("content");
        Collections.reverse(files);assertThat(TypeScriptConfigMetadata.read(files)).isEqualTo(metadata);
    }
    @Test void manifestHintsProtectArbitraryStartFilesAndImportsUnderPressure(){
        var files=new ArrayList<ProjectFile>();
        for(int i=0;i<180;i++)files.add(js("aaa/Panel%03d.js".formatted(i),"export const label=1;"));
        files.add(js("package.json","{\"main\":\"runtime/launch.js\",\"scripts\":{\"start\":\"node tools/run.cjs\",\"dev\":\"NODE_ENV=x node ignored.js\"}}"));
        files.add(js("runtime/launch.js","const start=require('../server');module.exports=start;"));
        files.add(js("tools/run.cjs","require('../runtime/launch.js');"));
        files.add(js("server/index.js","const handle=require('./helper');module.exports=handle;"));
        files.add(js("server/helper.js","module.exports=()=>1;"));
        files.add(js("ignored.js","module.exports=()=>1;"));
        var plan=TypeScriptSourceSelector.select(files);
        assertThat(plan.selected()).hasSize(100);
        assertThat(plan.selected()).extracting(c->c.file().relativePath()).contains("runtime/launch.js","tools/run.cjs","server/index.js","server/helper.js");
        assertThat(plan.selected()).filteredOn(c->List.of("runtime/launch.js","tools/run.cjs").contains(c.file().relativePath()))
                .allSatisfy(c->assertThat(c.reason()).isEqualTo("TS_NODE_MANIFEST_ENTRY_HINT"));
        Collections.shuffle(files,new Random(779));assertThat(TypeScriptSourceSelector.select(files)).isEqualTo(plan);
    }
    @Test void untrustedManifestSyntaxCannotInventAnEntryHint(){
        for(String text:List.of("{","{\"main\":\"a.js\",\"main\":\"b.js\"}","{\"main\":\"../../escape.js\"}",
                "{\"main\":{},\"scripts\":{\"start\":\"node ${TARGET}\",\"dev\":\"nodemon app.js\",\"test\":\"node app.js && node other.js\"}}")) {
            var plan=TypeScriptSourceSelector.select(List.of(js("package.json",text),js("app.js","export const a=1;")));
            assertThat(plan.selected()).noneMatch(c->c.reason().equals("TS_NODE_MANIFEST_ENTRY_HINT"));
        }
    }
    @Test void nestedManifestPathsAndMainWithoutExtensionStayWithinExistingCharacterCaps(){
        var plan=TypeScriptSourceSelector.select(List.of(js("api/package.json","{\"main\":\"./start\",\"scripts\":{\"start\":\"node ./serve.js\"}}"),
                js("api/start.js","module.exports={};"),js("api/serve.js","module.exports={};")));
        assertThat(plan.selected()).allSatisfy(c->assertThat(c.reason()).isEqualTo("TS_NODE_MANIFEST_ENTRY_HINT"));
        assertThat(plan.coverage().submittedCharacters()).isLessThanOrEqualTo(1_000_000);
        var metadata=NodeManifestMetadata.read(List.of(js("package.json","{\"main\":{},\"type\":\"module\"}")));
        assertThat(metadata.worker().get(0)).containsEntry("mainStatus","UNKNOWN").containsEntry("moduleType","module");
        var scripts=NodeManifestMetadata.read(List.of(js("package.json","{\"scripts\":{\"package\":\"node pack.js\",\"test\":\"node check.js\",\"start:prod\":\"node runtime.cjs\",\"dev\":\"nodemon dev.js\"}}")));
        assertThat(scripts.seeds()).containsExactly("runtime.cjs");
    }
    @Test void typeReferencesAreNotRuntimeSeedsAndEducationalMarkersDoNotExcludeLiveCode(){
        var plan=TypeScriptSourceSelector.select(List.of(
                js("checks/example.ts","import type { Express } from 'express';export const example=1;"),
                js("checks/notice.ts","import {type Request,type Response} from 'express';export const label=1;"),
                js("data/sample.ts","// educational example, vuln-code-snippet\nimport server from 'express';const app=server();app.get('/',(req,res)=>eval(req.query.value));"),
                js("factory.ts","import {Router as build} from 'express';const router=build();")));
        assertThat(plan.selected()).filteredOn(c->c.file().relativePath().startsWith("checks/"))
                .allSatisfy(c->assertThat(c.reason()).isEqualTo("TS_DETERMINISTIC_FALLBACK"));
        assertThat(plan.selected()).filteredOn(c->c.file().relativePath().equals("data/sample.ts")||c.file().relativePath().equals("factory.ts"))
                .allSatisfy(c->assertThat(c.reason()).isEqualTo("TS_EXPRESS_MODULE_HINT"));
    }
    @Test void boundedBroadDiscoveryFindsLateServerImportsBeforeEarlierLargeGeneralModulesConsumeHints(){
        var files=new ArrayList<ProjectFile>();
        for(int i=0;i<230;i++)files.add(js("aaa/Module%03d.ts".formatted(i),"export const text='"+"x".repeat(5000)+"';"));
        files.add(js("zzz/transport.ts","import express from 'express';import {handle} from './business';const app=express();app.post('/work',handle);\n"+" ".repeat(15_000)));
        files.add(js("zzz/business.ts","export function handle(req,res){return fetch(req.body.target);}"));
        var plan=TypeScriptSourceSelector.select(files);
        assertThat(plan.selected()).extracting(c->c.file().relativePath()).contains("zzz/transport.ts","zzz/business.ts");
        assertThat(plan.selected()).hasSize(100);
        Collections.shuffle(files,new Random(104));assertThat(TypeScriptSourceSelector.select(files)).isEqualTo(plan);
    }
    ProjectFile file(String path,String code,ProjectFileType type){return new ProjectFile(Path.of("/unreadable").resolve(path),path,type,code.lines().toList());}
    ProjectFile js(String p,String s){return file(p,s,ProjectFileType.TYPESCRIPT);}
    List<ProjectFile> fixture(){
        var files=new ArrayList<ProjectFile>();
        for(int i=0;i<180;i++)files.add(js("src/components/Tile"+i+".tsx","export const Tile=()=>null;"));
        files.add(js("supabase/functions/check/index.ts","import {check} from './helper'; Deno.serve(async(request)=>check(request));"));
        files.add(js("supabase/functions/check/helper.ts","export function check(request){return Response.json({ok:true});}"));
        for(int i=0;i<67;i++)files.add(file("supabase/migrations/20260101%06d_policy.sql".formatted(i),"CREATE TABLE public.t"+i+"(id uuid);",ProjectFileType.SUPABASE_SQL));
        return files;
    }
    @Test void protectsEntryHelperPoliciesAndGeneralSourcesWithoutIncreasingCaps(){
        var plan=TypeScriptSourceSelector.select(fixture());
        assertThat(plan.selected()).hasSize(100);
        assertThat(plan.selected().stream().filter(TypeScriptSourceSelector.Choice::sql)).hasSize(67);
        assertThat(plan.selected()).extracting(c->c.file().relativePath()).contains("supabase/functions/check/index.ts","supabase/functions/check/helper.ts");
        assertThat(plan.selected().stream().filter(c->c.priority()>=90)).hasSizeGreaterThanOrEqualTo(8);
        assertThat(plan.coverage().submittedCharacters()).isLessThanOrEqualTo(1_000_000);
        assertThat(plan.coverage().omittedFiles()).isEqualTo(149);
    }
    @Test void inputPermutationAndUnrelatedEarlierPathsDoNotDisplaceSecuritySeeds(){
        var files=fixture();var before=TypeScriptSourceSelector.select(files);
        Collections.shuffle(files,new Random(91));assertThat(TypeScriptSourceSelector.select(files)).isEqualTo(before);
        files.add(js("aaa/another.tsx","export const other=1;"));
        assertThat(TypeScriptSourceSelector.select(files).selected()).extracting(c->c.file().relativePath())
                .contains("supabase/functions/check/index.ts","supabase/functions/check/helper.ts");
    }
    @Test void nextAndExpressImportsAreSchedulingHintsNotEntryProof(){
        var files=List.of(js("src/app/api/check/route.ts","import {send} from '../../../lib/send';export async function POST(req){return send(req);}"),
                js("src/lib/send.ts","export function send(req){return unknown(req);}"),
                js("server/start.js","import express from 'express';import './routes';"),js("server/routes.ts","export const router=unknown();"),
                js("client/database.ts","import {createClient} from '@supabase/supabase-js';export const db=createClient(url,key);"));
        var plan=TypeScriptSourceSelector.select(files);
        assertThat(plan.selected()).filteredOn(c->c.file().relativePath().equals("src/lib/send.ts"))
                .extracting(TypeScriptSourceSelector.Choice::reason).containsExactly("TS_RELATED_IMPORT_HINT");
        assertThat(plan.selected()).hasSize(5);
        assertThat(plan.selected()).filteredOn(c->c.file().relativePath().equals("client/database.ts"))
                .extracting(TypeScriptSourceSelector.Choice::reason).containsExactly("TS_SUPABASE_CLIENT_MODULE_HINT");
    }
    @Test void oversizedAndUnfittingFilesDoNotPreventLaterSmallFilesAndUnusedReservationsAreReclaimed(){
        var files=new ArrayList<ProjectFile>();files.add(js("aaa.ts","x".repeat(100_001)));
        for(int i=0;i<110;i++)files.add(js("code/%03d.ts".formatted(i),"export const x=1;"));
        var plan=TypeScriptSourceSelector.select(files);
        assertThat(plan.selected()).hasSize(100);
        assertThat(plan.omissions().get("aaa.ts")).isEqualTo("SOURCE_FILE_SIZE_LIMIT");
        var sqlOnly=new ArrayList<ProjectFile>();for(int i=0;i<110;i++)sqlOnly.add(file("supabase/migrations/20260101%06d_x.sql".formatted(i),"SELECT 1;",ProjectFileType.SUPABASE_SQL));
        assertThat(TypeScriptSourceSelector.select(sqlOnly).selected()).hasSize(100);
    }
    @Test void characterReservationsDoNotStopScanningAfterAnUnfittingFile(){
        var files=new ArrayList<ProjectFile>();
        for(int i=0;i<20;i++)files.add(js("server/%02d.ts".formatted(i),"import express from 'express';\n"+" ".repeat(90_000)));
        files.add(js("zzz/small.ts","export const x=1;"));
        var plan=TypeScriptSourceSelector.select(files);
        assertThat(plan.selected()).extracting(c->c.file().relativePath()).contains("zzz/small.ts");
        assertThat(plan.coverage().submittedCharacters()).isLessThanOrEqualTo(1_000_000);
        assertThat(plan.coverage().omissionReasons()).containsKey("SOURCE_TOTAL_CHAR_LIMIT");
        assertThat(plan.hintsComplete()).isFalse();
    }
    @Test void omittedSqlDetailsAccountForTheSelectedPolicyRowsSharingTheOutputCap(){
        var files=fixture();for(int i=67;i<200;i++)files.add(file("supabase/migrations/20260101%06d_policy.sql".formatted(i),"SELECT 1;",ProjectFileType.SUPABASE_SQL));
        var plan=TypeScriptSourceSelector.select(files);
        long omittedJs=plan.omitted().stream().filter(c->!c.sql()).count();
        long omittedSql=plan.omitted().stream().filter(TypeScriptSourceSelector.Choice::sql).count();
        long selectedSql=plan.selected().stream().filter(TypeScriptSourceSelector.Choice::sql).count();
        assertThat(plan.coverage().omittedDetails()).isEqualTo((int)Math.max(0,omittedJs-100)+(int)Math.max(0,omittedSql-(100-selectedSql)));
    }
}
