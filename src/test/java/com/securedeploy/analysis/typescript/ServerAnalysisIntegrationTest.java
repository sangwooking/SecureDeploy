package com.securedeploy.analysis.typescript;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.github.model.*;
import com.securedeploy.github.service.GitHubRepositoryService;
import com.securedeploy.github.app.PrivateGitHubSourceService;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;
import java.io.ByteArrayOutputStream;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {"securedeploy.ai.provider=template", "securedeploy.sca.enabled=false", "securedeploy.threat-intelligence.enabled=false"})
@AutoConfigureMockMvc
@Transactional
class ServerAnalysisIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired JdbcTemplate jdbc;
    @Autowired jakarta.persistence.EntityManager entities;
    @MockBean GitHubRepositoryService github;
    @MockBean PrivateGitHubSourceService connected;
    @TempDir Path temp;

    @Test void externalAdapterPersistsProjectFlowButDoesNotInventSdkCallbacks() throws Exception {
        String token=signup();
        var files=new HashMap<String,String>();
        files.put("package.json","{\"dependencies\":{\"next\":\"15.2.4\",\"better-auth\":\"1.7.12\"}}");
        files.put("app/api/task/route.ts","import {toNextJsHandler} from 'better-auth/next-js';import {run} from './handler';export const {GET,POST}=toNextJsHandler(run);");
        files.put("app/api/task/handler.ts","export async function run(request){return fetch(new URL(request.url).searchParams.get('url'));}");
        var unsafe=uploadSources(token,files);var snapshot=unsafe.path("serverAnalysis");
        assertThat(snapshot.path("analyzerVersion").asText()).isEqualTo("ts-server-v44");
        assertThat(snapshot.path("validatedFindings")).hasSize(1);
        assertThat(snapshot.at("/validatedFindings/0/ruleId").asText()).isEqualTo("TS_SSRF_INPUT_FLOW");
        assertThat(snapshot.at("/validatedFindings/0/priority").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(snapshot.at("/validatedFindings/0/comparisonPolicy").asText()).isEqualTo("NOT_COMPARED");
        assertThat(snapshot.at("/validatedFindings/0/evidence/0/source/filePath").asText()).isEqualTo("app/api/task/handler.ts");
        assertThat(snapshot.at("/nodeUses").findValuesAsText("operation")).contains("BETTER_AUTH_NEXT_GET","BETTER_AUTH_NEXT_POST");
        assertThat(detail(token,unsafe.path("reviewId").asLong()).path("serverAnalysis")).isEqualTo(snapshot);
        var safeFiles=new HashMap<>(files);safeFiles.put("app/api/task/handler.ts","export async function run(request){return fetch('https://example.invalid/fixed');}");
        var safe=uploadSources(token,safeFiles);assertThat(safe.at("/serverAnalysis/validatedFindings")).isEmpty();
        assertThat(safe.path("securityScore")).isEqualTo(unsafe.path("securityScore"));
        files.put("app/api/task/route.ts","import {toNextJsHandler} from 'better-auth/next-js';import {betterAuth} from 'better-auth';const auth=betterAuth({callback:async request=>fetch(request.url)});export const {GET,POST}=toNextJsHandler(auth);");
        var unknown=uploadSources(token,files);assertThat(unknown.at("/serverAnalysis/validatedFindings")).isEmpty();
        assertThat(unknown.at("/serverAnalysis/nodeUses").findValuesAsText("kind")).contains("EXTERNAL_IMPLEMENTATION_UNKNOWN");
    }

    @Test void boundedSelectionPreservesAliasLinkedSourceSinkUnderUiPressure() throws Exception {
        String token=signup();var files=new HashMap<String,String>();
        for(int i=0;i<180;i++)files.put("aaa/View%03d.tsx".formatted(i),"export const text=1;");
        files.put("package.json","{\"dependencies\":{\"next\":\"15.2.4\"}}");
        files.put("tsconfig.json","{\"compilerOptions\":{\"moduleResolution\":\"bundler\",\"paths\":{\"@/*\":[\"./src/*\"]}}}");
        files.put("src/app/api/task/route.ts","import {run} from '@/lib/gateway';export async function GET(request){return run(new URL(request.url).searchParams.get('url'));}");
        files.put("src/lib/gateway/index.ts","export {run} from '@/domain/operation';");
        files.put("src/domain/operation.ts","export function run(value){return fetch(value);}");
        var unsafe=uploadSources(token,files);var snapshot=unsafe.path("serverAnalysis");
        assertThat(snapshot.path("validatedFindings")).hasSize(1);
        assertThat(snapshot.at("/validatedFindings/0/ruleId").asText()).isEqualTo("TS_SSRF_INPUT_FLOW");
        assertThat(snapshot.at("/validatedFindings/0/evidence/0/source/filePath").asText()).isEqualTo("src/app/api/task/route.ts");
        assertThat(snapshot.at("/validatedFindings/0/evidence/0/sink/filePath").asText()).isEqualTo("src/domain/operation.ts");
        assertThat(snapshot.at("/selectionCoverage/submittedFiles").asInt()).isEqualTo(100);
        assertThat(snapshot.at("/selectionCoverage/submittedCharacters").asInt()).isLessThanOrEqualTo(1_000_000);
        var safeFiles=new HashMap<>(files);safeFiles.put("src/domain/operation.ts","export function run(value){return fetch('https://example.invalid/fixed');}");
        var safe=uploadSources(token,safeFiles);assertThat(safe.at("/serverAnalysis/validatedFindings")).isEmpty();
        assertThat(safe.path("securityScore")).isEqualTo(unsafe.path("securityScore"));
        var unknownFiles=new HashMap<>(files);unknownFiles.put("tsconfig.json","{\"compilerOptions\":{\"paths\":{\"@/*\":[\"./src/*\",\"./fallback/*\"]}}}");
        assertThat(uploadSources(token,unknownFiles).at("/serverAnalysis/validatedFindings")).isEmpty();
    }

    @Test void wrappedNextRequestsPersistDistinctSourceSinkAndKeepUnknownOutOfValidatedFindings() throws Exception {
        String token=signup();
        var sources=Map.of("package.json","{\"dependencies\":{\"next\":\"15.2.4\"}}",
                "lib/wrapper.ts","export const wrap=(handler)=>async(request)=>handler(request);",
                "app/api/task/route.ts","import {wrap} from '../../../lib/wrapper';export const GET=wrap(async(request)=>fetch(new URL(request.url).searchParams.get('url')));");
        var unsafe=uploadSources(token,sources);
        var snapshot=unsafe.path("serverAnalysis");
        assertThat(snapshot.path("analyzerVersion").asText()).isEqualTo("ts-server-v44");
        assertThat(snapshot.path("validatedFindings")).hasSize(1);
        var finding=snapshot.at("/validatedFindings/0");
        assertThat(finding.path("ruleId").asText()).isEqualTo("TS_SSRF_INPUT_FLOW");
        assertThat(finding.path("priority").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(finding.path("comparisonPolicy").asText()).isEqualTo("NOT_COMPARED");
        assertThat(finding.at("/evidence/0/source/filePath").asText()).isEqualTo("app/api/task/route.ts");
        assertThat(finding.at("/evidence/0/sink/filePath").asText()).isEqualTo("app/api/task/route.ts");
        assertThat(snapshot.at("/authorizationContexts/0/entry/filePath").asText()).isEqualTo("app/api/task/route.ts");
        assertThat(snapshot.at("/nodeUses").findValuesAsText("operation")).contains("STATIC_NEXT_WRAPPER_BINDING");
        assertThat(snapshot.at("/nodeUses").findValuesAsText("filePath")).contains("lib/wrapper.ts");
        assertThat(detail(token,unsafe.path("reviewId").asLong()).path("serverAnalysis")).isEqualTo(snapshot);
        assertThat(unsafe.path("securityScore").asInt()).isEqualTo(100);
        var safeSources=new HashMap<>(sources);
        safeSources.put("app/api/task/route.ts","import {wrap} from '../../../lib/wrapper';export const GET=wrap(async(request)=>fetch('https://example.invalid/status'));");
        var safe=uploadSources(token,safeSources);
        assertThat(safe.at("/serverAnalysis/validatedFindings")).isEmpty();
        assertThat(safe.at("/serverAnalysis/httpUses").findValuesAsText("kind")).contains("FIXED_DESTINATION");
        var unknownSources=new HashMap<>(sources);
        unknownSources.put("lib/wrapper.ts","export const wrap=(handler)=>async(request)=>{if(external)return handler(request);return Response.json({ok:true});};");
        var unknown=uploadSources(token,unknownSources);
        assertThat(unknown.at("/serverAnalysis/validatedFindings")).isEmpty();
        assertThat(unknown.at("/serverAnalysis/findings").findValuesAsText("confidence")).contains("MEDIUM");
        var exposureSources=new HashMap<>(sources);
        exposureSources.put("app/api/task/route.ts","import {wrap} from '../../../lib/wrapper';export const GET=wrap(async(request)=>Response.json({ok:true,diagnostic:process.env.SERVICE_ROLE_KEY}));");
        var exposure=uploadSources(token,exposureSources);
        assertThat(exposure.at("/serverAnalysis/validatedFindings")).hasSize(1);
        assertThat(exposure.at("/serverAnalysis/validatedFindings/0/ruleId").asText()).isEqualTo("TS_SENSITIVE_DATA_EXPOSURE");
    }

    @Test void namedExportChainPersistsRealSourceSinkAndDoesNotPromoteRisk() throws Exception {
        String token=signup();
        var sources=Map.of(
                "worker.ts","import {query} from './api';export default {async fetch(request,env){const id=new URL(request.url).searchParams.get('id');return query(env.DB,id);}};",
                "api.ts","export {query} from './service';",
                "service.ts","function query(db,id){return db.prepare('SELECT * FROM records WHERE id='+id).all();}export {query};");
        var unsafe=uploadSources(token,sources);
        var snapshot=unsafe.path("serverAnalysis");
        assertThat(snapshot.path("analyzerVersion").asText()).isEqualTo("ts-server-v44");
        assertThat(snapshot.path("validatedFindings")).hasSize(1);
        var finding=snapshot.at("/validatedFindings/0");
        assertThat(finding.path("ruleId").asText()).isEqualTo("TS_SQL_INPUT_FLOW");
        assertThat(finding.path("priority").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(finding.path("comparisonPolicy").asText()).isEqualTo("NOT_COMPARED");
        assertThat(finding.at("/evidence/0/source/filePath").asText()).isEqualTo("worker.ts");
        assertThat(finding.at("/evidence/0/sink/filePath").asText()).isEqualTo("service.ts");
        assertThat(snapshot.at("/files").findValuesAsText("parseStatus")).containsOnly("PARSED");
        assertThat(unsafe.path("securityScore").asInt()).isEqualTo(100);
        assertThat(unsafe.path("vulnerabilityCount").asInt()).isZero();
        assertThat(detail(token,unsafe.path("reviewId").asLong()).path("serverAnalysis")).isEqualTo(snapshot);
        mvc.perform(get("/api/reviews/"+unsafe.path("reviewId").asLong()).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
        var safeSources=new HashMap<>(sources);
        safeSources.put("service.ts","function query(db,id){return db.prepare('SELECT * FROM records WHERE id=?').bind(id).all();}export {query};");
        var safe=uploadSources(token,safeSources);
        assertThat(safe.at("/serverAnalysis/validatedFindings")).isEmpty();
        assertThat(safe.at("/serverAnalysis/sqlUses").findValuesAsText("kind")).contains("PARAMETERIZED_QUERY");
        assertThat(safe.path("securityScore")).isEqualTo(unsafe.path("securityScore"));
        assertThat(safe.at("/riskAssessment/prioritySummary")).isEqualTo(unsafe.at("/riskAssessment/prioritySummary"));
        var unknownSources=new HashMap<>(sources);unknownSources.put("api.ts","export * from './service';");
        var unresolved=uploadSources(token,unknownSources);
        assertThat(unresolved.at("/serverAnalysis/validatedFindings")).isEmpty();
        assertThat(unresolved.path("serverAnalysis").toString()).contains("MODULE_WILDCARD_OR_NAMESPACE_EXPORT_NOT_SUPPORTED");
    }

    @Test void sequelizeRawQueryPersistsWithSourceAndSinkAcrossAllIntakes() throws Exception {
        String token=signup();
        var sources=Map.of("package.json","{\"dependencies\":{\"express\":\"4.21.2\",\"sequelize\":\"4.13.10\"}}", "server.cjs",
                "const express=require('express');const db=require('./store').sequelize;const app=express();app.post('/search',(req,res)=>{const sql='SELECT value FROM records WHERE id='+req.body.id;db.query(sql);});",
                "store/index.js","const fs=require('fs');const path=require('path');const Engine=require('sequelize');const connection=new Engine('unused');const db={};fs.readdirSync(__dirname).filter(function(file){return(file.indexOf('.')!==0)&&(file!=='index.js');}).forEach(function(file){var model=connection.import(path.join(__dirname,file));db[model.name]=model;});db.sequelize=connection;module.exports=db;",
                "store/record.js","module.exports=function(client,Types){return client.define('Record',{id:{type:Types.INTEGER}});};");
        var zip=uploadSources(token,sources);var snapshot=zip.path("serverAnalysis");
        assertThat(snapshot.path("validatedFindings")).hasSize(1);
        var finding=snapshot.at("/validatedFindings/0");
        assertThat(finding.path("ruleId").asText()).isEqualTo("JS_SEQUELIZE_SQL_INPUT_FLOW");
        assertThat(finding.path("priority").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(finding.path("comparisonPolicy").asText()).isEqualTo("NOT_COMPARED");
        assertThat(finding.at("/evidence/0/kind").asText()).isEqualTo("CWE-89");
        assertThat(finding.at("/evidence/0/source/kind").asText()).isEqualTo("EXPRESS_BODY");
        assertThat(finding.at("/evidence/0/sink/kind").asText()).isEqualTo("SEQUELIZE_RAW_QUERY");
        assertThat(zip.path("securityScore").asInt()).isEqualTo(100);
        var roots=new ArrayList<Path>();
        for(String name:List.of("sql-public","sql-private")) {
            Path root=Files.createDirectory(temp.resolve(name));roots.add(root);
            for(var source:sources.entrySet()){Path file=root.resolve(source.getKey());Files.createDirectories(file.getParent());Files.writeString(file,source.getValue());}
            Files.createDirectories(root.resolve(".git"));
            Files.writeString(root.resolve(".git/HEAD"),"ref: refs/heads/main");
        }
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/sql",roots.get(0),roots.get(0)));
        var pub=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/sql\",\"scanMode\":\"STANDARD\"}");
        var metadata=new GitHubSourceSnapshot("fixture","sql","https://github.com/fixture/sql","main","a".repeat(40),"aaaaaaa",null,null,null,null,2,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/sql",roots.get(1),roots.get(1),metadata));
        var prv=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        for(var response:List.of(pub,prv))assertThat(response.path("serverAnalysis")).isEqualTo(snapshot);
        for(var root:roots)assertThat(root).doesNotExist();
        long id=zip.path("reviewId").asLong();assertThat(detail(token,id).path("serverAnalysis")).isEqualTo(snapshot);
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
        var safeSources=new HashMap<>(sources);safeSources.put("server.cjs",sources.get("server.cjs")
                .replace("const sql='SELECT value FROM records WHERE id='+req.body.id;db.query(sql);","db.query('SELECT value FROM records WHERE id=$1',{bind:[req.body.id]});"));
        var bound=uploadSources(token,safeSources);
        assertThat(bound.at("/serverAnalysis/validatedFindings")).isEmpty();
        assertThat(bound.at("/serverAnalysis/nodeUses").findValuesAsText("kind")).contains("STATIC_OR_DATA_ONLY");
        var incomplete=new HashMap<>(sources);incomplete.put("store/unparsed-model.txt","not a supported static model");
        assertThat(uploadSources(token,incomplete).at("/serverAnalysis/validatedFindings")).isEmpty();
    }

    @Test void shellEvidencePersistsAcrossZipAndPublicAndPrivateInputsWithoutLegacyRiskPromotion() throws Exception {
        String token=signup();
        var sources=Map.of("package.json","{\"dependencies\":{\"express\":\"4.21.2\"}}", "server.cjs",
                "const express=require('express');const app=express();const {exec}=require('node:child_process');app.set('port',process.env.PORT||3001);app.post('/work',(req,res)=>{const text=req.body.value;const pattern=/(.*)/;if(typeof text==='string'&&text.match(pattern)){exec('fixed '+text.match(pattern)[1]);}});app.get('env');");
        var zip=uploadSources(token,sources);var snapshot=zip.path("serverAnalysis");
        assertThat(snapshot.path("validatedFindings")).hasSize(1);
        var finding=snapshot.at("/validatedFindings/0");
        assertThat(finding.path("ruleId").asText()).isEqualTo("JS_SHELL_COMMAND_INPUT_FLOW");
        assertThat(finding.path("priority").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(finding.path("comparisonPolicy").asText()).isEqualTo("NOT_COMPARED");
        assertThat(finding.at("/evidence/0/flow").findValuesAsText("kind")).contains("REGEX_CAPTURE");
        assertThat(zip.path("securityScore").asInt()).isEqualTo(100);
        assertThat(zip.path("vulnerabilityCount").asInt()).isZero();
        assertThat(zip.at("/resultSummary/flowCandidates").asInt()).isEqualTo(1);
        var roots=new ArrayList<Path>();
        for(String name:List.of("shell-public","shell-private")) {
            Path root=Files.createDirectory(temp.resolve(name));roots.add(root);
            for(var source:sources.entrySet())Files.writeString(root.resolve(source.getKey()),source.getValue());
        }
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/shell",roots.get(0),roots.get(0)));
        var pub=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/shell\",\"scanMode\":\"STANDARD\"}");
        var metadata=new GitHubSourceSnapshot("fixture","shell","https://github.com/fixture/shell","main","a".repeat(40),"aaaaaaa",null,null,null,null,2,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/shell",roots.get(1),roots.get(1),metadata));
        var prv=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        for(var response:List.of(pub,prv)) {
            assertThat(response.path("serverAnalysis")).isEqualTo(snapshot);
            assertThat(response.path("resultSummary")).isEqualTo(zip.path("resultSummary"));
            assertThat(response.at("/riskAssessment/prioritySummary")).isEqualTo(zip.at("/riskAssessment/prioritySummary"));
        }
        for(var root:roots)assertThat(root).doesNotExist();
        long id=zip.path("reviewId").asLong();assertThat(detail(token,id).path("serverAnalysis")).isEqualTo(snapshot);
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
    }

    @Test void nextBoundariesPersistIdenticallyAcrossZipPublicAndPrivateInputs() throws Exception {
        String token=signup();
        var sources=new LinkedHashMap<>(Map.of("package.json","{\"dependencies\":{\"next\":\"15.3.0\"}}",
                "app/api/check/route.ts","export async function POST(req:Request){const body=await req.json();await fetch(body.target);return Response.json({value:process.env.SYNTHETIC_API_KEY_NAME});}"));
        for(int i=0;i<180;i++)sources.put("src/components/Tile"+i+".tsx","export const Tile=()=>null;");
        for(int i=0;i<67;i++)sources.put("supabase/migrations/20260101%06d_selection.sql".formatted(i),"CREATE TABLE public.sample_"+i+"(id uuid);");
        var zip=uploadSources(token,sources);var snapshot=zip.path("serverAnalysis");
        assertThat(snapshot.at("/selectionCoverage/submittedFiles").asInt()).isEqualTo(100);
        assertThat(snapshot.at("/supabaseAnalysis/files")).hasSize(67);
        for(var policy:snapshot.at("/supabaseAnalysis/files"))assertThat(policy.path("status").asText()).isNotEqualTo("LIMIT_EXCEEDED");
        assertThat(snapshot.path("validatedFindings")).hasSize(2);
        for(var finding:snapshot.path("validatedFindings")) {
            assertThat(finding.path("priority").asText()).isEqualTo("REVIEW_REQUIRED");
            assertThat(finding.path("comparisonPolicy").asText()).isEqualTo("NOT_COMPARED");
        }
        assertThat(snapshot.toString()).doesNotContain("SYNTHETIC_API_KEY_NAME","process.env");
        assertThat(zip.path("securityScore").asInt()).isEqualTo(100);
        assertThat(zip.path("vulnerabilityCount").asInt()).isZero();
        assertThat(zip.at("/resultSummary/guidance").asText()).isEqualTo("REVIEW_NEEDED");
        assertThat(zip.at("/resultSummary/referenceScore").asInt()).isEqualTo(100);
        assertThat(zip.at("/resultSummary/flowCandidates").asInt()).isEqualTo(2);
        assertThat(zip.at("/resultSummary/coverageStatus").asText()).isEqualTo("PARTIAL");
        var roots=new ArrayList<Path>();
        for(String name:List.of("next-public","next-private")) {
            Path root=Files.createDirectory(temp.resolve(name));roots.add(root);
            for(var source:sources.entrySet()) {
                Path file=root.resolve(source.getKey());Files.createDirectories(file.getParent());Files.writeString(file,source.getValue());
            }
        }
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/next",roots.get(0),roots.get(0)));
        var pub=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/next\",\"scanMode\":\"STANDARD\"}");
        var metadata=new GitHubSourceSnapshot("fixture","next","https://github.com/fixture/next","main","a".repeat(40),"aaaaaaa",null,null,null,null,2,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/next",roots.get(1),roots.get(1),metadata));
        var prv=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        for(var response:List.of(pub,prv)) {
            assertThat(response.path("resultSummary")).isEqualTo(zip.path("resultSummary"));
            assertThat(response.path("serverAnalysis")).isEqualTo(snapshot);
            assertThat(response.path("securityScore")).isEqualTo(zip.path("securityScore"));
            assertThat(response.at("/riskAssessment/prioritySummary")).isEqualTo(zip.at("/riskAssessment/prioritySummary"));
        }
        for(var root:roots)assertThat(root).doesNotExist();
        long id=zip.path("reviewId").asLong();assertThat(detail(token,id).path("serverAnalysis")).isEqualTo(snapshot);
        assertThat(detail(token,id).path("resultSummary")).isEqualTo(zip.path("resultSummary"));
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
    }

    @Test void semanticStringReconciliationPersistsAndPublicGithubMatchesZip() throws Exception {
        String token=signup();
        String code="const icon=<svg xmlns=\"http://www.w3.org/2000/svg\"/>;\n"
                +"button.innerText=hidden?'Show Secret':'Hide Secret';\n"
                +"fetch('http://service.example.invalid');";
        var zip=uploadSource(token,"Controls.tsx",code);
        assertThat(zip.path("vulnerabilities")).hasSize(1);
        assertThat(zip.at("/vulnerabilities/0/ruleId").asText()).isEqualTo("INSECURE_API_URL");
        assertThat(zip.at("/vulnerabilities/0/confidence").asText()).isEqualTo("HIGH");
        Path root=Files.createDirectory(temp.resolve("string-public"));Files.writeString(root.resolve("Controls.tsx"),code);
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/strings",root,root));
        var pub=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/strings\",\"scanMode\":\"STANDARD\"}");
        assertThat(pub.path("vulnerabilityCount")).isEqualTo(zip.path("vulnerabilityCount"));
        assertThat(pub.path("securityScore")).isEqualTo(zip.path("securityScore"));
        assertThat(pub.at("/riskAssessment/prioritySummary")).isEqualTo(zip.at("/riskAssessment/prioritySummary"));
        assertThat(detail(token,zip.path("reviewId").asLong()).path("vulnerabilities")).isEqualTo(zip.path("vulnerabilities"));
        assertThat(root).doesNotExist();
    }

    @Test void htmlContextEvidencePersistsAcrossZipPublicAndPrivateWithoutClearingUnknown() throws Exception {
        String token=signup();
        String code="const fixed='<b>Notice</b>';\nconst Safe=()=> <p dangerouslySetInnerHTML={{__html:fixed}}/>;\n"
                +"const Unknown=({value})=> <p dangerouslySetInnerHTML={{__html:clean(value)}}/>;";
        var zip=uploadSource(token,"Notice.tsx",code);
        assertThat(zip.path("vulnerabilities")).hasSize(1);
        var finding=zip.at("/vulnerabilities/0");
        assertThat(finding.path("ruleId").asText()).isEqualTo("REACT_DANGEROUS_HTML");
        assertThat(finding.path("line").asInt()).isEqualTo(3);
        assertThat(finding.path("analysisNote").asText()).contains("HTML_CONTEXT=UNRESOLVED_HTML","SINK_LINE=3","외부 입력 연결");
        assertThat(finding.path("confidence").asText()).isEqualTo("HIGH");
        assertThat(finding.path("falsePositiveRisk").asText()).isEqualTo("LOW");
        var roots=new ArrayList<Path>();
        for(String name:List.of("html-public","html-private")) {
            var root=Files.createDirectory(temp.resolve(name));roots.add(root);Files.writeString(root.resolve("Notice.tsx"),code);
        }
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/html",roots.get(0),roots.get(0)));
        var pub=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/html\",\"scanMode\":\"STANDARD\"}");
        var metadata=new GitHubSourceSnapshot("fixture","html","https://github.com/fixture/html","main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/html",roots.get(1),roots.get(1),metadata));
        var prv=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        for(var response:List.of(pub,prv)) {
            assertThat(response.path("vulnerabilities")).hasSize(1);
            for(String field:List.of("ruleId","line","analysisNote","confidence","falsePositiveRisk"))
                assertThat(response.at("/vulnerabilities/0/"+field)).isEqualTo(finding.path(field));
            assertThat(response.path("securityScore")).isEqualTo(zip.path("securityScore"));
            assertThat(response.at("/riskAssessment/prioritySummary")).isEqualTo(zip.at("/riskAssessment/prioritySummary"));
            assertThat(detail(token,response.path("reviewId").asLong()).path("vulnerabilities")).isEqualTo(response.path("vulnerabilities"));
        }
        for(var root:roots)assertThat(root).doesNotExist();
        long id=zip.path("reviewId").asLong();
        assertThat(detail(token,id).path("vulnerabilities")).isEqualTo(zip.path("vulnerabilities"));
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
    }

    @Test void rlsSnapshotUsesAllInputPathsWithoutChangingRiskAndRetainsHistoryIsolation() throws Exception {
        String token=signup(),path="supabase/migrations/20260101000000_permissions.sql";
        String sql="CREATE TABLE public.entries(owner_id uuid);ALTER TABLE public.entries ENABLE ROW LEVEL SECURITY;GRANT UPDATE ON public.entries TO authenticated;CREATE POLICY broad ON public.entries FOR UPDATE TO authenticated USING(true) WITH CHECK(true);";
        String dataPath="src/data.ts",data="import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.invalid',process.env.ANON_KEY);db.from('entries').update({});";
        var zip=uploadSources(token,Map.of(path,sql,dataPath,data));
        var snapshot=zip.at("/serverAnalysis/supabaseAnalysis");assertThat(snapshot.path("findings")).hasSize(1);
        assertThat(snapshot.at("/findings/0/comparisonPolicy").asText()).isEqualTo("NOT_COMPARED");
        assertThat(snapshot.at("/accesses/0/authorizationEvidence/state").asText()).isEqualTo("BROAD_ACCESS_REVIEW");
        assertThat(zip.path("securityScore").asInt()).isEqualTo(100);assertThat(zip.path("vulnerabilityCount").asInt()).isZero();
        assertThat(zip.at("/riskAssessment/prioritySummary/BLOCKING").asInt()).isZero();
        var roots=new ArrayList<Path>();
        for(String name:List.of("rls-public","rls-private")){var root=Files.createDirectory(temp.resolve(name));roots.add(root);Files.createDirectories(root.resolve(path).getParent());Files.writeString(root.resolve(path),sql);Files.createDirectories(root.resolve(dataPath).getParent());Files.writeString(root.resolve(dataPath),data);}
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/rls",roots.get(0),roots.get(0)));
        var pub=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/rls\",\"scanMode\":\"STANDARD\"}");
        var metadata=new GitHubSourceSnapshot("fixture","rls","https://github.com/fixture/rls","main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/rls",roots.get(1),roots.get(1),metadata));
        var prv=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        assertThat(pub.at("/serverAnalysis/supabaseAnalysis")).isEqualTo(snapshot);assertThat(prv.at("/serverAnalysis/supabaseAnalysis")).isEqualTo(snapshot);
        assertThat(pub.at("/riskAssessment/prioritySummary")).isEqualTo(zip.at("/riskAssessment/prioritySummary"));
        for(var root:roots)assertThat(root).doesNotExist();
        long id=zip.path("reviewId").asLong();assertThat(detail(token,id).at("/serverAnalysis/supabaseAnalysis")).isEqualTo(snapshot);
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
        var legacy=(com.fasterxml.jackson.databind.node.ObjectNode)zip.path("serverAnalysis").deepCopy();legacy.remove("supabaseAnalysis");
        jdbc.update("update reviews set server_analysis_json=? where id=?",json.writeValueAsString(legacy),id);entities.clear();
        assertThat(detail(token,id).at("/serverAnalysis/supabaseAnalysis").isNull()).isTrue();
    }

    @Test void collectedAliasesAndLocalIdentityObservationsPersistWithoutClaimingAuthorization() throws Exception {
        String token=signup();
        var result=uploadSources(token,Map.of(
            "package.json","{\"dependencies\":{\"next\":\"15.2.0\"}}",
            "tsconfig.json","{\"compilerOptions\":{\"paths\":{\"@/*\":[\"./*\"]}}}",
            "lib/client.ts","import {createServerClient} from '@supabase/ssr';export function make(){const c=cookies();return createServerClient('https://example.invalid',process.env.PUBLIC_ANON_KEY,{cookies:{getAll(){return c.getAll();}}});}",
            "app/api/items/route.ts","import {make} from '@/lib/client';export async function GET(){const db=make();const {data:{user}}=await db.auth.getUser();if(!user)throw new Error('missing');return Response.json(await db.from('items').select().eq('user_id',user.id));}"));
        var access=result.at("/serverAnalysis/supabaseAnalysis/accesses/0");
        assertThat(access.path("clientStatus").asText()).isEqualTo("CLIENT_DECLARATION_LINKED");
        assertThat(access.at("/authorizationEvidence/authStatus").asText()).isEqualTo("IDENTITY_VERIFICATION_CALL_OBSERVED");
        assertThat(access.at("/authorizationEvidence/effectiveRole").asText()).isEqualTo("UNKNOWN");
        assertThat(access.at("/authorizationEvidence/requestEntry/kind").asText()).isEqualTo("NEXT_ROUTE_HANDLER");
        assertThat(access.at("/authorizationEvidence/authChecks/0/resultEvidence/userIdFilters")).hasSize(1);
        assertThat(detail(token,result.path("reviewId").asLong()).at("/serverAnalysis/supabaseAnalysis")).isEqualTo(result.at("/serverAnalysis/supabaseAnalysis"));
    }

    @Test void updateOwnershipRequiresBothRowPhasesAndDoesNotChangeLegacyRisk() throws Exception {
        String token=signup();
        for(String check:List.of(" WITH CHECK(true)","")){
            String sql="CREATE TABLE public.items(user_id uuid);ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;GRANT UPDATE ON public.items TO authenticated;CREATE POLICY p ON public.items FOR UPDATE TO authenticated USING(auth.uid()=user_id)"+check+";";
            var result=uploadSources(token,Map.of("supabase/migrations/20260101000000_policy.sql",sql,
                "app/api/items/route.ts","import {createClient} from '@supabase/supabase-js';const db=createClient('url',process.env.ANON_KEY);export async function POST(){return db.from('items').update({});}",
                "package.json","{\"dependencies\":{\"next\":\"15.2.0\"}}"));
            var s=result.at("/serverAnalysis/supabaseAnalysis");
            assertThat(s.path("findings")).hasSize(check.isEmpty()?0:1);
            assertThat(s.at("/accesses/0/authorizationEvidence/state").asText()).isEqualTo(check.isEmpty()?"CONFIRMED_POLICY_EVIDENCE":"BROAD_ACCESS_REVIEW");
            if(!check.isEmpty())assertThat(s.at("/findings/0/comparisonPolicy").asText()).isEqualTo("NOT_COMPARED");
            assertThat(result.path("securityScore").asInt()).isEqualTo(100);
            assertThat(result.at("/riskAssessment/prioritySummary/BLOCKING").asInt()).isZero();
            assertThat(detail(token,result.path("reviewId").asLong()).at("/serverAnalysis/supabaseAnalysis")).isEqualTo(s);
        }
    }

    @Test void guardedConfigurationFactoryLinksServerFunctionWithoutInventingIdentity() throws Exception {
        String token=signup();
        var result=uploadSources(token,Map.of(
            "package.json","{\"dependencies\":{\"next\":\"15.2.0\"}}",
            "lib/client.ts","import {createClient} from '@supabase/supabase-js';export function make(){const url=process.env.SERVICE_URL;const key=process.env.PUBLIC_ANON_KEY;if(!url||!key)throw new Error('missing');return createClient(url,key);}",
            "app/actions.ts","'use server';import {make} from '../lib/client';export async function change(formData){const db=make();return db.from('items').update({title:formData.get('title')});}"));
        var a=result.at("/serverAnalysis/supabaseAnalysis/accesses/0");
        assertThat(a.path("clientStatus").asText()).isEqualTo("CLIENT_DECLARATION_LINKED");
        assertThat(a.at("/authorizationEvidence/requestEntry/kind").asText()).isEqualTo("NEXT_SERVER_FUNCTION");
        assertThat(a.at("/authorizationEvidence/clientTrace").toString()).contains("FACTORY_CONFIGURATION_ABSENCE_THROW");
        assertThat(a.at("/authorizationEvidence/authChecks")).isEmpty();
        assertThat(a.at("/authorizationEvidence/state").asText()).isEqualTo("UNKNOWN");
        assertThat(detail(token,result.path("reviewId").asLong()).at("/serverAnalysis/supabaseAnalysis/accesses/0")).isEqualTo(a);
    }

    @Test void eightyJavaUnitsAndSourceLimitHavePersistedDistinctCoverage() throws Exception {
        String token=signup();var sources=new LinkedHashMap<String,String>();
        sources.put("Endpoint.java","import org.springframework.web.bind.annotation.*; import java.sql.Connection; @RestController class Endpoint { Connection c; @GetMapping(\"/\") void inspect(@RequestParam String input){c.prepareCall(\"{call \"+input+\"}\").execute();}}");
        for(int i=0;i<79;i++)sources.put("types/Record"+i+".java","class Record"+i+" {String copy(String value){return value;}}");
        var zip=uploadSources(token,sources);
        assertThat(zip.at("/serverAnalysis/javaAnalysis/analysis/files")).hasSize(80);
        for(var file:zip.at("/serverAnalysis/javaAnalysis/analysis/files"))assertThat(file.path("parseStatus").asText()).isEqualTo("PARSED");
        assertThat(zip.at("/serverAnalysis/javaAnalysis/findings")).hasSize(1);
        assertThat(zip.at("/serverAnalysis/javaAnalysis/findings/0/priority").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(detail(token,zip.path("reviewId").asLong()).path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        var limited=uploadSource(token,"Huge.java","x".repeat(100_001));
        assertThat(limited.at("/serverAnalysis/javaAnalysis/analysis/status").asText()).isEqualTo("UNAVAILABLE");
        assertThat(limited.at("/serverAnalysis/javaAnalysis/analysis/files/0/parseStatus").asText()).isEqualTo("LIMIT_EXCEEDED");
        assertThat(detail(token,limited.path("reviewId").asLong()).path("coverage")).isEqualTo(limited.path("coverage"));
        assertThat(limited.path("coverage").toString()).contains("SOURCE_SELECTION_LIMIT");
    }

    @Test void javaSqlUsesCommonInputsAndStoresIndependentReviewCandidates() throws Exception {
        String token=signup();
        String prefix="import org.springframework.web.bind.annotation.*; import java.sql.Connection; @RestController class Endpoint {Connection connection; @GetMapping(\"/\") void inspect(@RequestParam String input){\n";
        String code=prefix+"var values=new java.util.HashMap<String,String>();values.put(\"selected\",input);\n"
                +"Object stored=values.get(\"selected\");String text=(String)stored;\n"
                +"connection.prepareCall(\"{call \"+text+\"}\").execute();\n}}";
        var zip=uploadSource(token,"Endpoint.java",code);
        assertThat(zip.at("/serverAnalysis/javaAnalysis/findings")).hasSize(1);
        assertThat(zip.at("/serverAnalysis/javaAnalysis/findings/0/priority").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(zip.at("/serverAnalysis/javaAnalysis/findings/0/trace").toString()).contains("COLLECTION_READ","COLLECTION_WRITE","STRING_IDENTITY_CAST");
        assertThat(zip.path("vulnerabilityCount").asInt()).isZero();assertThat(zip.path("securityScore").asInt()).isEqualTo(100);
        assertThat(zip.at("/riskAssessment/prioritySummary/BLOCKING").asInt()).isZero();
        assertThat(zip.at("/coverage/analyzers").toString()).contains("JAVA_SQL_FLOW");
        Path pub=Files.createDirectory(temp.resolve("java-public")),prv=Files.createDirectory(temp.resolve("java-private"));
        Files.writeString(pub.resolve("Endpoint.java"),code);Files.writeString(prv.resolve("Endpoint.java"),code);
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/java",pub,pub));
        var publicResult=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/java\",\"scanMode\":\"STANDARD\"}");
        var metadata=new GitHubSourceSnapshot("fixture","java","https://github.com/fixture/java","main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/java",prv,prv,metadata));
        var privateResult=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        assertThat(publicResult.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(privateResult.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(pub).doesNotExist();assertThat(prv).doesNotExist();
        var normal=uploadSource(token,"Endpoint.java",prefix+"var s=connection.createStatement(); s.executeQuery(\"SELECT 1\");\n}}");
        assertThat(normal.at("/serverAnalysis/javaAnalysis/findings")).isEmpty();
        assertThat(normal.at("/comparison/counts/RESOLVED").asInt()).isZero();
        assertThat(normal.path("riskAssessment").path("prioritySummary")).isEqualTo(zip.path("riskAssessment").path("prioritySummary"));
        long id=zip.path("reviewId").asLong();
        assertThat(detail(token,id).path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(jdbc.queryForObject("select server_analysis_json from reviews where id=?",String.class,id)).contains(com.securedeploy.analysis.javaflow.JavaSqlWorker.VERSION,"JAVA_SQL_INPUT_FLOW").doesNotContain("{call ");
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
        var legacy=(com.fasterxml.jackson.databind.node.ObjectNode)zip.path("serverAnalysis").deepCopy();legacy.remove("javaAnalysis");
        jdbc.update("update reviews set server_analysis_json=? where id=?",json.writeValueAsString(legacy),id);entities.clear();
        assertThat(detail(token,id).at("/serverAnalysis/javaAnalysis").isNull()).isTrue();
    }

    @Test void mapperDeclarationsUseCommonInputsAndPersistWithoutSqlSource() throws Exception {
        String token=signup();var sources=new LinkedHashMap<String,String>();
        sources.put("Endpoint.java","package sample; import org.springframework.web.bind.annotation.*; @RestController class Endpoint {@org.springframework.beans.factory.annotation.Autowired Mapper mapper; @GetMapping(\"/\") void inspect(@RequestParam String input){mapper.lookup(input);}}");
        sources.put("Mapper.java","package sample; interface Mapper {String lookup(@org.apache.ibatis.annotations.Param(\"value\") String value);}");
        sources.put("queries.xml","<mapper namespace=\"sample.Mapper\"><select id=\"lookup\">SELECT * FROM test_items WHERE name=${value}</select></mapper>");
        var zip=uploadSources(token,sources);
        assertThat(zip.at("/serverAnalysis/javaAnalysis/analysis/dataAccess").toString()).contains("INPUT_SUBSTITUTION","queries.xml");
        assertThat(zip.at("/serverAnalysis/javaAnalysis/findings")).hasSize(1);
        var roots=new ArrayList<Path>();
        for(String name:List.of("mapper-public","mapper-private")) {
            Path root=Files.createDirectory(temp.resolve(name));roots.add(root);
            for(var entry:sources.entrySet())Files.writeString(root.resolve(entry.getKey()),entry.getValue());
        }
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/mapper",roots.get(0),roots.get(0)));
        var pub=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/mapper\",\"scanMode\":\"STANDARD\"}");
        var meta=new GitHubSourceSnapshot("fixture","mapper","https://github.com/fixture/mapper","main","a".repeat(40),"aaaaaaa",null,null,null,null,3,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/mapper",roots.get(1),roots.get(1),meta));
        var prv=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        for(var value:List.of(pub,prv))assertThat(value.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        for(var root:roots)assertThat(root).doesNotExist();
        long id=zip.path("reviewId").asLong();
        assertThat(detail(token,id).path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(jdbc.queryForObject("select server_analysis_json from reviews where id=?",String.class,id)).contains("dataAccess","INPUT_SUBSTITUTION").doesNotContain("SELECT * FROM test_items");
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
    }

    @Test void expressCommonInputsStoreReviewOnlyCandidatesAndPreserveHistoricalRisk() throws Exception {
        String token=signup();String code="const web=require('./web.cjs');const app=web();const router=web.Router();router.post('/run',(req,res)=>{eval(req.body.code);});app.use('/api',router);";
        String web="const express=require('express');module.exports=function(){return express();};module.exports.Router=()=>express.Router();";
        String auth="const passport=require('passport');const Bearer=require('passport-http-bearer').Strategy;const handlers=module.exports;handlers.verify=(token,done)=>done(null,false);handlers.setup=()=>passport.use(new Bearer(handlers.verify));";
        var sources=Map.of("server.cjs",code,"web.cjs",web,"auth.cjs",auth);
        var zip=uploadSources(token,sources);
        assertThat(zip.at("/serverAnalysis/validatedFindings/0/ruleId").asText()).isEqualTo("JS_EVAL_INPUT_FLOW");
        assertThat(zip.at("/serverAnalysis/validatedFindings/0/priority").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(zip.at("/serverAnalysis/nodeUses").toString()).contains("INPUT_TO_EXECUTION","ENTRY_REGISTERED","CALL_LINKED","CALLBACK_BOUND");
        assertThat(zip.at("/coverage/analyzers").toString()).contains("SOURCE_SUBMITTED","NODE_ENTRY_REGISTERED","STATIC_INPUT_EXECUTION_PATHS");
        assertThat(zip.path("securityScore").asInt()).isEqualTo(100);
        assertThat(zip.at("/riskAssessment/prioritySummary/BLOCKING").asInt()).isZero();
        Path pub=Files.createDirectory(temp.resolve("express-public")),prv=Files.createDirectory(temp.resolve("express-private"));
        for(var root:List.of(pub,prv))for(var entry:sources.entrySet())Files.writeString(root.resolve(entry.getKey()),entry.getValue());
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/express",pub,pub));
        var publicResult=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/express\",\"scanMode\":\"STANDARD\"}");
        var meta=new GitHubSourceSnapshot("fixture","express","https://github.com/fixture/express","main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/express",prv,prv,meta));
        var privateResult=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        for(var value:List.of(publicResult,privateResult))assertThat(value.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(pub).doesNotExist();assertThat(prv).doesNotExist();
        var fixed=uploadSources(token,Map.of("server.cjs",code.replace("eval(req.body.code)","Number(req.body.code)"),"web.cjs",web,"auth.cjs",auth));
        assertThat(fixed.at("/serverAnalysis/validatedFindings")).isEmpty();
        assertThat(fixed.at("/comparison/counts/RESOLVED").asInt()).isZero();
        assertThat(fixed.path("riskAssessment").path("prioritySummary")).isEqualTo(zip.path("riskAssessment").path("prioritySummary"));
        long id=zip.path("reviewId").asLong();assertThat(detail(token,id).path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
        var stored=(com.fasterxml.jackson.databind.node.ObjectNode)zip.path("serverAnalysis").deepCopy();stored.remove("nodeUses");
        stored.put("analyzerVersion","ts-server-v6");jdbc.update("update reviews set server_analysis_json=? where id=?",json.writeValueAsString(stored),id);entities.clear();
        assertThat(detail(token,id).at("/serverAnalysis/nodeUses").isNull()).isTrue();
        assertThat(detail(token,id).at("/serverAnalysis/analyzerVersion").asText()).isEqualTo("ts-server-v6");
    }

    @Test void commonJsDirectoryMainUsesSameZipPublicAndPrivateAnalysis() throws Exception {
        String token=signup();
        var sources=Map.of("package.json","{\"main\":\"transport/entry.cjs\",\"scripts\":{\"start\":\"node launch.js\"}}",
                "launch.js","const start=require('.');start();",
                "transport/entry.cjs","const express=require('express');module.exports=()=>{const app=express();app.post('/',(req,res)=>eval(req.body.code));return app;};");
        var zip=uploadSources(token,sources);
        assertThat(zip.at("/serverAnalysis/validatedFindings/0/ruleId").asText()).isEqualTo("JS_EVAL_INPUT_FLOW");
        assertThat(zip.at("/serverAnalysis/validatedFindings/0/comparisonPolicy").asText()).isEqualTo("NOT_COMPARED");
        assertThat(zip.path("serverAnalysis").toString()).contains("TS_NODE_MANIFEST_ENTRY_HINT","NODE_COMMONJS_DIRECTORY_SOURCE_LINK");
        Path pub=Files.createDirectory(temp.resolve("directory-public")),prv=Files.createDirectory(temp.resolve("directory-private"));
        for(var root:List.of(pub,prv))for(var entry:sources.entrySet()){
            Path target=root.resolve(entry.getKey());Files.createDirectories(target.getParent());Files.writeString(target,entry.getValue());
        }
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/directory",pub,pub));
        var publicResult=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/directory\",\"scanMode\":\"STANDARD\"}");
        var meta=new GitHubSourceSnapshot("fixture","directory","https://github.com/fixture/directory","main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/directory",prv,prv,meta));
        var privateResult=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        for(var value:List.of(publicResult,privateResult))assertThat(value.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(pub).doesNotExist();assertThat(prv).doesNotExist();
        mvc.perform(get("/api/reviews/"+zip.path("reviewId").asLong()).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
    }

    @Test void mongoProvenanceSharesAllSourcesAndPersistsOriginWithoutPromotingRisk() throws Exception {
        String token=signup();
        String code="const express=require('express');const {MongoClient}=require('mongodb');const app=express();"
                +"MongoClient.connect('unused',(err,db)=>{const unused={};unused.note=1;function pass(v){return v;}"
                +"function Store(value){this.db=value;this.get=()=>this.db.collection('items');}"
                +"function build(v){return new Store(v);}function middle(v){return build(v);}function outer(v){return middle(v);}"
                +"const store=outer(pass(db));const c=store.get();app.get('/',(req,res)=>c.find({$where:req.query.code}).toArray());});";
        String manifest="{\"dependencies\":{\"mongodb\":\"2.2.36\",\"express\":\"4.18.0\"}}";
        var sources=Map.of("server.cjs",code,"package.json",manifest);
        var zip=uploadSources(token,sources);
        assertThat(zip.at("/serverAnalysis/validatedFindings")).hasSize(1);
        assertThat(zip.at("/serverAnalysis/validatedFindings/0/ruleId").asText()).isEqualTo("JS_MONGO_WHERE_INPUT_FLOW");
        assertThat(zip.at("/serverAnalysis/validatedFindings/0/priority").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(zip.path("serverAnalysis").toString()).contains("MONGODB_COLLECTION_ORIGIN");
        assertThat(zip.path("serverAnalysis").toString()).contains("CONSTRUCTOR_SUMMARY_MUST");
        Path pub=Files.createDirectory(temp.resolve("mongo-public")),prv=Files.createDirectory(temp.resolve("mongo-private"));
        for(var root:List.of(pub,prv))for(var entry:sources.entrySet())Files.writeString(root.resolve(entry.getKey()),entry.getValue());
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/mongo",pub,pub));
        var publicResult=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/mongo\",\"scanMode\":\"STANDARD\"}");
        var metadata=new GitHubSourceSnapshot("fixture","mongo","https://github.com/fixture/mongo","main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/mongo",prv,prv,metadata));
        var privateResult=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        for(var value:List.of(publicResult,privateResult))assertThat(value.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(pub).doesNotExist();assertThat(prv).doesNotExist();
        var fixed=uploadSources(token,Map.of("server.cjs",code.replace("{$where:req.query.code}","{code:req.query.code}"),"package.json",manifest));
        assertThat(fixed.at("/serverAnalysis/validatedFindings")).isEmpty();
        for(String key:List.of("securityScore","vulnerabilityCount","deploymentStatus"))assertThat(fixed.path(key)).isEqualTo(zip.path(key));
        for(String key:List.of("prioritySummary","prioritizedDeploymentAssessment"))assertThat(fixed.path("riskAssessment").path(key)).isEqualTo(zip.path("riskAssessment").path(key));
        assertThat(fixed.at("/comparison/counts/RESOLVED").asInt()).isZero();
        long id=zip.path("reviewId").asLong();assertThat(detail(token,id).path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
    }

    @Test void ssrfUsesCommonSourcesAndSnapshotWithoutChangingRiskOrComparison() throws Exception {
        String token=signup();
        String code="export default {fetch(request){return fetch(new Request(new URL(request.url).searchParams.get('target')));}}";
        var zip=upload(token,code);
        assertThat(zip.at("/serverAnalysis/validatedFindings/0/ruleId").asText()).isEqualTo("TS_SSRF_INPUT_FLOW");
        assertThat(zip.at("/serverAnalysis/httpUses/0/kind").asText()).isEqualTo("INPUT_IN_DESTINATION");
        Path publicRoot=Files.createDirectory(temp.resolve("ssrf-public")); Files.writeString(publicRoot.resolve("worker.ts"),code);
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/server",publicRoot,publicRoot));
        var publicResult=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/server\",\"scanMode\":\"STANDARD\"}");
        Path privateRoot=Files.createDirectory(temp.resolve("ssrf-private")); Files.writeString(privateRoot.resolve("worker.ts"),code);
        var metadata=new GitHubSourceSnapshot("fixture","server","https://github.com/fixture/server","main","a".repeat(40),"aaaaaaa",
                null,null,null,null,1,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/server",privateRoot,privateRoot,metadata));
        var privateResult=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        assertThat(publicResult.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(privateResult.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(publicRoot).doesNotExist(); assertThat(privateRoot).doesNotExist();
        var safe=upload(token,"export default {fetch(request){return fetch('https://example.invalid/?q='+new URL(request.url).searchParams.get('target'));}}");
        assertThat(safe.at("/serverAnalysis/validatedFindings")).isEmpty();
        assertThat(safe.path("securityScore")).isEqualTo(zip.path("securityScore"));
        for(String key:List.of("prioritySummary","prioritizedDeploymentAssessment","codeFindings"))
            assertThat(safe.path("riskAssessment").path(key)).isEqualTo(zip.path("riskAssessment").path(key));
        assertThat(safe.at("/comparison/counts/RESOLVED").asInt()).isZero();
        long id=zip.path("reviewId").asLong();
        assertThat(detail(token,id).path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
    }

    @Test void exposureUsesCommonInputSourcesWithoutChangingRiskOrResolvedCounts() throws Exception {
        String token=signup(),code="Deno.serve(async request=>{const name=new URL(request.url).searchParams.get('name');return Response.json({value:Deno.env.get(name)});});";
        var zip=upload(token,code);var normal=upload(token,code.replace("Deno.env.get(name)","false"));
        assertThat(zip.at("/serverAnalysis/validatedFindings/0/ruleId").asText()).isEqualTo("TS_SENSITIVE_DATA_EXPOSURE");
        assertThat(zip.at("/serverAnalysis/exposureUses")).hasSize(1);
        Path pub=Files.createDirectory(temp.resolve("exposure-public")),prv=Files.createDirectory(temp.resolve("exposure-private"));
        Files.writeString(pub.resolve("worker.ts"),code);Files.writeString(prv.resolve("worker.ts"),code);
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/exposure",pub,pub));
        var publicResult=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/exposure\",\"scanMode\":\"STANDARD\"}");
        var metadata=new GitHubSourceSnapshot("fixture","exposure","https://github.com/fixture/exposure","main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/exposure",prv,prv,metadata));
        var privateResult=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        assertThat(publicResult.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));assertThat(privateResult.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(pub).doesNotExist();assertThat(prv).doesNotExist();
        assertThat(normal.at("/serverAnalysis/validatedFindings")).isEmpty();assertThat(normal.at("/comparison/counts/RESOLVED").asInt()).isZero();
        for(String key:List.of("securityScore","vulnerabilityCount","deploymentStatus"))assertThat(zip.path(key)).isEqualTo(normal.path(key));
        for(String key:List.of("prioritySummary","prioritizedDeploymentAssessment"))assertThat(zip.path("riskAssessment").path(key)).isEqualTo(normal.path("riskAssessment").path(key));
        assertThat(detail(token,zip.path("reviewId").asLong()).path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(zip.at("/coverage/analyzers").toString()).contains("TYPESCRIPT_EXPOSURE");
        mvc.perform(get("/api/reviews/"+zip.path("reviewId").asLong()).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
    }

    @Test void correctedStatePersistsWithoutChangingRiskOrCountingAFalselyResolvedIssue() throws Exception {
        String token = signup();
        String start = "export default { fetch(request,env) { let id=new URL(request.url).searchParams.get('id'); ";
        var before = upload(token, start + "return env.DB.prepare(id + (id='0')).all(); }}");
        var after = upload(token, start + "return env.DB.prepare((id='0') + id).all(); }}");
        assertThat(before.at("/serverAnalysis/validatedFindings")).hasSize(1);
        assertThat(after.at("/serverAnalysis/validatedFindings")).isEmpty();
        assertThat(after.at("/comparison/counts/RESOLVED").isIntegralNumber()).isTrue();
        assertThat(after.at("/comparison/counts/RESOLVED").asInt()).isZero();
        assertThat(after.path("securityScore")).isEqualTo(before.path("securityScore"));
        assertThat(after.at("/riskAssessment/prioritySummary")).isEqualTo(before.at("/riskAssessment/prioritySummary"));
        assertThat(after.at("/riskAssessment/prioritizedDeploymentAssessment")).isEqualTo(before.at("/riskAssessment/prioritizedDeploymentAssessment"));
        assertThat(detail(token, before.path("reviewId").asLong()).path("serverAnalysis")).isEqualTo(before.path("serverAnalysis"));
        assertThat(detail(token, after.path("reviewId").asLong()).path("serverAnalysis")).isEqualTo(after.path("serverAnalysis"));
    }

    @Test void zipPublicAndPrivateShareEvidencePersistenceAndCleanupWithoutChangingRisk() throws Exception {
        String token = signup();
        var zip = upload(token, TypeScriptServerAnalyzerTest.UNSAFE);
        var safe = upload(token, TypeScriptServerAnalyzerTest.SAFE);
        assertThat(zip.at("/serverAnalysis/findings")).hasSize(1);
        assertThat(zip.at("/serverAnalysis/validatedFindings")).hasSize(1);
        assertThat(zip.at("/serverAnalysis/validatedFindings/0/priority").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(zip.at("/serverAnalysis/validatedFindings/0/comparisonPolicy").asText()).isEqualTo("NOT_COMPARED");
        assertThat(zip.at("/serverAnalysis/validatedFindings/0/executionLocations")).isNotEmpty();
        assertThat(safe.at("/serverAnalysis/validatedFindings")).isEmpty();
        assertThat(safe.at("/serverAnalysis/findings")).isEmpty();
        for (String key : List.of("securityScore", "vulnerabilityCount", "deploymentStatus")) assertThat(zip.path(key)).isEqualTo(safe.path(key));
        for (String key : List.of("prioritySummary", "prioritizedDeploymentAssessment", "codeFindings"))
            assertThat(zip.path("riskAssessment").path(key)).isEqualTo(safe.path("riskAssessment").path(key));
        assertThat(zip.at("/semanticReview/semanticReviewStatus").asText()).isEqualTo("NOT_REQUESTED");
        Path publicRoot = source("public");
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture", "https://github.com/fixture/server", publicRoot, publicRoot));
        var publicResult = postJson("/api/reviews/github", token, "{\"repositoryUrl\":\"https://github.com/fixture/server\",\"scanMode\":\"STANDARD\"}");
        Path privateRoot = source("private");
        var metadata = new GitHubSourceSnapshot("fixture", "server", "https://github.com/fixture/server", "main", "a".repeat(40), "aaaaaaa",
                null, null, null, null, 1, 0, 0, 0, List.of()).withAccess(123L, 456L, true);
        when(connected.collect(anyLong(), eq(456L), eq(123L))).thenReturn(new ClonedRepository("fixture", "https://github.com/fixture/server", privateRoot, privateRoot, metadata));
        var privateResult = postJson("/api/reviews/github/connected", token, "{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        assertThat(publicResult.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(privateResult.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(publicRoot).doesNotExist(); assertThat(privateRoot).doesNotExist();
        long id = zip.path("reviewId").asLong();
        assertThat(detail(token, id).path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(jdbc.queryForObject("select server_analysis_json from reviews where id=?", String.class, id))
                .contains("TS_SQL_INPUT_FLOW", "ts-flow:", "verificationSteps").doesNotContain("SELECT *");
        mvc.perform(get("/api/reviews/" + id).header("Authorization", "Bearer " + signup())).andExpect(status().isForbidden());
        mvc.perform(get("/api/reviews").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        mvc.perform(get("/api/reviews/" + id + "/report").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        mvc.perform(get("/api/reviews/" + id + "/ai-summary").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        jdbc.update("update reviews set server_analysis_json=null where id=?", id); entities.clear();
        assertThat(detail(token, id).path("serverAnalysis").isNull()).isTrue();
        assertThat(detail(token, id).path("riskAssessment")).isEqualTo(zip.path("riskAssessment"));
    }
    @Test void syntaxFailureIsStoredAsIncompleteWithoutInventingFindings() throws Exception {
        String token = signup(); var result = upload(token, "export default { fetch( {");
        assertThat(result.at("/serverAnalysis/status").asText()).isEqualTo("PARTIAL");
        assertThat(result.at("/serverAnalysis/files/0/parseStatus").asText()).isEqualTo("PARSE_FAILED");
        assertThat(result.at("/serverAnalysis/findings")).isEmpty();
        assertThat(result.path("coverage").path("analyzers").toString()).contains("TYPESCRIPT_SERVER", "AST_PARSE_FAILED");
        assertThat(detail(token, result.path("reviewId").asLong()).path("serverAnalysis")).isEqualTo(result.path("serverAnalysis"));
    }
    Path source(String dir) throws Exception {
        Path root = Files.createDirectory(temp.resolve(dir)); Files.writeString(root.resolve("worker.ts"), TypeScriptServerAnalyzerTest.UNSAFE); return root;
    }
    String signup() throws Exception { return postJson("/api/auth/signup", null, json.writeValueAsString(Map.of(
            "email", UUID.randomUUID() + "@ts-fixture.invalid", "password", UUID.randomUUID().toString(), "name", "AST fixture"))).path("accessToken").asText(); }
    JsonNode postJson(String path, String token, String body) throws Exception {
        var request = post(path).contentType(MediaType.APPLICATION_JSON).content(body);
        if (token != null) request.header("Authorization", "Bearer " + token);
        return json.readTree(mvc.perform(request).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
    JsonNode detail(String token, long id) throws Exception { return json.readTree(mvc.perform(get("/api/reviews/" + id).header("Authorization", "Bearer " + token))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray()); }
    JsonNode upload(String token, String code) throws Exception {
        return uploadSource(token,"worker.ts",code);
    }
    JsonNode uploadSource(String token,String name,String code) throws Exception {
        return uploadSources(token,Map.of(name,code));
    }
    JsonNode uploadSources(String token,Map<String,String> sources) throws Exception {
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) {
            for(var entry:sources.entrySet()) {zip.putNextEntry(new ZipEntry("fixture/"+entry.getKey()));zip.write(entry.getValue().getBytes(StandardCharsets.UTF_8));zip.closeEntry();}
        }
        return json.readTree(mvc.perform(multipart("/api/reviews/upload").file(new MockMultipartFile("file", "fixture.zip", "application/zip", bytes.toByteArray()))
                .header("Authorization", "Bearer " + token)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
}
