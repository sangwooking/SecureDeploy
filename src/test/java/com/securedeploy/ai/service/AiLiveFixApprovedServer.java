package com.securedeploy.ai.service;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.ai.config.*;
import com.securedeploy.ai.usage.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/** Manual approved experiment only. Existing product transport/ledger/patch APIs, no bypass or retries. */
public final class AiLiveFixApprovedServer {
    static Path root;
    static final String MODEL="gpt-5.4-mini-2026-03-17";
    static final String EXPRESS="import express from 'express';\nconst app = express();\napp.get('/health', (req, res) => { return res.json({ ready: true, credential: process.env.API_SECRET, count: 12 }); });";
    static final Object lock=new Object();
    static String hash(byte[] bytes){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}catch(Exception e){throw new IllegalStateException();}}
    @TestConfiguration static class Approved {
        @Bean @Primary AiProviderResolver approvedResolver(AiProperties properties,ObjectMapper mapper,DurableAiLedger ledger) {
            var factory=new SimpleClientHttpRequestFactory();factory.setConnectTimeout(Duration.ofSeconds(15));factory.setReadTimeout(Duration.ofSeconds(30));
            var client=RestClient.builder().baseUrl("https://api.openai.com/v1").requestFactory(factory).requestInterceptor((request,body,execution)->{
                synchronized(lock){
                    var gate=mapper.readTree(Files.readAllBytes(root.resolve("live-approval.json")));
                    var data=mapper.readTree(body);var input=mapper.readTree(data.at("/input/0/content").asText());
                    String kind=data.at("/text/format/name").asText().equals("workspace_patch_plan_v1")?"EXPRESS":"SPRING";
                    boolean scope=kind.equals("EXPRESS")?EXPRESS.equals(input.at("/context/code").asText())&&input.at("/plan/requiredFields").size()==1&&"TS_SENSITIVE_DATA_EXPOSURE".equals(input.path("ruleId").asText()):"debug=true".equals(input.path("untrustedCode").asText())&&"DEBUG_ENABLED".equals(input.path("ruleId").asText());
                    var attempts=((com.fasterxml.jackson.databind.node.ObjectNode)gate).withArray("attempts");
                    if(!gate.path("approved").asBoolean()||gate.path("closed").asBoolean()||attempts.size()>=2||!MODEL.equals(data.path("model").asText())||body.length>30720||data.path("max_output_tokens").asInt()!=2000||data.path("store").asBoolean(true)||data.has("tools")||!data.at("/text/format/strict").asBoolean()||!request.getURI().toString().equals("https://api.openai.com/v1/responses")||!scope)throw new AiProviderFailure(AiProviderFailure.Kind.NOT_SENT,false);
                    for(var attempt:attempts)if(kind.equals(attempt.path("case").asText()))throw new AiProviderFailure(AiProviderFailure.Kind.NOT_SENT,false);
                    var event=mapper.createObjectNode().put("case",kind).put("requestSha256",hash(body)).put("requestBytes",body.length).put("at",Instant.now().toString());attempts.add(event);
                    ((com.fasterxml.jackson.databind.node.ObjectNode)gate).put("closed",attempts.size()>=2);
                    Path temp=root.resolve("live-approval.next");Files.write(temp,mapper.writeValueAsBytes(gate));
                    try(var file=java.nio.channels.FileChannel.open(temp,StandardOpenOption.WRITE)){file.force(true);}Files.move(temp,root.resolve("live-approval.json"),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
                    Files.write(root.resolve(kind+"-approved-request.json"),body,StandardOpenOption.CREATE_NEW);
                }
                return execution.execute(request,body);
            }).build();
            var provider=new RealOpenAiProvider(properties,mapper,client) {
                @Override public boolean isAvailable(){try{return super.isAvailable()&&!mapper.readTree(Files.readAllBytes(root.resolve("live-approval.json"))).path("closed").asBoolean(true);}catch(Exception unavailable){return false;}}
            };provider.configureLedger(ledger);
            return new AiProviderResolver(properties,List.of(provider,new TemplateAiProvider()));
        }
    }
    public static void main(String[]args)throws Exception{
        root=Path.of(Objects.requireNonNull(System.getenv("AILIVE_FIX_APPROVAL_ROOT"))).toRealPath();
        if(System.getenv("OPENAI_API_KEY")==null||!Files.exists(root.resolve("live-approval.json")))throw new IllegalStateException("APPROVAL_AND_KEY_REQUIRED");
        for(String arg:args)if(arg.startsWith("--spring.datasource.url=")&&!arg.equals("--spring.datasource.url=jdbc:postgresql://127.0.0.1:58850/ailivefix_live"))throw new IllegalStateException("ISOLATED_DB_REQUIRED");
        var app=new SpringApplicationBuilder(com.securedeploy.SecureDeployApplication.class,Approved.class).run(args);Runtime.getRuntime().addShutdownHook(new Thread(app::close));
    }
}
