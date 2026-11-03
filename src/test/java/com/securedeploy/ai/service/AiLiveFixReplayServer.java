package com.securedeploy.ai.service;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.ai.config.*;
import com.securedeploy.ai.usage.*;
import java.net.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/** Isolated loopback transport replay. Not packaged in the product JAR; never reads a real API key. */
public final class AiLiveFixReplayServer {
    static Path root;
    @TestConfiguration static class Replay {
        @Bean @Primary AiProviderResolver replayResolver(AiProperties properties,ObjectMapper mapper,DurableAiLedger ledger) {
            var factory=new SimpleClientHttpRequestFactory();factory.setConnectTimeout(Duration.ofSeconds(1));factory.setReadTimeout(Duration.ofSeconds(1));
            var replay=new RealOpenAiProvider(properties,mapper,RestClient.builder().baseUrl("http://127.0.0.1:58841/v1").requestFactory(factory).build()) {
                @Override public String executionOrigin(){return "MOCK";}
                @Override public Optional<AiTokenUsage> consumeLastTokenUsage(){return super.consumeLastTokenUsage().map(u->new AiTokenUsage(u.promptTokens(),u.completionTokens(),u.totalTokens(),false,u.cachedInputTokens(),u.model(),u.usageKnown()));}
            };
            replay.configureLedger(ledger);
            return new AiProviderResolver(properties,List.of(replay,new TemplateAiProvider()));
        }
    }
    public static void main(String[] args)throws Exception {
        if(System.getenv("OPENAI_API_KEY")!=null||System.getenv("SECUREDEPLOY_AI_OPENAI_API_KEY")!=null)throw new IllegalStateException("REAL_KEYS_FORBIDDEN");
        for(String arg:args)if(arg.startsWith("--spring.datasource.url=")&&!arg.equals("--spring.datasource.url=jdbc:postgresql://127.0.0.1:58850/ailivefix_replay"))throw new IllegalStateException("ISOLATED_DB_REQUIRED");
        root=Path.of(Objects.requireNonNull(System.getenv("AILIVE_FIX_TEST_ROOT"))).toRealPath();
        var mapper=new ObjectMapper();var server=com.sun.net.httpserver.HttpServer.create(new InetSocketAddress("127.0.0.1",58841),0);
        server.createContext("/v1/responses",exchange->{try{
            var bytes=exchange.getRequestBody().readNBytes(30721);if(bytes.length>30720)throw new IllegalArgumentException();var request=mapper.readTree(bytes);
            String mode=Files.exists(root.resolve("transport-mode"))?Files.readString(root.resolve("transport-mode")).trim():"PATCH";
            Files.writeString(root.resolve("transport-requests.jsonl"),mapper.writeValueAsString(Map.of("mode",mode,"request",request))+"\n",StandardOpenOption.CREATE,StandardOpenOption.APPEND);
            int status=200;Object result;
            if(mode.equals("TIMEOUT")){try{Thread.sleep(2000);}catch(InterruptedException e){Thread.currentThread().interrupt();}result=Map.of("status","incomplete");}
            else if(mode.equals("HTTP_ERROR")){status=429;result=Map.of("error","synthetic-private-provider-detail");}
            else if(mode.equals("REFUSED"))result=Map.of("status","completed","output",List.of(Map.of("type","message","content",List.of(Map.of("type","refusal","refusal","synthetic-refusal")))),"usage",Map.of("input_tokens",31,"output_tokens",7,"total_tokens",38));
            else if(mode.equals("INCOMPLETE"))result=Map.of("status","incomplete","output",List.of(),"usage",Map.of("input_tokens",31,"output_tokens",7,"total_tokens",38));
            else {
                var data=mapper.readTree(request.at("/input/0/content").asText());Object output;
                if(request.at("/text/format/name").asText().equals("workspace_patch_plan_v1")){
                    var fields=new ArrayList<Map<String,String>>();for(var field:data.at("/plan/requiredFields"))fields.add(Map.of("fieldId",field.path("fieldId").asText(),"operation","REMOVE_RESPONSE_FIELD"));
                    if(mode.equals("MISSING_FIELD")&&!fields.isEmpty())fields.remove(fields.size()-1);
                    output=Map.of("decision","PATCH","objectId",data.at("/plan/objectId").asText(),"operations",fields,"explanation","통제 HTTP 응답입니다. 클라이언트 계약과 정상 필드를 별도로 확인하세요.","verificationSteps",List.of("같은 HTTP 경로와 정상 필드 확인"),"limitations",List.of("Mock 전송 재현이며 실제 모델 검증이 아닙니다."));
                }else output=Map.of("decision","PATCH","fileId",data.path("fileId").asText(),"startLine",data.path("startLine").asInt(),"expectedHash",data.path("expectedHash").asText(),"replacement","debug=false","explanation","통제 설정 변경 제안입니다.","verificationSteps",List.of("설정 적용 확인"),"limitations",List.of("Mock 전송 재현"));
                result=Map.of("status","completed","model","mock-responses-replay","output",List.of(Map.of("type","message","content",List.of(Map.of("type","output_text","text",mapper.writeValueAsString(output))))),"usage",Map.of("input_tokens",31,"output_tokens",7,"total_tokens",38));
            }
            byte[] body=mapper.writeValueAsBytes(result);exchange.getResponseHeaders().set("Content-Type","application/json");exchange.sendResponseHeaders(status,body.length);exchange.getResponseBody().write(body);
        }catch(Exception ignored){/* No source, body, headers or credentials in logs. */}finally{exchange.close();}});
        server.setExecutor(Executors.newCachedThreadPool(r->{var t=new Thread(r,"ai-live-loopback");t.setDaemon(true);return t;}));server.start();
        var app=new SpringApplicationBuilder(com.securedeploy.SecureDeployApplication.class,Replay.class).run(args);
        Runtime.getRuntime().addShutdownHook(new Thread(()->{server.stop(0);app.close();}));
    }
}
