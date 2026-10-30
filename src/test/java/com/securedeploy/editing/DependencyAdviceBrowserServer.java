package com.securedeploy.editing;

import com.securedeploy.ai.config.*;
import com.securedeploy.ai.service.*;
import com.securedeploy.ai.dependency.DependencyAiAdvice;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.lang.reflect.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.util.*;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.*;
import static org.mockito.Mockito.*;

/** Explicit opt-in live evaluation: public Undici metadata only, persistent hard cap of two attempts. */
public final class DependencyAdviceBrowserServer {
    @TestConfiguration
    public static class AdviceFixture {
        @Bean @Primary AiProviderResolver guardedAdviceResolver(AiProperties properties,RealOpenAiProvider real,ObjectMapper json)throws Exception{
            if("1".equals(System.getenv("SECUREDEPLOY_AI03_LIVE"))||"1".equals(System.getenv("SECUREDEPLOY_NEXT01_LIVE")))throw new IllegalStateException("PATCH02_NO_REAL_MODEL_CALLS");
            boolean live="1".equals(System.getenv("SECUREDEPLOY_AI03_LIVE"));
            AiProvider selected;
            if(live){
                String key=System.getenv("OPENAI_API_KEY");if(key==null||key.isBlank())throw new IllegalStateException("LIVE_KEY_REQUIRED");
                properties.getOpenai().setApiKey(key);
                if(!"gpt-5.4-mini".equals(properties.getOpenai().getModel()))throw new IllegalStateException("APPROVED_MODEL_REQUIRED");
                selected=(AiProvider)Proxy.newProxyInstance(AiProvider.class.getClassLoader(),new Class<?>[]{AiProvider.class},(proxy,method,args)->{
                    if(!Set.of("providerType","isAvailable","consumeLastTokenUsage","executionOrigin","generateDependencyAdvice").contains(method.getName()))throw new UnsupportedOperationException("LIVE_SCOPE_LIMIT");
                    if(method.getName().equals("generateDependencyAdvice")){
                        var prompt=(WorkspacePatch.Prompt)args[0];var data=json.readTree(prompt.untrustedData());
                        if(!data.path("packageName").asText().equals("undici")||data.size()!=8
                                ||!Set.of("7.29.1","7.28.0","8.11.2").contains(data.path("lockedVersion").asText())
                                ||prompt.untrustedData().contains("runwhen")||prompt.untrustedData().contains("urisai")
                                ||json.writeValueAsBytes(prompt).length>8192)throw new IllegalArgumentException("PUBLIC_APPROVED_SCOPE_ONLY");
                        reserveLiveAttempt(prompt,json);
                    }
                    try{return method.invoke(real,args);}catch(InvocationTargetException e){throw e.getCause();}
                });
            }else{
                var mock=mock(AiProvider.class);when(mock.providerType()).thenReturn(AiProviderType.OPENAI);when(mock.isAvailable()).thenReturn(true);when(mock.executionOrigin()).thenReturn("MOCK");when(mock.consumeLastTokenUsage()).thenReturn(Optional.of(new com.securedeploy.ai.usage.AiTokenUsage(0,0,0,false,0,"mock-fixture-no-external",true)));
                when(mock.generateSemanticReview(any(),any())).thenAnswer(i->{
                    var slices=(java.util.List<com.securedeploy.ai.semantic.SecuritySlice>)i.getArgument(0);
                    if(slices.isEmpty())return java.util.List.of();var slice=slices.get(0);var c=slice.contexts().get(0);
                    var e=new com.securedeploy.ai.semantic.SemanticCandidate.Evidence(c.contextId(),c.filePath().contains("invalid")?"invented.ts":c.filePath(),c.startLine(),c.endLine(),c.functionName(),"입력 처리와 미확인 함수의 보호 조치를 직접 확인해야 합니다.");
                    return java.util.List.of(new com.securedeploy.ai.semantic.SemanticCandidate.Proposal(slice.sliceId(),com.securedeploy.ai.semantic.SemanticCandidate.CandidateType.COMMAND_INJECTION_CANDIDATE,"미완료 흐름 추가 검토",com.securedeploy.ai.dto.AiConfidence.LOW,"Mock 통제 의견입니다. 실제 보안 문제로 확정하지 않습니다.",true,java.util.List.of(e),java.util.List.of("미확인 함수의 입력 처리와 실행 경로를 확인하세요."),slice.existingFindings().stream().map(com.securedeploy.ai.semantic.SecuritySlice.ExistingFinding::findingId).toList()));
                });
                when(mock.generateWorkspacePatchPlan(any())).thenAnswer(i->{
                    var prompt=(WorkspacePatch.Prompt)i.getArgument(0);var data=json.readTree(prompt.untrustedData());var plan=data.path("plan");
                    Files.writeString(DependencyUpdateBrowserServer.root.resolve("patch03-prompt-"+plan.path("requiredFields").size()+".json"),json.writeValueAsString(prompt));
                    Path override=DependencyUpdateBrowserServer.root.resolve("patch03-mock-plan-output.json");
                    if(Files.isRegularFile(override)){var fault=json.readTree(override.toFile());if(fault.path("output").path("objectId").asText().equals(plan.path("objectId").asText())){Files.writeString(DependencyUpdateBrowserServer.root.resolve("patch03-negative-used.json"),fault.toString());return WorkspacePatchPlan.parse(fault.path("output"));}}
                    var operations=new ArrayList<WorkspacePatchPlan.Operation>();for(var field:plan.path("requiredFields"))operations.add(new WorkspacePatchPlan.Operation(field.path("fieldId").asText(),WorkspacePatchPlan.OPERATION));
                    return new WorkspacePatchPlan.Output("PATCH",plan.path("objectId").asText(),operations,"Mock 수정 방향 제안입니다. 실제 코드는 SecureDeploy가 AST 범위에서 생성하며 응답 필드 제거는 API 계약을 바꿀 수 있습니다.",List.of("정상 응답·상태 및 API 사용처를 확인하고 재검사하세요."),List.of("Mock 계획이며 실제 모델의 새 계약 준수와 전체 기능 호환성은 미검증입니다."));
                });
                when(mock.generateWorkspacePatch(any())).thenAnswer(i->{var d=json.readTree(((WorkspacePatch.Prompt)i.getArgument(0)).untrustedData());String code=d.path("untrustedCode").asText();
                    if(d.has("context")){
                        var ctx=d.path("context");if(!ctx.path("endpoint").asText().matches("(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) .*" )||ctx.path("sources").isEmpty()||ctx.path("preservedFields").isEmpty()||!d.has("sourceFileHash")||!d.has("contextHash"))throw new IllegalArgumentException("FIX01_CONTEXT_REQUIRED");
                        Files.writeString(DependencyUpdateBrowserServer.root.resolve("fix01-mock-prompt.json"),json.writeValueAsString((WorkspacePatch.Prompt)i.getArgument(0)));
                        Files.writeString(DependencyUpdateBrowserServer.root.resolve("patch02-prompt-"+ctx.path("sources").size()+".json"),json.writeValueAsString((WorkspacePatch.Prompt)i.getArgument(0)));
                    }
                    String replacement=d.path("ruleId").asText().equals("DEBUG_ENABLED")?code.replace("debug=true","debug=false"):code.replaceAll(",\\s*[A-Za-z_][A-Za-z0-9_]*:\\s*(?:process\\.env\\.[A-Z_][A-Z0-9_]*|Deno\\.env\\.get\\('[A-Z_][A-Z0-9_]*'\\))","");
                    Path override=DependencyUpdateBrowserServer.root.resolve("patch02-mock-output.json");
                    if(Files.isRegularFile(override)){var fault=json.readTree(override.toFile());if(fault.path("sourceFileHash").asText().equals(d.path("sourceFileHash").asText())){replacement=fault.path("replacement").asText();Files.writeString(DependencyUpdateBrowserServer.root.resolve("patch02-negative-used.json"),fault.toString());}}
                    return new WorkspacePatch.Output("PATCH",d.path("fileId").asText(),d.path("startLine").asInt(),d.path("expectedHash").asText(),replacement,"Mock 코드 수정 제안입니다. 원본 근거에 연결된 범위만 변경하며 실행 안전성은 확인하지 않았습니다.",List.of("정상 응답과 상태 코드를 확인하고 동일 진입점으로 재검사하세요."),List.of("Mock 생성이며 실제 모델 품질은 미검증입니다. API 호환성과 운영 환경은 별도 확인이 필요합니다."));});
                when(mock.generateDependencyAdvice(any())).thenAnswer(i->{var d=json.readTree(((WorkspacePatch.Prompt)i.getArgument(0)).untrustedData());return new DependencyAiAdvice.Output(d.path("evidenceHash").asText(),d.path("packageName").asText(),d.path("lockedVersion").asText(),d.path("advisoryId").asText(),"PROPOSE_UPDATE",d.path("verifiedCandidateVersions").get(0).asText(),
                        "잠금 버전에 보안 공지가 연결되어 있습니다.","사용 방식에 따라 영향을 받을 수 있어 검토가 필요합니다.","실제 실행 경로와 영향은 확인되지 않았습니다.","상위 의존성과 범위를 제한한 업데이트를 검토하세요.",List.of("변경 내용을 검토하고 재검사하세요."),List.of("Mock 통제 응답이며 실제 모델 품질과 호환성은 미검증입니다."));});selected=mock;
            }
            return new AiProviderResolver(properties,List.of(selected,new TemplateAiProvider()));
        }
    }
    private static synchronized void reserveLiveAttempt(WorkspacePatch.Prompt prompt,ObjectMapper json)throws Exception{
        Path root=DependencyUpdateBrowserServer.root,count=root.resolve("live-attempt-count.txt");
        try(var channel=FileChannel.open(count,StandardOpenOption.CREATE,StandardOpenOption.READ,StandardOpenOption.WRITE);var lock=channel.lock()){
            var b=ByteBuffer.allocate(16);channel.read(b);b.flip();String prior=java.nio.charset.StandardCharsets.UTF_8.decode(b).toString().trim();int n=prior.isEmpty()?0:Integer.parseInt(prior);
            if(n>=2)throw new IllegalStateException("APPROVED_TWO_ATTEMPT_LIMIT");
            channel.truncate(0);channel.position(0);channel.write(ByteBuffer.wrap(Integer.toString(n+1).getBytes(java.nio.charset.StandardCharsets.UTF_8)));channel.force(true);
            Files.writeString(root.resolve("live-request-"+(n+1)+".json"),prompt.untrustedData(),StandardOpenOption.CREATE_NEW);
        }
    }
    public static void main(String[] args)throws Exception{
        if(!"1".equals(System.getenv("SECUREDEPLOY_AI03_ADVICE")))throw new IllegalStateException("EXPLICIT_OPT_IN_REQUIRED");
        DependencyUpdateBrowserServer.main(args);
    }
}
