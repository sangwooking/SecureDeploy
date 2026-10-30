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
        @Bean @Primary AiProviderResolver guardedAdviceResolver(AiProperties properties,RealOpenAiProvider real,ObjectMapper json){
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
                when(mock.generateWorkspacePatch(any())).thenAnswer(i->{var d=json.readTree(((WorkspacePatch.Prompt)i.getArgument(0)).untrustedData());String code=d.path("untrustedCode").asText();
                    String replacement=d.path("ruleId").asText().equals("DEBUG_ENABLED")?code.replace("debug=true","debug=false"):code.replaceAll(",\\s*[A-Za-z_][A-Za-z0-9_]*:\\s*(?:process\\.env\\.[A-Z_][A-Z0-9_]*|Deno\\.env\\.get\\('[A-Z_][A-Z0-9_]*'\\))","");
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
