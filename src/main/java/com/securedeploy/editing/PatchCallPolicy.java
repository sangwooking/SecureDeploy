package com.securedeploy.editing;

import com.securedeploy.global.error.SecureDeployException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

/** Single-instance admission policy, not a durable billing ledger. Real calls default OFF. */
@Component
public class PatchCallPolicy {
    private record Attempt(long user,long project,String identity,Instant at,BigDecimal reserved) { }
    final class Permit implements AutoCloseable {
        private boolean closed;
        @Override public void close(){synchronized(PatchCallPolicy.this){if(!closed){active--;closed=true;}}}
    }
    private final boolean externalEnabled;
    private final Clock clock;
    private boolean persistentExhibit;
    @org.springframework.beans.factory.annotation.Autowired
    void configureExhibition(
            @Value("${spring.datasource.url:}") String datasource,
            @Value("${securedeploy.ai.exhibit.control-file:}") String control,
            @Value("${securedeploy.ai.main-cutover.control-file:}") String mainControl) {
        persistentExhibit=!mainControl.isBlank()||!control.isBlank()
                && "jdbc:postgresql://127.0.0.1:58869/securedeploy_exhibit_live".equals(datasource);
    }
    private final List<Attempt> attempts=new ArrayList<>();
    private int active;
    @org.springframework.beans.factory.annotation.Autowired
    public PatchCallPolicy(@Value("${securedeploy.ai.patch-policy.external-enabled:false}") boolean enabled){this(enabled,Clock.systemUTC());}
    PatchCallPolicy(boolean enabled,Clock clock){this.externalEnabled=enabled;this.clock=clock;}
    boolean available(String origin){return "MOCK".equals(origin)||("OPENAI".equals(origin)&&externalEnabled);}
    boolean available(String origin,String model){return available(origin)&&("MOCK".equals(origin)||("gpt-5.4-mini-2026-03-17".equals(model)&&com.securedeploy.ai.usage.AiCostPolicy.priced(model)));}
    synchronized Permit reserve(long user,long project,String hash,String model,String origin,WorkspacePatch.Prompt prompt){
        if(!available(origin))throw new SecureDeployException(HttpStatus.SERVICE_UNAVAILABLE,"외부 AI 코드 수정 호출은 서버 정책에서 비활성화되어 있습니다. 수동 편집과 검증된 자동 수정은 사용할 수 있습니다.");
        // Every UTF-8 byte is conservatively charged as one input token, plus fixed schema/framing allowance.
        int bytes=prompt.instructions().getBytes(StandardCharsets.UTF_8).length+prompt.untrustedData().getBytes(StandardCharsets.UTF_8).length;
        if(bytes>28000||hash==null||!hash.matches("[0-9a-f]{64}"))throw rejected("AI 전송 문맥 또는 입력 상한을 확인할 수 없습니다.");
        boolean mock="MOCK".equals(origin);
        if(!mock&&!available(origin,model))throw rejected("등록된 모델의 비용 상한을 확인할 수 없습니다.");
        Instant now=Instant.now(clock);attempts.removeIf(a->!a.at.isAfter(now.minusSeconds(86400)));
        String identity=project+"|"+hash+"|"+model+"|"+origin;
        if(active>=2||attempts.size()>=6000||attempts.stream().anyMatch(a->a.user==user&&a.identity.equals(identity)))throw rejected("중복 요청 또는 동시 요청 한도입니다. 자동 재시도하지 않습니다.");
        long userHourly=attempts.stream().filter(a->a.user==user&&a.at.isAfter(now.minusSeconds(3600))).count();
        long projectHourly=attempts.stream().filter(a->a.project==project&&a.at.isAfter(now.minusSeconds(3600))).count();
        // Reserve worst-case standard-token estimate; unknown/failed usage never refunds it.
        BigDecimal reserved=mock?BigDecimal.ZERO:new BigDecimal("0.033576");
        BigDecimal userBudget=attempts.stream().filter(a->a.user==user).map(Attempt::reserved).reduce(BigDecimal.ZERO,BigDecimal::add);
        BigDecimal projectBudget=attempts.stream().filter(a->a.project==project).map(Attempt::reserved).reduce(BigDecimal.ZERO,BigDecimal::add);
        if(userHourly>=6||projectHourly>=12||userBudget.add(reserved).compareTo(new BigDecimal(persistentExhibit?"0.50":"0.10"))>0||projectBudget.add(reserved).compareTo(new BigDecimal(persistentExhibit?"0.50":"0.20"))>0)throw rejected("AI 요청 횟수 또는 보수적 비용 예산 한도입니다.");
        attempts.add(new Attempt(user,project,identity,now,reserved));active++;return new Permit();
    }
    private SecureDeployException rejected(String message){return new SecureDeployException(HttpStatus.TOO_MANY_REQUESTS,message);}
}
