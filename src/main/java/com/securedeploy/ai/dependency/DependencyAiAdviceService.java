package com.securedeploy.ai.dependency;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.ai.config.*;
import com.securedeploy.ai.service.*;
import com.securedeploy.ai.usage.*;
import com.securedeploy.ai.dto.AiFeatureType;
import com.securedeploy.auth.service.CurrentUserService;
import com.securedeploy.editing.WorkspacePatch;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.sca.service.DependencyUpdatePlanService;
import java.time.*;
import java.util.*;
import java.util.concurrent.Semaphore;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class DependencyAiAdviceService {
    public record Prepare(String evidenceHash,int planIndex) { }
    public record Consent(String evidenceHash,boolean approved) { }
    public record Provider(String name,String model,boolean available,String origin,String unavailableReason) { }
    public record View(String id,long reviewId,int planIndex,String evidenceHash,String state,Provider provider,
                       String transmittedData,DependencyAiAdvice.Output output,String message,String reviewStatus,
                       String compatibility,boolean patchApplicable,String modelQuality,Instant expiresAt) { }
    private static final class Session {
        final String id=UUID.randomUUID().toString();final long user,review;final int index;
        final DependencyUpdatePlanService.Snapshot evidence;final WorkspacePatch.Prompt prompt;final Provider provider;final Instant expires;
        String state="APPROVAL_REQUIRED",message="표시된 공개 메타데이터만 전송합니다. 소스·경로·프로젝트명은 전송하지 않습니다.";
        DependencyAiAdvice.Output output;
        Session(long user,DependencyUpdatePlanService.Snapshot evidence,int index,WorkspacePatch.Prompt prompt,Provider provider,Instant now){
            this.user=user;this.review=evidence.reviewId();this.evidence=evidence;this.index=index;this.prompt=prompt;this.provider=provider;this.expires=now.plusSeconds(900);
        }
        View view(){return new View(id,review,index,evidence.evidenceHash(),state,provider,prompt.untrustedData(),output,message,"REVIEW_REQUIRED","NOT_VERIFIED",false,"NOT_VERIFIED",expires);}
    }
    private final DependencyUpdatePlanService plans;private final CurrentUserService users;private final AiProviderResolver resolver;
    private final AiProperties properties;private final ObjectMapper mapper;private final AiUsageTracker usage;
    private final Map<String,Session> sessions=new LinkedHashMap<>();private final Map<Long,Deque<Instant>> calls=new HashMap<>();
    private final Semaphore capacity=new Semaphore(2);
    public DependencyAiAdviceService(DependencyUpdatePlanService plans,CurrentUserService users,AiProviderResolver resolver,AiProperties properties,ObjectMapper mapper,AiUsageTracker usage){
        this.plans=plans;this.users=users;this.resolver=resolver;this.properties=properties;this.mapper=mapper;this.usage=usage;
    }
    private com.securedeploy.auth.service.ReviewAccessService reviewAccess;
    @org.springframework.beans.factory.annotation.Autowired
    void configureReviewAccess(com.securedeploy.auth.service.ReviewAccessService access){reviewAccess=access;}
    private boolean workspaceOnly;
    @org.springframework.beans.factory.annotation.Autowired
    void configureScope(
            @org.springframework.beans.factory.annotation.Value("${securedeploy.ai.main-cutover.control-file:}") String main,
            @org.springframework.beans.factory.annotation.Value("${securedeploy.ai.exhibit.control-file:}") String exhibit) {
        workspaceOnly=!main.isBlank()||!exhibit.isBlank();
    }
    public Provider provider(){return describe(resolver.resolve());}
    public Provider provider(long review){plans.get(review);return provider();}
    private Provider describe(AiProvider selected){
        String origin=selected.executionOrigin();if(!Set.of("OPENAI","MOCK").contains(origin==null?"":origin))origin="UNVERIFIED_PROVIDER";
        boolean available=properties.getProvider()==AiProviderType.OPENAI&&selected.providerType()==AiProviderType.OPENAI&&selected.isAvailable()&&!(workspaceOnly&&"OPENAI".equals(origin));
        return new Provider("OPENAI",properties.getOpenai().getModel(),available,origin,
                workspaceOnly&&"OPENAI".equals(origin)?"WORKSPACE_ONLY":null);
    }
    public View prepare(long review,Prepare input){
        var evidence=plans.get(review); // Authorize before retaining any data or resolving a provider.
        if(input==null||!Objects.equals(input.evidenceHash(),evidence.evidenceHash())||input.planIndex()<0||input.planIndex()>=evidence.plans().size())throw fail(HttpStatus.CONFLICT,"저장된 근거와 선택 항목이 일치하지 않습니다.");
        if(workspaceOnly&&"OPENAI".equals(provider().origin()))
            throw fail(HttpStatus.FORBIDDEN,"현재 실제 AI 호출은 승인된 코드 수정에만 허용됩니다. 라이브러리 업데이트는 저장된 공지와 수동 검토를 이용하세요.");
        WorkspacePatch.Prompt prompt;
        try{prompt=DependencyAiAdvice.prompt(evidence,input.planIndex(),mapper);}catch(RuntimeException e){throw fail(HttpStatus.UNPROCESSABLE_ENTITY,"검증된 npm 수정 후보와 선언 경로가 있는 항목만 지원합니다.");}
        synchronized(this){
            Instant now=Instant.now();sessions.values().removeIf(s->!s.expires.isAfter(now)&&!s.state.equals("GENERATING"));
            long user=users.currentUserId();if(sessions.size()>=128||sessions.values().stream().filter(s->s.user==user).count()>=6)throw fail(HttpStatus.TOO_MANY_REQUESTS,"제안 준비 한도에 도달했습니다. 만료 후 다시 확인하세요.");
            var s=new Session(user,evidence,input.planIndex(),prompt,provider(),now);sessions.put(s.id,s);return s.view();
        }
    }
    public View get(long review,String id){var s=owned(review,id);verifyEvidence(s);synchronized(this){return s.view();}}
    public View generate(long review,String id,Consent consent){
        var s=owned(review,id);verifyEvidence(s);var selected=resolver.resolve();var current=describe(selected);
        if(!current.available())throw fail(HttpStatus.SERVICE_UNAVAILABLE,"AI Provider가 비활성화되어 있습니다. 근거 기반 안내를 사용하세요.");
        synchronized(this){
            if(!s.state.equals("APPROVAL_REQUIRED")||consent==null||!consent.approved()||!s.evidence.evidenceHash().equals(consent.evidenceHash())||!s.provider.equals(current))throw fail(HttpStatus.CONFLICT,"전송 동의·근거·Provider가 일치하지 않거나 이미 사용한 요청입니다.");
            Instant now=Instant.now();calls.values().forEach(q->{while(!q.isEmpty()&&q.peekFirst().isBefore(now.minusSeconds(3600)))q.removeFirst();});calls.entrySet().removeIf(e->e.getValue().isEmpty());
            if(!calls.containsKey(s.user)&&calls.size()>=1000)throw fail(HttpStatus.TOO_MANY_REQUESTS,"요청 한도에 도달했습니다.");
            var times=calls.computeIfAbsent(s.user,k->new ArrayDeque<>());
            if(times.size()>=6||(!times.isEmpty()&&times.peekLast().isAfter(now.minusSeconds(10)))||!capacity.tryAcquire())throw fail(HttpStatus.TOO_MANY_REQUESTS,"요청은 10초 간격·시간당 6회이며 동시 요청은 제한됩니다.");
            times.addLast(now);s.state="GENERATING";s.message="동의한 메타데이터로 수정 방향을 생성 중입니다. 파일 변경은 없습니다.";
        }
        DependencyAiAdvice.Output output=null;String result="FAILED";String reason=null;boolean attempted=false;
        try{
            selected.consumeLastTokenUsage();
            attempted=true;
            if("OPENAI".equals(current.origin())){
                if(reviewAccess==null)throw new IllegalStateException("Project ownership unavailable");
                var owned=reviewAccess.findAccessibleReviewWithVulnerabilities(review,"분석 결과에 접근할 수 없습니다.");
                try(var admission=AiAdmission.open(s.user,owned.getProject().getId(),s.id,"dependency_update_advice_v1",s.evidence.evidenceHash(),current.model(),s.prompt.instructions(),s.prompt.untrustedData())){output=selected.generateDependencyAdvice(s.prompt);}
            }else output=selected.generateDependencyAdvice(s.prompt);
            try { DependencyAiAdvice.validate(output,s.evidence,s.index); }
            catch(IllegalArgumentException mismatch) { reason="EVIDENCE_MISMATCH";throw mismatch; }
            verifyEvidence(s);
            if(!current.equals(describe(selected)))throw new IllegalArgumentException();
            result=output.decision().equals("NEEDS_REVIEW")?"NEEDS_REVIEW":"GENERATED";
        }catch(com.securedeploy.ai.service.AiProviderFailure failure){
            attempted=failure.requestAttempted();
            reason=failure.kind().name();
            result=switch(failure.kind()){
                case REFUSED,INCOMPLETE -> "NEEDS_REVIEW";
                case INVALID_RESPONSE -> "INVALID";
                default -> "FAILED";
            };
        }catch(IllegalArgumentException invalid){result="INVALID";if(reason==null)reason="INVALID_RESPONSE";}
        catch(SecureDeployException stale){result="INVALID";reason="EVIDENCE_MISMATCH";}
        catch(RuntimeException unavailable){result="FAILED";}
        finally{
            try{var tokens=selected.consumeLastTokenUsage().orElse(new AiTokenUsage(0,0,0,attempted));usage.track(AiFeatureType.DEPENDENCY_UPDATE_ADVICE,selected.providerType(),null,null,tokens);}
            finally{capacity.release();synchronized(this){s.state=result;s.output=(result.equals("GENERATED")||result.equals("NEEDS_REVIEW"))?output:null;
                s.message=s.output==null?failureMessage(reason):"구조·버전·참조 근거 검증을 통과한 AI 의견입니다. 실제 수정·호환성·보안 효과는 별도 검증이 필요합니다.";}}
        }
        return get(review,id);
    }
    static String failureMessage(String reason){
        return switch(reason==null?"UNKNOWN":reason){
            case "NOT_SENT" -> "외부 요청 전에 정책 또는 원장 검사가 중단했습니다. 승인 범위와 원장 상태를 확인하세요.";
            case "REFUSED" -> "모델이 요청을 거부했습니다. 저장된 공지의 수정 후보를 검토하세요.";
            case "INCOMPLETE" -> "모델 응답이 불완전합니다. 적용할 수정안이 없습니다.";
            case "INVALID_RESPONSE" -> "모델 응답 형식이 계약과 일치하지 않습니다. 응답을 수정안으로 사용하지 않았습니다.";
            case "EVIDENCE_MISMATCH" -> "응답의 버전·공지·근거 또는 분석 상태가 확인된 계약과 일치하지 않습니다. 저장된 공지와 의존성 경로를 확인하세요.";
            case "HTTP_ERROR" -> "AI API 요청에 오류가 발생했습니다. Provider 상태를 확인하고 기존 근거로 검토하세요.";
            case "TIMEOUT" -> "AI 응답 제한 시간을 초과했습니다. 외부 처리와 비용은 원장에서 확인하세요.";
            case "EXHIBIT_COUNT_LIMIT","EXHIBIT_BUDGET_LIMIT" -> "AI 호출 횟수 또는 예약 비용 한도에 도달했습니다. 남은 한도를 확인하세요.";
            default -> "AI 제안을 생성하지 못했습니다. 원본 변경과 자동 재시도는 없습니다.";
        };
    }
    private synchronized Session owned(long review,String id){var s=sessions.get(id);if(s==null||s.user!=users.currentUserId()||s.review!=review||!s.expires.isAfter(Instant.now()))throw fail(HttpStatus.NOT_FOUND,"제안을 찾을 수 없거나 만료되었습니다.");return s;}
    private void verifyEvidence(Session s){var current=plans.get(s.review);if(!current.evidenceHash().equals(s.evidence.evidenceHash())||!Objects.equals(current.sourceRevision(),s.evidence.sourceRevision()))throw fail(HttpStatus.CONFLICT,"원본 분석 근거가 변경되었습니다. 새 제안을 준비하세요.");}
    private static SecureDeployException fail(HttpStatus status,String message){return new SecureDeployException(status,message);}
}
