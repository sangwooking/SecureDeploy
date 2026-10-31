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
    public record Provider(String name,String model,boolean available,String origin) { }
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
    public Provider provider(){return describe(resolver.resolve());}
    public Provider provider(long review){plans.get(review);return provider();}
    private Provider describe(AiProvider selected){
        String origin=selected.executionOrigin();if(!Set.of("OPENAI","MOCK").contains(origin==null?"":origin))origin="UNVERIFIED_PROVIDER";
        boolean available=properties.getProvider()==AiProviderType.OPENAI&&selected.providerType()==AiProviderType.OPENAI&&selected.isAvailable();
        return new Provider("OPENAI",properties.getOpenai().getModel(),available,origin);
    }
    public View prepare(long review,Prepare input){
        var evidence=plans.get(review); // Authorize before retaining any data or resolving a provider.
        if(input==null||!Objects.equals(input.evidenceHash(),evidence.evidenceHash())||input.planIndex()<0||input.planIndex()>=evidence.plans().size())throw fail(HttpStatus.CONFLICT,"저장된 근거와 선택 항목이 일치하지 않습니다.");
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
        DependencyAiAdvice.Output output=null;String result="FAILED";
        try{
            selected.consumeLastTokenUsage();
            if("OPENAI".equals(current.origin())){
                if(reviewAccess==null)throw new IllegalStateException("Project ownership unavailable");
                var owned=reviewAccess.findAccessibleReviewWithVulnerabilities(review,"분석 결과에 접근할 수 없습니다.");
                try(var admission=AiAdmission.open(s.user,owned.getProject().getId(),s.id,"dependency_update_advice_v1",s.evidence.evidenceHash(),current.model(),s.prompt.instructions(),s.prompt.untrustedData())){output=selected.generateDependencyAdvice(s.prompt);}
            }else output=selected.generateDependencyAdvice(s.prompt);
            DependencyAiAdvice.validate(output,s.evidence,s.index);
            verifyEvidence(s);
            if(!current.equals(describe(selected)))throw new IllegalArgumentException();
            result=output.decision().equals("NEEDS_REVIEW")?"NEEDS_REVIEW":"GENERATED";
        }catch(IllegalArgumentException invalid){result="INVALID";}
        catch(RuntimeException unavailable){result="FAILED";}
        finally{
            try{var tokens=selected.consumeLastTokenUsage().orElse(new AiTokenUsage(0,0,0,true));usage.track(AiFeatureType.DEPENDENCY_UPDATE_ADVICE,selected.providerType(),null,null,tokens);}
            finally{capacity.release();synchronized(this){s.state=result;s.output=(result.equals("GENERATED")||result.equals("NEEDS_REVIEW"))?output:null;
                s.message=s.output==null?"응답 생성 또는 근거 검증에 실패했습니다. 원본 변경과 자동 재시도는 없습니다.":"구조·버전·참조 근거 검증을 통과한 AI 의견입니다. 실제 수정·호환성·보안 효과는 별도 검증이 필요합니다.";}}
        }
        return get(review,id);
    }
    private synchronized Session owned(long review,String id){var s=sessions.get(id);if(s==null||s.user!=users.currentUserId()||s.review!=review||!s.expires.isAfter(Instant.now()))throw fail(HttpStatus.NOT_FOUND,"제안을 찾을 수 없거나 만료되었습니다.");return s;}
    private void verifyEvidence(Session s){var current=plans.get(s.review);if(!current.evidenceHash().equals(s.evidence.evidenceHash())||!Objects.equals(current.sourceRevision(),s.evidence.sourceRevision()))throw fail(HttpStatus.CONFLICT,"원본 분석 근거가 변경되었습니다. 새 제안을 준비하세요.");}
    private static SecureDeployException fail(HttpStatus status,String message){return new SecureDeployException(status,message);}
}
