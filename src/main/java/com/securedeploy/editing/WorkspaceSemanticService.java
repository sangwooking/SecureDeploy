package com.securedeploy.editing;
import com.securedeploy.ai.semantic.*;
import com.securedeploy.ai.service.AiProviderResolver;
import com.securedeploy.ai.config.*;
import com.securedeploy.auth.service.CurrentUserService;
import com.securedeploy.persistence.service.ReviewPersistenceService;
import com.securedeploy.review.model.ScanMode;
import com.securedeploy.global.error.SecureDeployException;
import java.time.*;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class WorkspaceSemanticService {
    public record Request(long revision) { }
    public record Consent(String inputHash,boolean approved) { }
    public record View(String id,String state,String inputHash,long revision,String origin,boolean available,
                       String model,String transmittedData,int selectedContexts,int omittedContexts,SemanticSnapshot result,List<String> limitations) { }
    private static final class Session {
        final String id=UUID.randomUUID().toString(),workspace,hash,payload,origin,model;final long user,revision,review;final Instant expires=Instant.now().plusSeconds(900);
        final SecuritySliceCollector.Collection collection;int selected,omitted;String state="APPROVAL_REQUIRED";SemanticSnapshot result;
        Session(String workspace,long user,long revision,long review,String hash,String payload,String origin,String model,SecuritySliceCollector.Collection collection){this.workspace=workspace;this.user=user;this.revision=revision;this.review=review;this.hash=hash;this.payload=payload;this.origin=origin;this.model=model;this.collection=collection;}
    }
    private final EditingWorkspaceService workspaces;private final ReviewPersistenceService reviews;private final CurrentUserService users;private final TypeScriptSemanticContextSelector selector;private final SemanticReviewService semantic;private final AiProviderResolver resolver;private final AiProperties properties;
    private final Map<String,Session> sessions=new LinkedHashMap<>();private final Map<Long,Instant> last=new HashMap<>();
    public WorkspaceSemanticService(EditingWorkspaceService workspaces,ReviewPersistenceService reviews,CurrentUserService users,TypeScriptSemanticContextSelector selector,SemanticReviewService semantic,AiProviderResolver resolver,AiProperties properties){this.workspaces=workspaces;this.reviews=reviews;this.users=users;this.selector=selector;this.semantic=semantic;this.resolver=resolver;this.properties=properties;}
    public View prepare(String id,Request request){
        try(var input=workspaces.captureScan(id,request.revision())){
            if(!input.provenance().baselineVerified()||input.provenance().files().stream().anyMatch(WorkspaceScanSnapshot.File::changed))throw fail(HttpStatus.CONFLICT,"원본 commit과 일치하는 변경 없는 작업 공간만 지원합니다.");
            var review=reviews.findReviewDetail(input.provenance().originalReviewId(),users.currentUserId());
            var parsed=review.serverAnalysis()==null||review.serverAnalysis().files()==null?java.util.Set.<String>of():review.serverAnalysis().files().stream().filter(f->f.parseStatus().equals("PARSED")).map(f->f.filePath()).collect(java.util.stream.Collectors.toSet());
            var sources=input.entries().stream().filter(e->parsed.contains(e.path())).limit(100).filter(e->e.path().matches(".*\\.(?:[cm]?[jt]sx?)")).map(e->new TypeScriptSemanticContextSelector.Source(e.path(),SourceArchive.text(e.bytes()),SourceArchive.hash(e.bytes()))).toList();
            var collection=selector.select(review.serverAnalysis(),sources);var prepared=semantic.prepare(review,collection);
            var selected=resolver.resolve();var s=new Session(id,users.currentUserId(),request.revision(),review.reviewId(),input.provenance().inputHash(),prepared.prompt()==null?"":prepared.prompt().untrustedData(),origin(),properties.getOpenai().getModel(),collection);
            s.selected=prepared.slices().size();s.omitted=prepared.omitted();
            if(prepared.prompt()==null)s.state="NO_SUPPORTED_CONTEXT";
            synchronized(this){sessions.values().removeIf(v->v.expires.isBefore(Instant.now())&&!v.state.equals("GENERATING"));if(sessions.size()>=128||sessions.values().stream().filter(v->v.user==s.user).count()>=6)throw fail(HttpStatus.TOO_MANY_REQUESTS,"검토 준비 한도입니다.");sessions.put(s.id,s);}
            return view(s);
        }
    }
    public View get(String workspace,String id){return view(owned(workspace,id));}
    public View generate(String workspace,String id,Consent consent){
        var s=owned(workspace,id);if(!available())throw fail(HttpStatus.SERVICE_UNAVAILABLE,"AI Provider가 비활성화되어 있습니다.");
        try(var input=workspaces.captureScan(workspace,s.revision)){
            if(!input.provenance().inputHash().equals(s.hash)||!origin().equals(s.origin)||!properties.getOpenai().getModel().equals(s.model))throw fail(HttpStatus.CONFLICT,"원본·Provider가 변경되었습니다.");
        }
        synchronized(this){if(!s.state.equals("APPROVAL_REQUIRED")||consent==null||!consent.approved()||!s.hash.equals(consent.inputHash()))throw fail(HttpStatus.CONFLICT,"일회용 전송 동의가 필요합니다.");
            Instant now=Instant.now();last.entrySet().removeIf(e->e.getValue().isBefore(now.minusSeconds(3600)));if(last.size()>=1000||last.getOrDefault(s.user,Instant.EPOCH).isAfter(now.minusSeconds(60)))throw fail(HttpStatus.TOO_MANY_REQUESTS,"추가 검토 요청은 1분 간격입니다.");last.put(s.user,now);s.state="GENERATING";}
        try{var review=reviews.findReviewDetail(s.review,s.user);var prepared=semantic.prepare(review,s.collection);if(prepared.prompt()==null||!prepared.prompt().untrustedData().equals(s.payload))throw new IllegalArgumentException();
            SemanticSnapshot result;
            try(var admission=com.securedeploy.ai.usage.AiAdmission.open(s.user,workspaces.projectId(workspace),s.id,"semantic_review",s.hash,s.model,prepared.prompt().instructions(),prepared.prompt().untrustedData())){
                result=semantic.generate(review,ScanMode.AI_ENHANCED,s.collection);
            }
            try(var input=workspaces.captureScan(workspace,s.revision)){if(!input.provenance().inputHash().equals(s.hash))throw new IllegalArgumentException();}
            synchronized(this){s.result=label(result,s.origin);s.state=result.semanticReviewStatus().name();}
        }catch(RuntimeException e){synchronized(this){s.state="FAILED";s.result=null;}}
        return get(workspace,id);
    }
    private SemanticSnapshot label(SemanticSnapshot r,String origin){
        if(origin.equals("OPENAI"))return r;
        String provider=origin.equals("MOCK")?"mock":"unverified";
        java.util.function.Function<SemanticCandidate,SemanticCandidate> copy=c->new SemanticCandidate(c.candidateId(),c.sliceId(),c.candidateType(),c.title(),c.semanticAnalysisConfidence(),c.reason(),c.verificationRequired(),c.evidence(),c.verificationSteps(),c.relatedExistingFindingIds(),c.generatedAt(),provider,c.model(),c.promptVersion());
        return new SemanticSnapshot(r.schemaVersion(),r.snapshotId(),r.scanMode(),r.semanticReviewStatus(),r.candidates().stream().map(copy).toList(),r.existingFindingEvidence().stream().map(copy).toList(),r.slices(),r.semanticSlicesAnalyzed(),r.omittedSlices(),r.rejectedCandidates(),r.deduplicatedCandidates(),r.validationStatus(),provider,r.model(),r.promptVersion(),r.generatedAt(),r.requestCount(),r.usage(),r.notices());
    }
    private Session owned(String workspace,String id){workspaces.get(workspace);synchronized(this){var s=sessions.get(id);if(s==null||s.user!=users.currentUserId()||!s.workspace.equals(workspace)||s.expires.isBefore(Instant.now()))throw fail(HttpStatus.NOT_FOUND,"검토 요청이 없거나 만료되었습니다.");return s;}}
    private boolean available(){var p=resolver.resolve();return properties.getProvider()==AiProviderType.OPENAI&&p.providerType()==AiProviderType.OPENAI&&p.isAvailable();}
    private String origin(){var value=resolver.resolve().executionOrigin();return value==null?"UNVERIFIED_PROVIDER":value;}
    private synchronized View view(Session s){return new View(s.id,s.state,s.hash,s.revision,s.origin,available(),s.model,s.payload,s.selected,s.omitted,s.result,List.of("AI_SECURITY_CANDIDATE / REVIEW_REQUIRED · 확정 취약점·점수·위험 평가에 합산하지 않습니다.","등록된 Express handler와 최대 두 개의 같은 파일 직접 호출 함수를 선별합니다. 파일 간 호출과 실행 경로는 미검증입니다. 다른 UNKNOWN·전체 프로젝트는 검토하지 않습니다.","문자열·정규식·주석을 제거했습니다. 원본 문맥 손실·미확인 사항이 남습니다."));}
    private static SecureDeployException fail(HttpStatus s,String m){return new SecureDeployException(s,m);}
}
