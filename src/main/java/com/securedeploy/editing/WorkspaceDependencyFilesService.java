package com.securedeploy.editing;
import com.securedeploy.ai.dependency.DependencyAiAdviceService;
import com.securedeploy.sca.service.DependencyUpdatePlanService;
import com.securedeploy.auth.service.CurrentUserService;
import com.securedeploy.global.error.SecureDeployException;
import java.time.*;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class WorkspaceDependencyFilesService {
    public record Prepare(long revision,String adviceId) { }
    public record Consent(String inputHash,boolean approved) { }
    public record View(String id,String state,long revision,String inputHash,String adviceId,String origin,String packageName,String fromVersion,String toVersion,boolean executionEnabled,List<EditingWorkspaceService.GeneratedDifference> differences,List<String> changedPackages,String message) { }
    private static final class Session {
        final String id=UUID.randomUUID().toString(),workspace,hash,advice,origin,name,from,to;final long user,revision,review;final boolean direct;final Instant expires=Instant.now().plusSeconds(900);
        String state="EXECUTION_APPROVAL_REQUIRED",message="원본 파일은 바뀌지 않았습니다. 공개 registry 조회와 스크립트 없는 npm 잠금 생성에 별도 동의가 필요합니다.";
        Map<String,byte[]> files=Map.of();List<EditingWorkspaceService.GeneratedDifference> differences=List.of();List<String> packages=List.of();
        Session(String workspace,long user,long revision,long review,String hash,DependencyAiAdviceService.View advice,boolean direct){this.workspace=workspace;this.user=user;this.revision=revision;this.review=review;this.hash=hash;this.advice=advice.id();this.origin=advice.provider().origin();this.name=advice.output().packageName();this.from=advice.output().lockedVersion();this.to=advice.output().candidateVersion();this.direct=direct;}
    }
    private final EditingWorkspaceService workspaces;private final DependencyAiAdviceService advice;private final DependencyUpdatePlanService plans;private final NpmUpdateGenerator generator;private final CurrentUserService users;
    private final Map<String,Session> sessions=new LinkedHashMap<>();
    public WorkspaceDependencyFilesService(EditingWorkspaceService workspaces,DependencyAiAdviceService advice,DependencyUpdatePlanService plans,NpmUpdateGenerator generator,CurrentUserService users){this.workspaces=workspaces;this.advice=advice;this.plans=plans;this.generator=generator;this.users=users;}
    public View prepare(String workspace,Prepare request){
        try(var input=workspaces.captureScan(workspace,request.revision())){
            if(!input.provenance().baselineVerified()||input.provenance().files().stream().anyMatch(WorkspaceScanSnapshot.File::changed))throw fail(HttpStatus.CONFLICT,"원본과 일치하는 변경 없는 작업 공간만 지원합니다.");
            long review=input.provenance().originalReviewId();var proposal=advice.get(review,request.adviceId());if(!"GENERATED".equals(proposal.state())||proposal.output()==null||!"PROPOSE_UPDATE".equals(proposal.output().decision()))throw fail(HttpStatus.UNPROCESSABLE_ENTITY,"검증된 버전 제안이 필요합니다.");
            var plan=plans.get(review).plans().get(proposal.planIndex());if(!Set.of("DIRECT","TRANSITIVE").contains(plan.dependencyKind()))throw fail(HttpStatus.UNPROCESSABLE_ENTITY,"직접·간접 경로가 혼재하거나 미확인입니다.");
            if(input.entries().stream().anyMatch(e->Set.of(".npmrc","npm-shrinkwrap.json","pnpm-lock.yaml","yarn.lock").contains(e.path())))throw fail(HttpStatus.UNPROCESSABLE_ENTITY,"다른 패키지 관리자 또는 프로젝트 설정이 있습니다.");
            var s=new Session(workspace,users.currentUserId(),request.revision(),review,input.provenance().inputHash(),proposal,plan.dependencyKind().equals("DIRECT"));
            synchronized(this){sessions.values().removeIf(v->{if(v.expires.isBefore(Instant.now())&&!v.state.equals("GENERATING")){v.files.values().forEach(b->Arrays.fill(b,(byte)0));return true;}return false;});if(sessions.size()>=64||sessions.values().stream().filter(v->v.user==s.user).count()>=3)throw fail(HttpStatus.TOO_MANY_REQUESTS,"생성 제안 준비 한도입니다.");sessions.put(s.id,s);}
            return view(s);
        }
    }
    public View get(String workspace,String id){return view(owned(workspace,id));}
    public View generate(String workspace,String id,Consent consent){
        var s=owned(workspace,id);if(!generator.enabled())throw fail(HttpStatus.SERVICE_UNAVAILABLE,"npm 파일 생성은 비활성화되어 있습니다.");
        if(consent==null||!consent.approved()||!s.hash.equals(consent.inputHash()))throw fail(HttpStatus.CONFLICT,"네트워크·패키지 관리자 실행 동의가 필요합니다.");
        synchronized(this){if(!s.state.equals("EXECUTION_APPROVAL_REQUIRED"))throw fail(HttpStatus.CONFLICT,"이미 사용한 생성 요청입니다.");s.state="GENERATING";}
        try(var input=workspaces.captureScan(workspace,s.revision)){
            if(!input.provenance().inputHash().equals(s.hash))throw new IllegalArgumentException();advice.get(s.review,s.advice);
            var manifest=input.entries().stream().filter(e->e.path().equals("package.json")).findFirst().orElseThrow();var lock=input.entries().stream().filter(e->e.path().equals("package-lock.json")).findFirst().orElseThrow();
            var result=generator.generate(manifest.bytes(),lock.bytes(),s.name,s.from,s.to,s.direct);
            var replacements=Map.of("package.json",result.manifest(),"package-lock.json",result.lockfile());
            var diffs=workspaces.generatedDifferences(workspace,s.revision,s.hash,replacements);
            synchronized(this){s.files=replacements;s.differences=diffs;s.packages=result.changedPackages();s.state="PROPOSED";s.message="npm 생성 결과와 변경 범위를 검증했습니다. 승인 전 Workspace 파일은 바뀌지 않습니다. 호환성은 NOT_VERIFIED입니다.";}
        }catch(Exception e){synchronized(this){s.state="FAILED";s.message="생성·계약·원본 검증에 실패했습니다. 원본 변경과 자동 재시도는 없습니다.";}}
        return get(workspace,id);
    }
    public EditingWorkspaceService.Workspace apply(String workspace,String id,Consent consent){
        var s=owned(workspace,id);synchronized(this){if(!s.state.equals("PROPOSED")||consent==null||!consent.approved()||!s.hash.equals(consent.inputHash()))throw fail(HttpStatus.CONFLICT,"Diff 확인과 적용 승인이 필요합니다.");
            advice.get(s.review,s.advice);var result=workspaces.applyGenerated(workspace,s.revision,s.hash,s.files,s.origin,s.advice);s.state="ACCEPTED";s.files.values().forEach(b->Arrays.fill(b,(byte)0));s.files=Map.of();return result;}
    }
    @jakarta.annotation.PreDestroy public synchronized void clear(){sessions.values().forEach(s->s.files.values().forEach(b->Arrays.fill(b,(byte)0)));sessions.clear();}
    private Session owned(String workspace,String id){workspaces.get(workspace);synchronized(this){var s=sessions.get(id);if(s==null||s.user!=users.currentUserId()||!s.workspace.equals(workspace)||s.expires.isBefore(Instant.now()))throw fail(HttpStatus.NOT_FOUND,"생성 제안이 없거나 만료되었습니다.");return s;}}
    private synchronized View view(Session s){return new View(s.id,s.state,s.revision,s.hash,s.advice,s.origin,s.name,s.from,s.to,generator.enabled(),s.differences,s.packages,s.message);}
    private static SecureDeployException fail(HttpStatus s,String m){return new SecureDeployException(s,m);}
}
