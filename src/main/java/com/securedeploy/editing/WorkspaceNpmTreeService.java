package com.securedeploy.editing;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.auth.service.ReviewAccessService;
import com.securedeploy.sca.client.VulnerabilityDataSource;
import com.securedeploy.sca.model.*;
import com.securedeploy.sca.service.DependencyUpdatePlanService;
import java.time.*;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.*;
import org.springframework.http.HttpStatus;

/** Deterministic dependency repair. No model. A failed/partial plan cannot be applied. */
@Service
public class WorkspaceNpmTreeService {
    public record Prepare(long revision,int planIndex){}
    public record Consent(String inputHash,boolean approved){}
    public record Attempt(String root,String version,String outcome){}
    public record View(String id,String state,long revision,String inputHash,String origin,String packageName,String lockedVersion,
            String rootPackage,String fromRootVersion,String declaredRange,Boolean withinDeclaredRange,String candidateVersion,List<String> affectedPaths,List<String> remainingPaths,
            Integer beforeAdvisoryItems,Integer afterAdvisoryItems,List<Attempt> attempts,List<EditingWorkspaceService.GeneratedDifference> differences,
            String evidenceHash,String npmVersion,String nodeVersion,String compatibility,String message,String executionId){}
    private static class Session {
        String execution;String id=UUID.randomUUID().toString(),workspace,hash,state="EXECUTION_CONSENT_REQUIRED",name,version,root,from,range,to,evidence,npm,node,message="공개 registry 조회와 스크립트 없는 npm 실행에 동의한 뒤 수정안을 만듭니다.";
        long user,revision,review;Instant expires=Instant.now().plusSeconds(900);List<String> paths=List.of(),remaining=List.of();List<Attempt> attempts=new ArrayList<>();List<EditingWorkspaceService.GeneratedDifference> differences=List.of();Map<String,byte[]> files=Map.of();Integer before,after;boolean partial;
    }
    private final EditingWorkspaceService workspaces;private final DependencyUpdatePlanService plans;private final ReviewAccessService access;private final NpmRegistry registry;private final NpmTreeExecutor npm;private final VulnerabilityDataSource osv;private final ObjectMapper json;private final Environment environment;private final boolean configured;
    private final Map<String,Session> sessions=new LinkedHashMap<>();private final java.util.concurrent.Semaphore capacity=new java.util.concurrent.Semaphore(1);
    public WorkspaceNpmTreeService(EditingWorkspaceService workspaces,DependencyUpdatePlanService plans,ReviewAccessService access,NpmRegistry registry,NpmTreeExecutor npm,VulnerabilityDataSource osv,ObjectMapper json,Environment environment,@Value("${securedeploy.editing.npm-tree-plans-enabled:false}")boolean enabled){this.workspaces=workspaces;this.plans=plans;this.access=access;this.registry=registry;this.npm=npm;this.osv=osv;this.json=json;this.environment=environment;this.configured=enabled;}
    public boolean executionAvailable(){return npm.available();}
    public boolean enabled(){return configured&&npm.available()&&environment.getProperty("securedeploy.editing.automation-enabled",Boolean.class,true)&&!environment.acceptsProfiles(Profiles.of("release-compatible","release-recovery"));}
    public View prepare(String workspace,Prepare request){
        workspaces.get(workspace);if(request==null||request.revision()<1||request.planIndex()<0)throw fail(HttpStatus.BAD_REQUEST,"올바른 수정본 revision과 저장된 공지 선택이 필요합니다.");
        if(!enabled())throw fail(HttpStatus.SERVICE_UNAVAILABLE,"안전한 실행 환경을 사용할 수 없어 자동 npm 생성을 중단했습니다. 기존 분석 근거와 수동 수정을 이용하세요.");
        try(var input=workspaces.captureScan(workspace,request.revision())){
            if(!input.provenance().baselineVerified()||input.provenance().files().stream().anyMatch(WorkspaceScanSnapshot.File::changed))throw fail(HttpStatus.CONFLICT,"검증된 원본과 일치하는 변경 없는 Workspace가 필요합니다.");
            var snapshot=plans.get(input.provenance().originalReviewId());if(request.planIndex()<0||request.planIndex()>=snapshot.plans().size())throw fail(HttpStatus.UNPROCESSABLE_ENTITY,"저장된 공지 계획을 선택하세요.");var selected=snapshot.plans().get(request.planIndex());
            if(!selected.ecosystem().equals("NPM"))throw fail(HttpStatus.UNPROCESSABLE_ENTITY,"npm v3 잠금 파일만 지원합니다.");
            var s=new Session();s.workspace=workspace;s.user=input.userId();s.review=input.provenance().originalReviewId();s.revision=request.revision();s.hash=input.provenance().inputHash();s.name=selected.packageName();s.version=selected.lockedVersion();
            try{var parsed=parseInput(input.entries());var target=NpmTreePlanner.target(parsed,s.name,s.version);s.root=target.root();s.from=target.rootVersion();s.range=target.declaredRange();s.paths=target.paths();s.remaining=s.paths;}catch(Exception unsupported){s.state="MANUAL_REVIEW";s.message="자동 수정 지원 범위를 확인하지 못했습니다: "+reason(unsupported)+". 상위 선언과 잠금 경로를 확인해 수동으로 수정하세요.";}
            synchronized(this){cleanup();if(sessions.size()>=32)throw fail(HttpStatus.TOO_MANY_REQUESTS,"수정안 준비 한도입니다.");sessions.put(s.id,s);}return view(s);
        }
    }
    private NpmTreePlanner.Input parseInput(List<SourceArchive.Entry> entries)throws Exception{
        for(var e:entries)if(!e.directory()&&(Set.of(".npmrc","yarn.lock","pnpm-lock.yaml","npm-shrinkwrap.json").contains(e.path().substring(e.path().lastIndexOf('/')+1))||e.path().contains("/")&&(e.path().endsWith("/package.json")||e.path().endsWith("/package-lock.json"))))throw new IllegalArgumentException("OTHER_MANAGER_OR_NESTED_PROJECT");
        return NpmTreePlanner.read(json,entry(entries,"package.json"),entry(entries,"package-lock.json"));
    }
    private byte[] entry(List<SourceArchive.Entry> entries,String name){return entries.stream().filter(e->e.path().equals(name)&&!e.directory()).findFirst().orElseThrow(()->new IllegalArgumentException("ROOT_MANIFEST_REQUIRED")).bytes();}
    public View get(String workspace,String id){return view(owned(workspace,id));}
    public View generate(String workspace,String id,Consent consent){
        var s=owned(workspace,id);if(!enabled())throw fail(HttpStatus.SERVICE_UNAVAILABLE,"의존성 자동 수정 비활성 상태입니다.");if(consent==null||!consent.approved()||!s.hash.equals(consent.inputHash()))throw fail(HttpStatus.CONFLICT,"전송 범위·npm 실행 동의가 필요합니다.");
        if(!capacity.tryAcquire())throw fail(HttpStatus.TOO_MANY_REQUESTS,"다른 의존성 계획을 검증 중입니다.");
        try{ synchronized(this){if(!s.state.equals("EXECUTION_CONSENT_REQUIRED"))throw fail(HttpStatus.CONFLICT,"이미 사용했거나 지원되지 않는 계획입니다.");s.state="GENERATING";}
            try(var input=workspaces.captureScan(workspace,s.revision)){
                if(!s.hash.equals(input.provenance().inputHash()))throw new IllegalArgumentException("INPUT_HASH_CHANGED");var before=parseInput(input.entries());var target=NpmTreePlanner.target(before,s.name,s.version);
                var review=access.findAccessibleReviewWithVulnerabilities(s.review,"분석 결과에 접근할 수 없습니다.");var original=review.getScaResult();if(original==null||original.dependencyVulnerabilities().stream().noneMatch(f->f.packageName().equals(s.name)&&f.installedVersion().equals(s.version)))throw new IllegalArgumentException("SAVED_TARGET_EVIDENCE_MISSING");
                var releases=registry.releases(target.root(),target.rootVersion());int generated=0;long end=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(100);var cache=new HashMap<String,JsonNode>();
                for(var release:releases){if(System.nanoTime()>end||generated>=3){s.attempts.add(new Attempt(s.root,null,"SEARCH_LIMIT_REVIEW_REQUIRED"));break;}String candidate=release.path("version").asText();
                    if(knownOldLeaf(release,target,cache)){s.attempts.add(new Attempt(s.root,candidate,"KNOWN_OLD_TARGET_REMAINS"));continue;}
                    generated++;NpmTreeExecutor.Output output=null;
                    try{output=npm.generate(entry(input.entries(),"package.json"),entry(input.entries(),"package-lock.json"),target.section(),target.root(),candidate);var after=NpmTreePlanner.read(json,output.manifest(),output.lockfile());NpmTreePlanner.validateGraph(before,after,target,candidate);
                        var root=after.lock().path("packages").path("node_modules/"+target.root());if(!root.path("version").asText().equals(candidate)||!root.path("integrity").asText().equals(release.at("/dist/integrity").asText())||!root.path("resolved").asText().equals(release.at("/dist/tarball").asText()))throw new IllegalArgumentException("ROOT_REGISTRY_IDENTITY");
                        for(String section:List.of("dependencies","optionalDependencies","peerDependencies","engines"))if(!Objects.equals(root.get(section),release.get(section)))throw new IllegalArgumentException("ROOT_REGISTRY_CONTRACT_CHANGED");
                        var union=new ArrayList<>(before.components());union.addAll(after.components());var facts=osv.lookup(union);var required=union.stream().map(DependencyComponent::identity).collect(java.util.stream.Collectors.toSet());if(facts.incomplete()||!facts.analyzedIdentities().containsAll(required))throw new IllegalArgumentException("OSV_PARTIAL_UNKNOWN");
                        Set<String> oldIds=before.components().stream().map(DependencyComponent::identity).collect(java.util.stream.Collectors.toSet()),newIds=after.components().stream().map(DependencyComponent::identity).collect(java.util.stream.Collectors.toSet());var oldFindings=facts.findings().stream().filter(f->oldIds.contains(identity(f))).toList();var newFindings=facts.findings().stream().filter(f->newIds.contains(identity(f))).toList();
                        if(oldFindings.stream().noneMatch(f->f.packageName().equals(s.name)&&f.installedVersion().equals(s.version)))throw new IllegalArgumentException("TARGET_EVIDENCE_CHANGED");
                        s.before=oldFindings.size();s.after=newFindings.size();Set<String> previous=oldFindings.stream().map(f->identity(f)+"|"+f.osvId()).collect(java.util.stream.Collectors.toSet());
                        if(newFindings.stream().anyMatch(f->!previous.contains(identity(f)+"|"+f.osvId())))throw new IllegalArgumentException("NEW_ADVISORY_INTRODUCED");if(newFindings.stream().anyMatch(f->f.packageName().equals(s.name)))throw new IllegalArgumentException("TARGET_ADVISORY_REMAINS");
                        for(var f:newFindings){long oldPaths=before.components().stream().filter(c->c.identity().equals(identity(f))).count(),newPaths=after.components().stream().filter(c->c.identity().equals(identity(f))).count();if(newPaths>oldPaths)throw new IllegalArgumentException("VULNERABLE_PATHS_INCREASED");}
                        s.evidence=SourceArchive.hash(json.writeValueAsBytes(Map.of("findings",facts.findings(),"analyzedIdentities",new TreeSet<>(facts.analyzedIdentities()))));s.files=Map.of("package.json",output.manifest().clone(),"package-lock.json",output.lockfile().clone());s.differences=workspaces.generatedDifferences(workspace,s.revision,s.hash,s.files);s.to=candidate;s.npm=output.npmVersion();s.node=output.nodeVersion();s.execution=output.executionId();s.remaining=List.of();s.state="PROPOSED";s.message="상위 선언과 모든 기존 위험 잠금 경로의 변경을 검증했습니다. 동일 OSV 조회 자료에서 새 공지 유입이 없었습니다. 앱 호환성은 미검증이며 Diff·사용자 승인이 필요합니다.";s.attempts.add(new Attempt(s.root,candidate,"VERIFIED_LOCK_REPAIR"));return view(s);
                    }catch(Exception rejected){wipe(s);s.differences=List.of();if(Set.of("TARGET_VERSION_REMAINS","OSV_PARTIAL_UNKNOWN").contains(reason(rejected)))s.partial=true;s.attempts.add(new Attempt(s.root,candidate,reason(rejected)));if(reason(rejected).startsWith("NPM_ISOLATION_")||reason(rejected).startsWith("NPM_METADATA_")){s.state="MANUAL_REVIEW";s.message="격리 실행 환경 또는 자원 한도에서 수정안을 검증하지 못했습니다. 호스트 실행으로 대체하지 않았으며 원본은 유지됩니다. 기존 근거와 수동 수정 가이드를 이용하세요.";return view(s);}}finally{if(output!=null){Arrays.fill(output.manifest(),(byte)0);Arrays.fill(output.lockfile(),(byte)0);}}
                }
                var fixes=original.dependencyVulnerabilities().stream().filter(f->f.packageName().equals(s.name)&&f.installedVersion().equals(s.version)).flatMap(f->f.fixedVersions().stream()).filter(v->NpmTreePlanner.upgrade(s.version,v)).distinct().sorted(NpmTreePlanner::compare).limit(5).toList();
                s.state=s.partial?"PARTIAL":"MANUAL_REVIEW";s.message=(s.partial?"잔존 위험 경로 또는 미조회 근거가 있어 해결을 확정하지 않았습니다. ":"")+"상위 "+s.root+"@"+s.from+" · "+s.name+"@"+s.version+" · 공지 수정 경계 "+fixes+". 제한된 후보 탐색에서 검증 가능한 상위 업데이트를 확보하지 못했습니다. 기존 위험은 해결되지 않았습니다. 상위 업데이트 불가·호환성 근거를 확인한 뒤에만 제한 override를 수동 검토하세요.";
            }catch(com.securedeploy.global.error.SecureDeployException conflict){s.state="MANUAL_REVIEW";throw conflict;}catch(Exception rejected){s.state="MANUAL_REVIEW";s.message="검증되지 않은 변경을 만들지 않았습니다: "+reason(rejected);}
            return view(s);
        }finally{capacity.release();}
    }
    private boolean knownOldLeaf(JsonNode root,NpmTreePlanner.Target target,Map<String,JsonNode> cache)throws Exception{
        // Skip only when every recorded chain still resolves to the exact known affected version.
        for(var chain:target.chains()){
            JsonNode node=root;if(chain.isEmpty())return false;
            for(int i=1;i<chain.size();i++){if(i>4||cache.size()>=24)return false;String name=chain.get(i).packageName(),spec=node.path("dependencies").path(name).asText();if(spec.isEmpty())spec=node.path("optionalDependencies").path(name).asText();if(i==chain.size()-1){if(!spec.equals(target.version()))return false;}else{if(!spec.matches("[0-9]+\\.[0-9]+\\.[0-9]+(?:-[A-Za-z0-9.-]+)?"))return false;String key=name+"@"+spec;node=cache.get(key);if(node==null){node=registry.version(name,spec);cache.put(key,node);}}}
            if(chain.size()==1)return root.path("version").asText().equals(target.version());
        }return true;
    }
    private String identity(DependencyVulnerability f){return f.ecosystem()+"|"+f.packageName()+"|"+f.installedVersion();}
    public EditingWorkspaceService.Workspace apply(String workspace,String id,Consent consent){var s=owned(workspace,id);if(!enabled())throw fail(HttpStatus.SERVICE_UNAVAILABLE,"자동 수정 비활성 상태입니다.");synchronized(this){if(!s.state.equals("PROPOSED")||consent==null||!consent.approved()||!s.hash.equals(consent.inputHash()))throw fail(HttpStatus.CONFLICT,"검증된 Diff와 적용 승인이 필요합니다.");var w=workspaces.applyGenerated(workspace,s.revision,s.hash,s.files,"VERIFIED_DEPENDENCY_GRAPH",s.id);s.state="ACCEPTED";wipe(s);return w;}}
    private Session owned(String workspace,String id){workspaces.get(workspace);synchronized(this){var s=sessions.get(id);if(s==null||!s.workspace.equals(workspace)||s.expires.isBefore(Instant.now()))throw fail(HttpStatus.NOT_FOUND,"수정 계획이 없거나 만료되었습니다.");return s;}}
    private synchronized View view(Session s){return new View(s.id,s.state,s.revision,s.hash,"DETERMINISTIC_NPM_GRAPH",s.name,s.version,s.root,s.from,s.range,s.to==null?null:NpmTreePlanner.satisfies(s.range,s.to),s.to,s.paths,s.remaining,s.before,s.after,List.copyOf(s.attempts),s.differences,s.evidence,s.npm,s.node,"NOT_VERIFIED",s.message,s.execution);}
    private void cleanup(){sessions.values().removeIf(s->{if(!s.state.equals("GENERATING")&&s.expires.isBefore(Instant.now())){wipe(s);return true;}return false;});}
    private void wipe(Session s){s.files.values().forEach(b->Arrays.fill(b,(byte)0));s.files=Map.of();}
    @jakarta.annotation.PreDestroy public synchronized void close(){sessions.values().forEach(this::wipe);sessions.clear();}
    private static String reason(Exception e){String m=e.getMessage();return m!=null&&m.matches("[A-Z0-9_]{1,80}")?m:"GENERATION_OR_EVIDENCE_CHECK_FAILED";}
    private static com.securedeploy.global.error.SecureDeployException fail(HttpStatus status,String message){return new com.securedeploy.global.error.SecureDeployException(status,message);}
}
