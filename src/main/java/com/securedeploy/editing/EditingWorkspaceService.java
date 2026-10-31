package com.securedeploy.editing;

import com.securedeploy.auth.service.*;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.project.service.ProjectLifecycleGuard;
import com.securedeploy.review.model.ReviewSourceType;
import jakarta.annotation.PreDestroy;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.eclipse.jgit.diff.*;
import org.eclipse.jgit.util.QuotedString;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class EditingWorkspaceService {
    // A tiny expression edit can still produce a full long-line diff in UTF-16 memory.
    private static final long PATCH_RESERVATION = 512 * 1024L;
    public record FileInfo(String id, String path, String originalHash, int size, boolean directory,
                           boolean editable, String readOnlyReason, boolean changed,String changeOrigin,List<ChangeAttribution> provenance) { }
    public record Workspace(String id, long reviewId, long revision, Instant createdAt, Instant expiresAt, String sourceRevision,
                            String identityStatus, List<FileInfo> files, List<String> changedFileIds,List<ExportApproval> exports,String storageMode) { }
    public record ExportApproval(long revision,String format,long userId,Instant at,String provenanceHash) { }
    public record Content(String fileId, long revision, String originalHash, String currentHash, String text, String newline, boolean bom) { }
    public record Change(long revision, String originalHash, String text) { }
    public record Approval(long revision, List<String> changedFileIds, boolean approved) { }
    public record Difference(long revision, String fileId, String originalHash, String patch,String changeOrigin,List<ChangeAttribution> provenance) { }
    public record Download(byte[] bytes, String filename, String type,String provenanceHash,long revision) { }
    private static final class StoredFile {
        final String id;
        final SourceArchive.Entry original;
        final String hash;
        byte[] edit;
        String changeOrigin = "UNCHANGED";
        final List<ChangeAttribution> provenance=new ArrayList<>();
        StoredFile(SourceArchive.Entry entry) { this(UUID.randomUUID().toString(),entry); }
        StoredFile(String id,SourceArchive.Entry entry) { this.id=id; original = entry; hash = SourceArchive.hash(entry.bytes()); }
        byte[] current() { return edit == null ? original.bytes() : edit; }
        boolean editable() { return !original.directory() && SourceArchive.text(original.bytes()) != null; }
        void clear() { Arrays.fill(original.bytes(), (byte) 0); if (edit != null) Arrays.fill(edit, (byte) 0); }
    }
    private static final class State {
        final String id;
        final long user, review;
        final long project;
        final ProjectLifecycleGuard.Lease lease;
        final Instant created, expires;
        final String source, identity;
        final List<StoredFile> files;
        final Map<String,WorkspacePatch.Session> patches = new LinkedHashMap<>();
        final List<ExportApproval> exports=new ArrayList<>();
        long revision = 1;
        long storeVersion;
        State(long user, long review, long project, ProjectLifecycleGuard.Lease lease, Instant now,
                String source, String identity, List<SourceArchive.Entry> entries,Duration retention) {
            this.id=UUID.randomUUID().toString();
            this.user = user; this.review = review; this.created = now; this.expires = now.plus(retention);
            this.project = project; this.lease = lease;
            this.source = source; this.identity = identity;
            this.files = entries.stream().sorted(Comparator.comparing(SourceArchive.Entry::path)).map(StoredFile::new).toList();
        }
        State(WorkspaceVault.Loaded loaded,ProjectLifecycleGuard.Lease lease) {
            var s=loaded.snapshot();this.id=s.id();this.user=s.owner();this.project=s.project();this.review=s.review();
            this.created=s.created();this.expires=s.expires();this.source=s.source();this.identity=s.identity();this.lease=lease;
            this.revision=s.revision();this.storeVersion=loaded.version();
            this.files=s.files().stream().map(f->{var v=new StoredFile(f.id(),new SourceArchive.Entry(f.path(),f.original(),f.directory(),f.mode()));v.edit=f.edit();v.changeOrigin=f.origin();v.provenance.addAll(f.provenance());return v;}).toList();
            this.exports.addAll(s.exports());
        }
        void clear() { try { files.forEach(StoredFile::clear); patches.clear(); } finally { lease.close(); } }
    }
    private final Map<String, State> states = new HashMap<>();
    private final Set<Long> creating = new HashSet<>();
    private final ReviewAccessService reviews;
    private final CurrentUserService users;
    private final EditingSourceService sources;
    private final ResponsePatchValidator responsePatches;
    private final Clock clock;
    private final ScheduledExecutorService expiry;
    private final ProjectLifecycleGuard lifecycle;
    private boolean closed;
    private WorkspaceVault vault;

    public EditingWorkspaceService(ReviewAccessService reviews, CurrentUserService users, EditingSourceService sources,
            ResponsePatchValidator responsePatches) {
        this(reviews, users, sources, responsePatches, new ProjectLifecycleGuard());
    }
    public EditingWorkspaceService(ReviewAccessService reviews, CurrentUserService users, EditingSourceService sources,
            ResponsePatchValidator responsePatches, ProjectLifecycleGuard lifecycle) {
        this(reviews, users, sources, Clock.systemUTC(), responsePatches, lifecycle);
    }
    @org.springframework.beans.factory.annotation.Autowired
    public EditingWorkspaceService(ReviewAccessService reviews,CurrentUserService users,EditingSourceService sources,
            ResponsePatchValidator validator,ProjectLifecycleGuard lifecycle,WorkspaceVault vault) {
        this(reviews,users,sources,Clock.systemUTC(),validator,lifecycle);this.vault=vault;
    }
    EditingWorkspaceService(ReviewAccessService reviews,CurrentUserService users,EditingSourceService sources,
            Clock clock,ProjectLifecycleGuard lifecycle,WorkspaceVault vault) {
        this(reviews,users,sources,clock,new ResponsePatchValidator(new com.securedeploy.analysis.typescript.TypeScriptAnalysisProperties()),lifecycle);this.vault=vault;
    }
    EditingWorkspaceService(ReviewAccessService reviews, CurrentUserService users, EditingSourceService sources, Clock clock) {
        this(reviews, users, sources, clock, new ProjectLifecycleGuard());
    }
    EditingWorkspaceService(ReviewAccessService reviews, CurrentUserService users, EditingSourceService sources,
            Clock clock, ProjectLifecycleGuard lifecycle) {
        this(reviews, users, sources, clock,
                new ResponsePatchValidator(new com.securedeploy.analysis.typescript.TypeScriptAnalysisProperties()), lifecycle);
    }
    private EditingWorkspaceService(ReviewAccessService reviews, CurrentUserService users, EditingSourceService sources,
            Clock clock, ResponsePatchValidator responsePatches, ProjectLifecycleGuard lifecycle) {
        this.reviews = reviews; this.users = users; this.sources = sources; this.clock = clock;
        this.responsePatches=responsePatches;
        this.lifecycle = lifecycle == null ? new ProjectLifecycleGuard() : lifecycle;
        expiry = Executors.newSingleThreadScheduledExecutor(r -> { var t = new Thread(r, "editing-expiry"); t.setDaemon(true); return t; });
        expiry.scheduleWithFixedDelay(()->{try {expire();if(vault!=null&&vault.enabled())vault.cleanup(Instant.now(clock));}catch(RuntimeException ignored){/* Reads/writes still fail closed; never log encrypted parameters. */}}, 15, 15, TimeUnit.SECONDS);
    }
    public Workspace create(long reviewId, MultipartFile zip) throws IOException {
        long user = users.currentUserId();
        var review = reviews.findAccessibleReviewWithVulnerabilities(reviewId, "분석 결과에 접근할 수 없습니다.");
        if (review.getSourceType() == ReviewSourceType.WORKSPACE)
            throw fail(HttpStatus.CONFLICT, "수정본 Review에는 원본 전체가 보관되지 않습니다. 기존 작업 공간을 이용하거나 다운로드한 ZIP으로 새 분석을 시작해 주세요.");
        synchronized (this) {
            if (closed) throw fail(HttpStatus.SERVICE_UNAVAILABLE, "작업 공간을 사용할 수 없습니다.");
            expire();
            if(vault!=null&&vault.enabled())vault.cleanupOwner(user,Instant.now(clock));
            restore(user);
            if (creating.contains(user) || states.values().stream().anyMatch(s -> s.user == user))
                throw new EditingConflictException("WORKSPACE_ALREADY_OPEN", "진행 중인 수정 작업이 있어요. 기존 작업을 확인하고 이어서 진행해 주세요.");
            if (states.size() + creating.size() >= 4) throw fail(HttpStatus.TOO_MANY_REQUESTS, "작업 공간이 가득 찼습니다. 잠시 후 다시 시도해 주세요.");
            creating.add(user);
        }
        List<SourceArchive.Entry> entries = null;
        boolean complete = false;
        ProjectLifecycleGuard.Lease lease = null;
        try {
            lease = lifecycle.work(review.getProject().getId());
            reviews.findAccessibleReviewWithVulnerabilities(reviewId, "분석 결과에 접근할 수 없습니다.");
            String source, identity;
            if (review.getSourceType() == ReviewSourceType.ZIP) {
                if (zip == null || zip.isEmpty() || zip.getSize() > SourceArchive.MAX_BYTES) throw SourceArchive.invalid();
                try (var input = zip.getInputStream()) { entries = SourceArchive.read(input); }
                source = manifest(entries); identity = "UNVERIFIED_REUPLOAD";
            } else {
                if (zip != null) throw SourceArchive.invalid();
                if (review.getSourceMetadata() == null || !Objects.equals(review.getRepositoryUrl(), review.getSourceMetadata().canonicalRepositoryUrl()))
                    throw fail(HttpStatus.CONFLICT, "원본 저장소 식별 정보가 불충분합니다. 새 기준으로 분석해 주세요.");
                entries = sources.github(user, review.getSourceMetadata());
                source = review.getSourceMetadata().commitSha(); identity = "EXACT_GIT_COMMIT";
            }
            // Recheck ownership after acquisition; deleting a Review must not create an orphan session.
            reviews.findAccessibleReviewWithVulnerabilities(reviewId, "분석 결과에 접근할 수 없습니다.");
            var state = new State(user, reviewId, review.getProject().getId(), lease, Instant.now(clock).truncatedTo(java.time.temporal.ChronoUnit.MILLIS), source, identity, entries, vault==null?Duration.ofMinutes(30):vault.retention());
            synchronized (this) {
                if (closed) throw fail(HttpStatus.SERVICE_UNAVAILABLE, "작업 공간을 사용할 수 없습니다.");
                var result = describe(state);
                persist(state);
                states.put(state.id, state);
                complete = true;
                return result;
            }
        } finally {
            synchronized (this) { creating.remove(user); }
            if (!complete) {
                if (entries != null) entries.forEach(e -> Arrays.fill(e.bytes(), (byte) 0));
                if (lease != null) lease.close();
            }
        }
    }
    public record Discovery(String state, Workspace workspace) { }
    public synchronized Discovery discover(long reviewId) {
        long user=users.currentUserId();
        var review=reviews.findAccessibleReviewWithVulnerabilities(reviewId,"분석 결과에 접근할 수 없습니다.");
        expire();
        if(closed)throw fail(HttpStatus.SERVICE_UNAVAILABLE,"작업 공간을 사용할 수 없습니다.");
        restore(user);
        for(var state:states.values())if(state.user==user) {
            if(state.review==reviewId&&state.project==review.getProject().getId())return new Discovery("AVAILABLE",describe(owned(state.id)));
            return new Discovery("OTHER_REVIEW",null);
        }
        return new Discovery(creating.contains(user)?"CREATING":"NONE",null);
    }
    synchronized long projectId(String id){return owned(id).project;}
    public synchronized Workspace get(String id) { return describe(owned(id)); }
    public synchronized Content content(String id, String fileId) {
        var state = owned(id); var file = file(state, fileId);
        if (!file.editable()) throw fail(HttpStatus.UNPROCESSABLE_ENTITY, "바이너리·대용량·불명확한 인코딩 파일은 편집할 수 없습니다.");
        String text = SourceArchive.text(file.current());
        boolean bom = text.startsWith("\ufeff");
        return new Content(file.id, state.revision, file.hash, SourceArchive.hash(file.current()), bom ? text.substring(1) : text,
                text.contains("\r\n") ? "CRLF" : "LF", bom);
    }
    public synchronized Workspace save(String id,String fileId,Change change,boolean revert) {
        saveInternal(id,fileId,change,revert);var state=owned(id);var f=file(state,fileId);
        record(state,f,"MANUAL",null,null,null,null,null,false);persist(state);return describe(state);
    }
    private Workspace saveInternal(String id, String fileId, Change change, boolean revert) {
        var state = owned(id); var file = file(state, fileId);
        if (change == null || change.revision() != state.revision || !file.hash.equals(change.originalHash()))
            throw new EditingConflictException("WORKSPACE_REVISION_CONFLICT", "다른 탭에서 저장했거나 원본 해시가 달라졌어요. 현재 편집을 먼저 내보낸 뒤 최신 내용을 확인해 주세요.");
        if (!file.editable()) throw fail(HttpStatus.UNPROCESSABLE_ENTITY, "이 파일은 읽기 전용입니다.");
        byte[] bytes = null;
        if (!revert) {
            bytes=editedBytes(file,change.text());
            if (Arrays.equals(bytes, file.original.bytes())) bytes = null;
        }
        ensureHistory(state,1);
        long size = state.patches.size() * PATCH_RESERVATION;
        for (var item : state.files) size += item.original.bytes().length + (item == file ? (bytes == null ? 0 : bytes.length) : (item.edit == null ? 0 : item.edit.length));
        if (size > SourceArchive.MAX_BYTES) throw SourceArchive.limit();
        if (file.edit != null) Arrays.fill(file.edit, (byte) 0);
        file.edit = bytes; state.revision++;
        file.changeOrigin = bytes == null ? "UNCHANGED" : state.patches.values().stream().anyMatch(p -> p.fileId.equals(file.id)&&"ACCEPTED".equals(p.state)&&p.method().equals("AI_ASSISTED")&&"MOCK".equals(p.provider.origin()))?"MANUAL_AFTER_MOCK_AI":state.patches.values().stream()
                .anyMatch(p -> p.fileId.equals(file.id) && "ACCEPTED".equals(p.state)&&p.method().equals("AI_ASSISTED")) ? "MANUAL_AFTER_AI"
                : state.patches.values().stream().anyMatch(p -> p.fileId.equals(file.id)&&"ACCEPTED".equals(p.state)) ? "MANUAL_AFTER_DETERMINISTIC" : "MANUAL";
        return describe(state);
    }
    public synchronized Difference diff(String id, String fileId) throws IOException {
        var state = owned(id); var file = file(state, fileId);
        return new Difference(state.revision, file.id, file.hash, patch(file),file.changeOrigin,List.copyOf(file.provenance));
    }
    public synchronized WorkspacePatch.View preparePatch(String id, WorkspacePatch.Prepare request, WorkspacePatch.Provider provider) {
        return preparePatch(id,request,provider,true);
    }
    public synchronized WorkspacePatch.View preparePlan(String id,WorkspacePatch.Prepare request,WorkspacePatch.Provider provider){return preparePatch(id,request,provider,true,true);}
    public synchronized WorkspacePatch.FixOption fixOption(String id,WorkspacePatch.Prepare request,WorkspacePatch.Provider provider) {
        var state=owned(id);var file=file(state,request.fileId());
        if(!"EXACT_GIT_COMMIT".equals(state.identity))return new WorkspacePatch.FixOption("MANUAL_REVIEW","원본 일치가 검증되지 않아 수동 편집 후 새 분석이 필요합니다.");
        if(!(file.original.path().endsWith(".properties")||file.original.path().matches(".*\\.[cm]?[jt]s")))
            return new WorkspacePatch.FixOption("UNSUPPORTED","이 파일 유형의 수정안 생성은 지원하지 않습니다.");
        try {
            preparePatch(id,request,request.flowFindingId()!=null?WorkspacePatch.DETERMINISTIC:provider,false);
            return new WorkspacePatch.FixOption(request.flowFindingId()!=null?"DETERMINISTIC_FIX":"AI_ASSISTED",
                    request.flowFindingId()!=null?"정적 근거로 응답 필드 제거 제안을 만들 수 있습니다. 외부 AI 전송·비용은 없습니다.":"지원되는 설정이지만 현재 제품의 제안 생성은 별도 AI 동의가 필요합니다.");
        }catch(com.securedeploy.global.error.SecureDeployException e){
            if(e.getStatus()!=HttpStatus.UNPROCESSABLE_ENTITY)throw e;
            if(request.flowFindingId()!=null)try{preparePatch(id,request,provider,false,true);return new WorkspacePatch.FixOption("AI_ASSISTED","검증된 Express 필드의 구조화 수정 계획을 지원합니다. 코드 변경은 서버가 생성하고 승인을 기다립니다.");}catch(com.securedeploy.global.error.SecureDeployException unsupported){if(unsupported.getStatus()!=HttpStatus.UNPROCESSABLE_ENTITY)throw unsupported;}
            return new WorkspacePatch.FixOption("MANUAL_REVIEW","수정 범위의 정적 근거를 확인하지 못했습니다. 직접 검토해 주세요.");
        }
    }
    public synchronized WorkspacePatch.View prepareDeterministicPatch(String id,WorkspacePatch.Prepare request) {
        if(request.flowFindingId()==null)throw fail(HttpStatus.UNPROCESSABLE_ENTITY,"자동 수정안은 지원되는 Deno·Express 환경값 응답 Finding만 허용합니다.");
        return preparePatch(id,request,WorkspacePatch.DETERMINISTIC,true);
    }
    private WorkspacePatch.View preparePatch(String id, WorkspacePatch.Prepare request, WorkspacePatch.Provider provider,boolean retain) {return preparePatch(id,request,provider,retain,false);}
    private WorkspacePatch.View preparePatch(String id, WorkspacePatch.Prepare request, WorkspacePatch.Provider provider,boolean retain,boolean plan) {
        var state=owned(id);
        if(!"EXACT_GIT_COMMIT".equals(state.identity))throw fail(HttpStatus.CONFLICT,"원본 일치 미검증 ZIP에는 AI 패치를 연결할 수 없습니다. 수동 편집 후 새 분석이 필요합니다.");
        if(retain&&!provider.available())throw fail(HttpStatus.SERVICE_UNAVAILABLE,"AI 수정 Provider가 준비되지 않았습니다. 수동 편집과 기존 가이드는 계속 사용할 수 있습니다.");
        var file=file(state,request.fileId());
        if(!file.editable()||request.revision()!=state.revision||!file.hash.equals(request.originalHash())
                || !SourceArchive.hash(file.current()).equals(request.currentHash()))throw fail(HttpStatus.CONFLICT,"현재 파일 해시 또는 revision이 다릅니다. 다시 불러와 주세요.");
        var review=reviews.findAccessibleReviewWithVulnerabilities(state.review,"분석 결과에 접근할 수 없습니다.");
        if(request.flowFindingId()!=null)return prepareResponsePatch(state,file,request,provider,review,retain,plan);
        if(plan)throw fail(HttpStatus.UNPROCESSABLE_ENTITY,"구조화 수정 계획은 검증된 Express 응답 객체만 지원합니다.");
        var finding=review.getVulnerabilities().stream().filter(v->v.getId()!=null&&v.getId()==request.findingId()).findFirst()
                .orElseThrow(()->fail(HttpStatus.NOT_FOUND,"연결된 Finding을 확인할 수 없습니다."));
        if(!file.original.path().equals(finding.getFilePath()))throw fail(HttpStatus.CONFLICT,"Finding과 현재 파일의 연결을 확인할 수 없습니다.");
        if(state.patches.size()>=3)throw fail(HttpStatus.TOO_MANY_REQUESTS,"한 작업 공간에서는 수정 제안을 최대 3개까지 준비할 수 있습니다.");
        long retained=state.files.stream().mapToLong(f->f.original.bytes().length+(f.edit==null?0:f.edit.length)).sum();
        if(retained+(state.patches.size()+1)*PATCH_RESERVATION>SourceArchive.MAX_BYTES)throw SourceArchive.limit();
        try {
            var target=WorkspacePatch.target(SourceArchive.text(file.original.bytes()),SourceArchive.text(file.current()),finding.getLine(),finding.getRuleId(),file.original.path());
            var sanitizer=new com.securedeploy.ai.remediation.RemediationSanitizer();
            for(String text:List.of(target.before(),file.original.path()))
                if(!text.equals(sanitizer.text(text,1024)))throw new IllegalArgumentException();
            String current=WorkspacePatch.normalize(SourceArchive.text(file.current()));
            String candidate=current.substring(0,target.offset())+target.after()+current.substring(target.offset()+target.before().length());
            String diff=patch(file.original.path(),file.current(),editedBytes(file,candidate),0);
            var session=new WorkspacePatch.Session(request,finding.getRuleId(),state.source,request.currentHash(),target.line(),target.offset(),target.before(),target.after(),diff,provider);
            if(retain)state.patches.put(session.id,session);return patchView(state,session,false);
        }catch(IllegalArgumentException | IOException unsupported){throw fail(HttpStatus.UNPROCESSABLE_ENTITY,"단순한 상수 설정 한 줄의 위치와 변경 근거를 확인할 수 없습니다. 민감정보·중복 설정·동적 값은 전송하지 않으며 수동 검토가 필요합니다.");}
    }
    public synchronized List<WorkspacePatch.View> patches(String id) {
        var state=owned(id);return state.patches.values().stream().map(p->{refreshPatch(state,p);return patchView(state,p,false);}).toList();
    }
    private WorkspacePatch.View prepareResponsePatch(State state,StoredFile file,WorkspacePatch.Prepare request,WorkspacePatch.Provider provider,ReviewEntity review,boolean retain,boolean plan) {
        if(request.findingId()!=0||request.flowFindingId().length()>200||state.patches.size()>=3)throw fail(HttpStatus.UNPROCESSABLE_ENTITY,"지원 범위 또는 수정 제안 한도를 확인해 주세요.");
        try {
            if(!file.original.path().matches(".*\\.[cm]?[jt]s")||!file.hash.equals(request.currentHash()))throw new IllegalArgumentException();
            var snapshot=review.getServerAnalysis();if(snapshot==null||snapshot.validatedFindings()==null)throw new IllegalArgumentException();
            var finding=snapshot.validatedFindings().stream().filter(f->f.findingId().equals(request.flowFindingId())).findFirst().orElseThrow();
            if(!finding.ruleId().equals("TS_SENSITIVE_DATA_EXPOSURE")||!finding.comparisonPolicy().equals("NOT_COMPARED")
                    ||!file.original.path().equals(finding.location().filePath())||!Set.of("HTTP_RESPONSE","EXPRESS_HTTP_RESPONSE").contains(finding.location().kind())||finding.evidence().isEmpty())throw new IllegalArgumentException();
            var sources=new ArrayList<com.securedeploy.analysis.typescript.ServerAnalysisSnapshot.Location>();
            var kinds=Set.of("SERVER_SECRET_ENVIRONMENT_VALUE","REQUEST_SELECTED_ENVIRONMENT_VALUE");
            for(var e:finding.evidence()) {
                if(!e.ruleId().equals(finding.ruleId())||!"HIGH".equals(e.confidence())||!e.sink().equals(finding.location())||!e.source().filePath().equals(file.original.path())||!kinds.contains(e.source().kind()))throw new IllegalArgumentException();
                if(finding.location().kind().equals("EXPRESS_HTTP_RESPONSE")) {
                    if(e.flow()==null||!e.flow().contains(e.source())||!e.flow().contains(finding.location())||!snapshot.findings().contains(e))throw new IllegalArgumentException();
                    for(var location:e.flow())if(kinds.contains(location.kind())) {
                        if(!location.filePath().equals(file.original.path())||snapshot.exposureUses()==null||snapshot.exposureUses().stream().noneMatch(use->use.location().equals(finding.location())&&use.status().equals("SENSITIVE_FLOW_CANDIDATE")&&use.trace().contains(location)))throw new IllegalArgumentException();
                        if(!sources.contains(location))sources.add(location);
                    }
                }else if(!sources.contains(e.source()))sources.add(e.source());
            }
            String source=WorkspacePatch.normalize(SourceArchive.text(file.current()));
            var contract=new ResponsePatchValidator.Contract(source,finding.location(),List.copyOf(sources));
            if(plan&&!finding.location().kind().equals("EXPRESS_HTTP_RESPONSE"))throw new IllegalArgumentException();
            var target=plan?responsePatches.checkPlan(contract,null):responsePatches.check(contract,null);var sanitizer=new com.securedeploy.ai.remediation.RemediationSanitizer();
            // Paths are never sent to the provider; validate only the exact transmitted code.
            if(!target.before().equals(sanitizer.text(target.before(),4096))||target.before().contains("@")||target.before().contains("<redacted>"))throw new IllegalArgumentException();
            long retained=state.files.stream().mapToLong(f->f.original.bytes().length+(f.edit==null?0:f.edit.length)).sum();
            if(retained+(state.patches.size()+1)*PATCH_RESERVATION>SourceArchive.MAX_BYTES)throw new IllegalArgumentException();
            var session=new WorkspacePatch.Session(request,finding.ruleId(),state.source,request.currentHash(),target.line(),target.offset(),target.before(),null,null,provider);
            session.plan=plan;
            session.responseContract=new ResponsePatchValidator.Contract(null,contract.sink(),contract.sources());
            if(!WorkspacePatch.DETERMINISTIC.equals(provider)&&finding.location().kind().equals("EXPRESS_HTTP_RESPONSE")) {
                var context=target.context();
                if(context==null||!context.code().equals(sanitizer.text(context.code(),6000))||context.code().contains("@")||context.code().contains("<redacted>"))throw new IllegalArgumentException();
                if(target.fields()==null||target.fields().size()!=sources.size())throw new IllegalArgumentException();
                var bindings=new ArrayList<ResponsePatchValidator.BoundField>();
                for(var field:target.fields()) {
                    var matches=sources.stream().filter(v->v.line()==field.source().line()&&v.column()==field.source().column()).toList();
                    if(matches.size()!=1||field.startOffset()<target.offset()||field.endOffset()>target.offset()+target.before().length()||field.startOffset()>=field.endOffset())throw new IllegalArgumentException();
                    var expressionHash=SourceArchive.hash(field.expression().getBytes(StandardCharsets.UTF_8));
                    String identity=state.project+"|"+state.review+"|"+finding.findingId()+"|"+file.hash+"|"+state.revision+"|"+matches.get(0)+"|"+finding.location()+"|"+field.field()+"|"+expressionHash;
                    bindings.add(new ResponsePatchValidator.BoundField(finding.findingId(),SourceArchive.hash(identity.getBytes(StandardCharsets.UTF_8)),field.field(),field.source(),context.sink(),field.startOffset(),field.endOffset(),expressionHash));
                }
                if(bindings.stream().map(ResponsePatchValidator.BoundField::sourceId).distinct().count()!=sources.size())throw new IllegalArgumentException();
                session.context=context.withBindings(List.copyOf(bindings));
            }
            session.limits=List.of("응답 필드 제거는 API 계약을 바꿀 수 있습니다. 응답을 사용하는 클라이언트와 호환성을 직접 확인하고 승인하세요.",
                    "서버 환경값 조회에서 HTTP 응답으로 전달되는 필드만 대상으로 합니다. 실제 비밀값·운영 인증·배포 상태·전체 안전성은 미확인입니다.",
                    "현재 파일이 원본과 같은 경우만 지원하며 복잡한 helper·별칭·전체 환경값 응답은 수동 검토가 필요합니다. 구조 비교는 NOT_COMPARED입니다.");
            session.checks=List.of("삭제될 응답 필드의 API 사용처와 기능 영향을 확인하세요.","승인 후 STANDARD 재검사에서 후보·새 경고·Coverage를 확인하세요.");
            if(retain&&WorkspacePatch.DETERMINISTIC.equals(provider)) {
                responsePatches.check(contract,target.suggestedReplacement());
                String candidate=source.substring(0,target.offset())+target.suggestedReplacement()+source.substring(target.offset()+target.before().length());
                String diff=patch(file.original.path(),file.current(),editedBytes(file,candidate),0);
                if(diff.length()>128*1024)throw new IllegalArgumentException();
                session.after=target.suggestedReplacement();session.diff=diff;session.state="PROPOSED";
                session.explanation="확인된 서버 환경값 응답 필드만 제거하는 자동 수정안입니다. 외부 AI 전송·비용은 없으며 승인 전에는 파일을 바꾸지 않습니다. API 사용처의 호환성을 확인해 주세요.";
            }
            if(retain)state.patches.put(session.id,session);return patchView(state,session,false);
        }catch(RuntimeException | IOException unsupported){throw fail(HttpStatus.UNPROCESSABLE_ENTITY,"환경값 응답 필드만 바꿀 수 있는 정적 근거를 확인하지 못했습니다. 민감정보·전체 응답·동적 코드·변경된 파일은 전송하지 않으며 수동 검토가 필요합니다.");}
    }
    public synchronized WorkspacePatch.View patch(String id,String proposal) {
        var state=owned(id);return patchView(state,patchOwned(state,proposal),false);
    }
    synchronized WorkspacePatch.View beginPatch(String id,String proposal,WorkspacePatch.Consent consent,WorkspacePatch.Provider provider) {
        var state=owned(id);var session=patchOwned(state,proposal);
        if(session.method().equals("DETERMINISTIC_FIX")||!"APPROVAL_REQUIRED".equals(session.state)||consent==null||!consent.consented()||consent.revision()!=session.revision
                ||session.context!=null&&!patchView(state,session,true).contextHash().equals(consent.contextHash())
                ||!session.currentHash.equals(consent.currentHash())||!session.provider.equals(provider))throw fail(HttpStatus.CONFLICT,"전송 동의가 없거나 코드·Provider·revision이 변경되었습니다. 새 제안을 준비해 주세요.");
        session.state="GENERATING";session.explanation="동의한 최소 코드 범위만 전송합니다. 아직 파일은 변경되지 않았습니다.";
        return patchView(state,session,true);
    }
    synchronized void recordPatchUsage(String id,String proposal,com.securedeploy.ai.usage.AiUsageRecord usage){var state=owned(id);patchOwned(state,proposal).usage=usage;}
    synchronized WorkspacePatch.View finishPatch(String id,String proposal,WorkspacePatch.Output output,String failure) {
        var state=owned(id);var session=patchOwned(state,proposal);
        if(!"GENERATING".equals(session.state))return patchView(state,session,false);
        if(failure!=null){session.state=failure;session.explanation="수정 제안을 생성하거나 검증하지 못했습니다. 코드 변경은 없으며 수동 편집할 수 있습니다.";}
        else {
            try {
                WorkspacePatch.validate(output,patchView(state,session,true));
                if(session.responseContract!=null&&output.decision().equals("PATCH")) {
                    var file=file(state,session.fileId);String current=WorkspacePatch.normalize(SourceArchive.text(file.current()));
                    var contract=new ResponsePatchValidator.Contract(current,session.responseContract.sink(),session.responseContract.sources());
                    if(session.plan)responsePatches.checkPlan(contract,output.replacement());else responsePatches.check(contract,output.replacement());
                    String candidate=current.substring(0,session.offset)+output.replacement()+current.substring(session.offset+session.before.length());
                    String diff=patch(file.original.path(),file.current(),editedBytes(file,candidate),0);
                    if(diff.length()>128*1024)throw new IllegalArgumentException();
                    session.diff=diff;session.after=output.replacement();
                }
                session.state=output.decision().equals("PATCH")?"PROPOSED":"NEEDS_REVIEW";
                session.explanation=output.explanation();
                // Provider text cannot remove the server-required compatibility and re-scan checks.
                var checks=new LinkedHashSet<>(session.checks);checks.addAll(output.verificationSteps());session.checks=List.copyOf(checks);
                var limits=new ArrayList<>(session.limits);limits.addAll(output.limitations());session.limits=List.copyOf(limits);
            }catch(RuntimeException | IOException invalid){session.state="INVALID";session.explanation="허용된 변경 범위를 확인할 수 없는 AI 응답을 거부했습니다. 파일은 변경되지 않았습니다.";}
        }
        return patchView(state,session,false);
    }
    public synchronized WorkspacePatch.View finishPlan(String id,String proposal,WorkspacePatchPlan.Output output,String failure){
        var state=owned(id);var session=patchOwned(state,proposal);
        if(!session.plan)throw fail(HttpStatus.CONFLICT,"수정 계획 계약이 아닙니다.");
        if(!"GENERATING".equals(session.state))return patchView(state,session,false);
        if(failure!=null)return finishPatch(id,proposal,null,failure);
        try{
            var view=patchView(state,session,true);WorkspacePatchPlan.validate(output,view);
            String replacement="";
            if("PATCH".equals(output.decision())){
                if(state.revision!=session.revision||!SourceArchive.hash(file(state,session.fileId).current()).equals(session.currentHash))throw new IllegalArgumentException();
                String current=WorkspacePatch.normalize(SourceArchive.text(file(state,session.fileId).current()));
                var target=responsePatches.checkPlan(new ResponsePatchValidator.Contract(current,session.responseContract.sink(),session.responseContract.sources()),null);
                if(!target.before().equals(session.before)||target.offset()!=session.offset||!target.removed().equals(session.context.removedFields()))throw new IllegalArgumentException();
                replacement=target.suggestedReplacement();
            }
            return finishPatch(id,proposal,new WorkspacePatch.Output(output.decision(),session.fileId,session.line,SourceArchive.hash(session.before.getBytes(StandardCharsets.UTF_8)),replacement,output.explanation(),output.verificationSteps(),output.limitations()),null);
        }catch(RuntimeException invalid){return finishPatch(id,proposal,null,"INVALID");}
    }
    public synchronized WorkspacePatch.View rejectPatch(String id,String proposal) {
        var state=owned(id);var session=patchOwned(state,proposal);
        if(!Set.of("APPROVAL_REQUIRED","GENERATING","PROPOSED","NEEDS_REVIEW").contains(session.state))throw fail(HttpStatus.CONFLICT,"이미 종료된 제안입니다.");
        session.state="REJECTED";session.explanation=session.method().equals("DETERMINISTIC_FIX")?"사용자가 자동 수정안을 거절했습니다. 파일 변경·외부 전송·AI 비용은 없습니다.":"사용자가 제안을 거절했습니다. 파일은 변경되지 않았습니다. 이미 전송한 외부 요청의 처리·요금 취소는 보증하지 않습니다.";
        return patchView(state,session,false);
    }
    public synchronized Workspace applyPatch(String id,String proposal,WorkspacePatch.Decision decision) {
        var state=owned(id);var session=patchOwned(state,proposal);
        if(!"PROPOSED".equals(session.state)||decision==null||!decision.approved()||decision.revision()!=state.revision
                ||!session.currentHash.equals(decision.currentHash())||(session.responseContract!=null&&!decision.responseContractAcknowledged()))throw fail(HttpStatus.CONFLICT,"적용 승인·응답 계약 영향 확인이 없거나 제안이 오래되었습니다. 최신 코드를 확인해 주세요.");
        var file=file(state,session.fileId);String current=WorkspacePatch.normalize(SourceArchive.text(file.current()));
        if(!current.regionMatches(session.offset,session.before,0,session.before.length()))throw fail(HttpStatus.CONFLICT,"예상한 변경 위치가 다릅니다.");
        String updated=current.substring(0,session.offset)+session.after+current.substring(session.offset+session.before.length());
        var next=saveInternal(id,file.id,new Change(state.revision,file.hash,updated),false);
        session.state="ACCEPTED";file.changeOrigin=session.method().equals("DETERMINISTIC_FIX")?"DETERMINISTIC_APPROVED":"MOCK".equals(session.provider.origin())?"MOCK_AI_APPROVED":"AI_APPROVED";
        record(state,file,session.plan?"SECUREDEPLOY_AST":session.method().equals("DETERMINISTIC_FIX")?"DETERMINISTIC":"MOCK".equals(session.provider.origin())?"MOCK":"OPENAI".equals(session.provider.origin())?"OPENAI":"UNVERIFIED_AI",session.provider.origin(),session.usage==null?session.provider.model():session.usage.model(),session.id,session.plan?session.provider.origin():null,null,true);persist(state);return describe(state);
    }
    private WorkspacePatch.Session patchOwned(State state,String id) {
        var session=state.patches.get(id);if(session==null)throw fail(HttpStatus.NOT_FOUND,"수정 제안에 접근할 수 없습니다.");
        refreshPatch(state,session);return session;
    }
    private void refreshPatch(State state,WorkspacePatch.Session session) {
        if(Set.of("APPROVAL_REQUIRED","GENERATING","PROPOSED").contains(session.state)
                &&(state.revision!=session.revision||!session.currentHash.equals(SourceArchive.hash(file(state,session.fileId).current())))){
            session.state="STALE";session.explanation="파일 또는 작업 공간 revision이 변경되어 적용할 수 없습니다. 자동 재요청하지 않았습니다.";
        }
    }
    private WorkspacePatch.View patchView(State state,WorkspacePatch.Session p,boolean internal) {
        boolean show=internal||Set.of("PROPOSED","ACCEPTED").contains(p.state);
        return new WorkspacePatch.View(p.id,p.state,p.fileId,p.findingId,p.rule,state.review,p.source,p.revision,p.originalHash,p.currentHash,p.line,
                p.before,show?p.after:null,show?p.diff:null,p.provider,p.explanation,p.checks,p.limits,p.flowFindingId,p.method(),p.usage,p.context);
    }
    public synchronized Download download(String id, String format, Approval approval) throws IOException {
        var state = owned(id);
        var changed = state.files.stream().filter(f -> f.edit != null).map(f -> f.id).toList();
        if (approval == null || !approval.approved() || approval.revision() != state.revision
                || !changed.equals(approval.changedFileIds())) throw fail(HttpStatus.CONFLICT, "현재 revision과 변경 목록을 확인하고 다시 승인해 주세요.");
        if (changed.isEmpty()) throw fail(HttpStatus.CONFLICT, "다운로드할 변경 사항이 없습니다.");
        if(!Set.of("zip","patch").contains(format))throw fail(HttpStatus.BAD_REQUEST,"지원하지 않는 다운로드 형식입니다.");
        if(state.exports.size()>=128)throw fail(HttpStatus.TOO_MANY_REQUESTS,"다운로드 승인 이력 한도에 도달했습니다.");
        String provenanceHash=provenanceHash(fileFacts(state));
        state.exports.add(new ExportApproval(state.revision,format,state.user,Instant.now(clock),provenanceHash));
        persist(state);
        if ("zip".equals(format)) {
            return new Download(SourceArchive.zip(currentEntries(state, false)), "securedeploy-edited-r" + state.revision + ".zip", "application/zip",provenanceHash,state.revision);
        }
        if ("patch".equals(format)) {
            var output = new ByteArrayOutputStream();
            for (var f : state.files) if (f.edit != null) output.write(patch(f).getBytes(StandardCharsets.UTF_8));
            return new Download(output.toByteArray(), "securedeploy-edited-r" + state.revision + ".patch", "text/x-diff;charset=UTF-8",provenanceHash,state.revision);
        }
        throw fail(HttpStatus.BAD_REQUEST, "지원하지 않는 내보내기 형식입니다.");
    }
    public record GeneratedDifference(String path,String fileId,String originalHash,String currentHash,String proposedHash,String patch) { }
    synchronized List<GeneratedDifference> generatedDifferences(String id,long revision,String inputHash,Map<String,byte[]> replacements) {
        var state=owned(id);verifyGenerated(state,revision,inputHash,replacements);
        var diffs=new ArrayList<GeneratedDifference>();
        try {for(var e:replacements.entrySet()) {var f=state.files.stream().filter(v->v.original.path().equals(e.getKey())).findFirst().orElseThrow();
            String diff=patch(e.getKey(),f.current(),e.getValue(),0);if(diff.length()>128*1024)throw new IllegalArgumentException();
            diffs.add(new GeneratedDifference(e.getKey(),f.id,f.hash,SourceArchive.hash(f.current()),SourceArchive.hash(e.getValue()),diff));
        }}catch(IOException e){throw fail(HttpStatus.UNPROCESSABLE_ENTITY,"변경안을 표시하지 못했습니다.");}
        return List.copyOf(diffs);
    }
    synchronized Workspace applyGenerated(String id,long revision,String inputHash,Map<String,byte[]> replacements) {return applyGenerated(id,revision,inputHash,replacements,null,null);}
    synchronized Workspace applyGenerated(String id,long revision,String inputHash,Map<String,byte[]> replacements,String directionOrigin,String adviceId) {
        var state=owned(id);verifyGenerated(state,revision,inputHash,replacements);
        ensureHistory(state,replacements.size());
        // All checks finish before either file changes; original entries are never modified.
        for(var e:replacements.entrySet()){var f=state.files.stream().filter(v->v.original.path().equals(e.getKey())).findFirst().orElseThrow();f.edit=e.getValue().clone();f.changeOrigin="PACKAGE_MANAGER_APPROVED";}
        state.revision++;for(var path:replacements.keySet()){var f=state.files.stream().filter(v->v.original.path().equals(path)).findFirst().orElseThrow();record(state,f,"NPM",null,null,null,directionOrigin,adviceId,true);}persist(state);return describe(state);
    }
    private void verifyGenerated(State state,long revision,String inputHash,Map<String,byte[]> replacements) {
        if(state.revision!=revision||!"EXACT_GIT_COMMIT".equals(state.identity)||!replacements.keySet().equals(Set.of("package.json","package-lock.json")))throw fail(HttpStatus.CONFLICT,"원본 revision 또는 허용 파일 범위가 다릅니다.");
        var entries=currentEntries(state,true);
        try {if(!manifest(entries).equals(inputHash))throw fail(HttpStatus.CONFLICT,"작업 공간 파일 해시가 변경되었습니다.");}finally{entries.forEach(e->Arrays.fill(e.bytes(),(byte)0));}
        long bytes=state.files.stream().mapToLong(f->f.original.bytes().length+(f.edit==null?0:f.edit.length)).sum();
        for(var e:replacements.entrySet()){var f=state.files.stream().filter(v->v.original.path().equals(e.getKey())&&v.editable()).findFirst().orElseThrow();if(SourceArchive.text(e.getValue())==null)throw fail(HttpStatus.UNPROCESSABLE_ENTITY,"변경 파일 형식이 지원되지 않습니다.");bytes+=e.getValue().length-(f.edit==null?0:f.edit.length);}
        if(bytes>SourceArchive.MAX_BYTES)throw fail(HttpStatus.PAYLOAD_TOO_LARGE,"수정본 크기 제한입니다.");
    }
    record ScanInput(long userId, String name, WorkspaceScanSnapshot provenance, List<SourceArchive.Entry> entries) implements AutoCloseable {
        @Override public void close() { entries.forEach(e -> Arrays.fill(e.bytes(), (byte) 0)); }
    }
    synchronized ScanInput captureScan(String id, long revision) {
        var state = owned(id);
        if (state.revision != revision) throw fail(HttpStatus.CONFLICT, "저장된 revision이 변경되었습니다. 최신 변경을 확인해 주세요.");
        var review = reviews.findAccessibleReviewWithVulnerabilities(state.review, "분석 결과에 접근할 수 없습니다.");
        var entries = currentEntries(state, true);
        var facts = fileFacts(state);
        var source = new WorkspaceScanSnapshot(1, id, state.user, state.review, revision, state.source, state.identity,
                manifest(entries), Instant.now(clock), null, "EXACT_GIT_COMMIT".equals(state.identity), facts, "",List.copyOf(state.exports));
        return new ScanInput(state.user, review.getProjectName(), source, entries);
    }
    synchronized <T> T whileScanLive(String id, java.util.function.Supplier<T> action) {
        owned(id);
        return action.get();
    }
    synchronized ProjectLifecycleGuard.Lease retainScanLease(String id) {
        return lifecycle.work(owned(id).project);
    }
    private List<SourceArchive.Entry> currentEntries(State state, boolean copy) {
        return state.files.stream().map(f -> new SourceArchive.Entry(f.original.path(), copy ? f.current().clone() : f.current(),
                f.original.directory(), f.original.mode())).toList();
    }
    public synchronized void delete(String id) {
        expire(); restore(users.currentUserId()); var state = states.get(id);
        if (state == null || state.user != users.currentUserId()) throw fail(HttpStatus.NOT_FOUND, "작업 공간이 없거나 만료되었습니다.");
        if(vault!=null)vault.delete(id,state.user,state.storeVersion);
        states.remove(id); state.clear();
    }
    private State owned(String id) {
        expire(); restore(users.currentUserId()); var state = states.get(id);
        if (state == null || state.user != users.currentUserId()) throw fail(HttpStatus.NOT_FOUND, "작업 공간이 없거나 만료되었습니다.");
        try { reviews.findAccessibleReviewWithVulnerabilities(state.review, "분석 결과에 접근할 수 없습니다."); }
        catch (SecureDeployException denied) {
            if (denied.getStatus() == HttpStatus.NOT_FOUND || denied.getStatus() == HttpStatus.FORBIDDEN) { states.remove(id); state.clear(); }
            throw denied;
        }
        return state;
    }
    private StoredFile file(State state, String id) {
        return state.files.stream().filter(f -> f.id.equals(id)).findFirst().orElseThrow(() -> fail(HttpStatus.NOT_FOUND, "파일에 접근할 수 없습니다."));
    }
    private Workspace describe(State state) {
        return new Workspace(state.id, state.review, state.revision, state.created, state.expires, state.source, state.identity,
                state.files.stream().map(f -> new FileInfo(f.id, f.original.path(), f.hash, f.original.bytes().length, f.original.directory(),
                        f.editable(), f.editable() ? null : (f.original.directory() ? "DIRECTORY" : "BINARY_SIZE_OR_ENCODING"), f.edit != null,f.changeOrigin,List.copyOf(f.provenance))).toList(),
                state.files.stream().filter(f -> f.edit != null).map(f -> f.id).toList(),List.copyOf(state.exports),vault!=null&&vault.enabled()?"ENCRYPTED_PERSISTENT":"MEMORY_TEMPORARY");
    }
    private void ensureHistory(State state,int count){if(state.files.stream().mapToInt(f->f.provenance.size()).sum()+count>1024)throw fail(HttpStatus.TOO_MANY_REQUESTS,"변경 출처 이력 한도에 도달했습니다. 현재 편집을 내보내고 새 작업을 시작하세요.");}
    private void record(State state,StoredFile file,String generator,String origin,String model,String proposal,String direction,String advice,boolean approved){file.provenance.add(new ChangeAttribution(state.revision,generator,origin,model,proposal,direction,advice,approved,state.user,Instant.now(clock),SourceArchive.hash(file.current())));}
    private List<WorkspaceScanSnapshot.File> fileFacts(State state){return state.files.stream().map(f->new WorkspaceScanSnapshot.File(f.id,f.original.path(),f.hash,SourceArchive.hash(f.current()),f.edit!=null,f.changeOrigin,List.copyOf(f.provenance))).toList();}
    static String provenanceHash(List<WorkspaceScanSnapshot.File> files){try{return SourceArchive.hash(new com.fasterxml.jackson.databind.ObjectMapper().findAndRegisterModules().writeValueAsBytes(files));}catch(IOException e){throw new IllegalArgumentException();}}
    private String patch(StoredFile file) throws IOException {
        if (file.edit == null) return "";
        return patch(file.original.path(),file.original.bytes(),file.edit,3);
    }
    private String patch(String path,byte[] oldBytes,byte[] newBytes,int context) throws IOException {
        var before = new RawText(oldBytes); var after = new RawText(newBytes);
        var edits = new HistogramDiff().diff(RawTextComparator.DEFAULT, before, after);
        var bytes = new ByteArrayOutputStream();
        String old = QuotedString.GIT_PATH.quote("a/" + path), next = QuotedString.GIT_PATH.quote("b/" + path);
        bytes.write(("diff --git " + old + " " + next + "\n--- " + old + "\n+++ " + next + "\n").getBytes(StandardCharsets.UTF_8));
        try (var formatter = new DiffFormatter(bytes)) { formatter.setContext(context);formatter.format(edits, before, after); formatter.flush(); }
        return bytes.toString(StandardCharsets.UTF_8);
    }
    private byte[] editedBytes(StoredFile file,String text) {
        if(text==null||text.length()>SourceArchive.EDIT_BYTES||text.contains("\ufeff"))throw SourceArchive.limit();
        String original=SourceArchive.text(file.original.bytes()),value=text.replace("\r\n","\n");
        if(value.contains("\r"))throw fail(HttpStatus.BAD_REQUEST,"지원하지 않는 줄바꿈입니다.");
        if(original.contains("\r\n"))value=value.replace("\n","\r\n");
        if(original.startsWith("\ufeff"))value="\ufeff"+value;
        try {
            var encoded=StandardCharsets.UTF_8.newEncoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(value));
            byte[] bytes=new byte[encoded.remaining()];encoded.get(bytes);
            if(SourceArchive.text(bytes)==null)throw SourceArchive.limit();return bytes;
        }catch(java.nio.charset.CharacterCodingException invalid){throw fail(HttpStatus.BAD_REQUEST,"유효한 UTF-8 텍스트만 저장할 수 있습니다.");}
    }
    private String manifest(List<SourceArchive.Entry> entries) {
        StringBuilder value = new StringBuilder();
        entries.stream().sorted(Comparator.comparing(SourceArchive.Entry::path)).forEach(e -> value.append(e.path()).append('\0')
                .append(e.directory()).append('\0').append(e.mode()).append('\0').append(SourceArchive.hash(e.bytes())).append('\n'));
        return SourceArchive.hash(value.toString().getBytes(StandardCharsets.UTF_8));
    }
    private void persist(State s) {
        if(vault==null||!vault.enabled())return;
        var snapshot=new WorkspaceVault.Snapshot(1,s.id,s.user,s.project,s.review,s.revision,s.created,s.expires,s.source,s.identity,
            s.files.stream().map(f->new WorkspaceVault.File(f.id,f.original.path(),f.original.bytes(),f.original.directory(),f.original.mode(),f.hash,f.edit,f.changeOrigin,List.copyOf(f.provenance))).toList(),List.copyOf(s.exports));
        try {s.storeVersion=vault.put(snapshot,s.storeVersion);}
        catch(RuntimeException failure){states.remove(s.id);s.clear();throw failure;}
    }
    private void restore(long user) {
        if(vault==null||!vault.enabled())return;
        var loaded=vault.owner(user,Instant.now(clock));
        var cached=states.values().stream().filter(s->s.user==user).findFirst().orElse(null);
        if(loaded.isEmpty()){if(cached!=null){states.remove(cached.id);cached.clear();}return;}
        var value=loaded.get();var s=value.snapshot();
        var review=reviews.findAccessibleReviewWithVulnerabilities(s.review(),"분석 결과에 접근할 수 없습니다.");
        if(review.getProject().getId()!=s.project())throw fail(HttpStatus.NOT_FOUND,"작업 공간에 접근할 수 없습니다.");
        if(cached!=null&&cached.id.equals(s.id())&&cached.storeVersion==value.version())return;
        if(cached!=null){states.remove(cached.id);cached.clear();}
        if(states.size()>=4)throw fail(HttpStatus.TOO_MANY_REQUESTS,"작업 공간이 가득 찼습니다.");
        var next=new State(value,lifecycle.work(s.project()));states.put(next.id,next);
    }
    private synchronized void expire() {
        var iterator = states.values().iterator();
        while (iterator.hasNext()) { var state = iterator.next(); if (!state.expires.isAfter(Instant.now(clock))) { iterator.remove(); state.clear(); } }
    }
    @PreDestroy public synchronized void shutdown() { closed = true; expiry.shutdownNow(); states.values().forEach(State::clear); states.clear(); }
    private SecureDeployException fail(HttpStatus status, String message) { return new SecureDeployException(status, message); }
}
