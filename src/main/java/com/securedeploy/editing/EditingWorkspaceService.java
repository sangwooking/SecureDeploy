package com.securedeploy.editing;

import com.securedeploy.auth.service.*;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.ReviewEntity;
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
    public record FileInfo(String id, String path, String originalHash, int size, boolean directory,
                           boolean editable, String readOnlyReason, boolean changed) { }
    public record Workspace(String id, long reviewId, long revision, Instant createdAt, Instant expiresAt, String sourceRevision,
                            String identityStatus, List<FileInfo> files, List<String> changedFileIds) { }
    public record Content(String fileId, long revision, String originalHash, String currentHash, String text, String newline, boolean bom) { }
    public record Change(long revision, String originalHash, String text) { }
    public record Approval(long revision, List<String> changedFileIds, boolean approved) { }
    public record Difference(long revision, String fileId, String originalHash, String patch) { }
    public record Download(byte[] bytes, String filename, String type) { }
    private static final class StoredFile {
        final String id = UUID.randomUUID().toString();
        final SourceArchive.Entry original;
        final String hash;
        byte[] edit;
        StoredFile(SourceArchive.Entry entry) { original = entry; hash = SourceArchive.hash(entry.bytes()); }
        byte[] current() { return edit == null ? original.bytes() : edit; }
        boolean editable() { return !original.directory() && SourceArchive.text(original.bytes()) != null; }
        void clear() { Arrays.fill(original.bytes(), (byte) 0); if (edit != null) Arrays.fill(edit, (byte) 0); }
    }
    private static final class State {
        final String id = UUID.randomUUID().toString();
        final long user, review;
        final Instant created, expires;
        final String source, identity;
        final List<StoredFile> files;
        final Map<String,WorkspacePatch.Session> patches = new LinkedHashMap<>();
        long revision = 1;
        State(long user, long review, Instant now, String source, String identity, List<SourceArchive.Entry> entries) {
            this.user = user; this.review = review; this.created = now; this.expires = now.plusSeconds(1800);
            this.source = source; this.identity = identity;
            this.files = entries.stream().sorted(Comparator.comparing(SourceArchive.Entry::path)).map(StoredFile::new).toList();
        }
        void clear() { files.forEach(StoredFile::clear); patches.clear(); }
    }
    private final Map<String, State> states = new HashMap<>();
    private final Set<Long> creating = new HashSet<>();
    private final ReviewAccessService reviews;
    private final CurrentUserService users;
    private final EditingSourceService sources;
    private final Clock clock;
    private final ScheduledExecutorService expiry;

    @org.springframework.beans.factory.annotation.Autowired
    public EditingWorkspaceService(ReviewAccessService reviews, CurrentUserService users, EditingSourceService sources) {
        this(reviews, users, sources, Clock.systemUTC());
    }
    EditingWorkspaceService(ReviewAccessService reviews, CurrentUserService users, EditingSourceService sources, Clock clock) {
        this.reviews = reviews; this.users = users; this.sources = sources; this.clock = clock;
        expiry = Executors.newSingleThreadScheduledExecutor(r -> { var t = new Thread(r, "editing-expiry"); t.setDaemon(true); return t; });
        expiry.scheduleWithFixedDelay(this::expire, 15, 15, TimeUnit.SECONDS);
    }
    public Workspace create(long reviewId, MultipartFile zip) throws IOException {
        long user = users.currentUserId();
        var review = reviews.findAccessibleReviewWithVulnerabilities(reviewId, "분석 결과에 접근할 수 없습니다.");
        synchronized (this) {
            expire();
            if (creating.contains(user) || states.values().stream().anyMatch(s -> s.user == user))
                throw fail(HttpStatus.CONFLICT, "열려 있는 수정 작업 공간을 먼저 닫아 주세요.");
            if (states.size() + creating.size() >= 4) throw fail(HttpStatus.TOO_MANY_REQUESTS, "작업 공간이 가득 찼습니다. 잠시 후 다시 시도해 주세요.");
            creating.add(user);
        }
        List<SourceArchive.Entry> entries = null;
        boolean complete = false;
        try {
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
            var state = new State(user, reviewId, Instant.now(clock), source, identity, entries);
            synchronized (this) { states.put(state.id, state); }
            complete = true;
            return describe(state);
        } finally {
            synchronized (this) { creating.remove(user); }
            if (!complete && entries != null) entries.forEach(e -> Arrays.fill(e.bytes(), (byte) 0));
        }
    }
    public synchronized Workspace get(String id) { return describe(owned(id)); }
    public synchronized Content content(String id, String fileId) {
        var state = owned(id); var file = file(state, fileId);
        if (!file.editable()) throw fail(HttpStatus.UNPROCESSABLE_ENTITY, "바이너리·대용량·불명확한 인코딩 파일은 편집할 수 없습니다.");
        String text = SourceArchive.text(file.current());
        boolean bom = text.startsWith("\ufeff");
        return new Content(file.id, state.revision, file.hash, SourceArchive.hash(file.current()), bom ? text.substring(1) : text,
                text.contains("\r\n") ? "CRLF" : "LF", bom);
    }
    public synchronized Workspace save(String id, String fileId, Change change, boolean revert) {
        var state = owned(id); var file = file(state, fileId);
        if (change == null || change.revision() != state.revision || !file.hash.equals(change.originalHash()))
            throw fail(HttpStatus.CONFLICT, "다른 탭에서 변경되었거나 원본 해시가 다릅니다. 최신 내용을 다시 불러와 주세요.");
        if (!file.editable()) throw fail(HttpStatus.UNPROCESSABLE_ENTITY, "이 파일은 읽기 전용입니다.");
        byte[] bytes = null;
        if (!revert) {
            bytes=editedBytes(file,change.text());
            if (Arrays.equals(bytes, file.original.bytes())) bytes = null;
        }
        long size = state.patches.size() * 65536L;
        for (var item : state.files) size += item.original.bytes().length + (item == file ? (bytes == null ? 0 : bytes.length) : (item.edit == null ? 0 : item.edit.length));
        if (size > SourceArchive.MAX_BYTES) throw SourceArchive.limit();
        if (file.edit != null) Arrays.fill(file.edit, (byte) 0);
        file.edit = bytes; state.revision++;
        return describe(state);
    }
    public synchronized Difference diff(String id, String fileId) throws IOException {
        var state = owned(id); var file = file(state, fileId);
        return new Difference(state.revision, file.id, file.hash, patch(file));
    }
    public synchronized WorkspacePatch.View preparePatch(String id, WorkspacePatch.Prepare request, WorkspacePatch.Provider provider) {
        var state=owned(id);
        if(!"EXACT_GIT_COMMIT".equals(state.identity))throw fail(HttpStatus.CONFLICT,"원본 일치 미검증 ZIP에는 AI 패치를 연결할 수 없습니다. 수동 편집 후 새 분석이 필요합니다.");
        if(!provider.available())throw fail(HttpStatus.SERVICE_UNAVAILABLE,"AI 수정 Provider가 준비되지 않았습니다. 수동 편집과 기존 가이드는 계속 사용할 수 있습니다.");
        var file=file(state,request.fileId());
        if(!file.editable()||request.revision()!=state.revision||!file.hash.equals(request.originalHash())
                || !SourceArchive.hash(file.current()).equals(request.currentHash()))throw fail(HttpStatus.CONFLICT,"현재 파일 해시 또는 revision이 다릅니다. 다시 불러와 주세요.");
        var review=reviews.findAccessibleReviewWithVulnerabilities(state.review,"분석 결과에 접근할 수 없습니다.");
        var finding=review.getVulnerabilities().stream().filter(v->v.getId()!=null&&v.getId()==request.findingId()).findFirst()
                .orElseThrow(()->fail(HttpStatus.NOT_FOUND,"연결된 Finding을 확인할 수 없습니다."));
        if(!file.original.path().equals(finding.getFilePath()))throw fail(HttpStatus.CONFLICT,"Finding과 현재 파일의 연결을 확인할 수 없습니다.");
        if(state.patches.size()>=3)throw fail(HttpStatus.TOO_MANY_REQUESTS,"한 작업 공간에서는 수정 제안을 최대 3개까지 준비할 수 있습니다.");
        long retained=state.files.stream().mapToLong(f->f.original.bytes().length+(f.edit==null?0:f.edit.length)).sum();
        if(retained+(state.patches.size()+1)*65536L>SourceArchive.MAX_BYTES)throw SourceArchive.limit();
        try {
            var target=WorkspacePatch.target(SourceArchive.text(file.original.bytes()),SourceArchive.text(file.current()),finding.getLine(),finding.getRuleId(),file.original.path());
            var sanitizer=new com.securedeploy.ai.remediation.RemediationSanitizer();
            for(String text:List.of(target.before(),file.original.path()))
                if(!text.equals(sanitizer.text(text,1024)))throw new IllegalArgumentException();
            String current=WorkspacePatch.normalize(SourceArchive.text(file.current()));
            String candidate=current.substring(0,target.offset())+target.after()+current.substring(target.offset()+target.before().length());
            String diff=patch(file.original.path(),file.current(),editedBytes(file,candidate),0);
            var session=new WorkspacePatch.Session(request,finding.getRuleId(),state.source,request.currentHash(),target.line(),target.offset(),target.before(),target.after(),diff,provider);
            state.patches.put(session.id,session);return patchView(state,session,false);
        }catch(IllegalArgumentException | IOException unsupported){throw fail(HttpStatus.UNPROCESSABLE_ENTITY,"단순한 상수 설정 한 줄의 위치와 변경 근거를 확인할 수 없습니다. 민감정보·중복 설정·동적 값은 전송하지 않으며 수동 검토가 필요합니다.");}
    }
    public synchronized List<WorkspacePatch.View> patches(String id) {
        var state=owned(id);return state.patches.values().stream().map(p->{refreshPatch(state,p);return patchView(state,p,false);}).toList();
    }
    public synchronized WorkspacePatch.View patch(String id,String proposal) {
        var state=owned(id);return patchView(state,patchOwned(state,proposal),false);
    }
    synchronized WorkspacePatch.View beginPatch(String id,String proposal,WorkspacePatch.Consent consent,WorkspacePatch.Provider provider) {
        var state=owned(id);var session=patchOwned(state,proposal);
        if(!"APPROVAL_REQUIRED".equals(session.state)||consent==null||!consent.consented()||consent.revision()!=session.revision
                ||!session.currentHash.equals(consent.currentHash())||!session.provider.equals(provider))throw fail(HttpStatus.CONFLICT,"전송 동의가 없거나 코드·Provider·revision이 변경되었습니다. 새 제안을 준비해 주세요.");
        session.state="GENERATING";session.explanation="동의한 설정 한 줄만 전송합니다. 아직 파일은 변경되지 않았습니다.";
        return patchView(state,session,true);
    }
    synchronized WorkspacePatch.View finishPatch(String id,String proposal,WorkspacePatch.Output output,String failure) {
        var state=owned(id);var session=patchOwned(state,proposal);
        if(!"GENERATING".equals(session.state))return patchView(state,session,false);
        if(failure!=null){session.state=failure;session.explanation="수정 제안을 생성하거나 검증하지 못했습니다. 코드 변경은 없으며 수동 편집할 수 있습니다.";}
        else {
            try {
                WorkspacePatch.validate(output,patchView(state,session,true));
                session.state=output.decision().equals("PATCH")?"PROPOSED":"NEEDS_REVIEW";
                session.explanation=output.explanation();session.checks=List.copyOf(output.verificationSteps());
                var limits=new ArrayList<>(session.limits);limits.addAll(output.limitations());session.limits=List.copyOf(limits);
            }catch(RuntimeException invalid){session.state="INVALID";session.explanation="허용된 설정 변경과 일치하지 않는 AI 응답을 거부했습니다. 파일은 변경되지 않았습니다.";}
        }
        return patchView(state,session,false);
    }
    public synchronized WorkspacePatch.View rejectPatch(String id,String proposal) {
        var state=owned(id);var session=patchOwned(state,proposal);
        if(!Set.of("APPROVAL_REQUIRED","GENERATING","PROPOSED","NEEDS_REVIEW").contains(session.state))throw fail(HttpStatus.CONFLICT,"이미 종료된 제안입니다.");
        session.state="REJECTED";session.explanation="사용자가 제안을 거절했습니다. 파일은 변경되지 않았습니다. 이미 전송한 외부 요청의 처리·요금 취소는 보증하지 않습니다.";
        return patchView(state,session,false);
    }
    public synchronized Workspace applyPatch(String id,String proposal,WorkspacePatch.Decision decision) {
        var state=owned(id);var session=patchOwned(state,proposal);
        if(!"PROPOSED".equals(session.state)||decision==null||!decision.approved()||decision.revision()!=state.revision
                ||!session.currentHash.equals(decision.currentHash()))throw fail(HttpStatus.CONFLICT,"적용 승인이 없거나 제안이 오래되었습니다. 최신 코드를 확인해 주세요.");
        var file=file(state,session.fileId);String current=WorkspacePatch.normalize(SourceArchive.text(file.current()));
        if(!current.regionMatches(session.offset,session.before,0,session.before.length()))throw fail(HttpStatus.CONFLICT,"예상한 변경 위치가 다릅니다.");
        String updated=current.substring(0,session.offset)+session.after+current.substring(session.offset+session.before.length());
        var next=save(id,file.id,new Change(state.revision,file.hash,updated),false);
        session.state="ACCEPTED";return next;
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
                p.before,show?p.after:null,show?p.diff:null,p.provider,p.explanation,p.checks,p.limits);
    }
    public synchronized Download download(String id, String format, Approval approval) throws IOException {
        var state = owned(id);
        var changed = state.files.stream().filter(f -> f.edit != null).map(f -> f.id).toList();
        if (approval == null || !approval.approved() || approval.revision() != state.revision
                || !changed.equals(approval.changedFileIds())) throw fail(HttpStatus.CONFLICT, "현재 revision과 변경 목록을 확인하고 다시 승인해 주세요.");
        if (changed.isEmpty()) throw fail(HttpStatus.CONFLICT, "다운로드할 변경 사항이 없습니다.");
        if ("zip".equals(format)) {
            var entries = state.files.stream().map(f -> new SourceArchive.Entry(f.original.path(), f.current(), f.original.directory(), f.original.mode())).toList();
            return new Download(SourceArchive.zip(entries), "securedeploy-edited-r" + state.revision + ".zip", "application/zip");
        }
        if ("patch".equals(format)) {
            var output = new ByteArrayOutputStream();
            for (var f : state.files) if (f.edit != null) output.write(patch(f).getBytes(StandardCharsets.UTF_8));
            return new Download(output.toByteArray(), "securedeploy-edited-r" + state.revision + ".patch", "text/x-diff;charset=UTF-8");
        }
        throw fail(HttpStatus.BAD_REQUEST, "지원하지 않는 내보내기 형식입니다.");
    }
    public synchronized void delete(String id) {
        expire(); var state = states.get(id);
        if (state == null || state.user != users.currentUserId()) throw fail(HttpStatus.NOT_FOUND, "작업 공간이 없거나 만료되었습니다.");
        states.remove(id); state.clear();
    }
    private State owned(String id) {
        expire(); var state = states.get(id);
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
                        f.editable(), f.editable() ? null : (f.original.directory() ? "DIRECTORY" : "BINARY_SIZE_OR_ENCODING"), f.edit != null)).toList(),
                state.files.stream().filter(f -> f.edit != null).map(f -> f.id).toList());
    }
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
                .append(e.directory()).append('\0').append(SourceArchive.hash(e.bytes())).append('\n'));
        return SourceArchive.hash(value.toString().getBytes(StandardCharsets.UTF_8));
    }
    private synchronized void expire() {
        var iterator = states.values().iterator();
        while (iterator.hasNext()) { var state = iterator.next(); if (!state.expires.isAfter(Instant.now(clock))) { iterator.remove(); state.clear(); } }
    }
    @PreDestroy public synchronized void shutdown() { expiry.shutdownNow(); states.values().forEach(State::clear); states.clear(); }
    private SecureDeployException fail(HttpStatus status, String message) { return new SecureDeployException(status, message); }
}
