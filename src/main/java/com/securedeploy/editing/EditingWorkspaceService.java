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
    public record Content(String fileId, long revision, String originalHash, String text, String newline, boolean bom) { }
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
        long revision = 1;
        State(long user, long review, Instant now, String source, String identity, List<SourceArchive.Entry> entries) {
            this.user = user; this.review = review; this.created = now; this.expires = now.plusSeconds(1800);
            this.source = source; this.identity = identity;
            this.files = entries.stream().sorted(Comparator.comparing(SourceArchive.Entry::path)).map(StoredFile::new).toList();
        }
        void clear() { files.forEach(StoredFile::clear); }
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
        return new Content(file.id, state.revision, file.hash, bom ? text.substring(1) : text,
                text.contains("\r\n") ? "CRLF" : "LF", bom);
    }
    public synchronized Workspace save(String id, String fileId, Change change, boolean revert) {
        var state = owned(id); var file = file(state, fileId);
        if (change == null || change.revision() != state.revision || !file.hash.equals(change.originalHash()))
            throw fail(HttpStatus.CONFLICT, "다른 탭에서 변경되었거나 원본 해시가 다릅니다. 최신 내용을 다시 불러와 주세요.");
        if (!file.editable()) throw fail(HttpStatus.UNPROCESSABLE_ENTITY, "이 파일은 읽기 전용입니다.");
        byte[] bytes = null;
        if (!revert) {
            if (change.text() == null || change.text().length() > SourceArchive.EDIT_BYTES || change.text().contains("\ufeff")) throw SourceArchive.limit();
            String original = SourceArchive.text(file.original.bytes());
            String value = change.text().replace("\r\n", "\n");
            if (value.contains("\r")) throw fail(HttpStatus.BAD_REQUEST, "지원하지 않는 줄바꿈입니다.");
            if (original.contains("\r\n")) value = value.replace("\n", "\r\n");
            if (original.startsWith("\ufeff")) value = "\ufeff" + value;
            try {
                var encoded = StandardCharsets.UTF_8.newEncoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                        .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(value));
                bytes = new byte[encoded.remaining()]; encoded.get(bytes);
            } catch (java.nio.charset.CharacterCodingException invalid) { throw fail(HttpStatus.BAD_REQUEST, "유효한 UTF-8 텍스트만 저장할 수 있습니다."); }
            if (SourceArchive.text(bytes) == null) throw SourceArchive.limit();
            if (Arrays.equals(bytes, file.original.bytes())) bytes = null;
        }
        long size = 0;
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
        var before = new RawText(file.original.bytes()); var after = new RawText(file.edit);
        var edits = new HistogramDiff().diff(RawTextComparator.DEFAULT, before, after);
        var bytes = new ByteArrayOutputStream();
        String old = QuotedString.GIT_PATH.quote("a/" + file.original.path()), next = QuotedString.GIT_PATH.quote("b/" + file.original.path());
        bytes.write(("diff --git " + old + " " + next + "\n--- " + old + "\n+++ " + next + "\n").getBytes(StandardCharsets.UTF_8));
        try (var formatter = new DiffFormatter(bytes)) { formatter.format(edits, before, after); formatter.flush(); }
        return bytes.toString(StandardCharsets.UTF_8);
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
