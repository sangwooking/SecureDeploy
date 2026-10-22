package com.securedeploy.editing;

import com.securedeploy.global.error.SecureDeployException;
import java.io.*;
import java.nio.*;
import java.nio.charset.*;
import java.security.*;
import java.text.Normalizer;
import java.util.*;
import java.util.zip.CRC32;
import org.apache.commons.compress.archivers.zip.*;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.springframework.http.HttpStatus;

/** Source bytes are never extracted to user-controlled filesystem paths. */
final class SourceArchive {
    static final int MAX_BYTES = 32 * 1024 * 1024, MAX_FILES = 5000, EDIT_BYTES = 256 * 1024;
    record Entry(String path, byte[] bytes, boolean directory, int mode) { }

    static List<Entry> read(InputStream input) throws IOException {
        byte[] archive = bounded(input, MAX_BYTES);
        // Reject ZIP64/multi-disk and excessive central-directory counts before parser allocation.
        int end = -1;
        for (int i = archive.length - 22; i >= Math.max(0, archive.length - 65557); i--) {
            if (le(archive, i, 4) == 0x06054b50L && i + 22 + le(archive, i + 20, 2) == archive.length) { end = i; break; }
        }
        if (end < 0 || le(archive, end + 4, 2) != 0 || le(archive, end + 6, 2) != 0
                || le(archive, end + 8, 2) != le(archive, end + 10, 2)
                || le(archive, end + 10, 2) > MAX_FILES || le(archive, end + 10, 2) == 0
                || le(archive, end + 12, 4) == 0xffffffffL || le(archive, end + 16, 4) == 0xffffffffL) throw invalid();
        var entries = new ArrayList<Entry>();
        long total = 0;
        long deadline = System.nanoTime() + 5_000_000_000L;
        try (var channel = new SeekableInMemoryByteChannel(archive);
             var zip = ZipFile.builder().setSeekableByteChannel(channel).get()) {
            var iterator = zip.getEntries();
            while (iterator.hasMoreElements()) {
                if (System.nanoTime() > deadline || entries.size() >= MAX_FILES) throw limit();
                var e = iterator.nextElement();
                for (byte b : e.getRawName()) if (b == '\\' || b == 0) throw invalid();
                String path = safePath(e.getName(), e.isDirectory());
                int type = e.getUnixMode() & 0170000;
                if (e.isUnixSymlink() || (type != 0 && type != 0100000 && type != 0040000)
                        || e.getGeneralPurposeBit().usesEncryption() || (e.getMethod() != 0 && e.getMethod() != 8)
                        || !zip.canReadEntryData(e) || e.getSize() < 0 || e.getSize() > MAX_BYTES - total) throw invalid();
                byte[] bytes;
                try (var stream = zip.getInputStream(e)) { bytes = bounded(stream, (int) (MAX_BYTES - total)); }
                var crc = new CRC32(); crc.update(bytes);
                if (bytes.length != e.getSize() || crc.getValue() != e.getCrc() || (e.isDirectory() && bytes.length != 0)) throw invalid();
                total += bytes.length;
                entries.add(new Entry(path, bytes, e.isDirectory(), e.getUnixMode()));
            }
        } catch (SecureDeployException rejected) { throw rejected; }
        catch (RuntimeException | IOException bad) { throw invalid(); }
        if (entries.size() != le(archive, end + 10, 2)) throw invalid();
        validate(entries);
        return List.copyOf(entries);
    }

    static void validate(List<Entry> entries) {
        if (entries.isEmpty() || entries.size() > MAX_FILES) throw invalid();
        var paths = new HashMap<String, Boolean>();
        long bytes = 0;
        for (var e : entries) {
            safePath(e.path(), e.directory());
            String key = Normalizer.normalize(e.path(), Normalizer.Form.NFC).toLowerCase(Locale.ROOT);
            if (paths.putIfAbsent(key, e.directory()) != null) throw invalid();
            bytes += e.bytes().length;
            if (bytes > MAX_BYTES) throw limit();
        }
        for (String p : paths.keySet()) {
            for (int slash = p.indexOf('/'); slash >= 0; slash = p.indexOf('/', slash + 1)) {
                if (Boolean.FALSE.equals(paths.get(p.substring(0, slash)))) throw invalid();
            }
        }
    }

    static String safePath(String raw, boolean directory) {
        String name = directory && raw.endsWith("/") ? raw.substring(0, raw.length() - 1) : raw;
        if (name.isEmpty() || name.length() > 512 || name.startsWith("/") || name.contains("\\")
                || name.chars().anyMatch(c -> c < 32 || c == 127 || c == ':' || c == '"')) throw invalid();
        for (String segment : name.split("/", -1)) {
            if (segment.isEmpty() || segment.equals(".") || segment.equals("..") || segment.equalsIgnoreCase(".git")
                    || segment.endsWith(".") || segment.endsWith(" ")
                    || segment.matches("(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\\..*)?")) throw invalid();
        }
        return name;
    }

    static byte[] zip(List<Entry> entries) throws IOException {
        validate(entries);
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipArchiveOutputStream(bytes)) {
            for (var e : entries) {
                var target = new ZipArchiveEntry(e.path() + (e.directory() ? "/" : ""));
                if (e.mode() != 0) target.setUnixMode(e.mode());
                target.setTime(0); zip.putArchiveEntry(target); zip.write(e.bytes()); zip.closeArchiveEntry();
            }
        }
        return bytes.toByteArray();
    }

    static String text(byte[] bytes) {
        if (bytes.length > EDIT_BYTES) return null;
        try {
            String value = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            if (value.chars().anyMatch(c -> (c < 32 && c != '\t' && c != '\n' && c != '\r') || c == 127)) return null;
            if (value.chars().filter(c -> c == '\n').count() > 10000) return null;
            String withoutCrLf = value.replace("\r\n", "");
            if (withoutCrLf.contains("\r") || (value.contains("\r\n") && withoutCrLf.contains("\n"))) return null;
            return value;
        } catch (CharacterCodingException invalid) { return null; }
    }
    static String hash(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
    static byte[] bounded(InputStream stream, int max) throws IOException {
        var output = new ByteArrayOutputStream(Math.min(max, 8192));
        byte[] buffer = new byte[8192]; int n;
        while ((n = stream.read(buffer)) != -1) { if (n > max - output.size()) throw limit(); output.write(buffer, 0, n); }
        return output.toByteArray();
    }
    private static long le(byte[] b, int start, int size) {
        long value = 0; for (int i = 0; i < size; i++) value |= (long) (b[start + i] & 255) << (8 * i); return value;
    }
    static SecureDeployException invalid() { return new SecureDeployException(HttpStatus.BAD_REQUEST, "원본에 지원하지 않는 ZIP 형식·경로·링크 또는 충돌이 있습니다. 안전한 ZIP으로 다시 준비해 주세요."); }
    static SecureDeployException limit() { return new SecureDeployException(HttpStatus.PAYLOAD_TOO_LARGE, "수정 작업 공간의 파일 수 또는 크기 제한을 초과했습니다."); }
}
