package com.securedeploy.editing;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.apache.commons.compress.archivers.zip.*;
import org.junit.jupiter.api.Test;

class SourceArchiveTest {
    byte[] zip(String[] names, byte[][] contents, int[] modes) throws Exception {
        var output = new ByteArrayOutputStream();
        try (var zip = new ZipArchiveOutputStream(output)) {
            for (int i = 0; i < names.length; i++) {
                var e = new ZipArchiveEntry(names[i]); if (modes != null) e.setUnixMode(modes[i]);
                zip.putArchiveEntry(e); zip.write(contents[i]); zip.closeArchiveEntry();
            }
        }
        return output.toByteArray();
    }
    List<SourceArchive.Entry> read(byte[] b) throws Exception { return SourceArchive.read(new ByteArrayInputStream(b)); }
    @Test void roundTripPreservesAllFilesIncludingBinaryAndIgnoredDirectories() throws Exception {
        var files = List.of(new SourceArchive.Entry("src/main.ts", "const x=1;\n".getBytes(StandardCharsets.UTF_8), false, 0100644),
                new SourceArchive.Entry("dist/image.bin", new byte[]{0, -1, 2}, false, 0100755));
        var result = read(SourceArchive.zip(files));
        assertEquals(2, result.size()); assertArrayEquals(files.get(1).bytes(), result.get(1).bytes());
        assertEquals(0100755, result.get(1).mode());
    }
    @Test void rejectsTraversalAbsoluteWindowsControlAndReservedNames() throws Exception {
        for (String name : List.of("../x", "/x", "a/../../x", "C:/x", "a\\x", "a/./x", "x\ny", ".git/config", "NUL.txt", "x ", "a//x")) {
            var output = new ByteArrayOutputStream();
            try (var zip = new java.util.zip.ZipOutputStream(output)) { zip.putNextEntry(new java.util.zip.ZipEntry(name)); zip.write(1); zip.closeEntry(); }
            byte[] data = output.toByteArray();
            assertThrows(RuntimeException.class, () -> read(data), name);
        }
    }
    @Test void rejectsDuplicateCaseUnicodeAndFileDirectoryCollisions() throws Exception {
        for (String[] names : List.of(new String[]{"a", "a"}, new String[]{"A", "a"}, new String[]{"é", "e\u0301"}, new String[]{"a", "a/b"})) {
            byte[] data = zip(names, new byte[][]{{1}, {2}}, null);
            assertThrows(RuntimeException.class, () -> read(data));
        }
    }
    @Test void rejectsSymlinkAndSpecialFiles() throws Exception {
        for (int mode : new int[]{0120777, 0010644, 0060644}) {
            byte[] bytes = zip(new String[]{"link"}, new byte[][]{"target".getBytes(StandardCharsets.UTF_8)}, new int[]{mode});
            assertThrows(RuntimeException.class, () -> read(bytes));
        }
    }
    @Test void rejectsCorruptionAndExcessExpandedSize() throws Exception {
        byte[] broken = zip(new String[]{"a"}, new byte[][]{{1,2,3}}, null);
        assertThrows(RuntimeException.class, () -> read(Arrays.copyOf(broken, broken.length - 3)));
        byte[] bomb = zip(new String[]{"big"}, new byte[][]{new byte[SourceArchive.MAX_BYTES + 1]}, null);
        assertThrows(RuntimeException.class, () -> read(bomb));
    }
    @Test void textLimitsRejectMalformedBinaryMixedNewlinesAndTooManyLines() {
        for (byte[] bytes : List.of(new byte[]{(byte) 0xc3, 0x28}, new byte[]{0, 1}, "a\r\nb\n".getBytes(StandardCharsets.UTF_8), new byte[SourceArchive.EDIT_BYTES + 1], "\n".repeat(10001).getBytes(StandardCharsets.UTF_8)))
            assertNull(SourceArchive.text(bytes));
        assertEquals("\ufeffa\r\n", SourceArchive.text("\ufeffa\r\n".getBytes(StandardCharsets.UTF_8)));
    }
}
