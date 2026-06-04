package com.securedeploy.global.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;

public final class FileUtils {

    private FileUtils() {
    }

    public static void deleteRecursively(Path path) {
        if (path == null || Files.notExists(path)) {
            return;
        }

        try (var paths = Files.walk(path)) {
            paths.sorted(Comparator.reverseOrder())
                    .forEach(FileUtils::deleteIfExists);
        } catch (IOException ignored) {
            // Temporary cleanup should not hide the review result.
        }
    }

    private static void deleteIfExists(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // Best-effort cleanup.
        }
    }
}
