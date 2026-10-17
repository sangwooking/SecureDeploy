package com.securedeploy.sca.parser;

import java.util.Locale;
import java.util.Set;

public final class PythonManifestFiles {
    private PythonManifestFiles() { }
    public static boolean isRequirements(String path) {
        String lower = path.replace('\\', '/').toLowerCase(Locale.ROOT);
        String name = name(lower);
        return name.matches("(?:requirements|constraints)(?:[-_.][a-z0-9_.-]+)?\\.(?:txt|in)")
                || (lower.contains("/requirements/") || lower.startsWith("requirements/")) && name.matches("[a-z0-9_.-]+\\.(?:txt|in)");
    }
    public static boolean isUnsupported(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        return Set.of("poetry.lock", "pipfile", "pipfile.lock", "uv.lock", "setup.cfg").contains(lower)
                || lower.matches("pylock(?:\\.[a-z0-9_-]+)?\\.toml");
    }
    public static boolean isPython(String path) {
        return isRequirements(path) || name(path).equalsIgnoreCase("pyproject.toml") || isUnsupported(name(path));
    }
    public static String name(String path) { return path.substring(path.lastIndexOf('/') + 1); }
}
