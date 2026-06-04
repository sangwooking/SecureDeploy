package com.securedeploy.rule.rules;

final class FrontendEvidenceSanitizer {

    private FrontendEvidenceSanitizer() {
    }

    static String maskSecrets(String evidence) {
        if (evidence == null) {
            return null;
        }
        return evidence
                .replaceAll("(?i)((?:vite[_-]?)?[a-z0-9_]*(?:api[_-]?key|secret|token)\s*=\s*)([^\s\"']+)", "$1<redacted>")
                .replaceAll("(?i)((?:api[_-]?key|secret|token|accessToken|refreshToken)\s*[:=]\s*[\"'])([^\"']+)([\"'])", "$1<redacted>$3")
                .replaceAll("(?i)((?:api[_-]?key|secret|token|accessToken|refreshToken)[\"']?\s*,\s*[\"'])([^\"']+)([\"'])", "$1<redacted>$3");
    }

    static boolean isDummyValue(String value) {
        if (value == null || value.isBlank()) {
            return true;
        }
        String normalized = value.trim().toLowerCase();
        return normalized.contains("localhost")
                || normalized.contains("dummy")
                || normalized.contains("example")
                || normalized.contains("changeme")
                || normalized.contains("change-me")
                || normalized.contains("test")
                || normalized.contains("your_")
                || normalized.contains("your-");
    }
}
