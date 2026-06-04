package com.securedeploy.rule.rules;

final class DevOpsEvidenceSanitizer {

    private DevOpsEvidenceSanitizer() {
    }

    static String maskSecrets(String evidence) {
        if (evidence == null) {
            return null;
        }
        return evidence
                .replaceAll("(?i)((?:password|token|secret|api[_-]?key|private[_-]?key)\s*[:=]\s*)([^\s\"']+)", "$1<redacted>")
                .replaceAll("(?i)((?:PASSWORD|TOKEN|SECRET|API_KEY|PRIVATE_KEY)\s+)([^\s\"']+)", "$1<redacted>")
                .replaceAll("(?i)((?:password|token|secret|api[_-]?key|private[_-]?key)[\"']?\s*:\s*[\"'])([^\"']+)([\"'])", "$1<redacted>$3");
    }
}
