package com.securedeploy.ai.remediation;

import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class RemediationSanitizer {
    private static final String MASK = "<redacted>";
    private static final Pattern PRIVATE_KEY = Pattern.compile("-----BEGIN [^-]*PRIVATE KEY-----[\\s\\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)");
    private static final Pattern CREDENTIAL = Pattern.compile("(?i)\\b(?:sk-(?:proj-)?[a-z0-9_-]{8,}|gh[pousr]_[a-z0-9_]{8,}|github_pat_[a-z0-9_]{8,}|xox[baprs]-[a-z0-9-]{8,}|AKIA[A-Z0-9]{16}|AIza[a-z0-9_-]{20,}|eyJ[a-z0-9_-]+\\.[a-z0-9_-]+\\.[a-z0-9_-]+)\\b");
    private static final Pattern ASSIGNMENT = Pattern.compile("(?i)(?<![\\w.-])([\\w.-]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)[\\w.-]*[\\\"']?\\s*[:=]\\s*)(?:\"(?:\\\\.|[^\"\\\\])*+\"|'(?:\\\\.|[^'\\\\])*+'|[^\\s,;<>]++)");
    private static final Pattern LONG_VALUE = Pattern.compile("(?<![\\w])[-A-Za-z0-9_+/=]{32,}(?![\\w])");
    private static final Pattern STRING_LITERAL = Pattern.compile("\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|`(?:\\\\.|[^`\\\\])*`", Pattern.DOTALL);

    public String text(String value, int limit) {
        if (value == null) return null;
        String safe = PRIVATE_KEY.matcher(value).replaceAll(MASK);
        safe = CREDENTIAL.matcher(safe).replaceAll(MASK);
        safe = safe.replaceAll("(?i)(Bearer\\s+)[A-Za-z0-9._~+/-]+=*", "$1<redacted>");
        safe = ASSIGNMENT.matcher(safe).replaceAll(match -> {
            String valuePart = match.group().substring(match.group(1).length());
            if (valuePart.matches("[\\\"']?\\$\\{[A-Z_][A-Z_0-9]*}[\\\"']?"))
                return java.util.regex.Matcher.quoteReplacement(match.group());
            return java.util.regex.Matcher.quoteReplacement(match.group(1) + MASK);
        });
        safe = LONG_VALUE.matcher(safe).replaceAll(MASK);
        safe = safe.replaceAll("(?i)(https?://)[^/\\s:@]+:[^/\\s@]+@", "$1<redacted>@");
        return safe.length() <= limit ? safe : safe.substring(0, Math.max(0, limit - 10)) + " [omitted]";
    }

    public String snippet(String value) {
        // Literal values are unnecessary for a structural example. Redact before truncating,
        // including quoted low-entropy passwords which entropy-based detectors would miss.
        String safe = text(value, 20_000);
        return safe == null ? null : text(STRING_LITERAL.matcher(safe).replaceAll("\"<redacted>\""), 1_200);
    }

    public RemediationContent output(RemediationContent content) {
        return new RemediationContent(text(content.summary(), 600), text(content.whyItMatters(), 1_200),
                text(content.recommendedAction(), 1_600), text(content.codeExample(), 1_600),
                text(content.configurationExample(), 1_600), content.verificationSteps().stream()
                .limit(8).map(value -> text(value, 400)).toList(), text(content.caution(), 800),
                content.remediationConfidence());
    }
}
