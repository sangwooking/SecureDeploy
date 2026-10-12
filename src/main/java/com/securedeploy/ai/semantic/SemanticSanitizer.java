package com.securedeploy.ai.semantic;

import com.securedeploy.ai.remediation.RemediationSanitizer;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class SemanticSanitizer {
    private static final Pattern LITERALS = Pattern.compile("\"\"\"[\\s\\S]*?\"\"\"|\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'", Pattern.DOTALL);
    private static final Pattern PEM = Pattern.compile("-----BEGIN [^-]*PRIVATE KEY-----[\\s\\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)");
    private final RemediationSanitizer sanitizer;
    public SemanticSanitizer(RemediationSanitizer sanitizer) { this.sanitizer = sanitizer; }
    public String text(String value, int limit) { return sanitizer.text(value, limit); }
    public String source(String source) {
        // Preserve original line numbers, including multi-line literals and PEM blocks.
        String masked = PEM.matcher(source).replaceAll(m -> mask(m.group()));
        masked = LITERALS.matcher(masked).replaceAll(m -> mask(m.group()));
        return masked.lines().map(line -> sanitizer.text(line, Math.max(100, line.length() + 20)))
                .collect(java.util.stream.Collectors.joining("\n"));
    }
    private static String mask(String value) {
        return "[REDACTED_SECRET]" + "\n".repeat((int) value.chars().filter(c -> c == '\n').count());
    }
}
