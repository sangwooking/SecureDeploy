package com.securedeploy.sca.parser;

import com.securedeploy.sca.model.VersionResolution;
import java.util.*;
import java.util.regex.Pattern;

/** A deliberately bounded subset of PEP 508; unsupported syntax is never an exact registry version. */
public record PythonRequirement(String name, String version, VersionResolution resolution, String specifier,
        List<String> extras, String markerStatus, List<String> markerVariables, String issue) {
    private static final String NAME = "[A-Za-z0-9](?:[A-Za-z0-9._-]{0,198}[A-Za-z0-9])?";
    private static final Pattern REQUIREMENT = Pattern.compile("^(" + NAME + ")(?:\\s*\\[([^]]*)])?\\s*(.*)$");
    private static final Pattern SPEC = Pattern.compile("(===|~=|==|!=|<=|>=|<|>)\\s*([A-Za-z0-9.!+*_-]+)");
    private static final Pattern EXACT = Pattern.compile("(?:[0-9]+!)?[0-9]+(?:\\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\\.post[0-9]+)?(?:\\.dev[0-9]+)?");
    private static final Set<String> VARIABLES = Set.of("python_version", "python_full_version", "os_name", "sys_platform",
            "platform_release", "platform_system", "platform_version", "platform_machine", "platform_python_implementation",
            "implementation_name", "implementation_version", "extra");
    public static String normalizeName(String name) {
        return name != null && name.matches(NAME) ? name.toLowerCase(Locale.ROOT).replaceAll("[-_.]+", "-") : null;
    }
    public static String exactVersion(String value) {
        if (value == null || value.length() > 128 || !EXACT.matcher(value).matches()) return null;
        // Require canonical numeric segments rather than guessing equivalence for arbitrary legacy versions.
        if (Pattern.compile("(?:^|[.!]|a|b|rc|post|dev)0[0-9]").matcher(value).find()) return null;
        return value;
    }
    public static PythonRequirement parse(String text) {
        if (text.length() > 4096) return unknown(null, "REQUIREMENT_LENGTH_LIMIT");
        if (text.strip().matches("(?i)^(?:git\\+|https?://|ssh://|file:|hg\\+|svn\\+|bzr\\+).*$")) return unknown(null, "NON_REGISTRY_REFERENCE");
        var match = REQUIREMENT.matcher(text.strip());
        if (!match.matches()) return unknown(null, "UNSUPPORTED_OR_INVALID_REQUIREMENT");
        String name = normalizeName(match.group(1));
        List<String> extras = new ArrayList<>();
        if (match.group(2) != null && !match.group(2).isBlank()) {
            for (String extra : match.group(2).split(",", -1)) {
                String normalized = normalizeName(extra.strip());
                if (normalized == null || extras.size() >= 20) return unknown(name, "INVALID_EXTRAS");
                extras.add(normalized);
            }
        }
        String remaining = match.group(3).strip();
        if (remaining.startsWith("@") || remaining.contains("://") || remaining.contains("${")) return unknown(name, "NON_REGISTRY_REFERENCE");
        String[] parts = remaining.split(";", 2);
        String markerStatus = "NONE"; List<String> variables = List.of();
        if (parts.length == 2) {
            variables = markerVariables(parts[1]);
            if (variables == null) return unknown(name, "UNSUPPORTED_OR_INVALID_MARKER");
            markerStatus = "CONDITIONAL_NOT_EVALUATED";
        }
        String spec = parts[0].strip();
        if (spec.startsWith("(") && spec.endsWith(")")) spec = spec.substring(1, spec.length() - 1).strip();
        String version = null; VersionResolution resolution = VersionResolution.UNRESOLVED;
        if (!spec.isEmpty()) {
            String[] entries = spec.split(",", -1); List<String> clean = new ArrayList<>();
            for (String entry : entries) {
                var constraint = SPEC.matcher(entry.strip());
                if (!constraint.matches()) return unknown(name, "UNSUPPORTED_OR_INVALID_SPECIFIER");
                String op = constraint.group(1), value = constraint.group(2);
                boolean prefix = (op.equals("==") || op.equals("!=")) && value.matches("[0-9]+(?:\\.[0-9]+)*\\.\\*");
                if (op.equals("===") || (!prefix && exactVersion(value) == null)
                        || (op.equals("~=") && !value.matches("[0-9]+\\.[0-9]+(?:\\.[0-9]+)*"))) {
                    return unknown(name, "UNSUPPORTED_VERSION_SEMANTICS");
                }
                clean.add(op + value);
                if (entries.length == 1 && op.equals("==") && !prefix) { version = value; resolution = VersionResolution.EXACT; }
            }
            spec = String.join(",", clean);
            if (version == null) { version = spec; resolution = VersionResolution.RANGE; }
        }
        return new PythonRequirement(name, version, resolution, spec.isEmpty() ? null : spec, List.copyOf(extras), markerStatus, variables, null);
    }
    public static PythonRequirement unknown(String name, String reason) {
        return new PythonRequirement(name == null ? "<unresolved-package>" : name, null, VersionResolution.UNRESOLVED,
                null, List.of(), "UNKNOWN", List.of(), reason);
    }

    // Validate simple comparisons/boolean composition, but never evaluate using the scanner host's environment.
    private static List<String> markerVariables(String value) {
        if (value.length() > 512) return null;
        var token = Pattern.compile("\\s*(?:(\\()|(\\))|((?:===|~=|==|!=|<=|>=|<|>))|('(?:[^'\\\\\\r\\n])*'|\"(?:[^\"\\\\\\r\\n])*\")|([a-z_]+))").matcher(value);
        List<String> tokens = new ArrayList<>(); int end = 0;
        while (token.find()) {
            if (token.start() != end || tokens.size() >= 80) return null;
            tokens.add(token.group().strip()); end = token.end();
        }
        if (!value.substring(end).isBlank() || tokens.isEmpty()) return null;
        try {
            var parser = new Marker(tokens); parser.expression(0);
            return parser.position == tokens.size() ? List.copyOf(parser.variables) : null;
        } catch (IllegalArgumentException invalid) { return null; }
    }
    private static final class Marker {
        final List<String> tokens; final Set<String> variables = new LinkedHashSet<>(); int position;
        Marker(List<String> tokens) { this.tokens = tokens; }
        String next() { if (position >= tokens.size()) throw new IllegalArgumentException(); return tokens.get(position++); }
        void expression(int depth) {
            if (depth > 8) throw new IllegalArgumentException();
            atom(depth);
            while (position < tokens.size() && Set.of("and", "or").contains(tokens.get(position))) { position++; atom(depth); }
        }
        void atom(int depth) {
            if (position < tokens.size() && tokens.get(position).equals("(")) {
                position++; expression(depth + 1); if (!next().equals(")")) throw new IllegalArgumentException(); return;
            }
            boolean left = operand(next()); String op = next();
            if (op.equals("not")) op += " " + next();
            if (!Set.of("==", "!=", "<=", ">=", "<", ">", "~=", "===", "in", "not in").contains(op)) throw new IllegalArgumentException();
            boolean right = operand(next()); if (left == right) throw new IllegalArgumentException();
        }
        boolean operand(String token) {
            if (VARIABLES.contains(token)) { variables.add(token); return true; }
            if (token.startsWith("'") || token.startsWith("\"")) return false;
            throw new IllegalArgumentException();
        }
    }
}
