package com.securedeploy.sca.parser;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.sca.model.*;
import java.util.*;
import java.util.regex.*;

public class GradleManifestParser {
    private static final String CONFIG = "(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|annotationProcessor|compile|runtime)";
    private static final Pattern LITERAL = Pattern.compile("\\b" + CONFIG + "\\s*(?:\\(\\s*)?[\"']([^\"'\\r\\n]+)[\"']");
    private static final Pattern MAP = Pattern.compile("\\b" + CONFIG + "\\s*(?:\\(\\s*)?group\\s*:\\s*[\"']([^\"']+)[\"']\\s*,\\s*name\\s*:\\s*[\"']([^\"']+)[\"'](?:\\s*,\\s*version\\s*:\\s*[\"']([^\"']+)[\"'])?");
    private static final Pattern OTHER = Pattern.compile("\\b" + CONFIG + "\\s*(?:\\(\\s*)?([A-Za-z_][A-Za-z0-9_.]*)");

    public List<DependencyComponent> parse(ProjectFile file) {
        List<DependencyComponent> result = new ArrayList<>();
        String input = stripComments(String.join("\n", file.lines()));
        int line = 0;
        for (String content : input.split("\n", -1)) {
            line++;
            Matcher literal = LITERAL.matcher(content);
            boolean matched = false;
            while (literal.find()) {
                matched = true;
                String[] coordinate = literal.group(2).split(":", 3);
                boolean concatenated = content.substring(literal.end()).stripLeading().startsWith("+");
                result.add(VersionClassifier.component(ScaEcosystem.MAVEN,
                        coordinate.length >= 2 ? coordinate[0] + ":" + coordinate[1] : null,
                        coordinate.length == 3 && !concatenated ? coordinate[2] : null, literal.group(1), true, file.relativePath(), line));
            }
            Matcher map = MAP.matcher(content);
            while (map.find()) {
                matched = true;
                result.add(VersionClassifier.component(ScaEcosystem.MAVEN, map.group(2) + ":" + map.group(3),
                        map.group(4), map.group(1), true, file.relativePath(), line));
            }
            if (!matched) {
                Matcher other = OTHER.matcher(content);
                while (other.find()) result.add(VersionClassifier.component(ScaEcosystem.MAVEN,
                        null, null, other.group(1), true, file.relativePath(), line));
            }
        }
        return result;
    }
    public List<DependencyComponent> parseLock(ProjectFile file) {
        List<DependencyComponent> result = new ArrayList<>();
        for (int i = 0; i < file.lines().size(); i++) {
            String line = file.lines().get(i).strip();
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("empty=")) continue;
            String[] parts = line.split("=", 2);
            String[] coordinate = parts[0].split(":", 3);
            if (coordinate.length != 3 || parts.length != 2) throw new IllegalArgumentException("Invalid Gradle lock");
            result.add(VersionClassifier.component(ScaEcosystem.MAVEN, coordinate[0] + ":" + coordinate[1],
                    coordinate[2], parts[1], null, file.relativePath(), i + 1));
        }
        return result;
    }
    // Preserve strings and line numbers while removing comments; never evaluate Groovy/Kotlin.
    static String stripComments(String text) {
        StringBuilder out = new StringBuilder();
        char quote = 0;
        boolean block = false, line = false, escape = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i), next = i + 1 < text.length() ? text.charAt(i + 1) : 0;
            if (line) { if (c == '\n') line = false; out.append(c == '\n' ? '\n' : ' '); }
            else if (block) { if (c == '*' && next == '/') { block = false; i++; out.append(' '); } out.append(c == '\n' ? '\n' : ' '); }
            else if (quote != 0) { out.append(c); if (escape) escape = false; else if (c == '\\') escape = true; else if (c == quote) quote = 0; }
            else if (c == '/' && next == '/') { line = true; i++; out.append("  "); }
            else if (c == '/' && next == '*') { block = true; i++; out.append("  "); }
            else { out.append(c); if (c == '\'' || c == '"') quote = c; }
        }
        return out.toString();
    }
}
