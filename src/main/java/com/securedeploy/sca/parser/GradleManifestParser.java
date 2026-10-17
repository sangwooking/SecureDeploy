package com.securedeploy.sca.parser;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.sca.model.*;
import java.util.*;

public class GradleManifestParser {
    private static final long MAX_SOURCE_CHARACTERS = 2_000_000;
    private static final Set<String> CONFIG = Set.of("implementation", "api", "compileOnly", "runtimeOnly",
            "testImplementation", "testRuntimeOnly", "annotationProcessor", "compile", "runtime");
    private record Token(String value, int line, boolean string) {
        boolean is(String text) { return !string && value.equals(text); }
    }

    public List<DependencyComponent> parse(ProjectFile file) {
        if (file.lines().stream().mapToLong(line -> line.length() + 1L).sum() > MAX_SOURCE_CHARACTERS) {
            throw new IllegalArgumentException("Gradle manifest size limit");
        }
        List<DependencyComponent> result = new ArrayList<>();
        List<Token> tokens = tokens(String.join("\n", file.lines()));
        Deque<Boolean> blocks = new ArrayDeque<>();
        for (int i = 0; i < tokens.size(); i++) {
            Token token = tokens.get(i);
            if (token.is("{")) {
                int prior = previous(tokens, i);
                blocks.push((prior >= 0 && tokens.get(prior).is("dependencies")) || (!blocks.isEmpty() && blocks.peek()));
                continue;
            }
            if (token.is("}")) { if (!blocks.isEmpty()) blocks.pop(); continue; }
            boolean qualified = i >= 2 && tokens.get(i - 1).is(".") && tokens.get(i - 2).is("dependencies");
            boolean declaration = !token.string() && (CONFIG.contains(token.value()) || token.is("add"));
            if (!declaration || (!qualified && !statementStart(tokens, i))
                    || (!qualified && !blocks.isEmpty() && !blocks.peek())) continue;
            int start = i + 1;
            if (start >= tokens.size() || tokens.get(start).is("=") || tokens.get(start).is("{")
                    || tokens.get(start).is(".") || tokens.get(start).is("\n")) continue;
            int end = expressionEnd(tokens, start);
            List<Token> args = unwrap(tokens.subList(start, end));
            String scope = token.value();
            if (token.is("add")) {
                if (!qualified && (blocks.isEmpty() || !blocks.peek())) continue;
                if (args.size() < 3 || !args.get(0).string() || !args.get(1).is(",")) continue;
                scope = args.get(0).value();
                if (!scope.matches("[A-Za-z][A-Za-z0-9_]{0,80}")) scope = "custom";
                args = args.subList(2, args.size());
            }
            if (!args.isEmpty()) result.add(component(file, token.line(), scope, args));
            i = Math.max(i, end - 1);
        }
        return result;
    }

    private DependencyComponent component(ProjectFile file, int line, String scope, List<Token> args) {
        String name = null, version = null;
        if (args.get(0).string()) {
            String[] coordinate = args.get(0).value().split(":", 3);
            if (coordinate.length >= 2) name = coordinate[0] + ":" + coordinate[1];
            if (coordinate.length == 3 && args.size() == 1) version = coordinate[2];
        } else {
            Map<String, String> values = new HashMap<>();
            for (int from = 0; from < args.size();) {
                int to = from;
                while (to < args.size() && !args.get(to).is(",")) to++;
                if (to - from == 3 && (args.get(from + 1).is(":") || args.get(from + 1).is("="))
                        && args.get(from + 2).string()) values.put(args.get(from).value(), args.get(from + 2).value());
                from = to + 1;
            }
            if (values.containsKey("group") && values.containsKey("name")) name = values.get("group") + ":" + values.get("name");
            version = values.get("version");
        }
        return VersionClassifier.component(ScaEcosystem.MAVEN, name, version, scope, true, file.relativePath(), line);
    }

    private static int previous(List<Token> tokens, int i) {
        do { i--; } while (i >= 0 && tokens.get(i).is("\n"));
        return i;
    }
    private static boolean statementStart(List<Token> tokens, int i) {
        return i == 0 || tokens.get(i - 1).is("\n") || tokens.get(i - 1).is(";")
                || tokens.get(i - 1).is("{") || tokens.get(i - 1).is("}");
    }
    private static int expressionEnd(List<Token> tokens, int start) {
        int depth = 0;
        for (int i = start; i < tokens.size(); i++) {
            var t = tokens.get(i);
            if (depth == 0 && (t.is("\n") || t.is(";") || t.is("{") || t.is("}"))) return i;
            if (t.is("(") || t.is("[")) depth++;
            if (t.is(")") || t.is("]")) depth--;
            if (depth < 0) return i;
        }
        return tokens.size();
    }
    private static List<Token> unwrap(List<Token> input) {
        List<Token> args = input.stream().filter(t -> !t.is("\n")).toList();
        if (args.size() >= 2 && args.get(0).is("(") && args.get(args.size() - 1).is(")")) {
            int depth = 0;
            for (int i = 0; i < args.size(); i++) {
                if (args.get(i).is("(")) depth++;
                if (args.get(i).is(")")) depth--;
                if (depth == 0 && i < args.size() - 1) return args;
            }
            return args.subList(1, args.size() - 1);
        }
        return args;
    }

    // Lex only: quoted documentation/comments cannot become calls; no Gradle code is evaluated.
    private static List<Token> tokens(String source) {
        List<Token> result = new ArrayList<>();
        int line = 1;
        for (int i = 0; i < source.length();) {
            char c = source.charAt(i);
            if (c == '\n') { result.add(new Token("\n", line++, false)); i++; continue; }
            if (Character.isWhitespace(c)) { i++; continue; }
            if (source.startsWith("//", i) || source.startsWith("/*", i)) {
                boolean block = source.startsWith("/*", i);
                i += 2;
                int depth = 1;
                while (i < source.length()) {
                    if (!block && source.charAt(i) == '\n') break;
                    if (block && source.startsWith("/*", i)) { depth++; i += 2; continue; }
                    if (block && source.startsWith("*/", i)) { i += 2; if (--depth == 0) break; continue; }
                    if (source.charAt(i++) == '\n') result.add(new Token("\n", line++, false));
                }
                continue;
            }
            int begin = i, startLine = line;
            if (c == '\'' || c == '"') {
                boolean triple = source.startsWith(String.valueOf(c).repeat(3), i);
                String delimiter = String.valueOf(c).repeat(triple ? 3 : 1);
                i += delimiter.length();
                int valueStart = i;
                while (i < source.length() && !source.startsWith(delimiter, i)) {
                    if (source.charAt(i) == '\\' && !triple && i + 1 < source.length()) { i += 2; continue; }
                    if (source.charAt(i++) == '\n') line++;
                }
                if (i >= source.length()) throw new IllegalArgumentException("Unterminated Gradle literal");
                result.add(new Token(source.substring(valueStart, i), startLine, true));
                i += delimiter.length();
            } else if (Character.isJavaIdentifierStart(c)) {
                while (i < source.length() && Character.isJavaIdentifierPart(source.charAt(i))) i++;
                result.add(new Token(source.substring(begin, i), startLine, false));
            } else { result.add(new Token(String.valueOf(c), line, false)); i++; }
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
}
