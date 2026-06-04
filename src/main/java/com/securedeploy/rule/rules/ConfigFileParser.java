package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.model.ProjectFileType;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class ConfigFileParser {

    private static final Pattern KEY_VALUE = Pattern.compile("^\\s*([A-Za-z0-9_.\\-]+)\\s*[:=]\\s*(.+?)\\s*$");
    private static final Pattern YAML_LINE = Pattern.compile("^(\\s*)([A-Za-z0-9_.\\-]+)\\s*:\\s*(.*?)\\s*$");

    private ConfigFileParser() {
    }

    static List<ConfigEntry> parse(ProjectFile file) {
        if (file.type() == ProjectFileType.YAML) {
            return parseYaml(file);
        }
        return parseFlat(file);
    }

    static Optional<ConfigEntry> parseLine(String line, int lineNumber) {
        String withoutComment = stripComment(line).strip();
        if (withoutComment.isEmpty()) {
            return Optional.empty();
        }

        Matcher matcher = KEY_VALUE.matcher(withoutComment);
        if (!matcher.matches()) {
            return Optional.empty();
        }

        String key = matcher.group(1).strip();
        String value = cleanValue(matcher.group(2));
        if (value.isBlank()) {
            return Optional.empty();
        }

        return Optional.of(toEntry(key, value, lineNumber));
    }

    static String normalizeKey(String key) {
        return key.toLowerCase(Locale.ROOT).replace('_', '.').replace('-', '.');
    }

    static boolean isPlaceholder(String value) {
        String stripped = value.strip();
        return stripped.startsWith("${") || stripped.startsWith("#{") || stripped.startsWith("$env:");
    }

    static boolean isBooleanFalse(String value) {
        return "false".equalsIgnoreCase(value.strip());
    }

    static boolean isBooleanTrue(String value) {
        return "true".equalsIgnoreCase(value.strip());
    }

    private static List<ConfigEntry> parseFlat(ProjectFile file) {
        List<ConfigEntry> entries = new ArrayList<>();
        List<String> lines = file.lines();

        for (int index = 0; index < lines.size(); index++) {
            parseLine(lines.get(index), index + 1).ifPresent(entries::add);
        }

        return entries;
    }

    private static List<ConfigEntry> parseYaml(ProjectFile file) {
        List<ConfigEntry> entries = new ArrayList<>();
        List<YamlKey> keyStack = new ArrayList<>();
        List<String> lines = file.lines();

        for (int index = 0; index < lines.size(); index++) {
            String withoutComment = stripComment(lines.get(index));
            if (withoutComment.strip().isEmpty()) {
                continue;
            }

            Matcher matcher = YAML_LINE.matcher(withoutComment);
            if (!matcher.matches()) {
                parseLine(withoutComment, index + 1).ifPresent(entries::add);
                continue;
            }

            int indent = matcher.group(1).length();
            String key = matcher.group(2).strip();
            String value = cleanValue(matcher.group(3));

            while (!keyStack.isEmpty() && keyStack.get(keyStack.size() - 1).indent() >= indent) {
                keyStack.remove(keyStack.size() - 1);
            }

            if (value.isBlank()) {
                keyStack.add(new YamlKey(indent, key));
                continue;
            }

            String fullKey = buildYamlKey(keyStack, key);
            entries.add(toEntry(fullKey, value, index + 1));
        }

        return entries;
    }

    private static ConfigEntry toEntry(String key, String value, int lineNumber) {
        return new ConfigEntry(key, normalizeKey(key), value, lineNumber, key + "=" + redactIfSensitive(key, value));
    }

    private static String buildYamlKey(List<YamlKey> keyStack, String key) {
        if (keyStack.isEmpty()) {
            return key;
        }

        StringBuilder builder = new StringBuilder();
        for (YamlKey yamlKey : keyStack) {
            if (!builder.isEmpty()) {
                builder.append('.');
            }
            builder.append(yamlKey.key());
        }
        if (!builder.isEmpty()) {
            builder.append('.');
        }
        builder.append(key);
        return builder.toString();
    }

    private static String stripComment(String line) {
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;

        for (int index = 0; index < line.length(); index++) {
            char current = line.charAt(index);
            if (current == '\'' && !inDoubleQuote) {
                inSingleQuote = !inSingleQuote;
            } else if (current == '"' && !inSingleQuote) {
                inDoubleQuote = !inDoubleQuote;
            } else if (current == '#' && !inSingleQuote && !inDoubleQuote) {
                return line.substring(0, index);
            }
        }
        return line;
    }

    private static String cleanValue(String value) {
        String stripped = value.strip();
        if ((stripped.startsWith("\"") && stripped.endsWith("\""))
                || (stripped.startsWith("'") && stripped.endsWith("'"))) {
            return stripped.substring(1, stripped.length() - 1).strip();
        }
        return stripped;
    }

    private static String redactIfSensitive(String key, String value) {
        String normalizedKey = normalizeKey(key);
        if (normalizedKey.contains("password") || normalizedKey.contains("secret") || normalizedKey.contains("api.key")) {
            return "<redacted>, length=" + value.length();
        }
        return value;
    }

    private record YamlKey(int indent, String key) {
    }
}
