package com.securedeploy.dependency.parser;

import com.securedeploy.dependency.model.DependencyEcosystem;
import com.securedeploy.dependency.model.DependencyInfo;
import com.securedeploy.project.model.ProjectFile;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NpmLockDependencyParser {

    private static final Set<String> WATCHED_PACKAGES = Set.of("event-stream", "lodash", "minimist", "axios", "serialize-javascript");
    private static final Pattern PACKAGE_LOCK_ENTRY = Pattern.compile("\\\"node_modules/([^\\\"]+)\\\"\\s*:\\s*\\{");
    private static final Pattern VERSION_LINE = Pattern.compile("\\\"version\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
    private static final Pattern YARN_HEADER = Pattern.compile("^\\\"?([^@\\\"]+)@[^:]*:\\s*$");
    private static final Pattern YARN_VERSION = Pattern.compile("^\\s*version\\s+\\\"([^\\\"]+)\\\"");
    private static final Pattern PNPM_HEADER = Pattern.compile("^\\s*/([^@/]+)@([^:]+):\\s*$");

    public List<DependencyInfo> parse(ProjectFile file) {
        String lowerPath = file.relativePath().toLowerCase();
        if (lowerPath.endsWith("package-lock.json")) {
            return parsePackageLock(file);
        }
        if (lowerPath.endsWith("yarn.lock")) {
            return parseYarnLock(file);
        }
        if (lowerPath.endsWith("pnpm-lock.yaml")) {
            return parsePnpmLock(file);
        }
        return List.of();
    }

    private List<DependencyInfo> parsePackageLock(ProjectFile file) {
        List<DependencyInfo> dependencies = new ArrayList<>();
        String currentName = null;
        int currentLine = 0;
        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            Matcher entryMatcher = PACKAGE_LOCK_ENTRY.matcher(line);
            if (entryMatcher.find()) {
                currentName = entryMatcher.group(1);
                currentLine = index + 1;
                continue;
            }
            if (currentName != null && WATCHED_PACKAGES.contains(currentName)) {
                Matcher versionMatcher = VERSION_LINE.matcher(line);
                if (versionMatcher.find()) {
                    dependencies.add(new DependencyInfo(currentName, versionMatcher.group(1), DependencyEcosystem.NPM, file.relativePath(), currentLine));
                    currentName = null;
                }
            }
        }
        return dependencies;
    }

    private List<DependencyInfo> parseYarnLock(ProjectFile file) {
        List<DependencyInfo> dependencies = new ArrayList<>();
        String currentName = null;
        int currentLine = 0;
        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            Matcher headerMatcher = YARN_HEADER.matcher(line.strip());
            if (headerMatcher.find() && WATCHED_PACKAGES.contains(headerMatcher.group(1))) {
                currentName = headerMatcher.group(1);
                currentLine = index + 1;
                continue;
            }
            if (currentName != null) {
                Matcher versionMatcher = YARN_VERSION.matcher(line);
                if (versionMatcher.find()) {
                    dependencies.add(new DependencyInfo(currentName, versionMatcher.group(1), DependencyEcosystem.NPM, file.relativePath(), currentLine));
                    currentName = null;
                }
            }
        }
        return dependencies;
    }

    private List<DependencyInfo> parsePnpmLock(ProjectFile file) {
        List<DependencyInfo> dependencies = new ArrayList<>();
        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            Matcher matcher = PNPM_HEADER.matcher(lines.get(index));
            if (matcher.find() && WATCHED_PACKAGES.contains(matcher.group(1))) {
                dependencies.add(new DependencyInfo(matcher.group(1), matcher.group(2), DependencyEcosystem.NPM, file.relativePath(), index + 1));
            }
        }
        return dependencies;
    }
}
