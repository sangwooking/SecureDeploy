package com.securedeploy.dependency.parser;

import com.securedeploy.dependency.model.DependencyEcosystem;
import com.securedeploy.dependency.model.DependencyInfo;
import com.securedeploy.project.model.ProjectFile;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PackageJsonDependencyParser {

    private static final Pattern SECTION_START = Pattern.compile("\\\"(dependencies|devDependencies)\\\"\\s*:\\s*\\{");
    private static final Pattern DEPENDENCY_LINE = Pattern.compile("\\\"([^\\\"]+)\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");

    public List<DependencyInfo> parse(ProjectFile file) {
        List<DependencyInfo> dependencies = new ArrayList<>();
        boolean inDependencySection = false;
        int depth = 0;
        List<String> lines = file.lines();

        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            if (!inDependencySection) {
                Matcher sectionMatcher = SECTION_START.matcher(line);
                if (sectionMatcher.find()) {
                    inDependencySection = true;
                    depth = braceDelta(line);
                }
                continue;
            }

            Matcher dependencyMatcher = DEPENDENCY_LINE.matcher(line);
            if (dependencyMatcher.find()) {
                dependencies.add(new DependencyInfo(
                        dependencyMatcher.group(1),
                        normalizeVersion(dependencyMatcher.group(2)),
                        DependencyEcosystem.NPM,
                        file.relativePath(),
                        index + 1
                ));
            }

            depth += braceDelta(line);
            if (depth <= 0 || line.strip().startsWith("}")) {
                inDependencySection = false;
                depth = 0;
            }
        }
        return dependencies;
    }

    private int braceDelta(String line) {
        int delta = 0;
        for (int i = 0; i < line.length(); i++) {
            char value = line.charAt(i);
            if (value == '{') {
                delta++;
            } else if (value == '}') {
                delta--;
            }
        }
        return delta;
    }

    private String normalizeVersion(String version) {
        return version == null ? "" : version.strip().replaceAll("^[~^]", "");
    }
}
