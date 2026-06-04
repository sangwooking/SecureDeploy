package com.securedeploy.dependency.parser;

import com.securedeploy.dependency.model.DependencyEcosystem;
import com.securedeploy.dependency.model.DependencyInfo;
import com.securedeploy.project.model.ProjectFile;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GradleDependencyParser {

    private static final Pattern STRING_NOTATION = Pattern.compile("\\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|compile|runtime)\\s*(?:\\(\\s*)?['\\\"]([^:'\\\"]+):([^:'\\\"]+):([^'\\\"]+)['\\\"]");
    private static final Pattern MAP_NOTATION = Pattern.compile("\\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\\s+group\\s*:\\s*['\\\"]([^'\\\"]+)['\\\"]\\s*,\\s*name\\s*:\\s*['\\\"]([^'\\\"]+)['\\\"]\\s*,\\s*version\\s*:\\s*['\\\"]([^'\\\"]+)['\\\"]");

    public List<DependencyInfo> parse(ProjectFile file) {
        List<DependencyInfo> dependencies = new ArrayList<>();
        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            Matcher stringMatcher = STRING_NOTATION.matcher(line);
            if (stringMatcher.find()) {
                dependencies.add(new DependencyInfo(
                        stringMatcher.group(1) + ":" + stringMatcher.group(2),
                        cleanVersion(stringMatcher.group(3)),
                        DependencyEcosystem.GRADLE,
                        file.relativePath(),
                        index + 1
                ));
                continue;
            }
            Matcher mapMatcher = MAP_NOTATION.matcher(line);
            if (mapMatcher.find()) {
                dependencies.add(new DependencyInfo(
                        mapMatcher.group(1) + ":" + mapMatcher.group(2),
                        cleanVersion(mapMatcher.group(3)),
                        DependencyEcosystem.GRADLE,
                        file.relativePath(),
                        index + 1
                ));
            }
        }
        return dependencies;
    }

    private String cleanVersion(String version) {
        return version == null ? "" : version.strip().replaceAll("\\)?\\s*$", "");
    }
}
