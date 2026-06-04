package com.securedeploy.dependency.parser;

import com.securedeploy.dependency.model.DependencyEcosystem;
import com.securedeploy.dependency.model.DependencyInfo;
import com.securedeploy.project.model.ProjectFile;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PomXmlDependencyParser {

    private static final Pattern GROUP_ID = Pattern.compile("<groupId>([^<]+)</groupId>");
    private static final Pattern ARTIFACT_ID = Pattern.compile("<artifactId>([^<]+)</artifactId>");
    private static final Pattern VERSION = Pattern.compile("<version>([^<]+)</version>");

    public List<DependencyInfo> parse(ProjectFile file) {
        List<DependencyInfo> dependencies = new ArrayList<>();
        boolean inDependency = false;
        String groupId = null;
        String artifactId = null;
        String version = null;
        int dependencyLine = 0;

        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            if (line.contains("<dependency>")) {
                inDependency = true;
                groupId = null;
                artifactId = null;
                version = null;
                dependencyLine = index + 1;
                continue;
            }
            if (!inDependency) {
                continue;
            }
            groupId = firstMatchOrCurrent(GROUP_ID, line, groupId);
            artifactId = firstMatchOrCurrent(ARTIFACT_ID, line, artifactId);
            version = firstMatchOrCurrent(VERSION, line, version);
            if (line.contains("</dependency>")) {
                if (groupId != null && artifactId != null && version != null && !version.contains("${")) {
                    dependencies.add(new DependencyInfo(groupId + ":" + artifactId, version, DependencyEcosystem.MAVEN, file.relativePath(), dependencyLine));
                }
                inDependency = false;
            }
        }
        return dependencies;
    }

    private String firstMatchOrCurrent(Pattern pattern, String line, String current) {
        Matcher matcher = pattern.matcher(line);
        return matcher.find() ? matcher.group(1).strip() : current;
    }
}
