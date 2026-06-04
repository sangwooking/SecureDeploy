package com.securedeploy.dependency.parser;

import com.securedeploy.dependency.model.DependencyEcosystem;
import com.securedeploy.dependency.model.DependencyInfo;
import com.securedeploy.project.model.ProjectFile;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DockerImageDependencyParser {

    private static final Pattern FROM_IMAGE = Pattern.compile("(?i)^\\s*FROM\\s+([^\\s]+)");
    private static final Pattern COMPOSE_IMAGE = Pattern.compile("(?i)^\\s*image\\s*:\\s*([^\\s#]+)");

    public List<DependencyInfo> parse(ProjectFile file) {
        List<DependencyInfo> dependencies = new ArrayList<>();
        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            Matcher fromMatcher = FROM_IMAGE.matcher(line);
            if (fromMatcher.find()) {
                dependencies.add(toDependency(fromMatcher.group(1), file, index + 1));
                continue;
            }
            Matcher composeMatcher = COMPOSE_IMAGE.matcher(line);
            if (composeMatcher.find()) {
                dependencies.add(toDependency(composeMatcher.group(1), file, index + 1));
            }
        }
        return dependencies;
    }

    private DependencyInfo toDependency(String imageReference, ProjectFile file, int line) {
        String image = imageReference.strip();
        if (image.contains("@")) {
            image = image.substring(0, image.indexOf('@'));
        }
        String name = image;
        String version = "latest";
        int slash = image.lastIndexOf('/');
        int colon = image.lastIndexOf(':');
        if (colon > slash) {
            name = image.substring(0, colon);
            version = image.substring(colon + 1);
        }
        int lastSlash = name.lastIndexOf('/');
        if (lastSlash >= 0) {
            name = name.substring(lastSlash + 1);
        }
        return new DependencyInfo(name, version, DependencyEcosystem.DOCKER, file.relativePath(), line);
    }
}
