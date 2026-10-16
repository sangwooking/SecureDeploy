package com.securedeploy.project.progress;

import com.securedeploy.project.model.ProjectStructure;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Component;

@Component
public class ComparisonContextCollector {
    private final String version = analyzerVersion();

    public ComparisonContext collect(ProjectStructure structure) {
        return new ComparisonContext(1, null, version, true, structure.analysisFiles().stream()
                .map(file -> normalize(file.relativePath())).distinct().sorted().toList());
    }

    static String normalize(String path) {
        String value = path == null ? "" : path.replace('\\', '/');
        while (value.startsWith("./")) value = value.substring(2);
        return value;
    }

    private static String analyzerVersion() {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            var resolver = new PathMatchingResourcePatternResolver();
            for (String area : new String[] {"rule", "dependency", "project/service", "project/coverage", "sca/parser"}) {
                var resources = resolver.getResources("classpath*:com/securedeploy/" + area + "/**/*.class");
                java.util.Arrays.sort(resources, java.util.Comparator.comparing(r -> r.getDescription()));
                for (var resource : resources) {
                    try (var input = resource.getInputStream()) { digest.update(input.readAllBytes()); }
                }
            }
            return "coverage-v2:" + HexFormat.of().formatHex(digest.digest());
        } catch (Exception failure) {
            // Unknown analyzer versions cannot establish negative evidence.
            return null;
        }
    }
}
