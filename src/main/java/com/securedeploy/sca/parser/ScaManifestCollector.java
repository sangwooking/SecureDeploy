package com.securedeploy.sca.parser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.project.model.*;
import com.securedeploy.project.service.ProjectIgnorePolicy;
import java.nio.file.Path;
import com.securedeploy.sca.model.*;
import java.util.*;
import org.springframework.stereotype.Component;

@Component
public class ScaManifestCollector {
    private final MavenManifestParser maven = new MavenManifestParser();
    private final GradleManifestParser gradle = new GradleManifestParser();
    private final NpmManifestParser npm;
    private static final Set<String> MANIFESTS = Set.of("pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile", "package.json", "package-lock.json");
    public ScaManifestCollector(ObjectMapper mapper) { npm = new NpmManifestParser(mapper); }
    public record Inventory(List<DependencyComponent> components, List<String> warnings, int manifestCount, List<ManifestObservation> observations) { }

    public Inventory collect(ProjectStructure structure) {
        List<ProjectFile> files = structure.analysisFiles().stream()
                .filter(f -> MANIFESTS.contains(name(f.relativePath())))
                .filter(f -> !ProjectIgnorePolicy.ignores(Path.of(f.relativePath())))
                .sorted(Comparator.comparing(ProjectFile::relativePath)).toList();
        List<String> warnings = new ArrayList<>();
        List<ManifestObservation> observations = new ArrayList<>();
        Map<String, List<DependencyComponent>> parsed = new LinkedHashMap<>();
        Set<String> present = new HashSet<>();
        files.forEach(f -> present.add(f.relativePath()));
        for (int index = 0; index < files.size(); index++) {
            ProjectFile file = files.get(index);
            String safePath = com.securedeploy.project.coverage.CoverageRecorder.safePath(file.relativePath());
            if (index >= 100) {
                observations.add(new ManifestObservation(safePath, "LIMIT_EXCEEDED", "MANIFEST_COUNT_LIMIT"));
                continue;
            }
            if (file.lines().stream().mapToLong(s -> s.length() + 1L).sum() > 2_000_000) {
                observations.add(new ManifestObservation(safePath, "LIMIT_EXCEEDED", "MANIFEST_SIZE_LIMIT"));
                warnings.add(safePath + ": SCA manifest 크기 제한으로 파싱하지 못했습니다.");
                continue;
            }
            try {
                List<DependencyComponent> items = switch (name(file.relativePath())) {
                    case "pom.xml" -> maven.parse(file);
                    case "build.gradle", "build.gradle.kts" -> gradle.parse(file);
                    case "gradle.lockfile" -> gradle.parseLock(file);
                    case "package.json" -> npm.parseManifest(file);
                    case "package-lock.json" -> npm.parseLock(file, files);
                    default -> List.of();
                };
                parsed.put(file.relativePath(), items);
                observations.add(new ManifestObservation(safePath, "COMPLETE", "STATIC_MANIFEST_PARSED"));
                if (name(file.relativePath()).equals("pom.xml") && file.lines().stream().anyMatch(l -> l.contains("<profiles"))) {
                    warnings.add(safePath + ": Maven profile 활성화 여부는 정적으로 확인하지 않습니다.");
                }
            } catch (Exception exception) {
                // Never include parser exceptions: their text can contain uploaded credentials/content.
                observations.add(new ManifestObservation(safePath, "FAILED", "UNSUPPORTED_OR_INVALID_MANIFEST"));
                warnings.add(safePath + ": 지원하지 않는 형식 또는 손상된 manifest로 파싱하지 못했습니다.");
            }
        }
        if (files.size() > 100) warnings.add("Manifest 100개 제한으로 일부 파일을 분석하지 못했습니다.");
        List<DependencyComponent> result = new ArrayList<>();
        for (var entry : parsed.entrySet()) {
            String path = entry.getKey(), base = directory(path), filename = name(path);
            List<DependencyComponent> lock = parsed.get(base + (filename.equals("package.json") ? "package-lock.json" : "gradle.lockfile"));
            boolean npmLocked = filename.equals("package.json") && present.contains(base + "package-lock.json");
            boolean gradleLocked = filename.startsWith("build.gradle") && lock != null;
            for (DependencyComponent item : entry.getValue()) {
                if (npmLocked) {
                    // Only the lock contains installed npm versions. Retain missing declarations as unresolved.
                    boolean found = lock != null && lock.stream().anyMatch(c -> c.packageName().equals(item.packageName()) && Boolean.TRUE.equals(c.direct()));
                    if (!found) result.add(new DependencyComponent(item.ecosystem(), item.packageName(), null,
                            item.scope(), true, item.sourceFile(), item.line(), VersionResolution.UNRESOLVED, item.context()));
                } else if (gradleLocked) {
                    List<DependencyComponent> locked = lock.stream().filter(c -> c.packageName().equals(item.packageName())).toList();
                    if (locked.isEmpty()) result.add(item);
                    else for (DependencyComponent c : locked) result.add(new DependencyComponent(c.ecosystem(), c.packageName(),
                            c.version(), item.scope(), true, path, item.line(), c.versionResolution()));
                } else result.add(item);
                if (result.size() >= 5000) break;
            }
            if (result.size() >= 5000) { warnings.add("의존성 위치 5000개 제한에 도달했습니다."); break; }
        }
        return new Inventory(List.copyOf(result), List.copyOf(warnings), files.size(), List.copyOf(observations));
    }
    private static String name(String path) { return path.substring(path.lastIndexOf('/') + 1); }
    private static String directory(String path) { return path.substring(0, path.lastIndexOf('/') + 1); }
}
