package com.securedeploy.sca.parser;
import com.fasterxml.jackson.databind.*;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.sca.model.*;
import java.util.*;

public class NpmManifestParser {
    private final ObjectMapper mapper;
    private static final List<String> SECTIONS = List.of("dependencies", "devDependencies", "optionalDependencies", "peerDependencies");
    public NpmManifestParser(ObjectMapper mapper) { this.mapper = mapper; }

    public List<DependencyComponent> parseManifest(ProjectFile file) throws Exception {
        JsonNode root = read(file);
        var lines = JsonSourceLines.read(mapper, file);
        List<DependencyComponent> result = new ArrayList<>();
        for (String section : SECTIONS) {
            if (root.has(section) && !root.get(section).isObject()) throw new IllegalArgumentException("Invalid dependency section");
            root.path(section).fields().forEachRemaining(e -> {
                String spec = e.getValue().asText();
                String name = spec.startsWith("npm:") ? aliasName(spec) : e.getKey();
                int line = lines.getOrDefault("/" + section + "/" + JsonSourceLines.key(e.getKey()), 0);
                var component = VersionClassifier.component(ScaEcosystem.NPM, name, spec, section, true, file.relativePath(), line);
                String declared = component.version();
                if (declared != null && !declared.matches("[vV0-9xX.*~^<>=|+()\\[\\] ,_-]+")) declared = "<unresolved-spec>";
                var path = new DependencyContext.DependencyPath(com.securedeploy.project.coverage.CoverageRecorder.safePath(file.relativePath()), line,
                        section, component.packageName(), declared, true, section.equals("optionalDependencies"), section.equals("peerDependencies"), List.of());
                result.add(component.withContext(new DependencyContext(1, "UNKNOWN", "NOT_ANALYZED", "", 0, List.of(), false,
                        List.of(path), List.of("Manifest 선언만 확인했습니다. 사용 가능한 lockfile 근거가 없어 실제 설치 경로와 환경을 확인하지 못했습니다.")), line));
            });
        }
        return result;
    }

    public List<DependencyComponent> parseLock(ProjectFile file) throws Exception {
        return parseLock(file, List.of());
    }
    public List<DependencyComponent> parseLock(ProjectFile file, List<ProjectFile> files) throws Exception {
        JsonNode root = read(file);
        int version = root.path("lockfileVersion").asInt();
        JsonNode packages = root.path("packages");
        if ((version != 2 && version != 3) || !packages.isObject()) throw new IllegalArgumentException("Unsupported npm lockfile");
        Set<String> directPaths = new HashSet<>();
        Map<String, String> aliasNames = new HashMap<>();
        List<DependencyComponent> missing = new ArrayList<>();
        // Root and workspace manifests declare direct dependencies. Resolve the nearest installed path.
        packages.fields().forEachRemaining(entry -> {
            String owner = entry.getKey();
            if (!entry.getValue().isObject()) throw new IllegalArgumentException("Invalid locked package");
            for (String section : SECTIONS) if (entry.getValue().has(section) && !entry.getValue().path(section).isObject())
                throw new IllegalArgumentException("Invalid locked dependency section");
            boolean directOwner = !owner.contains("node_modules");
            for (String section : SECTIONS) entry.getValue().path(section).fieldNames().forEachRemaining(name -> {
                String parent = owner;
                while (true) {
                    String candidate = (parent.isEmpty() ? "" : parent + "/") + "node_modules/" + name;
                    if (packages.has(candidate)) {
                        if (directOwner) directPaths.add(candidate);
                        String spec = entry.getValue().path(section).path(name).asText();
                        if (spec.startsWith("npm:")) {
                            aliasNames.put(candidate, aliasName(spec));
                        }
                        break;
                    }
                    if (parent.isEmpty()) {
                        if (directOwner) missing.add(VersionClassifier.component(ScaEcosystem.NPM, name, null, section,
                                true, file.relativePath(), 0));
                        break;
                    }
                    int slash = parent.lastIndexOf('/');
                    parent = slash < 0 ? "" : parent.substring(0, slash);
                }
            });
        });
        List<DependencyComponent> result = new ArrayList<>();
        Map<String, DependencyContext> contexts = new NpmDependencyGraph(mapper).collect(file, files, aliasNames);
        result.addAll(missing);
        packages.fields().forEachRemaining(entry -> {
            String path = entry.getKey();
            int start = path.lastIndexOf("node_modules/");
            if (start < 0) return;
            JsonNode pkg = entry.getValue();
            String name = pkg.path("name").asText(aliasNames.getOrDefault(path, path.substring(start + "node_modules/".length())));
            String installed = pkg.path("link").asBoolean() ? null : pkg.path("version").asText(null);
            String resolved = pkg.path("resolved").asText("");
            if (!resolved.isEmpty() && !resolved.startsWith("https://registry.npmjs.org/")) installed = null;
            String scope = pkg.path("dev").asBoolean() ? "devDependencies"
                    : pkg.path("optional").asBoolean() ? "optionalDependencies" : "dependencies";
            var context = contexts.get(path);
            result.add(VersionClassifier.component(ScaEcosystem.NPM, name, installed, scope,
                    packages.has("") ? directPaths.contains(path) : null, file.relativePath(), context == null ? 0 : context.lockLine())
                    .withContext(context, context == null ? 0 : context.lockLine()));
        });
        return result;
    }
    private JsonNode read(ProjectFile file) throws Exception {
        JsonNode root = mapper.readTree(String.join("\n", file.lines()));
        if (root == null || !root.isObject()) throw new IllegalArgumentException("Invalid npm manifest");
        return root;
    }
    private String aliasName(String spec) {
        int at = spec.lastIndexOf('@');
        return at > 4 ? spec.substring(4, at) : spec.substring(4);
    }
}
