package com.securedeploy.sca.parser;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.project.coverage.CoverageRecorder;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.sca.model.*;
import com.securedeploy.sca.model.DependencyContext.*;
import java.util.*;

/** Bounded lock v2/v3 graph. Never installs packages or follows registry/file URLs. */
final class NpmDependencyGraph {
    private static final List<String> SECTIONS = List.of("dependencies", "devDependencies", "optionalDependencies", "peerDependencies");
    private static final int MAX_PATHS = 12, MAX_DEPTH = 24, MAX_VISITS = 30000, MAX_STORED_HOPS = 20000;
    private final ObjectMapper mapper;
    NpmDependencyGraph(ObjectMapper mapper) { this.mapper = mapper; }

    Map<String, DependencyContext> collect(ProjectFile lock, List<ProjectFile> files, Map<String, String> aliasNames) throws Exception {
        JsonNode packages = mapper.readTree(String.join("\n", lock.lines())).path("packages");
        Map<String, Integer> lines = JsonSourceLines.read(mapper, lock);
        String base = lock.relativePath().substring(0, lock.relativePath().lastIndexOf('/') + 1);
        Map<String, ProjectFile> manifests = new HashMap<>();
        for (var file : files) manifests.put(file.relativePath(), file);
        Map<String, List<DependencyPath>> paths = new LinkedHashMap<>();
        Map<String, Boolean> complete = new HashMap<>();
        Set<String> truncated = new HashSet<>();
        ArrayDeque<Walk> queue = new ArrayDeque<>();
        boolean graphComplete = true;
        var owners = packages.fields();
        while (owners.hasNext()) {
            var owner = owners.next();
            if (owner.getKey().contains("node_modules")) continue;
            String declaration = base + (owner.getKey().isEmpty() ? "" : owner.getKey() + "/") + "package.json";
            ProjectFile manifest = manifests.get(declaration);
            JsonNode declared = null;
            Map<String, Integer> declarationLines = Map.of();
            if (manifest != null) {
                try {
                    if (manifest.lines().stream().mapToLong(line -> line.length() + 1L).sum() > 2_000_000)
                        throw new IllegalArgumentException("Manifest budget exceeded");
                    declared = mapper.readTree(String.join("\n", manifest.lines()));
                    declarationLines = JsonSourceLines.read(mapper, manifest);
                } catch (Exception invalid) { graphComplete = false; }
            }
            for (String section : SECTIONS) {
                var dependencies = owner.getValue().path(section).fields();
                while (dependencies.hasNext()) {
                    var edge = dependencies.next();
                    if (section.equals("dependencies") && owner.getValue().path("optionalDependencies").has(edge.getKey())) continue;
                    String target = resolve(packages, owner.getKey(), edge.getKey());
                    if (target == null) { if (!section.equals("optionalDependencies")) graphComplete = false; continue; }
                    boolean confirmed = declared != null && declared.path(section).path(edge.getKey()).isTextual()
                            && declared.path(section).path(edge.getKey()).asText().equals(edge.getValue().asText());
                    boolean consistent = declared == null && manifest == null || confirmed;
                    if (declared != null && !confirmed) complete.put(target, false);
                    String evidenceFile = confirmed ? declaration : lock.relativePath();
                    int line = confirmed ? declarationLines.getOrDefault("/" + section + "/" + JsonSourceLines.key(edge.getKey()), 0)
                            : lines.getOrDefault("/packages/" + JsonSourceLines.key(owner.getKey()) + "/" + section + "/" + JsonSourceLines.key(edge.getKey()), 0);
                    String spec = VersionClassifier.component(ScaEcosystem.NPM, edge.getKey(), edge.getValue().asText(), section,
                            true, evidenceFile, line).version();
                    if (spec != null && !spec.matches("[vV0-9xX.*~^<>=|+()\\[\\] ,_-]+")) spec = "<unresolved-spec>";
                    var path = new DependencyPath(CoverageRecorder.safePath(evidenceFile), line, section,
                            safeName(edge.getKey()), spec, confirmed, section.equals("optionalDependencies"),
                            section.equals("peerDependencies"), List.of());
                    queue.add(new Walk(target, path, Set.of(), consistent));
                }
            }
            // A stale lock must not invent production/development provenance.
            if (declared != null) for (String section : SECTIONS) {
                var names = declared.path(section).fieldNames();
                while (names.hasNext()) if (!owner.getValue().path(section).has(names.next())) graphComplete = false;
            }
        }
        int visits = 0, storedHops = 0;
        while (!queue.isEmpty() && visits++ < MAX_VISITS) {
            Walk walk = queue.remove();
            if (walk.seen().contains(walk.target())) continue;
            JsonNode node = packages.path(walk.target());
            List<DependencyPath> found = paths.computeIfAbsent(walk.target(), ignored -> new ArrayList<>());
            if (walk.path().chain().size() >= MAX_DEPTH) { truncated.add(walk.target()); continue; }
            var chain = new ArrayList<>(walk.path().chain());
            String installedName = node.path("name").asText(aliasNames.getOrDefault(walk.target(), walk.target().substring(walk.target().lastIndexOf("node_modules/") + 13)));
            chain.add(new Hop(safeName(installedName), VersionClassifier.component(ScaEcosystem.NPM, installedName,
                    node.path("version").asText(null), "", false, lock.relativePath(), 0).version(), CoverageRecorder.safePath(walk.target())));
            var path = new DependencyPath(walk.path().declarationFile(), walk.path().declarationLine(), walk.path().declarationSection(),
                    walk.path().declaredPackage(), walk.path().declaredVersion(), walk.path().declarationConfirmed(),
                    walk.path().optional(), walk.path().peer(), List.copyOf(chain));
            if (found.contains(path)) continue;
            if (found.size() >= MAX_PATHS || storedHops + chain.size() > MAX_STORED_HOPS) { truncated.add(walk.target()); continue; }
            found.add(path);
            storedHops += chain.size();
            complete.merge(walk.target(), walk.consistent(), (a, b) -> a && b);
            Set<String> seen = new HashSet<>(walk.seen()); seen.add(walk.target());
            for (String section : List.of("dependencies", "optionalDependencies", "peerDependencies")) {
                var children = node.path(section).fieldNames();
                while (children.hasNext()) {
                    String child = children.next();
                    if (section.equals("dependencies") && node.path("optionalDependencies").has(child)) continue;
                    String target = resolve(packages, walk.target(), child);
                    if (target == null) {
                        if (section.equals("dependencies")) graphComplete = false;
                        continue;
                    }
                    var next = new DependencyPath(path.declarationFile(), path.declarationLine(), path.declarationSection(),
                            path.declaredPackage(), path.declaredVersion(), path.declarationConfirmed(),
                            path.optional() || section.equals("optionalDependencies"), path.peer() || section.equals("peerDependencies"), path.chain());
                    if (queue.size() < MAX_VISITS) queue.add(new Walk(target, next, seen, walk.consistent()));
                    else truncated.add(target);
                }
            }
        }
        for (Walk pending : queue) truncated.add(pending.target());
        // A path cap affects that node and descendants, not an unrelated root's evidence.
        var affected = new ArrayDeque<>(truncated);
        while (!affected.isEmpty()) {
            String node = affected.remove();
            for (String section : List.of("dependencies", "optionalDependencies", "peerDependencies")) {
                var names = packages.path(node).path(section).fieldNames();
                while (names.hasNext()) {
                    String target = resolve(packages, node, names.next());
                    if (target != null && truncated.add(target)) affected.add(target);
                }
            }
        }
        Map<String, DependencyContext> result = new LinkedHashMap<>();
        var installed = packages.fields();
        while (installed.hasNext()) {
            var entry = installed.next();
            if (!entry.getKey().contains("node_modules/")) continue;
            var evidence = paths.getOrDefault(entry.getKey(), List.of());
            boolean full = graphComplete && !truncated.contains(entry.getKey()) && complete.getOrDefault(entry.getKey(), false)
                    && !entry.getValue().path("link").asBoolean();
            boolean dev = evidence.stream().anyMatch(p -> p.declarationSection().equals("devDependencies"));
            boolean prod = evidence.stream().anyMatch(p -> p.declarationSection().equals("dependencies") || p.declarationSection().equals("optionalDependencies"));
            boolean peer = evidence.stream().anyMatch(p -> p.declarationSection().equals("peerDependencies"));
            if (entry.getValue().path("dev").asBoolean() && prod) full = false;
            String environment = !full || peer || evidence.isEmpty() ? "UNKNOWN" : dev && prod ? "SHARED" : dev ? "DEVELOPMENT" : "PRODUCTION";
            List<String> flags = new ArrayList<>();
            for (String flag : List.of("dev", "optional", "devOptional", "link")) if (entry.getValue().path(flag).asBoolean()) flags.add(flag);
            List<String> limitations = new ArrayList<>();
            if (!full) limitations.add("경로 누락, 선언 불일치, 링크 또는 탐색 한도로 환경을 확정하지 못했습니다.");
            if (peer) limitations.add("Peer 의존성의 실제 소비 환경은 확인하지 못했습니다.");
            if (evidence.stream().anyMatch(p -> !p.declarationConfirmed())) limitations.add("일부 선언은 lockfile에서만 확인했습니다. package.json과 일치하는지 확인하세요.");
            result.put(entry.getKey(), new DependencyContext(1, environment, "NOT_ANALYZED", CoverageRecorder.safePath(entry.getKey()),
                    lines.getOrDefault("/packages/" + JsonSourceLines.key(entry.getKey()), 0), List.copyOf(flags), full,
                    List.copyOf(evidence), List.copyOf(limitations)));
        }
        return result;
    }

    static String resolve(JsonNode packages, String owner, String name) {
        if (name == null || !name.matches("(@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+") || name.equals("..")) return null;
        String parent = owner;
        while (true) {
            if (!parent.endsWith("node_modules")) {
                String candidate = (parent.isEmpty() ? "" : parent + "/") + "node_modules/" + name;
                if (packages.has(candidate)) return candidate;
            }
            if (parent.isEmpty()) return null;
            int slash = parent.lastIndexOf('/'); parent = slash < 0 ? "" : parent.substring(0, slash);
        }
    }
    private String safeName(String value) {
        return VersionClassifier.component(ScaEcosystem.NPM, value, null, "", false, "", 0).packageName();
    }
    private record Walk(String target, DependencyPath path, Set<String> seen, boolean consistent) { }
}
