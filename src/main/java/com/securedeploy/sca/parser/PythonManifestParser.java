package com.securedeploy.sca.parser;

import com.securedeploy.project.coverage.CoverageRecorder;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.sca.model.*;
import java.nio.file.Path;
import java.util.*;
import org.tomlj.*;

/** Static declarations only: includes resolve exclusively against already collected repository files. */
public final class PythonManifestParser {
    public record Inventory(List<DependencyComponent> components, List<ManifestObservation> observations, List<String> warnings) { }
    private record Entry(String file, int line, PythonRequirement requirement, String reference, boolean constraint, String scope) { }
    public Inventory collect(List<ProjectFile> files) { return new Session(files).collect(); }

    private static final class Session {
        final Map<String, ProjectFile> files = new LinkedHashMap<>();
        final Map<String, List<Entry>> parsed = new LinkedHashMap<>();
        final Map<String, ManifestObservation> observations = new LinkedHashMap<>();
        final Set<String> warnings = new LinkedHashSet<>();
        final Set<String> sourceOverrides = new HashSet<>(), nonRegistryRoots = new HashSet<>();
        final List<DependencyComponent> components = new ArrayList<>();
        int work;
        Session(List<ProjectFile> input) {
            input.stream().filter(f -> PythonManifestFiles.isPython(f.relativePath()))
                    .sorted(Comparator.comparing(ProjectFile::relativePath)).forEach(f -> files.put(f.relativePath(), f));
        }
        Inventory collect() {
            long retained = 0; int index = 0;
            for (var file : files.values()) {
                String path = file.relativePath(), name = PythonManifestFiles.name(path);
                observe(path, "COMPLETE", "STATIC_PYTHON_DECLARATIONS");
                long size = file.lines().stream().mapToLong(l -> l.length() + 1L).sum();
                if (++index > 100 || size > 200_000 || (retained += size) > 2_000_000 || file.lines().size() > 5000) {
                    issue(path, "LIMIT_EXCEEDED", "PYTHON_MANIFEST_LIMIT"); continue;
                }
                if (PythonManifestFiles.isUnsupported(name)) { issue(path, "UNSUPPORTED", "PYTHON_FORMAT_UNSUPPORTED"); continue; }
                try {
                    parsed.put(path, name.equalsIgnoreCase("pyproject.toml") ? project(file) : requirements(file));
                } catch (RuntimeException invalid) {
                    // Parser errors and raw URLs/markers can contain secrets. Never log or persist them.
                    issue(path, "FAILED", "INVALID_PYTHON_MANIFEST");
                }
            }
            Set<String> referenced = new HashSet<>();
            for (var entries : parsed.values()) for (var e : entries) if (e.reference() != null) {
                String target = target(e.file(), e.reference()); if (target != null) referenced.add(target);
            }
            Set<String> processed = new HashSet<>();
            for (String root : parsed.keySet()) {
                if (referenced.contains(root) || PythonManifestFiles.name(root).startsWith("constraints")) continue;
                analyzeRoot(root, processed);
            }
            // Components in a cycle still receive explicit incomplete evidence instead of disappearing.
            for (String root : parsed.keySet()) if (!processed.contains(root) && !PythonManifestFiles.name(root).startsWith("constraints")) analyzeRoot(root, processed);
            return new Inventory(List.copyOf(components), List.copyOf(observations.values()), List.copyOf(warnings));
        }
        void analyzeRoot(String root, Set<String> processed) {
            List<Entry> deps = new ArrayList<>(), constraints = new ArrayList<>();
            walk(root, root, false, new HashSet<>(), new HashSet<>(), processed, deps, constraints, 0);
            Map<String, Set<String>> pins = new HashMap<>();
            for (var e : deps) if (e.requirement().resolution() == VersionResolution.EXACT && e.requirement().markerStatus().equals("NONE")) {
                pins.computeIfAbsent(e.requirement().name(), k -> new HashSet<>()).add(e.requirement().version());
            }
            for (var e : constraints) if (pins.containsKey(e.requirement().name())
                    && e.requirement().resolution() == VersionResolution.EXACT && e.requirement().markerStatus().equals("NONE")) {
                pins.get(e.requirement().name()).add(e.requirement().version());
            }
            for (var e : deps) {
                if (components.size() >= 5000) { issue(root, "LIMIT_EXCEEDED", "PYTHON_COMPONENT_LIMIT"); break; }
                var r = e.requirement(); String version = r.version(), origin = r.resolution() == VersionResolution.EXACT ? "PINNED_DECLARATION" : "UNCONFIRMED";
                var resolution = r.resolution(); List<String> notes = new ArrayList<>();
                var applicable = constraints.stream().filter(c -> c.requirement().name().equals(r.name())).toList();
                if (!applicable.isEmpty()) {
                    var exact = applicable.stream().filter(c -> c.requirement().resolution() == VersionResolution.EXACT
                            && c.requirement().markerStatus().equals("NONE") && c.requirement().extras().isEmpty()).toList();
                    var versions = exact.stream().map(c -> c.requirement().version()).distinct().toList();
                    if (exact.size() == applicable.size() && versions.size() == 1 && r.markerStatus().equals("NONE")
                            && r.issue() == null && r.specifier() == null) {
                        version = versions.get(0); resolution = VersionResolution.EXACT; origin = "CONSTRAINT_PIN";
                    } else if (exact.size() != applicable.size() || versions.size() != 1 || !Objects.equals(version, versions.get(0))) {
                        resolution = VersionResolution.UNRESOLVED; origin = "CONSTRAINT_RELATION_UNCONFIRMED";
                        notes.add("제약과 요구 버전의 관계를 확정하지 못했습니다. 자동 버전 해석은 수행하지 않습니다.");
                        issue(root, "PARTIAL", "CONSTRAINT_RELATION_UNCONFIRMED");
                    }
                }
                if (pins.getOrDefault(r.name(), Set.of()).size() > 1 && r.markerStatus().equals("NONE")) {
                    resolution = VersionResolution.UNRESOLVED; origin = "CONFLICTING_PINS";
                    notes.add("같은 설치 입력에서 서로 다른 고정 버전 선언이 발견됐습니다.");
                    issue(root, "PARTIAL", "CONFLICTING_PYTHON_PINS");
                }
                if (nonRegistryRoots.contains(root)) {
                    resolution = VersionResolution.UNRESOLVED; origin = "PACKAGE_SOURCE_UNCONFIRMED";
                    notes.add("사용자 지정 패키지 저장소/소스 설정 때문에 PyPI 패키지와 동일한지 확인하지 못했습니다.");
                }
                if (r.issue() != null) notes.add("지원하지 않는 선언 또는 형식 오류로 이름·버전을 확정하지 못했습니다.");
                if (!r.markerStatus().equals("NONE")) notes.add("환경 조건을 실행하거나 현재 서버 환경에 대입하지 않았습니다. 실제 설치 여부를 확인해야 합니다.");
                if (!r.extras().isEmpty()) notes.add("요청된 extras 이름만 확인했으며 추가되는 간접 패키지는 해석하지 않았습니다.");
                notes.add("정적 선언 근거입니다. 실제 설치 버전, 간접 의존성 전체와 운영 실행 여부는 확인하지 않았습니다.");
                String scope = e.scope() == null ? environment(root) : e.scope();
                var python = new PythonDependencyContext(1, safe(root), scope, origin, r.specifier(), r.extras(),
                        r.markerStatus(), r.markerVariables(), applicable.stream().limit(20)
                        .map(c -> new PythonDependencyContext.Location(safe(c.file()), c.line())).toList(), List.copyOf(notes));
                // requirements may be a freeze/export including transitives; directness is not proven there.
                components.add(new DependencyComponent(ScaEcosystem.PYPI, r.name(), version, scope, e.scope() == null ? null : true,
                        safe(e.file()), e.line(), resolution, null, python));
            }
        }
        void walk(String root, String file, boolean constraint, Set<String> active, Set<String> visited,
                  Set<String> processed, List<Entry> deps, List<Entry> constraints, int depth) {
            if (depth > 8 || ++work > 10_000) { issue(root, "LIMIT_EXCEEDED", "PYTHON_REFERENCE_LIMIT"); return; }
            String key = file + ":" + constraint;
            if (active.contains(file)) { issue(root, "PARTIAL", "CYCLIC_REQUIREMENTS_REFERENCE"); return; }
            if (!visited.add(key)) return;
            processed.add(file);
            if (sourceOverrides.contains(file)) { nonRegistryRoots.add(root); issue(root, "PARTIAL", "PACKAGE_SOURCE_UNCONFIRMED"); }
            if (!parsed.containsKey(file)) { issue(root, "PARTIAL", "REFERENCE_NOT_AVAILABLE"); return; }
            active.add(file);
            for (var e : parsed.get(file)) {
                if (++work > 10_000) { issue(root, "LIMIT_EXCEEDED", "PYTHON_REFERENCE_LIMIT"); break; }
                if (e.reference() != null) {
                    if (constraint && !e.constraint()) {
                        issue(root, "PARTIAL", "REQUIREMENT_FROM_CONSTRAINT_UNSUPPORTED"); continue;
                    }
                    String target = target(file, e.reference());
                    if (target == null || !PythonManifestFiles.isRequirements(target)) issue(root, "PARTIAL", "REFERENCE_NOT_AVAILABLE");
                    else walk(root, target, constraint || e.constraint(), active, visited, processed, deps, constraints, depth + 1);
                } else if (constraint) constraints.add(e); else deps.add(e);
            }
            active.remove(file);
        }
        List<Entry> requirements(ProjectFile file) {
            List<Entry> result = new ArrayList<>(); StringBuilder joined = new StringBuilder(); int start = 1;
            for (int i = 0; i < file.lines().size(); i++) {
                String line = file.lines().get(i);
                if (joined.isEmpty()) start = i + 1;
                if (line.length() > 8192 || joined.length() + line.length() > 8192) throw new IllegalArgumentException();
                boolean continuation = line.endsWith("\\");
                joined.append(continuation ? line.substring(0, line.length() - 1) : line);
                if (continuation) { joined.append(' '); continue; }
                String text = joined.toString().replaceFirst("(?:^|\\s)#.*$", "").strip(); joined.setLength(0);
                if (text.isEmpty()) continue;
                var ref = java.util.regex.Pattern.compile("^(?:-([rc])\\s*|--(requirement|constraint)(?:=|\\s+))(.+)$").matcher(text);
                if (ref.matches()) {
                    boolean constraint = "c".equals(ref.group(1)) || "constraint".equals(ref.group(2));
                    result.add(new Entry(file.relativePath(), start, null, ref.group(3).strip(), constraint, null)); continue;
                }
                if (text.startsWith("-")) {
                    issue(file.relativePath(), "PARTIAL", "INSTALL_OPTION_NOT_EVALUATED");
                    if (text.matches("^(?:--(?:index-url|extra-index-url|no-index|find-links))(?:[=\\s].*|$)")
                            || text.startsWith("-i") || text.startsWith("-f")) sourceOverrides.add(file.relativePath());
                    if (text.startsWith("-e") || text.startsWith("--editable")) result.add(entry(file, start, PythonRequirement.unknown(null, "NON_REGISTRY_REFERENCE"), null));
                    continue;
                }
                // Hashes constrain artifacts, not the package version; never store hash values.
                text = text.replaceAll("\\s+--hash=(?:sha256|sha384|sha512):[a-fA-F0-9]+", "").strip();
                result.add(entry(file, start, PythonRequirement.parse(text), null));
            }
            if (!joined.isEmpty()) throw new IllegalArgumentException();
            return result;
        }
        List<Entry> project(ProjectFile file) {
            String text = String.join("\n", file.lines());
            if (text.chars().filter(c -> c == '[' || c == '{').count() > 256) {
                issue(file.relativePath(), "LIMIT_EXCEEDED", "PYPROJECT_STRUCTURE_LIMIT"); return List.of();
            }
            var toml = Toml.parse(text);
            if (toml.hasErrors()) throw new IllegalArgumentException();
            List<Entry> result = new ArrayList<>();
            array(file, toml.getArray("project.dependencies"), "PROJECT_DECLARATION", result);
            var optional = toml.getTable("project.optional-dependencies");
            if (optional != null) for (String group : optional.keySet()) {
                array(file, optional.getArray(List.of(group)), "OPTIONAL_DECLARATION", result);
            }
            array(file, toml.getArray("build-system.requires"), "BUILD_DECLARATION", result);
            var groups = toml.getTable("dependency-groups");
            if (groups != null) for (String group : groups.keySet()) {
                String normalized = group.toLowerCase(Locale.ROOT);
                String scope = Set.of("dev", "development", "test", "tests").contains(normalized) ? "DEVELOPMENT_GROUP_DECLARATION"
                        : Set.of("prod", "production").contains(normalized) ? "PRODUCTION_GROUP_DECLARATION" : "GROUP_DECLARATION";
                array(file, groups.getArray(List.of(group)), scope, result);
            }
            var dynamic = toml.getArray("project.dynamic");
            if (dynamic != null && dynamic.toList().stream().anyMatch(v -> Set.of("dependencies", "optional-dependencies").contains(v))) {
                result.add(entry(file, 0, PythonRequirement.unknown(null, "DYNAMIC_PROJECT_DEPENDENCIES"), "UNKNOWN"));
            }
            if (toml.contains("project.requires-python")) issue(file.relativePath(), "PARTIAL", "PROJECT_ENVIRONMENT_NOT_EVALUATED");
            if (toml.contains("tool.poetry") || toml.contains("tool.pdm") || toml.contains("tool.uv")) {
                issue(file.relativePath(), "PARTIAL", "TOOL_SPECIFIC_DEPENDENCIES_UNSUPPORTED");
                // Tool source overrides may change the package selected by the standard declaration.
                result = new ArrayList<>(result.stream().map(e -> entry(file, e.line(),
                        PythonRequirement.unknown(e.requirement().name(), "TOOL_OVERRIDES_UNCONFIRMED"), e.scope())).toList());
                if (result.isEmpty()) result.add(entry(file, 0, PythonRequirement.unknown(null, "TOOL_DEPENDENCIES_UNSUPPORTED"), "UNKNOWN"));
            }
            return result;
        }
        void array(ProjectFile file, TomlArray values, String scope, List<Entry> result) {
            if (values == null) return;
            for (int i = 0; i < values.size(); i++) {
                if (result.size() >= 5000) { issue(file.relativePath(), "LIMIT_EXCEEDED", "PYTHON_COMPONENT_LIMIT"); break; }
                var r = values.get(i) instanceof String value ? PythonRequirement.parse(value)
                        : PythonRequirement.unknown(null, "DYNAMIC_GROUP_UNSUPPORTED");
                result.add(entry(file, values.inputPositionOf(i).line(), r, scope));
            }
        }
        Entry entry(ProjectFile file, int line, PythonRequirement requirement, String scope) {
            if (requirement.issue() != null) issue(file.relativePath(), "PARTIAL", requirement.issue());
            if (requirement.markerStatus().equals("CONDITIONAL_NOT_EVALUATED")) issue(file.relativePath(), "PARTIAL", "ENVIRONMENT_MARKER_NOT_EVALUATED");
            return new Entry(file.relativePath(), line, requirement, null, false, scope);
        }
        String target(String file, String reference) {
            if (!reference.matches("[A-Za-z0-9_./-]{1,240}") || reference.startsWith("/")) return null;
            Path parent = Path.of(file).getParent();
            Path path = (parent == null ? Path.of(reference) : parent.resolve(reference)).normalize();
            if (path.isAbsolute() || path.startsWith("..")) return null;
            return path.toString().replace('\\', '/');
        }
        String environment(String path) {
            String name = PythonManifestFiles.name(path).toLowerCase(Locale.ROOT);
            if (name.matches(".*(?:[-_.])(?:dev|test|tests|development)(?:[-_.]).*")) return "DEVELOPMENT_FILENAME_HINT";
            if (name.matches(".*(?:[-_.])(?:prod|production)(?:[-_.]).*")) return "PRODUCTION_FILENAME_HINT";
            return "UNKNOWN";
        }
        void issue(String file, String status, String reason) {
            observe(file, status, reason);
            if (warnings.size() < 150) warnings.add(safe(file) + ": Python 의존성 확인이 일부 제한됩니다 (" + reason + ").");
        }
        void observe(String file, String status, String reason) {
            var previous = observations.get(file);
            var order = List.of("COMPLETE", "PARTIAL", "UNSUPPORTED", "FAILED", "LIMIT_EXCEEDED");
            if (previous == null || order.indexOf(previous.status()) < order.indexOf(status)) observations.put(file, new ManifestObservation(safe(file), status, reason));
        }
        String safe(String path) { return CoverageRecorder.safePath(path); }
    }
}
