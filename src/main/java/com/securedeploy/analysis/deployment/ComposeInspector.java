package com.securedeploy.analysis.deployment;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.coverage.CoverageRecorder;
import java.io.StringReader;
import java.util.*;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.nodes.*;

/** YAML nodes only: no arbitrary object construction, external reference loading or execution. */
public final class ComposeInspector {
    public static final int MAX_CHARS = 100_000;
    private final List<DeploymentSnapshot.Observation> observations = new ArrayList<>();
    private final Set<String> limitations = new LinkedHashSet<>();
    private int nodes;
    private int services;
    private final long deadline = System.nanoTime() + 500_000_000L;
    private ComposeInspector() { }
    public static DeploymentSnapshot.FileResult inspect(ProjectFile file) {
        var inspector = new ComposeInspector(); String status = "PARSED";
        try {
            if (file.lines().stream().mapToLong(s -> s.length() + 1L).sum() > MAX_CHARS) throw new Limit();
            var options = new LoaderOptions();
            options.setCodePointLimit(MAX_CHARS); options.setNestingDepthLimit(32);
            options.setMaxAliasesForCollections(0); options.setAllowDuplicateKeys(false);
            Node node = new Yaml(options).compose(new StringReader(String.join("\n", file.lines())));
            inspector.validate(node, 0, Collections.newSetFromMap(new IdentityHashMap<>()));
            var root = map(node);
            if (root.containsKey("include")) inspector.limitations.add("EXTERNAL_INCLUDE_NOT_RESOLVED");
            var services = map(root.get("services"));
            if (services.isEmpty()) inspector.limitations.add("NO_SERVICE_MAPPING");
            for (var entry : services.entrySet()) inspector.service(entry.getKey(), map(entry.getValue()));
        } catch (Limit failure) {
            status = "LIMIT_EXCEEDED"; inspector.observations.clear(); inspector.limitations.add("CONFIG_RESOURCE_LIMIT");
        } catch (RuntimeException failure) {
            status = "PARSE_FAILED"; inspector.observations.clear(); inspector.limitations.add("INVALID_OR_UNSUPPORTED_YAML");
        }
        inspector.limitations.add("DECLARATIONS_ONLY_RUNTIME_AND_OVERRIDES_UNKNOWN");
        return new DeploymentSnapshot.FileResult(CoverageRecorder.safePath(file.relativePath()), "COMPOSE", status,
                List.copyOf(inspector.observations), List.copyOf(inspector.limitations));
    }
    private void validate(Node node, int depth, Set<Node> visited) {
        if (node == null || depth > 32 || ++nodes > 5000 || System.nanoTime() > deadline) throw new Limit();
        if (!visited.add(node)) throw new IllegalArgumentException("YAML_ALIAS_UNSUPPORTED");
        if (!Set.of(Tag.MAP, Tag.SEQ, Tag.STR, Tag.BOOL, Tag.INT, Tag.NULL, Tag.FLOAT).contains(node.getTag())) throw new IllegalArgumentException("UNSUPPORTED_TAG");
        if (node instanceof MappingNode mapping) {
            var keys = new HashSet<String>();
            for (var tuple : mapping.getValue()) {
                if (!(tuple.getKeyNode() instanceof ScalarNode key) || !Tag.STR.equals(key.getTag()) || !keys.add(key.getValue()) || key.getValue().equals("<<")) throw new IllegalArgumentException("UNSUPPORTED_KEY");
                validate(tuple.getKeyNode(), depth + 1, visited); validate(tuple.getValueNode(), depth + 1, visited);
            }
        } else if (node instanceof SequenceNode sequence) for (var item : sequence.getValue()) validate(item, depth + 1, visited);
    }
    private void service(String name, Map<String, Node> service) {
        services++;
        String safeName = safeIdentifier(name);
        String scope = "service:" + (safeName.equals("[redacted-name]") ? "[redacted-service-" + services + "]" : safeName);
        if (service.isEmpty()) { limitations.add("SERVICE_SHAPE_UNSUPPORTED"); return; }
        for (String key : List.of("extends", "env_file", "profiles", "provider")) if (service.containsKey(key)) limitations.add("SERVICE_ACTIVATION_OR_REFERENCE_UNRESOLVED");
        simple(scope, service, "privileged", "true", "DOCKER_PRIVILEGED");
        simple(scope, service, "network_mode", "host", "DOCKER_HOST_NETWORK");
        if (service.containsKey("user")) {
            Node node = service.get("user"); String user = scalar(node);
            boolean known = user.matches("[A-Za-z_0-9][A-Za-z0-9_.-]*(?::[A-Za-z_0-9][A-Za-z0-9_.-]*)?");
            boolean root = known && (user.split(":")[0].equals("root") || user.split(":")[0].matches("0+"));
            add(node, scope, "user", known, root ? "root declaration" : "non-root declaration", root ? "COMPOSE_ROOT_OVERRIDE" : "");
            limitations.add("USER_OVERRIDES_IMAGE_DEFAULT_BUILD_TARGET_AND_RUNTIME_NOT_RESOLVED");
        } else observations.add(new DeploymentSnapshot.Observation(1, scope, "user", "UNKNOWN", "image/runtime user not inspected", ""));
        list(scope, service, "cap_add", (node, index) -> {
            String value = scalar(node).toUpperCase(Locale.ROOT).replaceFirst("^CAP_", "");
            add(node, scope, "cap_add[" + index + "]", value.matches("[A-Z_]+"), "capability declaration",
                    Set.of("ALL", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "DAC_READ_SEARCH", "DAC_OVERRIDE", "SYS_MODULE").contains(value) ? "COMPOSE_CAPABILITY" : "");
        });
        list(scope, service, "security_opt", (node, index) -> {
            String value = scalar(node);
            boolean disabled = Set.of("seccomp:unconfined", "seccomp=unconfined", "apparmor:unconfined", "apparmor=unconfined", "label:disable", "label=disable", "no-new-privileges:false", "no-new-privileges=false").contains(value);
            add(node, scope, "security_opt[" + index + "]", !value.isEmpty() && !value.contains("$"), disabled ? "security restriction disabled" : "security option declared", disabled ? "COMPOSE_SECURITY_DISABLED" : "");
        });
        list(scope, service, "volumes", (node, index) -> volume(scope, node, index));
        list(scope, service, "ports", (node, index) -> port(scope, node, index));
        if (service.containsKey("build")) limitations.add("DOCKERFILE_TARGET_IMAGE_AND_COMPOSE_USER_NOT_MERGED");
        Set<String> checked = Set.of("privileged", "network_mode", "user", "cap_add", "security_opt", "volumes", "ports");
        if (service.keySet().stream().anyMatch(k -> !checked.contains(k))) limitations.add("OTHER_SERVICE_OPTIONS_NOT_SECURITY_VALIDATED");
    }
    private void simple(String scope, Map<String, Node> service, String key, String risky, String rule) {
        if (!service.containsKey(key)) return;
        Node node = service.get(key); String value = scalar(node);
        boolean known = key.equals("privileged") ? Set.of("true", "false").contains(value.toLowerCase(Locale.ROOT)) : value.matches("[A-Za-z0-9_.:-]+");
        boolean match = key.equals("privileged") ? value.equalsIgnoreCase(risky) : value.equals(risky);
        add(node, scope, key, known, match ? risky : "other static declaration", match ? rule : "");
    }
    private void volume(String scope, Node node, int index) {
        String source = "", type = ""; boolean known = false;
        if (node instanceof MappingNode) {
            var fields = map(node); source = scalar(fields.get("source")); type = scalar(fields.get("type")); String target = scalar(fields.get("target"));
            known = Set.of("bind", "volume", "tmpfs", "image").contains(type) && !source.contains("$") && target.startsWith("/") && !target.contains("$");
        } else {
            String[] parts = scalar(node).split(":", -1);
            if (parts.length >= 2 && parts.length <= 3 && !scalar(node).contains("$")) {
                source = parts[0]; type = source.startsWith("/") || source.startsWith(".") ? "bind" : "volume";
                known = !source.isEmpty() && parts[1].startsWith("/");
            } else if (parts.length == 1 && parts[0].startsWith("/") && !parts[0].contains("$")) { known = true; type = "volume"; }
        }
        if (known && type.equals("bind") && source.startsWith("/")) source = java.nio.file.Path.of(source).normalize().toString();
        limitations.add("MOUNT_CONTENTS_AND_SYMLINKS_NOT_INSPECTED");
        boolean socket = known && type.equals("bind") && Set.of("/var/run/docker.sock", "/run/docker.sock").contains(source);
        boolean host = known && type.equals("bind") && Set.of("/", "/etc", "/proc", "/sys", "/dev", "/var/run", "/run").contains(source);
        add(node, scope, "volumes[" + index + "]", known, socket ? "Docker socket bind" : host ? "sensitive host bind" : "mount declaration", socket ? "COMPOSE_SOCKET" : host ? "COMPOSE_HOST_MOUNT" : "");
    }
    private void port(String scope, Node node, int index) {
        String host = ""; boolean known = false;
        if (node instanceof MappingNode) {
            var fields = map(node); host = scalar(fields.get("host_ip"));
            known = scalar(fields.get("target")).matches("[0-9]+") && scalar(fields.get("published")).matches("[0-9]+(?:-[0-9]+)?") && !host.contains("$");
        } else {
            String value = scalar(node).replaceFirst("/(tcp|udp)$", "");
            var matcher = java.util.regex.Pattern.compile("(?:(\\[[0-9a-fA-F:]+\\]|[0-9.]+):)?([0-9]+(?:-[0-9]+)?):([0-9]+(?:-[0-9]+)?)").matcher(value);
            if (matcher.matches()) { known = true; host = matcher.group(1) == null ? "" : matcher.group(1); }
            else if (value.matches("[0-9]+")) known = true;
        }
        boolean broad = known && Set.of("", "0.0.0.0", "::", "[::]").contains(host);
        add(node, scope, "ports[" + index + "]", known, broad ? "host binding unspecified/all interfaces" : "explicit interface declaration", broad ? "COMPOSE_PORT_BINDING" : "");
    }
    private void list(String scope, Map<String, Node> service, String key, java.util.function.BiConsumer<Node, Integer> consumer) {
        if (!service.containsKey(key)) return;
        Node node = service.get(key);
        if (!(node instanceof SequenceNode sequence)) { add(node, scope, key, false, "", ""); return; }
        int index = 0; for (var item : sequence.getValue()) consumer.accept(item, index++);
    }
    private void add(Node node, String scope, String key, boolean known, String summary, String rule) {
        if (observations.size() >= 200 || System.nanoTime() > deadline) throw new Limit();
        if (!known) limitations.add("DYNAMIC_OR_UNSUPPORTED_SETTING");
        observations.add(new DeploymentSnapshot.Observation(node.getStartMark().getLine() + 1, scope, key, known ? "STATIC" : "UNKNOWN", known ? summary : "not resolved", known ? rule : ""));
    }
    static String safeIdentifier(String value) {
        return value.matches("[A-Za-z_][A-Za-z0-9_.-]{0,63}") && !CoverageRecorder.safePath(value).equals("[redacted-path]") ? value : "[redacted-name]";
    }
    private static Map<String, Node> map(Node node) {
        if (!(node instanceof MappingNode mapping)) throw new IllegalArgumentException("EXPECTED_MAPPING");
        var result = new LinkedHashMap<String, Node>();
        for (var pair : mapping.getValue()) result.put(((ScalarNode) pair.getKeyNode()).getValue(), pair.getValueNode());
        return result;
    }
    private static String scalar(Node node) { return node instanceof ScalarNode value ? value.getValue() : ""; }
    private static final class Limit extends RuntimeException { }
}
