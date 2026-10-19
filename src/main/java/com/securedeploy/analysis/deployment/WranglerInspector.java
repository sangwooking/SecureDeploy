package com.securedeploy.analysis.deployment;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.*;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.coverage.CoverageRecorder;
import java.util.*;
import org.tomlj.Toml;

/** Inventory only. Does not infer sensitive values from variable names or merge environments. */
final class WranglerInspector {
    private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
            .enable(JsonReadFeature.ALLOW_JAVA_COMMENTS).enable(JsonReadFeature.ALLOW_TRAILING_COMMA)
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(32).maxStringLength(100_000).maxNumberLength(100).build()).build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    static DeploymentSnapshot.FileResult inspect(ProjectFile file) {
        var observations = new ArrayList<DeploymentSnapshot.Observation>();
        var limits = new ArrayList<>(List.of("ENVIRONMENTS_NOT_MERGED_OR_ACTIVATED", "VARS_VALUES_OMITTED_NOT_ASSUMED_SECRET", "BINDINGS_ROUTES_AND_PLATFORM_SECRET_VALUES_NOT_VERIFIED"));
        String status = "PARSED";
        try {
            if (file.lines().stream().mapToLong(s -> s.length() + 1L).sum() > 100_000) throw new Limit();
            String content = String.join("\n", file.lines()); JsonNode root;
            if (file.relativePath().endsWith(".toml")) {
                // Bound dotted-key/table recursion before entering the TOML parser, including invalid input.
                if (file.lines().stream().anyMatch(s -> s.chars().filter(c -> c == '.' || c == '[' || c == '{').count() > 32)) throw new Limit();
                var parsed = Toml.parse(content);
                if (parsed.hasErrors()) throw new IllegalArgumentException("INVALID_TOML");
                root = JSON.readTree(parsed.toJson());
            } else root = JSON.readTree(content);
            if (root == null || !root.isObject()) throw new IllegalArgumentException("EXPECTED_OBJECT");
            scope(root, "default (activation unknown)", observations);
            if (root.has("env")) {
                if (!root.get("env").isObject() || root.get("env").size() > 40) throw new IllegalArgumentException("UNSUPPORTED_ENV_SHAPE");
                var environments = root.get("env").fields();
                int index = 0;
                while (environments.hasNext()) {
                    var entry = environments.next();
                    if (!entry.getValue().isObject()) throw new IllegalArgumentException("UNSUPPORTED_ENV_SHAPE");
                    String name = ComposeInspector.safeIdentifier(entry.getKey()); index++;
                    scope(entry.getValue(), "env:" + (name.equals("[redacted-name]") ? "[redacted-env-" + index + "]" : name), observations);
                }
            }
        } catch (Limit failure) {
            status = "LIMIT_EXCEEDED"; observations.clear(); limits.add("CONFIG_RESOURCE_LIMIT");
        } catch (Exception failure) {
            status = "PARSE_FAILED"; observations.clear(); limits.add("INVALID_OR_UNSUPPORTED_WRANGLER");
        }
        return new DeploymentSnapshot.FileResult(CoverageRecorder.safePath(file.relativePath()), "WRANGLER", status, observations, limits);
    }
    private static void scope(JsonNode node, String scope, List<DeploymentSnapshot.Observation> output) {
        for (String key : List.of("vars", "secrets", "secrets_store_secrets", "unsafe", "routes", "route", "workers_dev", "preview_urls",
                "kv_namespaces", "d1_databases", "r2_buckets", "services", "durable_objects", "queues", "ai", "assets")) {
            if (!node.has(key)) continue;
            if (output.size() >= 200) throw new Limit();
            JsonNode value = node.get(key);
            boolean known = switch (key) {
                case "vars", "durable_objects", "queues", "ai", "assets" -> value.isObject();
                case "workers_dev", "preview_urls" -> value.isBoolean();
                case "routes", "kv_namespaces", "d1_databases", "r2_buckets", "services", "secrets_store_secrets" -> value.isArray();
                case "route" -> value.isTextual() || value.isObject();
                default -> false;
            };
            String summary = !known ? "not resolved" : value.isBoolean() ? String.valueOf(value.booleanValue())
                    : value.isContainerNode() ? value.size() + " declarations (values omitted)" : "declaration (value omitted)";
            // Line 1 is document-level evidence; never invent a precise key line from string matching.
            output.add(new DeploymentSnapshot.Observation(1, scope, key, known ? "STATIC" : "UNKNOWN", summary, ""));
        }
    }
    private static final class Limit extends RuntimeException { }
}
