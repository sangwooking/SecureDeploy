package com.securedeploy.analysis.python;

import com.securedeploy.project.model.ProjectFile;
import java.util.*;
import java.util.regex.Pattern;

/** Lexical scheduling hints only. The worker must independently validate every entry and import. */
final class PythonSourceSelector {
    private static final int MAX_HINT_FILES = 1000, MAX_HINT_CHARACTERS = 1_000_000;
    private static final Pattern FROM = Pattern.compile("(?m)^\\s*from\\s+([.\\w]+)\\s+import\\s+([^\\n#]+)");
    private static final Pattern IMPORT = Pattern.compile("(?m)^\\s*import\\s+([^\\n#]+)");
    private static final Pattern URLCONF = Pattern.compile("(?m)^\\s*ROOT_URLCONF\\s*=\\s*['\"]([\\w.]+)['\"]");
    private static final Pattern INCLUDE = Pattern.compile("\\binclude\\(\\s*['\"]([\\w.]+)['\"]");
    record Candidate(ProjectFile file, String reason, int priority) { }

    static List<Candidate> order(List<ProjectFile> files) {
        files = files.stream().sorted(Comparator.comparing(ProjectFile::relativePath)).toList();
        Map<String, String> modules = new HashMap<>();
        Set<String> ambiguous = new HashSet<>();
        for (var file : files) {
            String module = module(file.relativePath());
            if (modules.putIfAbsent(module, file.relativePath()) != null) ambiguous.add(module);
        }
        ambiguous.forEach(modules::remove);
        Map<String, Set<String>> edges = new HashMap<>();
        Map<String, Integer> priorities = new HashMap<>();
        Map<String, String> reasons = new HashMap<>();
        int hintFiles = 0, hintCharacters = 0;
        for (var file : files) {
            String path = file.relativePath();
            Set<String> references = new TreeSet<>();
            edges.put(path, references);
            priorities.put(path, 99); reasons.put(path, "DETERMINISTIC_FALLBACK");
            long length = file.lines().stream().mapToLong(s -> s.length() + 1L).sum();
            if (length > 100_000) continue;
            if (hintFiles >= MAX_HINT_FILES || hintCharacters + length > MAX_HINT_CHARACTERS) {
                reasons.put(path, "SELECTION_HINT_LIMIT");
                continue;
            }
            hintFiles++; hintCharacters += (int) length;
            String source = String.join("\n", file.lines());
            boolean framework = false, routing = false, entry = false;
            var from = FROM.matcher(source);
            while (from.find()) {
                String imported = resolveRelative(path, from.group(1));
                if (imported == null) continue;
                add(references, modules, imported);
                for (String name : from.group(2).replace("(", "").replace(")", "").split(",")) {
                    String symbol = name.strip().split("\\s+")[0];
                    if (symbol.matches("[A-Za-z_]\\w*")) add(references, modules, imported + "." + symbol);
                }
                framework |= imported.startsWith("django.") || imported.startsWith("rest_framework.");
                routing |= imported.equals("django.urls") || imported.equals("django.conf.urls") || imported.equals("rest_framework.routers");
                entry |= imported.startsWith("django.views") || imported.startsWith("rest_framework.views")
                        || imported.startsWith("rest_framework.viewsets") || imported.equals("rest_framework.decorators");
            }
            var imports = IMPORT.matcher(source);
            while (imports.find()) for (String item : imports.group(1).split(",")) {
                String imported = item.strip().split("\\s+")[0];
                add(references, modules, imported);
                routing |= imported.equals("django.urls") || imported.equals("rest_framework.routers");
                entry |= imported.startsWith("django.views") || imported.startsWith("rest_framework.views") || imported.startsWith("rest_framework.viewsets");
                framework |= imported.startsWith("django.") || imported.startsWith("rest_framework.");
            }
            for (var pattern : List.of(URLCONF, INCLUDE)) {
                var matcher = pattern.matcher(source);
                while (matcher.find()) add(references, modules, matcher.group(1));
            }
            if (routing || URLCONF.matcher(source).find()) {
                priorities.put(path, 0); reasons.put(path, "DJANGO_ROUTING_HINT");
            } else if (entry && framework) {
                priorities.put(path, 1); reasons.put(path, "DJANGO_ENTRY_HINT");
            }
        }
        // Bounded breadth-first import expansion; path order breaks ties reproducibly.
        for (int depth = 0; depth < 5; depth++) {
            var before = new HashMap<>(priorities);
            for (var path : new TreeSet<>(edges.keySet())) {
                int rank = before.get(path);
                if (rank > depth + 1) continue;
                for (var target : edges.get(path)) {
                    int next = Math.max(2, rank + 1);
                    if (next < priorities.get(target)) {
                        priorities.put(target, next); reasons.put(target, "RELATED_IMPORT_HINT");
                    }
                }
            }
        }
        return files.stream().map(f -> new Candidate(f, reasons.get(f.relativePath()), priorities.get(f.relativePath())))
                .sorted(Comparator.comparingInt(Candidate::priority).thenComparing(c -> c.file().relativePath())).toList();
    }

    private static void add(Set<String> paths, Map<String, String> modules, String module) {
        if (modules.containsKey(module)) paths.add(modules.get(module));
    }
    private static String module(String path) {
        String name = path.substring(0, path.length() - 3).replace('/', '.');
        return name.endsWith(".__init__") ? name.substring(0, name.length() - 9) : name;
    }
    private static String resolveRelative(String path, String imported) {
        if (!imported.startsWith(".")) return imported;
        int level = 0;
        while (level < imported.length() && imported.charAt(level) == '.') level++;
        var parts = new ArrayList<>(Arrays.asList(module(path).split("\\.")));
        if (!path.endsWith("/__init__.py")) parts.remove(parts.size() - 1);
        if (level > parts.size() + 1) return null;
        for (int i = 1; i < level; i++) parts.remove(parts.size() - 1);
        String prefix = String.join(".", parts), tail = imported.substring(level);
        return prefix.isEmpty() ? tail : tail.isEmpty() ? prefix : prefix + "." + tail;
    }
}
