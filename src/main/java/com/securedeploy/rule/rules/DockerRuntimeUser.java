package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import java.util.*;
import java.util.regex.Pattern;

/** Default final stage only: does not resolve registry image config, build targets or runtime overrides. */
public final class DockerRuntimeUser {
    public enum Status { ROOT_DECLARED, NON_ROOT_DECLARED, UNKNOWN }
    public record Result(Status status, int line, String reason) { }
    private static final Pattern HEREDOC = Pattern.compile("<<-?['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?");
    private DockerRuntimeUser() { }

    public static Result inspect(ProjectFile file) {
        Map<String, Result> stages = new HashMap<>();
        Set<String> onbuildStages = new HashSet<>();
        String alias = null;
        Result state = new Result(Status.UNKNOWN, 1, "NO_SUPPORTED_FINAL_STAGE");
        boolean stage = false, onbuild = false;
        char escape = '\\';
        Deque<String> heredocs = new ArrayDeque<>();
        StringBuilder logical = new StringBuilder();
        int logicalLine = 1;
        for (int i = 0; i < file.lines().size(); i++) {
            String line = file.lines().get(i).strip();
            if (!heredocs.isEmpty()) { if (line.equals(heredocs.peek())) heredocs.remove(); continue; }
            if (line.startsWith("#")) {
                if (!stage && line.matches("(?i)#\\s*escape\\s*=\\s*`")) escape = '`';
                continue;
            }
            if (line.isEmpty()) continue;
            if (logical.isEmpty()) logicalLine = i + 1;
            boolean continued = line.charAt(line.length() - 1) == escape;
            logical.append(continued ? line.substring(0, line.length() - 1) : line).append(' ');
            if (continued) continue;
            String instruction = logical.toString().strip(); logical.setLength(0);
            String[] split = instruction.split("\\s+", 2);
            String op = split[0].toUpperCase(Locale.ROOT);
            String value = split.length == 2 ? split[1].strip() : "";
            if (op.equals("RUN") || op.equals("COPY")) {
                var here = HEREDOC.matcher(value);
                while (here.find()) heredocs.add(here.group(1));
            }
            if (op.equals("FROM")) {
                if (stage && alias != null) { stages.put(alias, state); if (onbuild) onbuildStages.add(alias); }
                String[] parts = value.split("\\s+");
                int base = 0;
                while (base < parts.length && parts[base].startsWith("--")) base++;
                String parent = base < parts.length ? parts[base].toLowerCase(Locale.ROOT) : "";
                state = stages.getOrDefault(parent, new Result(Status.UNKNOWN, logicalLine, "BASE_IMAGE_USER_NOT_INSPECTED"));
                if (onbuildStages.contains(parent)) state = new Result(Status.UNKNOWN, logicalLine, "ONBUILD_INHERITANCE_NOT_RESOLVED");
                alias = base + 2 < parts.length && parts[base + 1].equalsIgnoreCase("AS")
                        ? parts[base + 2].toLowerCase(Locale.ROOT) : null;
                stage = true; onbuild = false;
            } else if (stage && op.equals("USER")) {
                if (!value.matches("[A-Za-z_0-9][A-Za-z0-9_.-]*(?::[A-Za-z_0-9][A-Za-z0-9_.-]*)?")) {
                    state = new Result(Status.UNKNOWN, logicalLine, "USER_EXPRESSION_NOT_RESOLVED");
                } else {
                    String user = value.split(":", 2)[0];
                    boolean root = user.equals("root") || user.matches("0+");
                    state = new Result(root ? Status.ROOT_DECLARED : Status.NON_ROOT_DECLARED, logicalLine,
                            root ? "FINAL_STAGE_ROOT_USER" : "FINAL_STAGE_NON_ROOT_DECLARATION");
                }
            } else if (stage && op.equals("ONBUILD")) onbuild = true;
        }
        if (!logical.isEmpty() || !heredocs.isEmpty()) return new Result(Status.UNKNOWN, logicalLine, "INCOMPLETE_DOCKER_INSTRUCTION");
        return state;
    }
}
