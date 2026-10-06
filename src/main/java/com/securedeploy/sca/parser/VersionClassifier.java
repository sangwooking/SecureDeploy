package com.securedeploy.sca.parser;
import com.securedeploy.sca.model.*;
public final class VersionClassifier {
    private VersionClassifier() { }
    public static DependencyComponent component(ScaEcosystem ecosystem, String name, String version,
                                                 String scope, Boolean direct, String file, int line) {
        String value = version == null ? "" : version.strip();
        VersionResolution resolution = classify(ecosystem, value);
        String namePattern = ecosystem == ScaEcosystem.MAVEN
                ? "[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+" : "(@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+";
        if (name == null || name.length() > 256 || !name.matches(namePattern)) {
            resolution = VersionResolution.UNRESOLVED;
            name = "<unresolved-package>";
        }
        // Git/URL specs may contain credentials. Never persist or query these values.
        if (value.length() > 128 || value.contains(":") || value.contains("/") || value.contains("@")) {
            value = "<non-registry-spec>";
            resolution = VersionResolution.UNRESOLVED;
        }
        return new DependencyComponent(ecosystem, name, value.isEmpty() ? null : value,
                scope, direct, file, line, resolution);
    }
    public static VersionResolution classify(ScaEcosystem ecosystem, String value) {
        if (value == null || value.isBlank() || value.contains("$") || value.contains(":")
                || value.contains("/") || value.toUpperCase().endsWith("SNAPSHOT")
                || value.equalsIgnoreCase("latest") || value.equalsIgnoreCase("release")) {
            return VersionResolution.UNRESOLVED;
        }
        if (value.matches(".*[~^*<>=|\\[\\](),\\s].*") || value.endsWith("+")
                || value.matches(".*(?:^|\\.)[xX](?:\\.|$).*")) return VersionResolution.RANGE;
        boolean exact = ecosystem == ScaEcosystem.NPM
                ? value.matches("(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\\+[0-9A-Za-z.-]+)?")
                : value.matches("[0-9][0-9A-Za-z._-]*");
        if (exact && ecosystem == ScaEcosystem.NPM) {
            String withoutBuild = value.split("\\+", 2)[0];
            int hyphen = withoutBuild.indexOf('-');
            if (hyphen >= 0) for (String part : withoutBuild.substring(hyphen + 1).split("\\.", -1)) {
                if (part.isEmpty() || part.matches("0[0-9]+")) exact = false;
            }
            int plus = value.indexOf('+');
            if (plus >= 0) for (String part : value.substring(plus + 1).split("\\.", -1)) {
                if (part.isEmpty()) exact = false;
            }
        }
        return exact ? VersionResolution.EXACT : VersionResolution.UNRESOLVED;
    }
}
