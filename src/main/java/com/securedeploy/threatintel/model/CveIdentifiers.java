package com.securedeploy.threatintel.model;

import com.securedeploy.sca.model.DependencyVulnerability;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

public final class CveIdentifiers {
    private CveIdentifiers() { }
    public static String normalize(String value) {
        if (value == null) return null;
        String normalized = value.toUpperCase(Locale.ROOT);
        return normalized.matches("CVE-[0-9]{4}-[0-9]{4,19}") ? normalized : null;
    }
    public static List<String> from(DependencyVulnerability finding) {
        return Stream.concat(Stream.of(finding.osvId()), finding.aliases().stream())
                .map(CveIdentifiers::normalize).filter(java.util.Objects::nonNull).distinct().sorted().toList();
    }
}
