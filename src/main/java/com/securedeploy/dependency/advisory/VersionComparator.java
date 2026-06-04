package com.securedeploy.dependency.advisory;

final class VersionComparator {

    private VersionComparator() {
    }

    static boolean isLessThan(String currentVersion, String targetVersion) {
        return compare(currentVersion, targetVersion) < 0;
    }

    static boolean isLessThanOrEqual(String currentVersion, String targetVersion) {
        return compare(currentVersion, targetVersion) <= 0;
    }

    static int compare(String left, String right) {
        int[] leftParts = parse(left);
        int[] rightParts = parse(right);
        int max = Math.max(leftParts.length, rightParts.length);
        for (int i = 0; i < max; i++) {
            int leftValue = i < leftParts.length ? leftParts[i] : 0;
            int rightValue = i < rightParts.length ? rightParts[i] : 0;
            if (leftValue != rightValue) {
                return Integer.compare(leftValue, rightValue);
            }
        }
        return 0;
    }

    private static int[] parse(String version) {
        if (version == null || version.isBlank()) {
            return new int[0];
        }
        String normalized = version.strip()
                .replaceAll("^[~^<>=v\\s]+", "")
                .replaceAll("[^0-9.].*$", "");
        if (normalized.isBlank()) {
            return new int[0];
        }
        String[] tokens = normalized.split("\\.");
        int[] parts = new int[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            try {
                parts[i] = Integer.parseInt(tokens[i].replaceAll("\\D", ""));
            } catch (NumberFormatException exception) {
                parts[i] = 0;
            }
        }
        return parts;
    }
}
