package com.securedeploy.rule.rules;

record ConfigEntry(
        String key,
        String normalizedKey,
        String value,
        int line,
        String evidence
) {
}
