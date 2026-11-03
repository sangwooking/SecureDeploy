package com.securedeploy.ai.usage;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

/** Optional policy for the dedicated exhibition instance and its dedicated ledger database. */
final class ExhibitAiGate {
    private static final String MODEL = "gpt-5.4-mini-2026-03-17";
    private static final BigDecimal BUDGET = new BigDecimal("0.10");
    static final String LIVE_AUTHORIZATION = "securedeploy-exhibit-v1:10:0.50";
    private final Path control;
    private final boolean persistent;
    private final String bootToken = UUID.randomUUID().toString();
    private final String expressScope;
    private final String springScope;

    ExhibitAiGate(Path control, String expressScope, String springScope) {
        this(control, expressScope, springScope, false);
    }

    ExhibitAiGate(Path control, String expressScope, String springScope, boolean persistent) {
        this.control = control;
        this.persistent = persistent;
        this.expressScope = expressScope;
        this.springScope = springScope;
        if (persistent) return;
        try {
            Files.writeString(control.resolveSibling(control.getFileName()+".challenge"), bootToken);
        } catch (IOException e) {
            throw new IllegalStateException("Exhibition control unavailable", e);
        }
    }

    boolean persistent(){return persistent;}

    boolean open() {
        try {
            String expected = persistent ? LIVE_AUTHORIZATION : bootToken;
            return Files.isRegularFile(control, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                    && Files.size(control)==expected.length()
                    && expected.equals(Files.readString(control));
        } catch (IOException e) {
            return false;
        }
    }

    boolean permits(AiAdmission.Request request, String source, int input, int output) {
        if (!open() || request==null || !MODEL.equals(request.model())
                || input<1 || input>32768 || output<1 || output>2000) return false;
        var expected = switch (request.feature()) {
            case "workspace_patch_plan_v1" -> expressScope;
            case "workspace_patch_v1" -> springScope;
            default -> "";
        };
        return source!=null && expected.matches("[1-9][0-9]*:[1-9][0-9]*:[0-9a-f]{64}:[0-9a-f]{64}:(TS_SENSITIVE_DATA_EXPOSURE|DEBUG_ENABLED)")
                && expected.equals(request.user()+":"+request.project()+":"+source)
                && expected.endsWith("workspace_patch_v1".equals(request.feature())
                    ? ":DEBUG_ENABLED" : ":TS_SENSITIVE_DATA_EXPOSURE");
    }

    boolean permitsReservation(int count, int sameFeature, BigDecimal total, BigDecimal cost) {
        return open() && count<(persistent?10:2) && (persistent||sameFeature==0)
                && total.add(cost).compareTo(persistent?new BigDecimal("0.50"):BUDGET)<=0;
    }
}
