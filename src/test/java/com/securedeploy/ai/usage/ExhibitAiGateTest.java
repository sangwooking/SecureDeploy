package com.securedeploy.ai.usage;

import static org.junit.jupiter.api.Assertions.*;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ExhibitAiGateTest {
    @TempDir Path directory;

    @Test void liveAuthorizationPersistsAndEnforcesSharedCeilings() throws Exception {
        Path control=directory.resolve("authorization");
        assertFalse(new ExhibitAiGate(control,"","",true).open());
        Files.writeString(control,ExhibitAiGate.LIVE_AUTHORIZATION);
        var gate=new ExhibitAiGate(control,"","",true);
        assertTrue(gate.open());
        assertTrue(gate.permitsReservation(9,9,new BigDecimal("0.302184"),new BigDecimal("0.033576")));
        assertFalse(gate.permitsReservation(10,0,BigDecimal.ZERO,BigDecimal.ZERO));
        assertFalse(gate.permitsReservation(9,0,new BigDecimal("0.48"),new BigDecimal("0.033576")));
        assertTrue(new ExhibitAiGate(control,"","",true).open());
        Files.delete(control);
        assertFalse(gate.open());
    }

    @Test void aSingleAuthorizationFileCannotOpenBothServers() throws Exception {
        Path control=directory.resolve("authorization");
        var exhibit=new ExhibitAiGate(control,"","",true);
        var main=new ExhibitAiGate(control,"","",true,ExhibitAiGate.MAIN_AUTHORIZATION);
        Files.writeString(control,ExhibitAiGate.LIVE_AUTHORIZATION);
        assertTrue(exhibit.open());
        assertFalse(main.open());
        Files.delete(control);
        assertFalse(exhibit.open());
        assertFalse(main.open());
        Files.writeString(control,ExhibitAiGate.MAIN_AUTHORIZATION);
        assertFalse(exhibit.open());
        assertTrue(main.open());
    }

    @Test void consentScopeBudgetAndRestartAreFailClosed() throws Exception {
        Path control=directory.resolve("enable");
        Path challenge=directory.resolve("enable.challenge");
        String source="a".repeat(64)+":"+"b".repeat(64)+":DEBUG_ENABLED";
        var request=new AiAdmission.Request(1,2,"request","workspace_patch_v1","c".repeat(64),
                "gpt-5.4-mini-2026-03-17","d".repeat(64));
        var gate=new ExhibitAiGate(control,"","1:2:"+source);
        assertFalse(gate.permits(request,source,32768,2000));
        Files.copy(challenge,control);
        assertTrue(gate.permits(request,source,32768,2000));
        assertFalse(gate.permits(request,source+"x",32768,2000));
        assertFalse(gate.permits(request,source,32769,2000));
        assertFalse(gate.permits(request,source,32768,2001));
        assertTrue(gate.permitsReservation(1,0,new BigDecimal("0.03"),new BigDecimal("0.03")));
        assertFalse(gate.permitsReservation(2,0,BigDecimal.ZERO,BigDecimal.ZERO));
        assertFalse(gate.permitsReservation(1,1,BigDecimal.ZERO,BigDecimal.ZERO));
        assertFalse(gate.permitsReservation(1,0,new BigDecimal("0.09"),new BigDecimal("0.02")));
        assertFalse(new ExhibitAiGate(control,"","1:2:"+source).open());
        Files.delete(control);
        assertFalse(gate.open());
    }
}
