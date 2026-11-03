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

    @Test void scaIsOptInForMainAndBoundToOwnerProjectAndEvidence() throws Exception {
        var control=directory.resolve("main");
        Files.writeString(control,ExhibitAiGate.MAIN_AUTHORIZATION);
        var main=new ExhibitAiGate(control,"","",true,ExhibitAiGate.MAIN_AUTHORIZATION);
        var evidence="a".repeat(64);
        var request=new AiAdmission.Request(1,2,"id","dependency_update_advice_v1",evidence,
                "gpt-5.4-mini-2026-03-17","b".repeat(64));
        assertFalse(main.permits(request,evidence,1000,2000));
        main.configureDependency("1:2:"+evidence);
        assertTrue(main.permits(request,evidence,1000,2000));
        assertFalse(main.permitsDependency(3,2,evidence));
        assertFalse(main.permitsDependency(1,3,evidence));
        assertFalse(main.permits(request,"c".repeat(64),1000,2000));
        assertFalse(main.permits(request,evidence,1000,2001));
        Files.writeString(control,ExhibitAiGate.LIVE_AUTHORIZATION);
        var exhibition=new ExhibitAiGate(control,"","",true);
        exhibition.configureDependency("1:2:"+evidence);
        assertFalse(exhibition.permits(request,evidence,1000,2000));
        assertFalse(main.permits(request,evidence,1000,2000));
    }

    @Test void pinnedSourceCanBeReusedAcrossFreshReviewsWithoutExpandingScope() throws Exception {
        var control=directory.resolve("pinned-source");
        Files.writeString(control,ExhibitAiGate.MAIN_AUTHORIZATION);
        var gate=new ExhibitAiGate(control,"","",true,ExhibitAiGate.MAIN_AUTHORIZATION);
        var source="987:"+"a".repeat(40)+":undici:7.29.1";
        gate.configureDependencySource("1:"+source);
        for(int project: new int[]{43,51}){
            var evidence=(project==43?"b":"c").repeat(64);
            var request=new AiAdmission.Request(1,project,"fresh-"+project,"dependency_update_advice_v1",evidence,
                "gpt-5.4-mini-2026-03-17","d".repeat(64));
            assertTrue(gate.permits(request,source,1000,2000));
            assertFalse(gate.permits(request,source.replace("7.29.1","7.29.2"),1000,2000));
        }
        assertFalse(gate.permitsDependencySource(2,source));
        assertFalse(gate.permitsDependencySource(1,source.replace("987:","988:")));
    }
}
