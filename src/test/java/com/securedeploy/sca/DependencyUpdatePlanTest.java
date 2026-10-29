package com.securedeploy.sca;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.auth.service.ReviewAccessService;
import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.rule.model.Severity;
import com.securedeploy.sca.model.*;
import com.securedeploy.sca.service.DependencyUpdatePlanService;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

class DependencyUpdatePlanTest {
    DependencyComponent component(Boolean direct,boolean confirmed) {
        var path=new DependencyContext.DependencyPath("tools/package.json",9,"devDependencies",direct==Boolean.TRUE?"public-lib":"parent-tool","^1.0.0",confirmed,false,true,List.of());
        return new DependencyComponent(ScaEcosystem.NPM,"public-lib","1.0.0","devDependencies",direct,"tools/package-lock.json",23,VersionResolution.EXACT,
                new DependencyContext(1,"DEVELOPMENT","NOT_ANALYZED","node_modules/public-lib",23,List.of(),true,List.of(path),List.of()));
    }
    DependencyVulnerability dep(List<String> fixes) {
        return new DependencyVulnerability(ScaEcosystem.NPM,"public-lib","1.0.0","GHSA-synthetic",List.of("CVE-synthetic"),"Synthetic only",Severity.HIGH,null,List.of(),fixes,null,"2026-10-01",List.of(),List.of("tools/package-lock.json"));
    }
    DependencyUpdatePlanService.Snapshot plan(List<DependencyComponent> components,List<String> fixes) {
        var access=mock(ReviewAccessService.class);var review=mock(ReviewEntity.class);
        when(access.findAccessibleReviewWithVulnerabilities(1L,"분석 결과에 접근할 수 없습니다.")).thenReturn(review);
        when(review.getScaResult()).thenReturn(new ScaResult(2,ScaResult.Status.COMPLETE,Instant.EPOCH,null,components,List.of(dep(fixes)),List.of()));
        return new DependencyUpdatePlanService(access,new ObjectMapper().findAndRegisterModules()).get(1);
    }
    @Test void directAndTransitiveKeepDifferentActionsAndImmutableEvidence() {
        var direct=plan(List.of(component(true,true)),List.of("1.0.1","2.0.0","1.1.0-beta.1")).plans().get(0);
        assertEquals("DIRECT",direct.dependencyKind());assertEquals("REVIEW_DIRECT_DECLARATION",direct.action());assertEquals(List.of("1.0.1"),direct.sameMajorCandidates());
        assertEquals(List.of("1.0.1","2.0.0","1.1.0-beta.1"),direct.fixedVersionEvidence());assertEquals("tools/package.json",direct.locations().get(0).file());
        var indirect=plan(List.of(component(false,true)),List.of("2.0.0")).plans().get(0);
        assertEquals("REVIEW_PARENT_OR_SCOPED_OVERRIDE",indirect.action());assertEquals("parent-tool",indirect.locations().get(0).parentPackage());assertTrue(indirect.sameMajorCandidates().isEmpty());
        assertFalse(indirect.patchApplicable());assertEquals("NOT_VERIFIED",indirect.compatibility());assertEquals("REVIEW_REQUIRED",indirect.status());
    }
    @Test void unknownVersionMissingFixAndMissingDeclarationNeverBecomeApplicablePatches() {
        assertEquals("VERIFY_EXACT_VERSION",plan(List.of(),List.of("1.0.1")).plans().get(0).action());
        assertEquals("NO_FIXED_VERSION_EVIDENCE",plan(List.of(component(true,true)),List.of()).plans().get(0).action());
        assertEquals("VERIFY_DECLARATION",plan(List.of(component(true,false)),List.of("1.0.1")).plans().get(0).action());
    }
    @Test void stableFingerprintAndNoModelClaimAndNoMutation() {
        var a=plan(List.of(component(false,true)),List.of("1.0.1"));var b=plan(List.of(component(false,true)),List.of("1.0.1"));
        assertEquals(a.evidenceHash(),b.evidenceHash());assertEquals(64,a.evidenceHash().length());assertEquals("NOT_RUN",a.modelVerification());assertEquals("SAVED_SCA_EVIDENCE",a.origin());
        assertThrows(UnsupportedOperationException.class,()->a.plans().clear());assertNull(a.sourceRevision());
    }
    @Test void authorizationFailurePreventsEvidenceDisclosure() {
        var access=mock(ReviewAccessService.class);when(access.findAccessibleReviewWithVulnerabilities(anyLong(),anyString())).thenThrow(new IllegalStateException("denied"));
        assertThrows(IllegalStateException.class,()->new DependencyUpdatePlanService(access,new ObjectMapper()).get(1));
    }
    @Test void legacyAbsentScaDoesNotInventPlans() {
        var access=mock(ReviewAccessService.class);when(access.findAccessibleReviewWithVulnerabilities(anyLong(),anyString())).thenReturn(mock(ReviewEntity.class));
        assertTrue(new DependencyUpdatePlanService(access,new ObjectMapper()).get(1).plans().isEmpty());
    }
}
