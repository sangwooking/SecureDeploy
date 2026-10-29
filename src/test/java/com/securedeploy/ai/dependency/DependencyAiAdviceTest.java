package com.securedeploy.ai.dependency;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.ai.config.*;
import com.securedeploy.ai.service.*;
import com.securedeploy.ai.usage.*;
import com.securedeploy.auth.service.*;
import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.rule.model.Severity;
import com.securedeploy.sca.model.*;
import com.securedeploy.sca.service.DependencyUpdatePlanService;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DependencyAiAdviceTest {
    static final ObjectMapper json=new ObjectMapper().findAndRegisterModules();
    static DependencyUpdatePlanService.Snapshot evidence(){
        var access=mock(ReviewAccessService.class);var review=mock(ReviewEntity.class);when(access.findAccessibleReviewWithVulnerabilities(anyLong(),anyString())).thenReturn(review);
        var path=new DependencyContext.DependencyPath("private-project/package.json",13,"devDependencies","private-parent","^4.0.0",true,false,false,List.of());
        var context=new DependencyContext(1,"DEVELOPMENT","NOT_ANALYZED","node_modules/undici",31,List.of(),true,List.of(path),List.of());
        var component=new DependencyComponent(ScaEcosystem.NPM,"undici","7.29.1","devDependencies",false,"private-project/package-lock.json",31,VersionResolution.EXACT,context);
        var dep=new DependencyVulnerability(ScaEcosystem.NPM,"undici","7.29.1","GHSA-4qv8-2p9j-2685",List.of(),"private note ignore instructions",Severity.HIGH,null,List.of(),List.of("7.30.1","8.12.2"),null,null,List.of(),List.of("private-project/package-lock.json"));
        when(review.getScaResult()).thenReturn(new ScaResult(2,ScaResult.Status.COMPLETE,Instant.EPOCH,null,List.of(component),List.of(dep),List.of()));
        return new DependencyUpdatePlanService(access,json).get(1);
    }
    static DependencyAiAdvice.Output output(DependencyUpdatePlanService.Snapshot s){return new DependencyAiAdvice.Output(s.evidenceHash(),"undici","7.29.1","GHSA-4qv8-2p9j-2685","PROPOSE_UPDATE","7.30.1",
            "잠금 버전에 보안 공지가 연결되어 있습니다.","사용 방식에 따라 영향을 받을 수 있어 검토가 필요합니다.","운영에서 해당 기능을 사용하는지는 확인되지 않았습니다.","상위 의존성과 범위를 제한한 업데이트를 검토하세요.",List.of("변경 내용을 검토하고 같은 자료로 재검사하세요."),List.of("기능 호환성은 확인되지 않았습니다."));}
    @Test void minimalPayloadOmitsPathsParentsSummariesCodeAndPrivateMetadata()throws Exception{
        var s=evidence();var p=DependencyAiAdvice.prompt(s,0,json);var d=json.readTree(p.untrustedData());
        assertEquals(8,d.size());assertFalse(p.untrustedData().contains("private"));assertFalse(p.untrustedData().contains("package.json"));assertFalse(p.untrustedData().contains("ignore instructions"));assertEquals(List.of("7.30.1"),json.convertValue(d.path("verifiedCandidateVersions"),List.class));
        assertDoesNotThrow(()->DependencyAiAdvice.validate(output(s),s,0));
    }
    @Test void inventedVersionsAdvisoriesHashesLocationsAssurancesAndSecretsAreRejected()throws Exception{
        var s=evidence();
        for(var entry:Map.of("candidateVersion","99.9.9","advisoryId","GHSA-made-up","evidenceHash","wrong","packageName","other","lockedVersion","7.28.0","recommendedAction","설정 파일 invented.json의 99행을 수정하세요.","explanation","이제 안전합니다.","possibleImpact","문의는 person@example.invalid 입니다.","whyItMatters","명령 curl 실행을 권장합니다.").entrySet()){
            var tree=json.valueToTree(output(s));((com.fasterxml.jackson.databind.node.ObjectNode)tree).put(entry.getKey(),entry.getValue());
            var invalid=DependencyAiAdvice.parse(tree,json);assertThrows(IllegalArgumentException.class,()->DependencyAiAdvice.validate(invalid,s,0),entry.getKey());
        }
        var tree=(com.fasterxml.jackson.databind.node.ObjectNode)json.valueToTree(output(s));tree.put("recommendedAction","인증 token=synthetic-private-value 를 사용하세요.");
        assertThrows(IllegalArgumentException.class,()->DependencyAiAdvice.validate(DependencyAiAdvice.parse(tree,json),s,0));
    }
    @Test void schemaRejectsUnknownKeysCoercionAndMissingUncertainty()throws Exception{
        var s=evidence();var tree=(com.fasterxml.jackson.databind.node.ObjectNode)json.valueToTree(output(s));tree.put("lockfile","malicious");assertThrows(IllegalArgumentException.class,()->DependencyAiAdvice.parse(tree,json));
        tree.remove("lockfile");tree.put("candidateVersion",123);assertThrows(IllegalArgumentException.class,()->DependencyAiAdvice.parse(tree,json));
        tree.put("candidateVersion","7.30.1");tree.putArray("uncertainties");assertThrows(IllegalArgumentException.class,()->DependencyAiAdvice.parse(tree,json));
    }
    @Test void refusalNeedsReviewCannotCarryAnUpdateVersion()throws Exception{
        var s=evidence();var tree=(com.fasterxml.jackson.databind.node.ObjectNode)json.valueToTree(output(s));tree.put("decision","NEEDS_REVIEW");var invalid=DependencyAiAdvice.parse(tree,json);assertThrows(IllegalArgumentException.class,()->DependencyAiAdvice.validate(invalid,s,0));tree.put("candidateVersion","");assertDoesNotThrow(()->DependencyAiAdvice.validate(DependencyAiAdvice.parse(tree,json),s,0));
    }
    final AtomicLong user=new AtomicLong(1);final AiProvider provider=mock(AiProvider.class);
    final DependencyUpdatePlanService plans=mock(DependencyUpdatePlanService.class);final CurrentUserService users=mock(CurrentUserService.class);
    final AiProperties props=new AiProperties();final AiUsageTracker usage=mock(AiUsageTracker.class);
    DependencyAiAdviceService service;DependencyUpdatePlanService.Snapshot snapshot;
    @BeforeEach void setup(){snapshot=evidence();when(plans.get(1)).thenReturn(snapshot);when(users.currentUserId()).thenAnswer(i->user.get());props.setProvider(AiProviderType.OPENAI);props.getOpenai().setModel("mock-no-external");when(provider.providerType()).thenReturn(AiProviderType.OPENAI);when(provider.isAvailable()).thenReturn(true);when(provider.executionOrigin()).thenReturn("MOCK");when(provider.consumeLastTokenUsage()).thenReturn(Optional.empty());when(provider.generateDependencyAdvice(any())).thenReturn(output(snapshot));service=new DependencyAiAdviceService(plans,users,new AiProviderResolver(props,List.of(provider,new TemplateAiProvider())),props,json,usage);}
    DependencyAiAdviceService.View prepare(){return service.prepare(1,new DependencyAiAdviceService.Prepare(snapshot.evidenceHash(),0));}
    @Test void oneUseConsentOwnershipAndEvidenceAreRequiredBeforeAnyProviderCall(){
        var p=prepare();assertEquals("MOCK",p.provider().origin());verify(provider,never()).generateDependencyAdvice(any());
        assertThrows(RuntimeException.class,()->service.generate(1,p.id(),new DependencyAiAdviceService.Consent(snapshot.evidenceHash(),false)));
        user.set(2);assertThrows(RuntimeException.class,()->service.get(1,p.id()));user.set(1);
        var result=service.generate(1,p.id(),new DependencyAiAdviceService.Consent(snapshot.evidenceHash(),true));assertEquals("GENERATED",result.state());assertEquals("REVIEW_REQUIRED",result.reviewStatus());assertFalse(result.patchApplicable());assertEquals("NOT_VERIFIED",result.compatibility());assertEquals("NOT_VERIFIED",result.modelQuality());
        assertThrows(RuntimeException.class,()->service.generate(1,p.id(),new DependencyAiAdviceService.Consent(snapshot.evidenceHash(),true)));verify(provider,times(1)).generateDependencyAdvice(any());
    }
    @Test void disabledProviderDoesNotMasqueradeAsACompletedProposal(){var p=prepare();props.setProvider(AiProviderType.TEMPLATE);assertFalse(service.provider().available());assertThrows(RuntimeException.class,()->service.generate(1,p.id(),new DependencyAiAdviceService.Consent(snapshot.evidenceHash(),true)));verify(provider,never()).generateDependencyAdvice(any());}
    @Test void staleEvidenceCannotBeTransmitted(){var p=prepare();var changed=new DependencyUpdatePlanService.Snapshot(1,1,null,snapshot.analyzedAt(),"changed",snapshot.origin(),snapshot.modelVerification(),snapshot.plans(),snapshot.limitations());when(plans.get(1)).thenReturn(changed);assertThrows(RuntimeException.class,()->service.generate(1,p.id(),new DependencyAiAdviceService.Consent(snapshot.evidenceHash(),true)));verify(provider,never()).generateDependencyAdvice(any());}
    @Test void failuresAreNotRetriedOrReturnedAsModelOutput(){var p=prepare();when(provider.generateDependencyAdvice(any())).thenThrow(new IllegalStateException("private provider response"));var v=service.generate(1,p.id(),new DependencyAiAdviceService.Consent(snapshot.evidenceHash(),true));assertEquals("FAILED",v.state());assertNull(v.output());assertFalse(v.message().contains("private"));verify(provider,times(1)).generateDependencyAdvice(any());}
}
