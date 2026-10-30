package com.securedeploy.ai.usage;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.math.BigDecimal;
class AiCostPolicyTest {
 @Test void actualUsageSeparatesCachedTokensAndIncludesModel(){var u=new AiTokenUsage(1000,100,1100,true,400,"gpt-5.4-mini",true);assertEquals(0,new BigDecimal("0.000930").compareTo(AiCostPolicy.cost(u)));var p=new com.securedeploy.ai.config.AiProperties();var record=new TemplateAiUsageTracker(p).track(com.securedeploy.ai.dto.AiFeatureType.WORKSPACE_PATCH,com.securedeploy.ai.config.AiProviderType.OPENAI,null,null,u);assertEquals(u.model(),record.model());assertEquals(400,record.cachedInputTokens());assertTrue(record.usageKnown());}
 @Test void unknownUsageAndModelAreNotReportedAsFree(){assertNull(AiCostPolicy.cost(new AiTokenUsage(0,0,0,true)));assertNull(AiCostPolicy.cost(new AiTokenUsage(10,20,30,true,0,"unpriced-model",true)));assertNull(AiCostPolicy.disclosure("unpriced-model").get("maximumEstimatedUsd"));assertEquals(BigDecimal.ZERO,AiCostPolicy.cost(new AiTokenUsage(0,0,0,false)));}
}
