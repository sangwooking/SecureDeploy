package com.securedeploy.ui;

import com.securedeploy.ai.config.AiProperties;
import com.securedeploy.ai.config.AiProviderType;
import com.securedeploy.ai.service.AiProviderResolver;
import com.securedeploy.editing.NpmUpdateGenerator;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Read-only negotiation for existing optional APIs; never invokes a model or reads project data. */
@RestController
public class UiCapabilitiesController {
    private final AiProperties properties;
    private final AiProviderResolver resolver;
    private final NpmUpdateGenerator npm;
    public UiCapabilitiesController(AiProperties properties, AiProviderResolver resolver, NpmUpdateGenerator npm) {
        this.properties=properties;this.resolver=resolver;this.npm=npm;
    }
    private org.springframework.core.env.Environment environment;
    private com.securedeploy.ai.usage.DurableAiLedger ledger;
    @org.springframework.beans.factory.annotation.Autowired
    void releaseState(org.springframework.core.env.Environment environment,com.securedeploy.ai.usage.DurableAiLedger ledger){this.environment=environment;this.ledger=ledger;}
    @GetMapping("/api/ui-capabilities")
    public Map<String,Object> capabilities() {
        var provider=resolver.resolve();
        boolean available=properties.getProvider()==AiProviderType.OPENAI&&provider.providerType()==AiProviderType.OPENAI&&provider.isAvailable();
        var result=new java.util.LinkedHashMap<String,Object>(Map.of("schemaVersion",1,"dependencyPlans",true,"dependencyAdvice",true,"workspaceSemanticReview",true,
                "dependencyFiles",true,"npmGeneration",npm.enabled(),"providerAvailable",available,
                "providerOrigin",provider.executionOrigin()==null?"UNVERIFIED_PROVIDER":provider.executionOrigin()));
        result.put("advisoryDetails",true);
        result.put("aiCost",com.securedeploy.ai.usage.AiCostPolicy.disclosure(properties.getOpenai().getModel()));
        result.put("structuredPatchPlans",true);
        result.put("patchScopes",java.util.List.of("SPRING_LITERAL_PROPERTIES","DENO_DIRECT_ENV_JSON","EXPRESS_DIRECT_ENV_JSON"));
        result.put("aiCapabilityMatrix",AiCapabilityMatrix.entries());
        boolean recovery=environment!=null&&environment.acceptsProfiles(org.springframework.core.env.Profiles.of("release-recovery"));
        boolean compatible=environment!=null&&environment.acceptsProfiles(org.springframework.core.env.Profiles.of("release-compatible"));
        result.put("compatibilityMode",compatible);result.put("deterministicFixes",!compatible&&!recovery);
        result.put("recoveryReadOnly",recovery);result.put("durableAiAdmission",ledger!=null&&ledger.enabled());
        result.put("legacyAiReport",false); // No per-request consent contract: real legacy reports remain disabled.
        if(recovery||compatible){for(String name:java.util.List.of("dependencyAdvice","workspaceSemanticReview","dependencyFiles","npmGeneration","providerAvailable","structuredPatchPlans"))result.put(name,false);}
        return result;
    }
}
