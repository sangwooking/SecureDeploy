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
    @GetMapping("/api/ui-capabilities")
    public Map<String,Object> capabilities() {
        var provider=resolver.resolve();
        boolean available=properties.getProvider()==AiProviderType.OPENAI&&provider.providerType()==AiProviderType.OPENAI&&provider.isAvailable();
        return Map.of("schemaVersion",1,"dependencyPlans",true,"dependencyAdvice",true,"workspaceSemanticReview",true,
                "dependencyFiles",true,"npmGeneration",npm.enabled(),"providerAvailable",available,
                "providerOrigin",provider.executionOrigin()==null?"UNVERIFIED_PROVIDER":provider.executionOrigin());
    }
}
