package com.securedeploy.ai.context;

import java.util.List;

public record SnippetGroup(
        List<AiCodeSnippet> securityConfigSnippets,
        List<AiCodeSnippet> controllerSnippets,
        List<AiCodeSnippet> serviceSnippets,
        List<AiCodeSnippet> repositorySnippets,
        List<AiCodeSnippet> configSnippets,
        List<AiCodeSnippet> clientSnippets
) {

    public List<AiCodeSnippet> all() {
        return java.util.stream.Stream.of(
                        securityConfigSnippets,
                        controllerSnippets,
                        serviceSnippets,
                        repositorySnippets,
                        configSnippets,
                        clientSnippets
                )
                .flatMap(List::stream)
                .toList();
    }

    public static SnippetGroup empty() {
        return new SnippetGroup(List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
    }
}
