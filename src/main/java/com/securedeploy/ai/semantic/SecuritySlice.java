package com.securedeploy.ai.semantic;

import java.util.List;

public record SecuritySlice(String sliceId, String entryPoint, String endpoint, String httpMethod,
                            String authenticationContext, List<String> relevantParameters,
                            List<CodeContext> contexts, List<ExistingFinding> existingFindings,
                            List<String> limitations) {
    public record CodeContext(String contextId, String filePath, int startLine, int endLine,
                              String functionName, boolean authorizationDeclared, String content) { }
    public record ExistingFinding(String findingId, String ruleId, String filePath, int line) { }
    public SecuritySlice withFindings(List<ExistingFinding> findings) {
        return new SecuritySlice(sliceId, entryPoint, endpoint, httpMethod, authenticationContext,
                relevantParameters, contexts, List.copyOf(findings), limitations);
    }
    public Metadata metadata() {
        return new Metadata(sliceId, entryPoint, endpoint, httpMethod, authenticationContext,
                contexts.stream().map(c -> new Location(c.filePath(), c.startLine(), c.endLine(), c.functionName())).toList(), limitations);
    }
    public record Location(String filePath, int startLine, int endLine, String functionName) { }
    public record Metadata(String sliceId, String entryPoint, String endpoint, String httpMethod,
                           String authenticationContext, List<Location> locations, List<String> limitations) { }
}
