package com.securedeploy.ai.prompt;

import com.securedeploy.ai.dto.AiProjectContext;
import com.securedeploy.ai.dto.AiReviewRequest;
import org.springframework.stereotype.Component;

@Component
public class PromptBuilder {

    private static final int MAX_AUDIT_PROMPT_CHARS = 12_000;

    public String buildVulnerabilityReviewPrompt(AiReviewRequest request) {
        return """
                You are a security reviewer for SecureDeploy, a Spring Boot deployment security review tool.
                Do not discover new vulnerabilities in this task.
                Explain only the vulnerability already detected by the Rule Engine.
                Return only valid JSON. Do not wrap it in markdown.

                Required JSON shape:
                {
                  "title": "...",
                  "description": "...",
                  "riskExplanation": "...",
                  "attackScenario": "...",
                  "recommendation": "...",
                  "priority": "즉시 수정 | 높은 우선순위 | 계획된 수정 | 점검 권장"
                }

                Rule ID: %s
                Severity: %s
                Category: %s
                File Path: %s
                Line: %d
                Message: %s
                Existing Recommendation: %s
                Evidence: %s
                """.formatted(
                request.ruleId(),
                request.severity(),
                request.category(),
                request.filePath(),
                request.line(),
                request.message(),
                request.recommendation(),
                request.evidence() == null ? "-" : request.evidence()
        );
    }

    public String buildVulnerabilityReviewBatchPrompt(AiProjectContext context) {
        return """
                You are a security reviewer for SecureDeploy.
                Do not discover new vulnerabilities in this task.
                Generate vulnerability-level explanations only from the Rule Engine findings.

                Project: %s
                Findings: %s
                """.formatted(context.projectName(), context.findings());
    }

    public String buildProjectSummaryPrompt(AiProjectContext context) {
        return """
                You are a senior application security reviewer.
                Use only the Rule Engine findings below and do not infer secrets or inspect full source code.
                Return only valid JSON. Do not wrap it in markdown.

                Required JSON shape:
                {
                  "overallSummary": "...",
                  "mostRiskyArea": "...",
                  "priorityFixes": ["...", "..."],
                  "deploymentAdvice": "...",
                  "aiOpinion": "..."
                }

                Project: %s
                Source Type: %s
                Repository URL: %s
                Scanned Files: %d
                Vulnerability Count: %d
                Security Score: %d
                Deployment Status: %s
                Findings: %s
                """.formatted(
                context.projectName(),
                context.sourceType(),
                context.repositoryUrl() == null ? "-" : context.repositoryUrl(),
                context.scannedFileCount(),
                context.vulnerabilityCount(),
                context.securityScore(),
                context.deploymentStatus(),
                context.findings()
        );
    }

    public String buildRemediationPrompt(AiProjectContext context) {
        return """
                You are a Spring Boot remediation assistant.
                Use only the detected Rule Engine findings. Do not request full project code.
                Return only valid JSON array. Do not wrap it in markdown.

                Required JSON shape:
                [
                  {
                    "ruleId": "...",
                    "title": "...",
                    "beforeExample": "...",
                    "afterExample": "...",
                    "explanation": "..."
                  }
                ]

                Project: %s
                Findings: %s
                """.formatted(context.projectName(), context.findings());
    }

    public String buildSecurityAuditPrompt(AiProjectContext context) {
        String prompt = """
                You are assisting SecureDeploy with an AI Security Audit.
                The Rule Engine already produced confirmed findings. Your role is not to assert new confirmed vulnerabilities.
                Provide additional review opinions about logical or structural risks that the Rule Engine may miss.
                Express every item as an AI-assisted review suggestion, not a confirmed vulnerability.
                Do not request or assume full source code. Use only the metadata below.
                Return only valid JSON. Do not wrap it in markdown.

                Required JSON shape:
                {
                  "findings": [
                    {
                      "title": "...",
                      "riskArea": "AUTHORIZATION | AUTHENTICATION | CONFIGURATION | DATABASE | INPUT_VALIDATION | SECRET_MANAGEMENT | FRONTEND_SECURITY | CLIENT_SECRET_EXPOSURE | CLIENT_STORAGE | CLIENT_XSS | CLIENT_REDIRECT | DEPENDENCY | DEVOPS_SECURITY | CONTAINER_SECURITY | CI_CD_SECURITY | KUBERNETES_SECURITY",
                      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
                      "reasoning": "...",
                      "possibleImpact": "...",
                      "recommendation": "...",
                      "confidence": "HIGH | MEDIUM | LOW"
                    }
                  ]
                }

                Audit scope:
                - Authentication/authorization flow risks
                - Admin API authorization gaps
                - Controller-Service-Repository flow risks
                - File upload validation risks
                - Exception handling or information disclosure risks
                - Configuration risks around Spring Boot deployment
                - Frontend token storage risks in localStorage/sessionStorage
                - React dangerouslySetInnerHTML and client-side XSS risks
                - Client environment variable and API URL exposure risks
                - Redirect parameter validation risks
                - Known vulnerable dependency candidate usage in package.json, pom.xml, Gradle, and lock files
                - Software supply-chain risks from outdated libraries, risky package scripts, and unpinned dependencies
                - Dependency update priority and deployment impact
                - Docker root container execution and latest/outdated base image risks
                - CI/CD secret handling and curl/wget pipe execution risks
                - Kubernetes privileged container, NodePort, plaintext Secret risks
                - Nginx directory listing, server token, HTTP-only deployment risks

                Project: %s
                Source Type: %s
                Repository URL: %s
                Security Score: %d
                Deployment Status: %s
                Scanned File Count: %d
                Vulnerability Count: %d
                Rule Engine Findings: %s
                Major File Paths From Findings: %s

                Selected code snippets for AI audit. These snippets are intentionally limited and masked for cost and secret protection.
                Config/DevOps snippets:
                %s

                SecurityConfig snippets:
                %s

                Controller snippets:
                %s

                Service snippets:
                %s

                Repository snippets:
                %s

                Client/frontend snippets:
                %s
                """.formatted(
                context.projectName(),
                context.sourceType(),
                context.repositoryUrl() == null ? "-" : context.repositoryUrl(),
                context.securityScore(),
                context.deploymentStatus(),
                context.scannedFileCount(),
                context.vulnerabilityCount(),
                context.findings(),
                context.findings().stream().map(finding -> finding.filePath()).distinct().toList(),
                formatSnippets(context.configSnippets()),
                formatSnippets(context.securityConfigSnippets()),
                formatSnippets(context.controllerSnippets()),
                formatSnippets(context.serviceSnippets()),
                formatSnippets(context.repositorySnippets()),
                formatSnippets(context.clientSnippets())
        );
        return limitPrompt(prompt);
    }

    private String formatSnippets(java.util.List<com.securedeploy.ai.context.AiCodeSnippet> snippets) {
        if (snippets == null || snippets.isEmpty()) {
            return "- none";
        }
        return snippets.stream()
                .map(snippet -> "File: " + snippet.filePath() + "\n```\n" + snippet.content() + "\n```")
                .collect(java.util.stream.Collectors.joining("\n\n"));
    }

    private String limitPrompt(String prompt) {
        if (prompt.length() <= MAX_AUDIT_PROMPT_CHARS) {
            return prompt;
        }
        return prompt.substring(0, MAX_AUDIT_PROMPT_CHARS) + "\n... prompt truncated for AI audit cost control";
    }


    public String buildComparisonInsightPrompt(com.securedeploy.project.dto.ReviewComparisonResponse comparison) {
        return """
                You are a security improvement consultant for SecureDeploy.
                Rule Engine findings are confirmed by the tool. Your role is to interpret the comparison and recommend next steps.
                Return only valid JSON. Do not wrap it in markdown.

                Required JSON shape:
                {
                  "overallInsight": "...",
                  "improvementSummary": "...",
                  "remainingRiskSummary": "...",
                  "newRiskSummary": "...",
                  "deploymentReadinessOpinion": "...",
                  "nextRecommendedActions": ["...", "..."]
                }

                Comparison data:
                Project ID: %d
                Latest Review ID: %s
                Previous Review ID: %s
                Latest Score: %d
                Previous Score: %d
                Score Diff: %d
                Latest Vulnerability Count: %d
                Previous Vulnerability Count: %d
                Vulnerability Count Diff: %d
                Resolved Vulnerabilities: %s
                New Vulnerabilities: %s
                Persisted Vulnerabilities: %s
                Message: %s
                """.formatted(
                comparison.projectId(),
                comparison.latestReviewId(),
                comparison.previousReviewId(),
                comparison.latestSecurityScore(),
                comparison.previousSecurityScore(),
                comparison.scoreDiff(),
                comparison.latestVulnerabilityCount(),
                comparison.previousVulnerabilityCount(),
                comparison.vulnerabilityCountDiff(),
                comparison.resolvedVulnerabilities(),
                comparison.newVulnerabilities(),
                comparison.persistedVulnerabilities(),
                comparison.message()
        );
    }

    public String buildPriorityPrompt(AiProjectContext context) {
        return """
                You are a security triage consultant for SecureDeploy.
                Rule Engine already detected the findings. Rank fixes by risk, deployment impact, exploitability, fix difficulty, blast radius, and urgency.
                Return only valid JSON. Do not wrap it in markdown.

                Required JSON shape:
                {
                  "priorities": [
                    {
                      "rank": 1,
                      "ruleId": "...",
                      "title": "...",
                      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
                      "reason": "...",
                      "expectedImpact": "...",
                      "fixDifficulty": "낮음 | 보통 | 높음",
                      "recommendedAction": "...",
                      "urgency": "즉시 | 높음 | 보통 | 낮음"
                    }
                  ]
                }

                Review ID: %d
                Project: %s
                Security Score: %d
                Deployment Status: %s
                Findings: %s
                """.formatted(
                context.reviewId(),
                context.projectName(),
                context.securityScore(),
                context.deploymentStatus(),
                context.findings()
        );
    }

    public String buildSecurityRoadmapPrompt(AiProjectContext context) {
        return """
                You are a security improvement strategist for SecureDeploy.
                Use Rule Engine findings and project context to create a practical improvement roadmap.
                Return only valid JSON. Do not wrap it in markdown.

                Required JSON shape:
                {
                  "immediateActions": [
                    {"title":"...", "description":"...", "relatedRuleIds":["..."], "reason":"...", "expectedBenefit":"..."}
                  ],
                  "thisWeekActions": [
                    {"title":"...", "description":"...", "relatedRuleIds":["..."], "reason":"...", "expectedBenefit":"..."}
                  ],
                  "beforeDeploymentChecklist": [
                    {"title":"...", "description":"...", "relatedRuleIds":["..."], "reason":"...", "expectedBenefit":"..."}
                  ],
                  "longTermImprovements": [
                    {"title":"...", "description":"...", "relatedRuleIds":["..."], "reason":"...", "expectedBenefit":"..."}
                  ]
                }

                Review ID: %d
                Project: %s
                Source Type: %s
                Security Score: %d
                Deployment Status: %s
                Findings: %s
                SecurityConfig snippets: %s
                Controller snippets: %s
                Config snippets: %s
                Client snippets: %s
                """.formatted(
                context.reviewId(),
                context.projectName(),
                context.sourceType(),
                context.securityScore(),
                context.deploymentStatus(),
                context.findings(),
                formatSnippets(context.securityConfigSnippets()),
                formatSnippets(context.controllerSnippets()),
                formatSnippets(context.configSnippets()),
                formatSnippets(context.clientSnippets())
        );
    }

    public String build(AiReviewRequest request) {
        return buildVulnerabilityReviewPrompt(request);
    }
}
