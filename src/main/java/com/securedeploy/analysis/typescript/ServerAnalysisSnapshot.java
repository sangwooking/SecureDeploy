package com.securedeploy.analysis.typescript;

import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import com.securedeploy.project.coverage.CoverageLedger;

/** Structural evidence is deliberately outside the legacy score and risk policy. */
public record ServerAnalysisSnapshot(int schemaVersion, String analyzerVersion, String parserVersion,
        String status, List<FileCoverage> files, List<Finding> findings, List<SqlUse> sqlUses,
        List<AuthorizationContext> authorizationContexts, List<String> limitations,
        List<ServerFlowFinding> validatedFindings, List<HttpUse> httpUses, ServerAnalysisSnapshot pythonAnalysis,
        SelectionCoverage selectionCoverage, com.securedeploy.analysis.deployment.DeploymentSnapshot deploymentAnalysis,
        List<ResourceUse> resourceUses, List<TokenUse> tokenUses) {
    public ServerAnalysisSnapshot(int schemaVersion, String analyzerVersion, String parserVersion,
            String status, List<FileCoverage> files, List<Finding> findings, List<SqlUse> sqlUses,
            List<AuthorizationContext> authorizationContexts, List<String> limitations,
            List<ServerFlowFinding> validatedFindings, List<HttpUse> httpUses, ServerAnalysisSnapshot pythonAnalysis,
            SelectionCoverage selectionCoverage, com.securedeploy.analysis.deployment.DeploymentSnapshot deploymentAnalysis,
            List<ResourceUse> resourceUses) {
        this(schemaVersion, analyzerVersion, parserVersion, status, files, findings, sqlUses, authorizationContexts,
                limitations, validatedFindings, httpUses, pythonAnalysis, selectionCoverage, deploymentAnalysis, resourceUses, null);
    }
    public ServerAnalysisSnapshot withTokenUses(List<TokenUse> value) {
        return new ServerAnalysisSnapshot(schemaVersion, analyzerVersion, parserVersion, status, files, findings, sqlUses,
                authorizationContexts, limitations, validatedFindings, httpUses, pythonAnalysis, selectionCoverage, deploymentAnalysis, resourceUses, value);
    }
    public ServerAnalysisSnapshot(int schemaVersion, String analyzerVersion, String parserVersion,
            String status, List<FileCoverage> files, List<Finding> findings, List<SqlUse> sqlUses,
            List<AuthorizationContext> authorizationContexts, List<String> limitations,
            List<ServerFlowFinding> validatedFindings, List<HttpUse> httpUses, ServerAnalysisSnapshot pythonAnalysis,
            SelectionCoverage selectionCoverage, com.securedeploy.analysis.deployment.DeploymentSnapshot deploymentAnalysis) {
        this(schemaVersion, analyzerVersion, parserVersion, status, files, findings, sqlUses, authorizationContexts,
                limitations, validatedFindings, httpUses, pythonAnalysis, selectionCoverage, deploymentAnalysis, null);
    }
    public ServerAnalysisSnapshot withResourceUses(List<ResourceUse> value) {
        return new ServerAnalysisSnapshot(schemaVersion, analyzerVersion, parserVersion, status, files, findings, sqlUses,
                authorizationContexts, limitations, validatedFindings, httpUses, pythonAnalysis, selectionCoverage, deploymentAnalysis, value, tokenUses);
    }
    public ServerAnalysisSnapshot(int schemaVersion, String analyzerVersion, String parserVersion,
            String status, List<FileCoverage> files, List<Finding> findings, List<SqlUse> sqlUses,
            List<AuthorizationContext> authorizationContexts, List<String> limitations,
            List<ServerFlowFinding> validatedFindings, List<HttpUse> httpUses, ServerAnalysisSnapshot pythonAnalysis,
            SelectionCoverage selectionCoverage) {
        this(schemaVersion, analyzerVersion, parserVersion, status, files, findings, sqlUses, authorizationContexts,
                limitations, validatedFindings, httpUses, pythonAnalysis, selectionCoverage, null);
    }
    public ServerAnalysisSnapshot withDeploymentAnalysis(com.securedeploy.analysis.deployment.DeploymentSnapshot value) {
        return new ServerAnalysisSnapshot(schemaVersion, analyzerVersion, parserVersion, status, files, findings, sqlUses,
                authorizationContexts, limitations, validatedFindings, httpUses, pythonAnalysis, selectionCoverage, value, resourceUses, tokenUses);
    }
    public record SelectionCoverage(int discoveredFiles, int submittedFiles, int omittedFiles, int omittedDetails,
            int submittedCharacters, Map<String, Integer> omissionReasons) { }
    public ServerAnalysisSnapshot(int schemaVersion, String analyzerVersion, String parserVersion,
            String status, List<FileCoverage> files, List<Finding> findings, List<SqlUse> sqlUses,
            List<AuthorizationContext> authorizationContexts, List<String> limitations,
            List<ServerFlowFinding> validatedFindings, List<HttpUse> httpUses, ServerAnalysisSnapshot pythonAnalysis) {
        this(schemaVersion, analyzerVersion, parserVersion, status, files, findings, sqlUses,
                authorizationContexts, limitations, validatedFindings, httpUses, pythonAnalysis, null);
    }
    public ServerAnalysisSnapshot withSelectionCoverage(SelectionCoverage selection) {
        return new ServerAnalysisSnapshot(schemaVersion, analyzerVersion, parserVersion, status, files, findings,
                sqlUses, authorizationContexts, limitations, validatedFindings, httpUses, pythonAnalysis, selection, deploymentAnalysis, resourceUses, tokenUses);
    }
    public ServerAnalysisSnapshot(int schemaVersion, String analyzerVersion, String parserVersion,
            String status, List<FileCoverage> files, List<Finding> findings, List<SqlUse> sqlUses,
            List<AuthorizationContext> authorizationContexts, List<String> limitations,
            List<ServerFlowFinding> validatedFindings, List<HttpUse> httpUses) {
        this(schemaVersion, analyzerVersion, parserVersion, status, files, findings, sqlUses,
                authorizationContexts, limitations, validatedFindings, httpUses, null);
    }
    public ServerAnalysisSnapshot withPythonAnalysis(ServerAnalysisSnapshot value) {
        return new ServerAnalysisSnapshot(schemaVersion, analyzerVersion, parserVersion, status, files, findings,
                sqlUses, authorizationContexts, limitations, validatedFindings, httpUses, value, selectionCoverage, deploymentAnalysis, resourceUses, tokenUses);
    }
    public ServerAnalysisSnapshot(int schemaVersion, String analyzerVersion, String parserVersion,
            String status, List<FileCoverage> files, List<Finding> findings, List<SqlUse> sqlUses,
            List<AuthorizationContext> authorizationContexts, List<String> limitations, List<ServerFlowFinding> validatedFindings) {
        this(schemaVersion, analyzerVersion, parserVersion, status, files, findings, sqlUses,
                authorizationContexts, limitations, validatedFindings, null);
    }
    public ServerAnalysisSnapshot(int schemaVersion, String analyzerVersion, String parserVersion,
            String status, List<FileCoverage> files, List<Finding> findings, List<SqlUse> sqlUses,
            List<AuthorizationContext> authorizationContexts, List<String> limitations) {
        this(schemaVersion, analyzerVersion, parserVersion, status, files, findings, sqlUses,
                authorizationContexts, limitations, null, null);
    }
    public record Location(String filePath, int line, int column, String functionName, String kind) { }
    public record FileCoverage(String filePath, String parseStatus, String flowStatus, int entrypoints,
            int functionsAnalyzed, int prepareCallSites, int tracedPrepareCallSites, List<String> limitations,
            Integer httpCallSites, Integer tracedHttpCallSites, String selectionReason,
            Integer resourceCallSites, Integer tracedResourceCallSites) {
        public FileCoverage(String filePath, String parseStatus, String flowStatus, int entrypoints,
                int functionsAnalyzed, int prepareCallSites, int tracedPrepareCallSites, List<String> limitations,
                Integer httpCallSites, Integer tracedHttpCallSites, String selectionReason) {
            this(filePath, parseStatus, flowStatus, entrypoints, functionsAnalyzed, prepareCallSites,
                    tracedPrepareCallSites, limitations, httpCallSites, tracedHttpCallSites, selectionReason, null, null);
        }
        public FileCoverage(String filePath, String parseStatus, String flowStatus, int entrypoints,
                int functionsAnalyzed, int prepareCallSites, int tracedPrepareCallSites, List<String> limitations,
                Integer httpCallSites, Integer tracedHttpCallSites) {
            this(filePath, parseStatus, flowStatus, entrypoints, functionsAnalyzed, prepareCallSites,
                    tracedPrepareCallSites, limitations, httpCallSites, tracedHttpCallSites, null);
        }
        public FileCoverage withSelectionReason(String reason) {
            return new FileCoverage(filePath, parseStatus, flowStatus, entrypoints, functionsAnalyzed,
                    prepareCallSites, tracedPrepareCallSites, limitations, httpCallSites, tracedHttpCallSites, reason, resourceCallSites, tracedResourceCallSites);
        }
        public FileCoverage(String filePath, String parseStatus, String flowStatus, int entrypoints,
                int functionsAnalyzed, int prepareCallSites, int tracedPrepareCallSites, List<String> limitations) {
            this(filePath, parseStatus, flowStatus, entrypoints, functionsAnalyzed, prepareCallSites, tracedPrepareCallSites, limitations, null, null);
        }
        public FileCoverage(String filePath, String parseStatus, String flowStatus, int entrypoints,
                int functionsAnalyzed, List<String> limitations) {
            this(filePath, parseStatus, flowStatus, entrypoints, functionsAnalyzed, 0, 0, limitations);
        }
    }
    public record Finding(String ruleId, String kind, String confidence, String disposition,
            Location source, Location sink, List<Location> flow, List<Location> defenses,
            List<String> limitations, String message, String recommendation) { }
    public record SqlUse(String kind, Location location, List<Location> trace, List<Location> defenses,
            List<String> limitations, boolean executionObserved, List<Location> executionLocations) { }
    public record HttpUse(String kind, String controlledPart, Location location, List<Location> trace,
            List<Location> defenses, List<String> limitations) { }
    public record ResourceUse(String ruleId, String kind, Location location, List<Location> trace,
            List<Location> defenses, List<String> limitations, boolean executionObserved) { }
    public record TokenUse(String operation, Location location, String signatureStatus, String keySource,
            String usageStatus, List<Location> trace, List<String> limitations) { }
    public record AuthorizationContext(Location entry, List<Location> checks, List<Location> defenses,
            List<Location> resources, String conclusion, List<String> limitations, AuthorizationDetails details) {
        public AuthorizationContext(Location entry, List<Location> checks, List<Location> defenses,
                List<Location> resources, String conclusion, List<String> limitations) {
            this(entry, checks, defenses, resources, conclusion, limitations, null);
        }
    }
    public record PermissionDeclaration(String source, List<String> permissions, Location location) { }
    public record AuthorizationAccess(String operation, Location location, Location resourceLocation,
            List<Location> identifierInputs, List<Location> checks, String conclusion, List<String> limitations) { }
    public record AuthorizationDetails(String authenticationStatus, String objectAuthorizationStatus, String permissionSource,
            List<PermissionDeclaration> permissionDeclarations, List<Location> principalReferences,
            List<Location> ownershipComparisons, List<AuthorizationAccess> accesses, List<String> limitations) { }

    public static ServerAnalysisSnapshot unavailable(String status, List<FileCoverage> files, String reason) {
        return new ServerAnalysisSnapshot(1, "ts-server-v4", null, status, files, List.of(), List.of(), List.of(), List.of(reason));
    }

    public CoverageLedger attachCoverage(CoverageLedger ledger) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        files.forEach(file -> {
            counts.merge("AST_" + file.parseStatus(), 1, Integer::sum);
            counts.merge("FLOW_" + file.flowStatus(), 1, Integer::sum);
            if (analyzerVersion.startsWith("py-django-")) {
                counts.merge("ENTRYPOINTS", file.entrypoints(), Integer::sum);
                counts.merge("FUNCTIONS_TRACED", file.functionsAnalyzed(), Integer::sum);
                file.limitations().forEach(reason -> counts.merge("LIMITATION_" + reason, 1, Integer::sum));
            }
        });
        if (selectionCoverage != null) {
            counts.put("DISCOVERED_PYTHON_FILES", selectionCoverage.discoveredFiles());
            counts.put("SUBMITTED_PYTHON_FILES", selectionCoverage.submittedFiles());
            counts.put("OMITTED_PYTHON_FILES", selectionCoverage.omittedFiles());
        }
        if (resourceUses != null) resourceUses.forEach(use -> counts.merge("RESOURCE_" + use.kind(), 1, Integer::sum));
        var analyzers = new java.util.ArrayList<>(ledger.analyzers());
        boolean python = analyzerVersion.startsWith("py-django-");
        analyzers.add(new CoverageLedger.Analyzer(python ? "PYTHON_SERVER" : "TYPESCRIPT_SERVER", status,
                python ? "Django/DRF 진입점의 제한된 SQL·파일 경로·pickle/YAML 값 전달 검사. 전체 Python, 인증·소유권, 파일시스템·실행 가능성은 미검증이며 기존 Risk 계산과 분리됩니다."
                : "Workers/Pages 진입점의 제한된 구문·값 전달 검사. 전체 TypeScript, 실행 가능성, 인증·소유권 보증 및 Risk 계산에는 포함되지 않습니다.", counts));
        if (python) {
            if (tokenUses != null || "py-django-v5".equals(analyzerVersion)) analyzers.add(new CoverageLedger.Analyzer("PYTHON_TOKEN_SECURITY", files.isEmpty() ? "NOT_APPLICABLE"
                    : List.of("COMPLETE", "PARTIAL").contains(status) ? "PARTIAL" : status,
                    "지원 Django/DRF 경로의 PyJWT 2.x API 형태·검증 생략 사용·서명 키 출처 검사. 실제 설치 버전·외부 검증·전체 암호화는 미확인.",
                    tokenUses == null ? Map.of("UNRECORDED", 1) : Map.of("TOKEN_CALLS_TRACED", tokenUses.size())));
            var authorization = new LinkedHashMap<String, Integer>();
            authorizationContexts.forEach(context -> {
                if (context.details() == null) { authorization.merge("LEGACY_OR_UNRECORDED", 1, Integer::sum); return; }
                authorization.merge("CONTEXTS_TRACED", 1, Integer::sum);
                authorization.merge("AUTHENTICATION_" + context.details().authenticationStatus(), 1, Integer::sum);
                authorization.merge("OBJECT_" + context.details().objectAuthorizationStatus(), 1, Integer::sum);
            });
            analyzers.add(new CoverageLedger.Analyzer("PYTHON_AUTHORIZATION", files.isEmpty() ? "NOT_APPLICABLE"
                    : List.of("COMPLETE", "PARTIAL").contains(status) ? "PARTIAL" : status,
                    "지원 Django/DRF 진입점의 권한 선언·사용자/FK 조회 범위·차단 분기 근거. 전역 설정 활성화·미들웨어·상속·전체 객체 권한은 미검증. 인증은 소유권 보증이 아닙니다.", authorization));
        }
        String combined = "FAILED".equals(ledger.status()) ? "FAILED"
                : !List.of("COMPLETE", "NOT_APPLICABLE").contains(status) || python && !files.isEmpty() ? "PARTIAL" : ledger.status();
        return new CoverageLedger(ledger.schemaVersion(), ledger.policyVersion(), combined, ledger.discoveredFiles(),
                ledger.selectedFiles(), ledger.unsupportedFiles(), ledger.excludedFiles(), ledger.failedFiles(),
                ledger.inventoryComplete(), ledger.omittedEntries(), ledger.entries(), List.copyOf(analyzers), ledger.inspectionScope());
    }
}
