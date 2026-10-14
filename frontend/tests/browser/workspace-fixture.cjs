// Adapts synthetic review fixtures to the backend-owned Workspace contract.
module.exports = function workspaceFixture(path, result, history = [result]) {
  const summary = review => ({ ...review, riskSummary: review.riskAssessment ? {
    deploymentAssessment: review.riskAssessment.prioritizedDeploymentAssessment,
    prioritySummary: review.riskAssessment.prioritySummary,
    semanticCandidateCount: review.semanticReview?.candidates.length ?? 0,
    referenceSecurityScore: review.securityScore,
  } : null, comparisonAvailable: !!review.comparison?.baselineReviewId,
    findingCount: review.riskAssessment ? Object.values(review.riskAssessment.prioritySummary).reduce((a, b) => a + b, 0) : null });
  const project = { projectId: result.projectId, name: result.projectName, sourceType: result.sourceType ?? 'ZIP',
    repositoryUrl: result.repositoryUrl ?? null, reviewCount: history.length, createdAt: result.createdAt, updatedAt: result.createdAt,
    latestReview: summary(result), latestProgress: result.comparison ?? null };
  if (path === '/api/workspace') return { projectCount: 1, analyzedProjectCount: 1,
    blockedProjectCount: +(result.riskAssessment?.prioritizedDeploymentAssessment === 'BLOCKED'),
    reviewRequiredProjectCount: +(result.riskAssessment?.prioritizedDeploymentAssessment === 'REVIEW_REQUIRED'),
    unassessedProjectCount: result.riskAssessment ? 0 : 1, projects: [project] };
  if (path === `/api/projects/${result.projectId}`) return project;
  if (path === `/api/projects/${result.projectId}/reviews`) return history.map(summary);
};
