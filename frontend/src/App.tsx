import { ChangeEvent, FormEvent, useEffect, useMemo, useState } from 'react';
import {
  deleteProject,
  deleteReview,
  downloadAiReviewReport,
  downloadReviewReport,
  fetchAiComparisonInsight,
  fetchAiPriorities,
  fetchAiProjectSummary,
  fetchAiRoadmap,
  fetchAiRemediation,
  fetchAiReview,
  fetchAiSecurityAudit,
  fetchLatestReviewComparison,
  fetchProjectDashboard,
  fetchReviewDetail,
  fetchReviewHistory,
  fetchVulnerabilityStatusSummary,
  login as loginRequest,
  reviewGithubRepository,
  signup as signupRequest,
  updateVulnerabilityStatus,
  uploadZipForReview,
} from './api/securityReviewApi';
import type {
  AuthResponse,
  AiComparisonInsightResponse,
  AiPriorityResponse,
  AiProjectSummaryResponse,
  AiRemediationResultResponse,
  AiReviewResultResponse,
  AiSecurityAuditResponse,
  AiSecurityRoadmapResponse,
  AiUsageResponse,
  ProjectSecurityDashboardResponse,
  ReviewComparisonResponse,
  ReviewHistoryResponse,
  SecurityReviewResponse,
  Severity,
  Vulnerability,
  VulnerabilityStatus,
  VulnerabilityStatusResponse,
  VulnerabilityStatusSummaryResponse,
} from './types/securityReview';

type SeverityFilter = 'ALL' | Severity;
type AnalysisMode = 'ZIP' | 'GITHUB';
type ResultTab = 'RESULT' | 'AI_REVIEW';
type AiSubTab = 'VULNERABILITY_REVIEW' | 'PROJECT_SUMMARY' | 'REMEDIATION' | 'SECURITY_AUDIT' | 'PRIORITIES' | 'ROADMAP';

const severityOrder: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
};

const severityFilters: SeverityFilter[] = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const vulnerabilityStatuses: VulnerabilityStatus[] = ['UNCHECKED', 'ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED', 'IGNORED'];

const vulnerabilityStatusLabels: Record<VulnerabilityStatus, string> = {
  UNCHECKED: '미확인',
  ACKNOWLEDGED: '확인 완료',
  IN_PROGRESS: '수정 중',
  RESOLVED: '수정 완료',
  IGNORED: '무시',
};

const ACCESS_TOKEN_STORAGE_KEY = 'securedeploy.accessToken';
const AUTH_USER_STORAGE_KEY = 'securedeploy.authUser';

type AuthMode = 'LOGIN' | 'SIGNUP';

function loadStoredAuthSession(): AuthResponse | null {
  const accessToken = localStorage.getItem(ACCESS_TOKEN_STORAGE_KEY);
  const userJson = localStorage.getItem(AUTH_USER_STORAGE_KEY);
  if (!accessToken || !userJson) {
    return null;
  }

  try {
    return {
      accessToken,
      tokenType: 'Bearer',
      user: JSON.parse(userJson),
    };
  } catch {
    localStorage.removeItem(ACCESS_TOKEN_STORAGE_KEY);
    localStorage.removeItem(AUTH_USER_STORAGE_KEY);
    return null;
  }
}

function storeAuthSession(session: AuthResponse) {
  localStorage.setItem(ACCESS_TOKEN_STORAGE_KEY, session.accessToken);
  localStorage.setItem(AUTH_USER_STORAGE_KEY, JSON.stringify(session.user));
}

function clearStoredAuthSession() {
  localStorage.removeItem(ACCESS_TOKEN_STORAGE_KEY);
  localStorage.removeItem(AUTH_USER_STORAGE_KEY);
}

function App() {
  const [authSession, setAuthSession] = useState<AuthResponse | null>(() => loadStoredAuthSession());
  const [authMode, setAuthMode] = useState<AuthMode>('LOGIN');
  const [authEmail, setAuthEmail] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authName, setAuthName] = useState('');
  const [isAuthLoading, setIsAuthLoading] = useState(false);
  const [authErrorMessage, setAuthErrorMessage] = useState('');
  const [analysisMode, setAnalysisMode] = useState<AnalysisMode>('ZIP');
  const [activeResultTab, setActiveResultTab] = useState<ResultTab>('RESULT');
  const [activeAiSubTab, setActiveAiSubTab] = useState<AiSubTab>('VULNERABILITY_REVIEW');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [repositoryUrl, setRepositoryUrl] = useState('');
  const [result, setResult] = useState<SecurityReviewResponse | null>(null);
  const [reviewHistory, setReviewHistory] = useState<ReviewHistoryResponse[]>([]);
  const [reviewComparison, setReviewComparison] = useState<ReviewComparisonResponse | null>(null);
  const [projectDashboard, setProjectDashboard] = useState<ProjectSecurityDashboardResponse | null>(null);
  const [statusSummary, setStatusSummary] = useState<VulnerabilityStatusSummaryResponse | null>(null);
  const [aiComparisonInsight, setAiComparisonInsight] = useState<AiComparisonInsightResponse | null>(null);
  const [aiReviewResult, setAiReviewResult] = useState<AiReviewResultResponse | null>(null);
  const [aiProjectSummary, setAiProjectSummary] = useState<AiProjectSummaryResponse | null>(null);
  const [aiRemediationResult, setAiRemediationResult] = useState<AiRemediationResultResponse | null>(null);
  const [aiSecurityAudit, setAiSecurityAudit] = useState<AiSecurityAuditResponse | null>(null);
  const [aiPriorities, setAiPriorities] = useState<AiPriorityResponse | null>(null);
  const [aiRoadmap, setAiRoadmap] = useState<AiSecurityRoadmapResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isHistoryLoading, setIsHistoryLoading] = useState(false);
  const [isComparisonLoading, setIsComparisonLoading] = useState(false);
  const [isDashboardLoading, setIsDashboardLoading] = useState(false);
  const [deletingReviewId, setDeletingReviewId] = useState<number | null>(null);
  const [deletingProjectId, setDeletingProjectId] = useState<number | null>(null);
  const [isAiComparisonLoading, setIsAiComparisonLoading] = useState(false);
  const [isReportDownloading, setIsReportDownloading] = useState(false);
  const [isAiReportDownloading, setIsAiReportDownloading] = useState(false);
  const [isAiReviewLoading, setIsAiReviewLoading] = useState(false);
  const [isAiSummaryLoading, setIsAiSummaryLoading] = useState(false);
  const [isAiRemediationLoading, setIsAiRemediationLoading] = useState(false);
  const [isAiAuditLoading, setIsAiAuditLoading] = useState(false);
  const [isAiPriorityLoading, setIsAiPriorityLoading] = useState(false);
  const [isAiRoadmapLoading, setIsAiRoadmapLoading] = useState(false);
  const [statusUpdatingId, setStatusUpdatingId] = useState<number | null>(null);
  const [selectedReviewId, setSelectedReviewId] = useState<number | null>(null);
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [historyErrorMessage, setHistoryErrorMessage] = useState('');
  const [comparisonErrorMessage, setComparisonErrorMessage] = useState('');
  const [dashboardErrorMessage, setDashboardErrorMessage] = useState('');
  const [statusSummaryErrorMessage, setStatusSummaryErrorMessage] = useState('');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('ALL');
  const [statusComments, setStatusComments] = useState<Record<number, string>>({});

  useEffect(() => {
    if (authSession) {
      void loadReviewHistory();
    }
  }, [authSession?.accessToken]);

  const scoreTone = useMemo(() => {
    if (!result) {
      return 'neutral';
    }
    if (result.securityScore >= 80) {
      return 'safe';
    }
    if (result.securityScore >= 60) {
      return 'warning';
    }
    return 'danger';
  }, [result]);

  const deploymentStatus = useMemo(() => {
    if (!result) {
      return '';
    }
    if (result.securityScore >= 80) {
      return '배포 가능';
    }
    if (result.securityScore >= 60) {
      return '주의 필요';
    }
    return '배포 비권장';
  }, [result]);

  const sortedVulnerabilities = useMemo(() => {
    if (!result) {
      return [];
    }

    return [...result.vulnerabilities].sort((a, b) => {
      const severityDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (severityDiff !== 0) {
        return severityDiff;
      }
      return a.filePath.localeCompare(b.filePath) || a.line - b.line;
    });
  }, [result]);

  const filteredVulnerabilities = useMemo(() => {
    if (severityFilter === 'ALL') {
      return sortedVulnerabilities;
    }
    return sortedVulnerabilities.filter((vulnerability) => vulnerability.severity === severityFilter);
  }, [severityFilter, sortedVulnerabilities]);

  const loadReviewHistory = async () => {
    setIsHistoryLoading(true);
    setHistoryErrorMessage('');

    try {
      const histories = await fetchReviewHistory();
      setReviewHistory(histories);
    } catch (error) {
      setHistoryErrorMessage(error instanceof Error ? error.message : '분석 이력을 불러오지 못했습니다.');
    } finally {
      setIsHistoryLoading(false);
    }
  };

  const loadStatusSummary = async (projectId?: number | null) => {
    if (!projectId) {
      setStatusSummary(null);
      setStatusSummaryErrorMessage('');
      return;
    }

    setStatusSummaryErrorMessage('');

    try {
      const summary = await fetchVulnerabilityStatusSummary(projectId);
      setStatusSummary(summary);
    } catch (error) {
      setStatusSummary(null);
      setStatusSummaryErrorMessage(error instanceof Error ? error.message : '취약점 상태 요약을 불러오지 못했습니다.');
    }
  };

  const resetAiResults = () => {
    setAiReviewResult(null);
    setAiProjectSummary(null);
    setAiRemediationResult(null);
    setAiSecurityAudit(null);
    setAiPriorities(null);
    setAiRoadmap(null);
    setActiveAiSubTab('VULNERABILITY_REVIEW');
  };

  const resetCurrentResult = () => {
    setResult(null);
    setSelectedReviewId(null);
    setSeverityFilter('ALL');
    resetAiResults();
    setActiveResultTab('RESULT');
    setReviewComparison(null);
    setProjectDashboard(null);
    setAiComparisonInsight(null);
    setComparisonErrorMessage('');
    setDashboardErrorMessage('');
    setStatusSummary(null);
    setStatusSummaryErrorMessage('');
    setStatusComments({});
  };

  const handleModeChange = (mode: AnalysisMode) => {
    setAnalysisMode(mode);
    setErrorMessage('');
    setSuccessMessage('');
    resetCurrentResult();
  };

  const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0] ?? null;
    setSelectedFile(file);
    setErrorMessage('');
    setSuccessMessage('');
  };

  const handleRepositoryUrlChange = (event: ChangeEvent<HTMLInputElement>) => {
    setRepositoryUrl(event.target.value);
    setErrorMessage('');
    setSuccessMessage('');
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const validationError = validateAnalysisInput();
    if (validationError) {
      setErrorMessage(validationError);
      return;
    }

    setIsLoading(true);
    setErrorMessage('');
    setSuccessMessage('');
    resetCurrentResult();

    try {
      const reviewResult = analysisMode === 'ZIP'
        ? await uploadZipForReview(selectedFile as File)
        : await reviewGithubRepository(repositoryUrl.trim());
      setResult(reviewResult);
      setSelectedReviewId(reviewResult.reviewId ?? null);
      await loadStatusSummary(reviewResult.projectId);
      setSuccessMessage(`${analysisMode === 'ZIP' ? 'ZIP 프로젝트' : 'GitHub 저장소'} 분석이 완료되었습니다.`);
      await loadReviewHistory();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : '알 수 없는 오류가 발생했습니다.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleHistoryClick = async (reviewId: number) => {
    setIsLoading(true);
    setErrorMessage('');
    setSuccessMessage('');
    setSeverityFilter('ALL');
    resetAiResults();
    setActiveResultTab('RESULT');

    try {
      const reviewDetail = await fetchReviewDetail(reviewId);
      setResult(reviewDetail);
      setSelectedReviewId(reviewId);
      await loadStatusSummary(reviewDetail.projectId);
      setReviewComparison(null);
      setProjectDashboard(null);
      setDashboardErrorMessage('');
      setComparisonErrorMessage('');
      setSuccessMessage('저장된 분석 결과를 불러왔습니다.');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : '분석 상세 결과를 불러오지 못했습니다.');
    } finally {
      setIsLoading(false);
    }
  };


  const handleCompareLatest = async (projectId?: number | null) => {
    if (!projectId) {
      setComparisonErrorMessage('프로젝트에 연결된 분석 이력만 비교할 수 있습니다.');
      return;
    }

    setIsComparisonLoading(true);
    setComparisonErrorMessage('');
    setReviewComparison(null);
    setProjectDashboard(null);
    setDashboardErrorMessage('');
    setAiComparisonInsight(null);

    try {
      const comparison = await fetchLatestReviewComparison(projectId);
      setReviewComparison(comparison);
    } catch (error) {
      setComparisonErrorMessage(error instanceof Error ? error.message : '최근 분석 비교 결과를 불러오지 못했습니다.');
    } finally {
      setIsComparisonLoading(false);
    }
  };


  const handleProjectDashboardOpen = async (projectId?: number | null) => {
    if (!projectId) {
      setDashboardErrorMessage('프로젝트에 연결된 분석 이력만 대시보드를 볼 수 있습니다.');
      return;
    }

    setIsDashboardLoading(true);
    setDashboardErrorMessage('');
    setComparisonErrorMessage('');
    setReviewComparison(null);
    setAiComparisonInsight(null);
    setProjectDashboard(null);

    try {
      const dashboard = await fetchProjectDashboard(projectId);
      setProjectDashboard(dashboard);
    } catch (error) {
      setDashboardErrorMessage(error instanceof Error ? error.message : '프로젝트 보안 대시보드를 불러오지 못했습니다.');
    } finally {
      setIsDashboardLoading(false);
    }
  };

  const refreshProjectPanelsAfterDelete = async (projectId?: number | null) => {
    if (!projectId) {
      return;
    }

    if (projectDashboard?.projectId === projectId) {
      try {
        const dashboard = await fetchProjectDashboard(projectId);
        setProjectDashboard(dashboard);
      } catch (error) {
        setProjectDashboard(null);
        setDashboardErrorMessage(error instanceof Error ? error.message : '프로젝트 보안 대시보드를 다시 불러오지 못했습니다.');
      }
    }

    if (reviewComparison?.projectId === projectId) {
      try {
        const comparison = await fetchLatestReviewComparison(projectId);
        setReviewComparison(comparison);
      } catch (error) {
        setReviewComparison(null);
        setComparisonErrorMessage(error instanceof Error ? error.message : '최근 분석 비교 결과를 다시 불러오지 못했습니다.');
      }
      setAiComparisonInsight(null);
    }
  };

  const handleReviewDelete = async (history: ReviewHistoryResponse) => {
    if (!window.confirm(`분석 결과 #${history.reviewId}을 삭제할까요? 연결된 취약점과 AI Audit snippet도 함께 삭제됩니다.`)) {
      return;
    }

    setDeletingReviewId(history.reviewId);
    setErrorMessage('');
    setSuccessMessage('');
    setHistoryErrorMessage('');

    try {
      const response = await deleteReview(history.reviewId);
      setReviewHistory((previous) => previous.filter((item) => item.reviewId !== history.reviewId));
      const currentProjectId = result?.projectId ?? null;
      if (selectedReviewId === history.reviewId || result?.reviewId === history.reviewId) {
        resetCurrentResult();
      } else if (currentProjectId === history.projectId) {
        await loadStatusSummary(currentProjectId);
      }
      await refreshProjectPanelsAfterDelete(history.projectId);
      await loadReviewHistory();
      setSuccessMessage(response.message);
    } catch (error) {
      setHistoryErrorMessage(error instanceof Error ? error.message : '분석 결과를 삭제하지 못했습니다.');
    } finally {
      setDeletingReviewId(null);
    }
  };

  const handleProjectDelete = async (projectId: number) => {
    if (!window.confirm('프로젝트를 삭제할까요? 연결된 모든 분석 결과, 취약점, snippet이 함께 삭제됩니다.')) {
      return;
    }

    setDeletingProjectId(projectId);
    setErrorMessage('');
    setSuccessMessage('');
    setDashboardErrorMessage('');

    try {
      const response = await deleteProject(projectId);
      setReviewHistory((previous) => previous.filter((item) => item.projectId !== projectId));
      if (result?.projectId === projectId || projectDashboard?.projectId === projectId || reviewComparison?.projectId === projectId) {
        resetCurrentResult();
      } else {
        setProjectDashboard(null);
        setReviewComparison(null);
        setAiComparisonInsight(null);
      }
      await loadReviewHistory();
      setSuccessMessage(response.message);
    } catch (error) {
      setDashboardErrorMessage(error instanceof Error ? error.message : '프로젝트를 삭제하지 못했습니다.');
    } finally {
      setDeletingProjectId(null);
    }
  };

  const handleAiComparisonGenerate = async (projectId: number) => {
    setIsAiComparisonLoading(true);
    setComparisonErrorMessage('');
    setAiComparisonInsight(null);

    try {
      const insight = await fetchAiComparisonInsight(projectId);
      setAiComparisonInsight(insight);
    } catch (error) {
      setComparisonErrorMessage(error instanceof Error ? error.message : 'AI 비교 해석을 생성하지 못했습니다.');
    } finally {
      setIsAiComparisonLoading(false);
    }
  };

  const handleAiPrioritiesGenerate = async () => {
    if (!result?.reviewId) {
      setErrorMessage('AI 수정 우선순위를 생성할 분석 결과가 없습니다.');
      return;
    }

    setIsAiPriorityLoading(true);
    setErrorMessage('');
    setSuccessMessage('');

    try {
      const priorities = await fetchAiPriorities(result.reviewId);
      setAiPriorities(priorities);
      setActiveResultTab('AI_REVIEW');
      setActiveAiSubTab('PRIORITIES');
      setSuccessMessage('AI 수정 우선순위가 생성되었습니다.');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'AI 수정 우선순위를 생성하지 못했습니다.');
    } finally {
      setIsAiPriorityLoading(false);
    }
  };

  const handleAiRoadmapGenerate = async () => {
    if (!result?.reviewId) {
      setErrorMessage('AI 보안 개선 로드맵을 생성할 분석 결과가 없습니다.');
      return;
    }

    setIsAiRoadmapLoading(true);
    setErrorMessage('');
    setSuccessMessage('');

    try {
      const roadmap = await fetchAiRoadmap(result.reviewId);
      setAiRoadmap(roadmap);
      setActiveResultTab('AI_REVIEW');
      setActiveAiSubTab('ROADMAP');
      setSuccessMessage('AI 보안 개선 로드맵이 생성되었습니다.');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'AI 보안 개선 로드맵을 생성하지 못했습니다.');
    } finally {
      setIsAiRoadmapLoading(false);
    }
  };

  const handleReportDownload = async () => {
    if (!result?.reviewId) {
      setErrorMessage('PDF 리포트를 다운로드할 분석 결과가 없습니다.');
      return;
    }

    setIsReportDownloading(true);
    setErrorMessage('');
    setSuccessMessage('');

    try {
      const reportBlob = await downloadReviewReport(result.reviewId);
      downloadBlob(reportBlob, `securedeploy-report-${result.reviewId}.pdf`);
      setSuccessMessage('기본 PDF 리포트 다운로드가 시작되었습니다.');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'PDF 리포트를 다운로드하지 못했습니다.');
    } finally {
      setIsReportDownloading(false);
    }
  };

  const handleAiReportDownload = async () => {
    if (!result?.reviewId) {
      setErrorMessage('AI 리뷰 포함 PDF를 다운로드할 분석 결과가 없습니다.');
      return;
    }

    setIsAiReportDownloading(true);
    setErrorMessage('');
    setSuccessMessage('');

    try {
      const reportBlob = await downloadAiReviewReport(result.reviewId);
      downloadBlob(reportBlob, `securedeploy-ai-report-${result.reviewId}.pdf`);
      setSuccessMessage('AI 리뷰 포함 PDF 리포트 다운로드가 시작되었습니다.');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'AI 리뷰 포함 PDF 리포트를 다운로드하지 못했습니다.');
    } finally {
      setIsAiReportDownloading(false);
    }
  };

  const handleAiReviewGenerate = async () => {
    if (!result?.reviewId) {
      setErrorMessage('AI 리뷰를 생성할 분석 결과가 없습니다.');
      return;
    }

    setIsAiReviewLoading(true);
    setErrorMessage('');
    setSuccessMessage('');

    try {
      const generatedReview = await fetchAiReview(result.reviewId);
      setAiReviewResult(generatedReview);
      setActiveResultTab('AI_REVIEW');
      setActiveAiSubTab('VULNERABILITY_REVIEW');
      setSuccessMessage('취약점별 AI 리뷰가 생성되었습니다.');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'AI 리뷰를 생성하지 못했습니다.');
    } finally {
      setIsAiReviewLoading(false);
    }
  };

  const handleAiSummaryGenerate = async () => {
    if (!result?.reviewId) {
      setErrorMessage('AI 종합 진단을 생성할 분석 결과가 없습니다.');
      return;
    }

    setIsAiSummaryLoading(true);
    setErrorMessage('');
    setSuccessMessage('');

    try {
      const summary = await fetchAiProjectSummary(result.reviewId);
      setAiProjectSummary(summary);
      setActiveResultTab('AI_REVIEW');
      setActiveAiSubTab('PROJECT_SUMMARY');
      setSuccessMessage('AI 종합 진단이 생성되었습니다.');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'AI 종합 진단을 생성하지 못했습니다.');
    } finally {
      setIsAiSummaryLoading(false);
    }
  };

  const handleAiAuditGenerate = async () => {
    if (!result?.reviewId) {
      setErrorMessage('AI 보조 진단을 실행할 분석 결과가 없습니다.');
      return;
    }

    setIsAiAuditLoading(true);
    setErrorMessage('');
    setSuccessMessage('');

    try {
      const audit = await fetchAiSecurityAudit(result.reviewId);
      setAiSecurityAudit(audit);
      setActiveResultTab('AI_REVIEW');
      setActiveAiSubTab('SECURITY_AUDIT');
      setSuccessMessage('AI 보조 진단이 생성되었습니다.');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'AI 보조 진단을 실행하지 못했습니다.');
    } finally {
      setIsAiAuditLoading(false);
    }
  };

  const handleAiRemediationGenerate = async () => {
    if (!result?.reviewId) {
      setErrorMessage('AI 수정 제안을 생성할 분석 결과가 없습니다.');
      return;
    }

    setIsAiRemediationLoading(true);
    setErrorMessage('');
    setSuccessMessage('');

    try {
      const remediation = await fetchAiRemediation(result.reviewId);
      setAiRemediationResult(remediation);
      setActiveResultTab('AI_REVIEW');
      setActiveAiSubTab('REMEDIATION');
      setSuccessMessage('AI 수정 제안이 생성되었습니다.');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'AI 수정 제안을 생성하지 못했습니다.');
    } finally {
      setIsAiRemediationLoading(false);
    }
  };

  const handleStatusCommentChange = (vulnerabilityId: number, comment: string) => {
    setStatusComments((previous) => ({
      ...previous,
      [vulnerabilityId]: comment,
    }));
  };

  const handleVulnerabilityStatusChange = async (vulnerability: Vulnerability, status: VulnerabilityStatus) => {
    if (!vulnerability.vulnerabilityId) {
      setErrorMessage('저장된 취약점만 상태를 변경할 수 있습니다. 분석 이력을 다시 열어 주세요.');
      return;
    }

    const comment = statusComments[vulnerability.vulnerabilityId] ?? vulnerability.statusComment ?? '';
    setStatusUpdatingId(vulnerability.vulnerabilityId);
    setErrorMessage('');
    setSuccessMessage('');

    try {
      const updated = await updateVulnerabilityStatus(vulnerability.vulnerabilityId, status, comment);
      setResult((previous) => previous ? updateVulnerabilityInResult(previous, updated) : previous);
      await loadStatusSummary(result?.projectId);
      setSuccessMessage('취약점 상태가 변경되었습니다.');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : '취약점 상태를 변경하지 못했습니다.');
    } finally {
      setStatusUpdatingId(null);
    }
  };

  const handleAuthSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsAuthLoading(true);
    setAuthErrorMessage('');

    try {
      const session = authMode === 'SIGNUP'
        ? await signupRequest(authEmail.trim(), authPassword, authName.trim())
        : await loginRequest(authEmail.trim(), authPassword);
      storeAuthSession(session);
      setAuthSession(session);
      setAuthPassword('');
      setAuthName('');
      setSuccessMessage(`${session.user.name}님, 로그인되었습니다.`);
    } catch (error) {
      setAuthErrorMessage(error instanceof Error ? error.message : '인증 처리 중 오류가 발생했습니다.');
    } finally {
      setIsAuthLoading(false);
    }
  };

  const handleLogout = () => {
    clearStoredAuthSession();
    setAuthSession(null);
    setReviewHistory([]);
    setErrorMessage('');
    setSuccessMessage('');
    resetCurrentResult();
  };

  const switchAuthMode = (mode: AuthMode) => {
    setAuthMode(mode);
    setAuthErrorMessage('');
  };

  const validateAnalysisInput = () => {
    if (analysisMode === 'ZIP') {
      return selectedFile ? '' : '분석할 ZIP 파일을 선택해 주세요.';
    }

    const trimmedUrl = repositoryUrl.trim();
    if (!trimmedUrl) {
      return '분석할 GitHub Repository URL을 입력해 주세요.';
    }

    try {
      const url = new URL(trimmedUrl);
      if (url.hostname !== 'github.com') {
        return 'github.com 저장소 URL만 분석할 수 있습니다.';
      }
      if (url.protocol !== 'https:') {
        return 'https://github.com 형식의 저장소 URL을 입력해 주세요.';
      }
    } catch {
      return '올바른 GitHub Repository URL을 입력해 주세요.';
    }

    return '';
  };

  if (!authSession) {
    return (
      <AuthScreen
        mode={authMode}
        email={authEmail}
        password={authPassword}
        name={authName}
        errorMessage={authErrorMessage}
        isLoading={isAuthLoading}
        onModeChange={switchAuthMode}
        onEmailChange={setAuthEmail}
        onPasswordChange={setAuthPassword}
        onNameChange={setAuthName}
        onSubmit={(event) => void handleAuthSubmit(event)}
      />
    );
  }

  return (
    <main className="app-shell">
      <section className="workspace">
        <div className="masthead">
          <div>
            <p className="eyebrow">SecureDeploy MVP</p>
            <h1>Spring Boot 보안 리뷰</h1>
          </div>
          <div className="session-box">
            <span className="status-pill">{authSession.user.name}</span>
            <button className="secondary-button logout-button" type="button" onClick={handleLogout}>로그아웃</button>
          </div>
        </div>

        <form className="upload-panel review-panel" onSubmit={handleSubmit}>
          <div className="upload-copy">
            <h2>{analysisMode === 'ZIP' ? '프로젝트 ZIP 업로드' : 'GitHub Repository 분석'}</h2>
            <p>
              {analysisMode === 'ZIP'
                ? 'Spring Boot 프로젝트 압축 파일을 분석해 배포 전 보안 위험을 점검합니다.'
                : '공개 GitHub 저장소를 clone한 뒤 동일한 보안 분석 파이프라인으로 점검합니다.'}
            </p>
          </div>

          <div className="analysis-controls">
            <div className="mode-switch" aria-label="분석 방식 선택">
              <button className={analysisMode === 'ZIP' ? 'mode-button mode-button-active' : 'mode-button'} type="button" disabled={isLoading} onClick={() => handleModeChange('ZIP')}>
                ZIP 업로드
              </button>
              <button className={analysisMode === 'GITHUB' ? 'mode-button mode-button-active' : 'mode-button'} type="button" disabled={isLoading} onClick={() => handleModeChange('GITHUB')}>
                GitHub URL 입력
              </button>
            </div>

            {analysisMode === 'ZIP' ? (
              <label className="file-drop">
                <input type="file" accept=".zip,application/zip" onChange={handleFileChange} disabled={isLoading} />
                <span className="file-name">{selectedFile ? selectedFile.name : 'ZIP 파일 선택'}</span>
                <span className="file-hint">.java, JS/TS, 의존성, Docker/배포 설정까지 분석합니다.</span>
              </label>
            ) : (
              <label className="github-input-wrap">
                <span>Repository URL</span>
                <input type="url" value={repositoryUrl} placeholder="https://github.com/user/project.git" onChange={handleRepositoryUrlChange} disabled={isLoading} />
              </label>
            )}
          </div>

          <div className="feedback-stack">
            {errorMessage && <div className="feedback-message feedback-error">{errorMessage}</div>}
            {successMessage && <div className="feedback-message feedback-success">{successMessage}</div>}
          </div>

          <button className="primary-button" type="submit" disabled={isLoading}>
            {isLoading ? '분석 중...' : '분석 시작'}
          </button>
        </form>

        {isLoading && (
          <section className="loading-panel" aria-live="polite">
            <div className="spinner" />
            <p>
              {result
                ? '저장된 분석 결과를 불러오고 있습니다.'
                : analysisMode === 'ZIP'
                  ? '업로드한 프로젝트를 해제하고 취약점 룰을 실행하고 있습니다.'
                  : 'GitHub 저장소를 clone하고 취약점 룰을 실행하고 있습니다.'}
            </p>
          </section>
        )}

        {!isLoading && !result && <section className="empty-state empty-initial">아직 분석 결과가 없습니다.</section>}

        {result && (
          <section className="result-area">
            <div className="summary-grid">
              <Metric label="프로젝트명" value={result.projectName} />
              <Metric label="스캔 파일 수" value={result.scannedFileCount.toLocaleString()} />
              <Metric label="취약점 개수" value={result.vulnerabilityCount.toLocaleString()} />
              <Metric label="보안 점수" value={`${result.securityScore}점`} tone={scoreTone} />
              <Metric label="배포 적합성" value={deploymentStatus} tone={scoreTone} />
            </div>

            {statusSummary && <VulnerabilityProgressPanel summary={statusSummary} />}
            {statusSummaryErrorMessage && <div className="feedback-message feedback-error status-summary-error">{statusSummaryErrorMessage}</div>}

            <div className="section-heading result-heading">
              <div>
                <h2>{activeResultTab === 'RESULT' ? '분석 결과' : 'AI 보안 리뷰'}</h2>
                <p>{selectedReviewId ? `분석 이력 #${selectedReviewId} 상세 결과입니다.` : '현재 분석 결과입니다.'}</p>
              </div>
              <div className="result-actions">
                {result.reviewId && (
                  <>
                    <button className="secondary-button" type="button" onClick={() => void handleReportDownload()} disabled={isReportDownloading}>
                      {isReportDownloading ? 'PDF 생성 중...' : '기본 리포트 다운로드'}
                    </button>
                    {aiReviewResult && (
                      <button className="secondary-button" type="button" onClick={() => void handleAiReportDownload()} disabled={isAiReportDownloading}>
                        {isAiReportDownloading ? 'AI PDF 생성 중...' : 'AI 리뷰 포함 리포트 다운로드'}
                      </button>
                    )}
                  </>
                )}
              </div>
            </div>

            <div className="result-tab-bar" aria-label="결과 화면 전환">
              <button className={activeResultTab === 'RESULT' ? 'result-tab result-tab-active' : 'result-tab'} type="button" onClick={() => setActiveResultTab('RESULT')}>
                분석 결과
              </button>
              <button className={activeResultTab === 'AI_REVIEW' ? 'result-tab result-tab-active' : 'result-tab'} type="button" onClick={() => setActiveResultTab('AI_REVIEW')}>
                AI 리뷰
              </button>
            </div>

            {activeResultTab === 'RESULT' ? (
              <>
                <div className="section-heading vulnerability-heading">
                  <div>
                    <h2>취약점 목록</h2>
                    <p>심각도 순으로 정렬된 분석 결과입니다.</p>
                  </div>
                  <span>{filteredVulnerabilities.length} / {result.vulnerabilities.length}건</span>
                </div>

                <div className="filter-bar" aria-label="severity 필터">
                  {severityFilters.map((filter) => (
                    <button className={severityFilter === filter ? 'filter-button filter-button-active' : 'filter-button'} type="button" key={filter} onClick={() => setSeverityFilter(filter)}>
                      {filter === 'ALL' ? '전체' : filter}
                    </button>
                  ))}
                </div>

                {renderVulnerabilityList(
                  result,
                  filteredVulnerabilities,
                  statusUpdatingId,
                  statusComments,
                  handleStatusCommentChange,
                  (vulnerability, status) => void handleVulnerabilityStatusChange(vulnerability, status)
                )}
              </>
            ) : (
              <AiReviewSection
                activeAiSubTab={activeAiSubTab}
                aiProjectSummary={aiProjectSummary}
                aiRemediationResult={aiRemediationResult}
                aiSecurityAudit={aiSecurityAudit}
                aiPriorities={aiPriorities}
                aiRoadmap={aiRoadmap}
                aiReviewResult={aiReviewResult}
                isReviewLoading={isAiReviewLoading}
                isSummaryLoading={isAiSummaryLoading}
                isRemediationLoading={isAiRemediationLoading}
                isAuditLoading={isAiAuditLoading}
                isPriorityLoading={isAiPriorityLoading}
                isRoadmapLoading={isAiRoadmapLoading}
                onGenerateReview={() => void handleAiReviewGenerate()}
                onGenerateSummary={() => void handleAiSummaryGenerate()}
                onGenerateRemediation={() => void handleAiRemediationGenerate()}
                onGenerateAudit={() => void handleAiAuditGenerate()}
                onGeneratePriorities={() => void handleAiPrioritiesGenerate()}
                onGenerateRoadmap={() => void handleAiRoadmapGenerate()}
                onTabChange={setActiveAiSubTab}
              />
            )}
          </section>
        )}

        <section className="history-panel">
          <div className="section-heading history-heading">
            <div>
              <h2>분석 이력</h2>
              <p>저장된 분석 결과를 다시 열어볼 수 있습니다.</p>
            </div>
            <button className="secondary-button" type="button" onClick={() => void loadReviewHistory()} disabled={isHistoryLoading}>
              {isHistoryLoading ? '불러오는 중...' : '새로고침'}
            </button>
          </div>

          {historyErrorMessage && <p className="error-message history-error">{historyErrorMessage}</p>}
          {comparisonErrorMessage && <p className="error-message history-error">{comparisonErrorMessage}</p>}
          {dashboardErrorMessage && <p className="error-message history-error">{dashboardErrorMessage}</p>}

          {isHistoryLoading && reviewHistory.length === 0 ? (
            <div className="empty-state">분석 이력을 불러오고 있습니다.</div>
          ) : reviewHistory.length === 0 ? (
            <div className="empty-state">저장된 분석 이력이 없습니다.</div>
          ) : (
            <div className="history-list">
              {reviewHistory.map((history) => (
                <div className="history-row" key={history.reviewId}>
                  <button className={selectedReviewId === history.reviewId ? 'history-item history-item-active' : 'history-item'} type="button" onClick={() => void handleHistoryClick(history.reviewId)}>
                    <div className="history-main">
                      <span className="history-project">{history.projectName}</span>
                      <span className="source-badge">{history.sourceType}</span>
                    </div>
                    <div className="history-meta">
                      <span>취약점 {history.vulnerabilityCount}건</span>
                      <span>{history.securityScore}점</span>
                      <span>{history.deploymentStatus}</span>
                      <time dateTime={history.createdAt}>{formatDateTime(history.createdAt)}</time>
                    </div>
                  </button>
                  <div className="history-actions">
                    <button className="compare-button" type="button" onClick={() => void handleProjectDashboardOpen(history.projectId)} disabled={isDashboardLoading}>
                      {isDashboardLoading ? '로딩 중...' : '보안 대시보드'}
                    </button>
                    <button className="compare-button" type="button" onClick={() => void handleCompareLatest(history.projectId)} disabled={isComparisonLoading}>
                      {isComparisonLoading ? '비교 중...' : '최근 분석 비교'}
                    </button>
                    <button className="delete-button" type="button" onClick={() => void handleReviewDelete(history)} disabled={deletingReviewId === history.reviewId || deletingProjectId === history.projectId}>
                      {deletingReviewId === history.reviewId ? '삭제 중...' : '삭제'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {projectDashboard && <ProjectSecurityDashboardPanel dashboard={projectDashboard} isDeleting={deletingProjectId === projectDashboard.projectId} onDelete={() => void handleProjectDelete(projectDashboard.projectId)} />}

          {reviewComparison && <ReviewComparisonPanel comparison={reviewComparison} aiInsight={aiComparisonInsight} isAiLoading={isAiComparisonLoading} onGenerateAi={() => void handleAiComparisonGenerate(reviewComparison.projectId)} />}
        </section>
      </section>
    </main>
  );
}


interface AuthScreenProps {
  mode: AuthMode;
  email: string;
  password: string;
  name: string;
  errorMessage: string;
  isLoading: boolean;
  onModeChange: (mode: AuthMode) => void;
  onEmailChange: (value: string) => void;
  onPasswordChange: (value: string) => void;
  onNameChange: (value: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}

function AuthScreen({
  mode,
  email,
  password,
  name,
  errorMessage,
  isLoading,
  onModeChange,
  onEmailChange,
  onPasswordChange,
  onNameChange,
  onSubmit,
}: AuthScreenProps) {
  const isSignup = mode === 'SIGNUP';

  return (
    <main className="app-shell auth-shell">
      <section className="auth-panel">
        <div className="auth-copy">
          <p className="eyebrow">SecureDeploy</p>
          <h1>{isSignup ? '계정 생성' : '로그인'}</h1>
          <p>프로젝트별 보안 분석 이력, 취약점 상태, AI 리뷰를 사용자 계정 기준으로 관리합니다.</p>
        </div>

        <form className="auth-form" onSubmit={onSubmit}>
          <div className="mode-switch auth-mode-switch" aria-label="인증 방식 선택">
            <button className={mode === 'LOGIN' ? 'mode-button mode-button-active' : 'mode-button'} type="button" disabled={isLoading} onClick={() => onModeChange('LOGIN')}>
              로그인
            </button>
            <button className={mode === 'SIGNUP' ? 'mode-button mode-button-active' : 'mode-button'} type="button" disabled={isLoading} onClick={() => onModeChange('SIGNUP')}>
              회원가입
            </button>
          </div>

          {isSignup && (
            <label>
              <span>이름</span>
              <input type="text" value={name} placeholder="박상우" onChange={(event) => onNameChange(event.target.value)} disabled={isLoading} required />
            </label>
          )}

          <label>
            <span>이메일</span>
            <input type="email" value={email} placeholder="user@test.com" onChange={(event) => onEmailChange(event.target.value)} disabled={isLoading} required />
          </label>

          <label>
            <span>비밀번호</span>
            <input type="password" value={password} placeholder="password1234" onChange={(event) => onPasswordChange(event.target.value)} disabled={isLoading} minLength={8} required />
          </label>

          {errorMessage && <div className="feedback-message feedback-error">{errorMessage}</div>}

          <button className="primary-button auth-submit" type="submit" disabled={isLoading}>
            {isLoading ? '처리 중...' : isSignup ? '회원가입' : '로그인'}
          </button>
        </form>
      </section>
    </main>
  );
}

function ProjectSecurityDashboardPanel({ dashboard, isDeleting, onDelete }: { dashboard: ProjectSecurityDashboardResponse; isDeleting: boolean; onDelete: () => void }) {
  const comparison = dashboard.comparisonSummary;
  const latestScore = dashboard.latestSecurityScore ?? 0;
  const latestVulnerabilityCount = dashboard.latestVulnerabilityCount ?? 0;
  const maxHistoryScore = Math.max(100, ...dashboard.scoreHistory.map((item) => item.securityScore));
  const totalStatuses = Object.values(dashboard.statusCounts).reduce((sum, count) => sum + count, 0);
  const resolvedCount = dashboard.statusCounts.RESOLVED ?? 0;

  return (
    <section className="project-dashboard-panel">
      <div className="project-dashboard-header">
        <div>
          <span className="source-badge">{dashboard.sourceType}</span>
          <h2>{dashboard.projectName}</h2>
          {dashboard.repositoryUrl && <p>{dashboard.repositoryUrl}</p>}
        </div>
        <div className="project-dashboard-meta">
          <span>최신 분석 {dashboard.latestAnalyzedAt ? formatDateTime(dashboard.latestAnalyzedAt) : '없음'}</span>
          <strong>{dashboard.latestDeploymentStatus ?? '분석 전'}</strong>
          <button className="delete-button project-delete-button" type="button" onClick={onDelete} disabled={isDeleting}>
            {isDeleting ? '삭제 중...' : '프로젝트 삭제'}
          </button>
        </div>
      </div>

      <div className="dashboard-metrics">
        <Metric label="최신 보안 점수" value={dashboard.latestReviewId ? `${latestScore}점` : '-'} tone={latestScore >= 80 ? 'safe' : latestScore >= 60 ? 'warning' : 'danger'} />
        <Metric label="취약점 개수" value={dashboard.latestReviewId ? `${latestVulnerabilityCount.toLocaleString()}건` : '-'} tone={latestVulnerabilityCount === 0 ? 'safe' : 'warning'} />
        <Metric label="해결률" value={`${dashboard.resolutionRate}%`} tone={dashboard.resolutionRate >= 70 ? 'safe' : dashboard.resolutionRate >= 30 ? 'warning' : 'danger'} />
        <Metric label="점수 변화" value={comparison?.latestReviewId ? signedNumber(comparison.scoreDiff) : '-'} tone={(comparison?.scoreDiff ?? 0) >= 0 ? 'safe' : 'danger'} />
        <Metric label="취약점 변화" value={comparison?.latestReviewId ? signedNumber(comparison.vulnerabilityCountDiff) : '-'} tone={(comparison?.vulnerabilityCountDiff ?? 0) <= 0 ? 'safe' : 'danger'} />
      </div>

      <div className="dashboard-grid">
        <article className="dashboard-card score-history-card">
          <h3>보안 점수 추이</h3>
          {dashboard.scoreHistory.length === 0 ? (
            <p className="dashboard-empty">분석 이력이 없습니다.</p>
          ) : (
            <div className="score-history-list">
              {dashboard.scoreHistory.map((item) => (
                <div className="score-history-row" key={item.reviewId}>
                  <div>
                    <strong>#{item.reviewId}</strong>
                    <span>{formatDateTime(item.createdAt)}</span>
                  </div>
                  <div className="score-bar-track">
                    <div className="score-bar-fill" style={{ width: `${Math.min((item.securityScore / maxHistoryScore) * 100, 100)}%` }} />
                  </div>
                  <span>{item.securityScore}점 / {item.vulnerabilityCount}건</span>
                </div>
              ))}
            </div>
          )}
        </article>

        <article className="dashboard-card">
          <h3>Severity 분포</h3>
          <div className="distribution-list">
            {severityFilters.filter((item): item is Severity => item !== 'ALL').map((severity) => (
              <div key={severity}>
                <SeverityBadge severity={severity} />
                <strong>{(dashboard.severityCounts[severity] ?? 0).toLocaleString()}건</strong>
              </div>
            ))}
          </div>
        </article>

        <article className="dashboard-card">
          <h3>상태별 진행 현황</h3>
          <div className="progress-track dashboard-progress" aria-label={`해결률 ${dashboard.resolutionRate}%`}>
            <div className="progress-fill" style={{ width: `${Math.min(dashboard.resolutionRate, 100)}%` }} />
          </div>
          <div className="distribution-list status-distribution">
            {vulnerabilityStatuses.map((status) => (
              <div key={status}>
                <VulnerabilityStatusBadge status={status} />
                <strong>{(dashboard.statusCounts[status] ?? 0).toLocaleString()}건</strong>
              </div>
            ))}
          </div>
          <p className="dashboard-note">전체 {totalStatuses.toLocaleString()}건 중 수정 완료 {resolvedCount.toLocaleString()}건</p>
        </article>

        <article className="dashboard-card comparison-summary-card">
          <h3>최근 분석 비교 요약</h3>
          {comparison?.latestReviewId ? (
            <div className="comparison-summary-grid">
              <Metric label="점수 변화" value={signedNumber(comparison.scoreDiff)} tone={comparison.scoreDiff >= 0 ? 'safe' : 'danger'} />
              <Metric label="해결" value={`${comparison.resolvedCount}건`} tone="safe" />
              <Metric label="신규" value={`${comparison.newCount}건`} tone={comparison.newCount === 0 ? 'safe' : 'danger'} />
              <Metric label="지속" value={`${comparison.persistedCount}건`} tone={comparison.persistedCount === 0 ? 'safe' : 'warning'} />
            </div>
          ) : (
            <p className="dashboard-empty">{comparison?.message ?? '비교할 분석 이력이 부족합니다.'}</p>
          )}
        </article>
      </div>

      <article className="dashboard-card high-risk-card">
        <div className="section-heading dashboard-card-heading">
          <div>
            <h3>최근 고위험 취약점</h3>
            <p>최신 분석 기준 severity가 높은 순서로 최대 5개를 표시합니다.</p>
          </div>
        </div>
        {dashboard.recentHighRiskVulnerabilities.length === 0 ? (
          <p className="dashboard-empty">최근 고위험 취약점이 없습니다.</p>
        ) : (
          <div className="high-risk-list">
            {dashboard.recentHighRiskVulnerabilities.map((vulnerability) => (
              <article key={vulnerability.vulnerabilityId}>
                <div className="high-risk-header">
                  <span className="rule-id">{vulnerability.ruleId}</span>
                  <div className="vulnerability-badges">
                    <SeverityBadge severity={vulnerability.severity} />
                    <VulnerabilityStatusBadge status={vulnerability.status} />
                  </div>
                </div>
                <strong>{vulnerability.message}</strong>
                <p>{vulnerability.filePath}:{vulnerability.line}</p>
                <span>{vulnerability.category}</span>
              </article>
            ))}
          </div>
        )}
      </article>
    </section>
  );
}

function ReviewComparisonPanel({ comparison, aiInsight, isAiLoading, onGenerateAi }: { comparison: ReviewComparisonResponse; aiInsight: AiComparisonInsightResponse | null; isAiLoading: boolean; onGenerateAi: () => void }) {
  const isComparable = comparison.latestReviewId && comparison.previousReviewId;

  if (!isComparable) {
    return <div className="comparison-panel empty-state">{comparison.message}</div>;
  }

  return (
    <section className="comparison-panel">
      <div className="section-heading comparison-heading">
        <div>
          <h2>최근 분석 비교</h2>
          <p>최신 분석 #{comparison.latestReviewId}와 직전 분석 #{comparison.previousReviewId}의 변화입니다.</p>
        </div>
      </div>
      <button className="secondary-button" type="button" onClick={onGenerateAi} disabled={isAiLoading}>
        {isAiLoading ? 'AI 비교 해석 생성 중...' : 'AI 비교 해석'}
      </button>
      {aiInsight && <AiComparisonInsightCard insight={aiInsight} />}
      <div className="comparison-metrics">
        <Metric label="점수 변화" value={signedNumber(comparison.scoreDiff)} tone={comparison.scoreDiff >= 0 ? 'safe' : 'danger'} />
        <Metric label="취약점 변화" value={signedNumber(comparison.vulnerabilityCountDiff)} tone={comparison.vulnerabilityCountDiff <= 0 ? 'safe' : 'danger'} />
        <Metric label="해결" value={`${comparison.resolvedVulnerabilities.length}건`} tone="safe" />
        <Metric label="신규" value={`${comparison.newVulnerabilities.length}건`} tone={comparison.newVulnerabilities.length === 0 ? 'safe' : 'danger'} />
        <Metric label="지속" value={`${comparison.persistedVulnerabilities.length}건`} tone={comparison.persistedVulnerabilities.length === 0 ? 'safe' : 'warning'} />
      </div>
      <ComparisonList title="해결된 취약점" items={comparison.resolvedVulnerabilities} emptyText="해결된 취약점이 없습니다." />
      <ComparisonList title="새로 생긴 취약점" items={comparison.newVulnerabilities} emptyText="새로 생긴 취약점이 없습니다." />
      <ComparisonList title="지속 취약점" items={comparison.persistedVulnerabilities} emptyText="지속 취약점이 없습니다." />
    </section>
  );
}


function AiComparisonInsightCard({ insight }: { insight: AiComparisonInsightResponse }) {
  return (
    <article className="ai-review-card ai-strategy-card">
      <div className="ai-review-card-header">
        <span className="rule-id">AI_COMPARISON_INSIGHT</span>
      </div>
      <h3>AI 재분석 비교 해석</h3>
      <AiUsageMeta usage={insight.usage} />
      <dl className="ai-review-detail">
        <div>
          <dt>overall insight</dt>
          <dd>{insight.overallInsight}</dd>
        </div>
        <div>
          <dt>improvement</dt>
          <dd>{insight.improvementSummary}</dd>
        </div>
        <div>
          <dt>remaining risk</dt>
          <dd>{insight.remainingRiskSummary}</dd>
        </div>
        <div>
          <dt>new risk</dt>
          <dd>{insight.newRiskSummary}</dd>
        </div>
        <div>
          <dt>deployment opinion</dt>
          <dd>{insight.deploymentReadinessOpinion}</dd>
        </div>
      </dl>
      <AiListCard title="다음 권장 조치" items={insight.nextRecommendedActions} />
    </article>
  );
}

function ComparisonList({ title, items, emptyText }: { title: string; items: ReviewComparisonResponse['resolvedVulnerabilities']; emptyText: string }) {
  return (
    <div className="comparison-list">
      <h3>{title}</h3>
      {items.length === 0 ? (
        <p>{emptyText}</p>
      ) : (
        <div className="comparison-vulnerabilities">
          {items.map((item, index) => (
            <article key={`${title}-${item.ruleId}-${item.filePath}-${index}`}>
              <div>
                <span className="rule-id">{item.ruleId}</span>
                <SeverityBadge severity={item.severity} />
              </div>
              <strong>{item.message}</strong>
              <p>{item.filePath}:{item.line}</p>
              {item.evidence && <code>{item.evidence}</code>}
            </article>
          ))}
        </div>
      )}
    </div>
  );
}

function signedNumber(value: number) {
  return value > 0 ? `+${value}` : `${value}`;
}

function renderVulnerabilityList(
  result: SecurityReviewResponse,
  filteredVulnerabilities: SecurityReviewResponse['vulnerabilities'],
  statusUpdatingId: number | null,
  statusComments: Record<number, string>,
  onStatusCommentChange: (vulnerabilityId: number, comment: string) => void,
  onStatusChange: (vulnerability: Vulnerability, status: VulnerabilityStatus) => void
) {
  if (result.vulnerabilities.length === 0) {
    return <div className="empty-state">탐지된 취약점이 없습니다.</div>;
  }

  if (filteredVulnerabilities.length === 0) {
    return <div className="empty-state">선택한 severity에 해당하는 취약점이 없습니다.</div>;
  }

  return (
    <div className="vulnerability-list">
      {filteredVulnerabilities.map((vulnerability, index) => {
        const vulnerabilityId = vulnerability.vulnerabilityId ?? null;
        const status = vulnerability.status ?? 'UNCHECKED';
        const isUpdating = vulnerabilityId !== null && statusUpdatingId === vulnerabilityId;
        const comment = vulnerabilityId !== null
          ? statusComments[vulnerabilityId] ?? vulnerability.statusComment ?? ''
          : vulnerability.statusComment ?? '';

        return (
          <article className={`vulnerability-item vulnerability-${vulnerability.severity.toLowerCase()}`} key={`${vulnerability.ruleId}-${vulnerability.filePath}-${vulnerability.line}-${index}`}>
            <div className="vulnerability-header">
              <div>
                <span className="rule-id">{vulnerability.ruleId}</span>
                <h3>{vulnerability.message}</h3>
              </div>
              <div className="vulnerability-badges">
                <SeverityBadge severity={vulnerability.severity} />
                <VulnerabilityStatusBadge status={status} />
              </div>
            </div>

            <div className="status-manager">
              <label>
                <span>상태</span>
                <select value={status} disabled={!vulnerabilityId || isUpdating} onChange={(event) => onStatusChange(vulnerability, event.target.value as VulnerabilityStatus)}>
                  {vulnerabilityStatuses.map((item) => (
                    <option key={item} value={item}>{vulnerabilityStatusLabels[item]}</option>
                  ))}
                </select>
              </label>
              <label>
                <span>메모</span>
                <input
                  type="text"
                  value={comment}
                  placeholder="예: 다음 배포에서 수정 예정"
                  disabled={!vulnerabilityId || isUpdating}
                  onChange={(event) => vulnerabilityId && onStatusCommentChange(vulnerabilityId, event.target.value)}
                />
              </label>
              {isUpdating && <span className="status-updating">저장 중...</span>}
            </div>

            <dl className="detail-grid">
              <div>
                <dt>category</dt>
                <dd>{vulnerability.category}</dd>
              </div>
              <div className="file-path-cell">
                <dt>filePath</dt>
                <dd>{vulnerability.filePath}</dd>
              </div>
              <div className="line-cell">
                <dt>line</dt>
                <dd>{vulnerability.line}</dd>
              </div>
            </dl>

            <div className="message-block">
              <span>message</span>
              <p>{vulnerability.message}</p>
            </div>

            {vulnerability.evidence && (
              <div className="evidence-block">
                <span>evidence</span>
                <code>{vulnerability.evidence}</code>
              </div>
            )}

            <div className="recommendation">
              <span>recommendation</span>
              <p>{vulnerability.recommendation}</p>
            </div>
          </article>
        );
      })}
    </div>
  );
}

function updateVulnerabilityInResult(result: SecurityReviewResponse, updated: VulnerabilityStatusResponse): SecurityReviewResponse {
  return {
    ...result,
    vulnerabilities: result.vulnerabilities.map((vulnerability) => (
      vulnerability.vulnerabilityId === updated.vulnerabilityId
        ? { ...vulnerability, ...updated }
        : vulnerability
    )),
  };
}

function VulnerabilityStatusBadge({ status }: { status: VulnerabilityStatus }) {
  return <span className={`vulnerability-status vulnerability-status-${status.toLowerCase().replace('_', '-')}`}>{vulnerabilityStatusLabels[status]}</span>;
}

function VulnerabilityProgressPanel({ summary }: { summary: VulnerabilityStatusSummaryResponse }) {
  const total = summary.total || summary.unchecked + summary.acknowledged + summary.inProgress + summary.resolved + summary.ignored;
  const resolved = summary.resolvedCount ?? summary.resolved;

  return (
    <section className="status-progress-panel" aria-label="프로젝트 보안 진행률">
      <div className="section-heading status-progress-heading">
        <div>
          <h2>프로젝트 보안 진행률</h2>
          <p>취약점 수정 진행 상태를 프로젝트 단위로 추적합니다.</p>
        </div>
        <strong>{summary.resolutionRate}%</strong>
      </div>
      <div className="progress-track" aria-label={`해결률 ${summary.resolutionRate}%`}>
        <div className="progress-fill" style={{ width: `${Math.min(summary.resolutionRate, 100)}%` }} />
      </div>
      <div className="status-summary-grid">
        <Metric label="전체 취약점" value={`${total.toLocaleString()}건`} />
        <Metric label="수정 완료" value={`${resolved.toLocaleString()}건`} tone="safe" />
        <Metric label="해결률" value={`${summary.resolutionRate}%`} tone={summary.resolutionRate >= 70 ? 'safe' : summary.resolutionRate >= 30 ? 'warning' : 'danger'} />
        <Metric label="수정 중" value={`${summary.inProgress.toLocaleString()}건`} tone="warning" />
        <Metric label="미확인" value={`${summary.unchecked.toLocaleString()}건`} tone={summary.unchecked === 0 ? 'safe' : 'danger'} />
      </div>
    </section>
  );
}


interface AiReviewSectionProps {
  activeAiSubTab: AiSubTab;
  aiReviewResult: AiReviewResultResponse | null;
  aiProjectSummary: AiProjectSummaryResponse | null;
  aiRemediationResult: AiRemediationResultResponse | null;
  aiSecurityAudit: AiSecurityAuditResponse | null;
  aiPriorities: AiPriorityResponse | null;
  aiRoadmap: AiSecurityRoadmapResponse | null;
  isReviewLoading: boolean;
  isSummaryLoading: boolean;
  isRemediationLoading: boolean;
  isAuditLoading: boolean;
  isPriorityLoading: boolean;
  isRoadmapLoading: boolean;
  onGenerateReview: () => void;
  onGenerateSummary: () => void;
  onGenerateRemediation: () => void;
  onGenerateAudit: () => void;
  onGeneratePriorities: () => void;
  onGenerateRoadmap: () => void;
  onTabChange: (tab: AiSubTab) => void;
}

function AiReviewSection({
  activeAiSubTab,
  aiReviewResult,
  aiProjectSummary,
  aiRemediationResult,
  aiSecurityAudit,
  aiPriorities,
  aiRoadmap,
  isReviewLoading,
  isSummaryLoading,
  isRemediationLoading,
  isAuditLoading,
  isPriorityLoading,
  isRoadmapLoading,
  onGenerateReview,
  onGenerateSummary,
  onGenerateRemediation,
  onGenerateAudit,
  onGeneratePriorities,
  onGenerateRoadmap,
  onTabChange,
}: AiReviewSectionProps) {
  return (
    <section className="ai-review-panel">
      <div className="ai-subtab-bar" aria-label="AI 리뷰 기능 선택">
        <button className={activeAiSubTab === 'VULNERABILITY_REVIEW' ? 'ai-subtab ai-subtab-active' : 'ai-subtab'} type="button" onClick={() => onTabChange('VULNERABILITY_REVIEW')}>
          취약점별 AI 리뷰
        </button>
        <button className={activeAiSubTab === 'PROJECT_SUMMARY' ? 'ai-subtab ai-subtab-active' : 'ai-subtab'} type="button" onClick={() => onTabChange('PROJECT_SUMMARY')}>
          AI 종합 진단
        </button>
        <button className={activeAiSubTab === 'REMEDIATION' ? 'ai-subtab ai-subtab-active' : 'ai-subtab'} type="button" onClick={() => onTabChange('REMEDIATION')}>
          AI 수정 제안
        </button>
        <button className={activeAiSubTab === 'SECURITY_AUDIT' ? 'ai-subtab ai-subtab-active' : 'ai-subtab'} type="button" onClick={() => onTabChange('SECURITY_AUDIT')}>
          AI 보조 진단
        </button>
        <button className={activeAiSubTab === 'PRIORITIES' ? 'ai-subtab ai-subtab-active' : 'ai-subtab'} type="button" onClick={() => onTabChange('PRIORITIES')}>
          AI 수정 우선순위
        </button>
        <button className={activeAiSubTab === 'ROADMAP' ? 'ai-subtab ai-subtab-active' : 'ai-subtab'} type="button" onClick={() => onTabChange('ROADMAP')}>
          AI 개선 로드맵
        </button>
      </div>

      {activeAiSubTab === 'VULNERABILITY_REVIEW' && (
        <VulnerabilityAiReviewSection aiReviewResult={aiReviewResult} isLoading={isReviewLoading} onGenerate={onGenerateReview} />
      )}
      {activeAiSubTab === 'PROJECT_SUMMARY' && (
        <ProjectAiSummarySection aiProjectSummary={aiProjectSummary} isLoading={isSummaryLoading} onGenerate={onGenerateSummary} />
      )}
      {activeAiSubTab === 'REMEDIATION' && (
        <AiRemediationSection aiRemediationResult={aiRemediationResult} isLoading={isRemediationLoading} onGenerate={onGenerateRemediation} />
      )}
      {activeAiSubTab === 'SECURITY_AUDIT' && (
        <AiSecurityAuditSection aiSecurityAudit={aiSecurityAudit} isLoading={isAuditLoading} onGenerate={onGenerateAudit} />
      )}
      {activeAiSubTab === 'PRIORITIES' && (
        <AiPrioritiesSection aiPriorities={aiPriorities} isLoading={isPriorityLoading} onGenerate={onGeneratePriorities} />
      )}
      {activeAiSubTab === 'ROADMAP' && (
        <AiRoadmapSection aiRoadmap={aiRoadmap} isLoading={isRoadmapLoading} onGenerate={onGenerateRoadmap} />
      )}
    </section>
  );
}

function VulnerabilityAiReviewSection({ aiReviewResult, isLoading, onGenerate }: { aiReviewResult: AiReviewResultResponse | null; isLoading: boolean; onGenerate: () => void }) {
  if (!aiReviewResult) {
    return (
      <div className="ai-review-empty">
        <h2>취약점별 AI 리뷰가 아직 생성되지 않았습니다.</h2>
        <p>Rule Engine이 탐지한 취약점을 바탕으로 설명, 위험성, 공격 시나리오, 수정 방법을 생성할 수 있습니다.</p>
        <button className="primary-button" type="button" onClick={onGenerate} disabled={isLoading}>
          {isLoading ? 'AI 리뷰 생성 중...' : 'AI 리뷰 생성'}
        </button>
      </div>
    );
  }

  return (
    <div>
      <div className="section-heading ai-review-heading">
        <div>
          <h2>취약점별 AI 리뷰</h2>
          <p>탐지된 취약점을 사람이 이해하기 쉬운 설명과 조치 기준으로 정리했습니다.</p>
        </div>
        <span>{aiReviewResult.reviews.length}건</span>
      </div>
      <AiUsageMeta usage={aiReviewResult.usage} />
      <div className="ai-review-list">
        {aiReviewResult.reviews.map((review, index) => (
          <article className="ai-review-card" key={`${review.ruleId}-${index}`}>
            <div className="ai-review-card-header">
              <span className="rule-id">{review.ruleId}</span>
              <span className="priority-badge">{review.priority}</span>
            </div>
            <h3>{review.title}</h3>
            <dl className="ai-review-detail">
              <div>
                <dt>description</dt>
                <dd>{review.description}</dd>
              </div>
              <div>
                <dt>risk</dt>
                <dd>{review.riskExplanation}</dd>
              </div>
              <div>
                <dt>attack scenario</dt>
                <dd>{review.attackScenario}</dd>
              </div>
              <div>
                <dt>recommendation</dt>
                <dd>{review.recommendation}</dd>
              </div>
            </dl>
          </article>
        ))}
      </div>
    </div>
  );
}

function ProjectAiSummarySection({ aiProjectSummary, isLoading, onGenerate }: { aiProjectSummary: AiProjectSummaryResponse | null; isLoading: boolean; onGenerate: () => void }) {
  if (!aiProjectSummary) {
    return (
      <div className="ai-review-empty">
        <h2>AI 종합 진단이 아직 생성되지 않았습니다.</h2>
        <p>프로젝트 전체 점수, 취약점 분포, 배포 상태를 바탕으로 종합 보안 의견을 생성합니다.</p>
        <button className="primary-button" type="button" onClick={onGenerate} disabled={isLoading}>
          {isLoading ? 'AI 종합 진단 생성 중...' : 'AI 종합 진단 생성'}
        </button>
      </div>
    );
  }

  return (
    <div>
      <div className="section-heading ai-review-heading">
        <div>
          <h2>AI 종합 진단</h2>
          <p>분석 결과 전체를 기준으로 배포 전 보안 상태를 요약했습니다.</p>
        </div>
        <time dateTime={aiProjectSummary.generatedAt}>{formatDateTime(aiProjectSummary.generatedAt)}</time>
      </div>
      <AiUsageMeta usage={aiProjectSummary.usage} />
      <article className="ai-review-card ai-summary-card">
        <dl className="ai-review-detail">
          <div>
            <dt>overall status</dt>
            <dd>{aiProjectSummary.overallSecurityStatus}</dd>
          </div>
          <div>
            <dt>risky area</dt>
            <dd>{aiProjectSummary.mostRiskyArea}</dd>
          </div>
          <div>
            <dt>deployment opinion</dt>
            <dd>{aiProjectSummary.deploymentOpinion}</dd>
          </div>
        </dl>
      </article>
      <div className="ai-two-column">
        <AiListCard title="우선 수정 순위" items={aiProjectSummary.priorityFixes} />
        <AiListCard title="배포 전 권장 조치" items={aiProjectSummary.preDeploymentActions} />
      </div>
    </div>
  );
}

function AiRemediationSection({ aiRemediationResult, isLoading, onGenerate }: { aiRemediationResult: AiRemediationResultResponse | null; isLoading: boolean; onGenerate: () => void }) {
  if (!aiRemediationResult) {
    return (
      <div className="ai-review-empty">
        <h2>AI 수정 제안이 아직 생성되지 않았습니다.</h2>
        <p>탐지된 취약점별로 안전한 설정 또는 코드 예시와 검증 방법을 생성합니다.</p>
        <button className="primary-button" type="button" onClick={onGenerate} disabled={isLoading}>
          {isLoading ? 'AI 수정 제안 생성 중...' : 'AI 수정 제안 생성'}
        </button>
      </div>
    );
  }

  if (aiRemediationResult.remediations.length === 0) {
    return <div className="empty-state">수정 제안이 필요한 취약점이 없습니다.</div>;
  }

  return (
    <div>
      <div className="section-heading ai-review-heading">
        <div>
          <h2>AI 수정 제안</h2>
          <p>취약점별 안전한 코드/설정 예시와 확인 방법입니다.</p>
        </div>
        <span>{aiRemediationResult.remediations.length}건</span>
      </div>
      <AiUsageMeta usage={aiRemediationResult.usage} />
      <div className="ai-review-list">
        {aiRemediationResult.remediations.map((remediation, index) => (
          <article className="ai-review-card" key={`${remediation.ruleId}-${remediation.filePath}-${remediation.line}-${index}`}>
            <div className="ai-review-card-header">
              <div>
                <span className="rule-id">{remediation.ruleId}</span>
                <p className="ai-file-ref">{remediation.filePath}:{remediation.line}</p>
              </div>
              <SeverityBadge severity={remediation.severity} />
            </div>
            <h3>{remediation.title}</h3>
            <dl className="ai-review-detail">
              <div>
                <dt>before</dt>
                <dd><pre className="code-example">{remediation.beforeExample}</pre></dd>
              </div>
              <div>
                <dt>after</dt>
                <dd><pre className="code-example">{remediation.afterExample}</pre></dd>
              </div>
              <div>
                <dt>explanation</dt>
                <dd>{remediation.explanation}</dd>
              </div>
              <div>
                <dt>verification</dt>
                <dd>{remediation.verification}</dd>
              </div>
            </dl>
          </article>
        ))}
      </div>
    </div>
  );
}


function AiSecurityAuditSection({ aiSecurityAudit, isLoading, onGenerate }: { aiSecurityAudit: AiSecurityAuditResponse | null; isLoading: boolean; onGenerate: () => void }) {
  if (!aiSecurityAudit) {
    return (
      <div className="ai-review-empty">
        <h2>AI 보조 진단이 아직 실행되지 않았습니다.</h2>
        <p>Rule Engine 확정 탐지와 별도로, 논리적·구조적 보안 위험에 대한 추가 검토 의견을 생성합니다.</p>
        <button className="primary-button" type="button" onClick={onGenerate} disabled={isLoading}>
          {isLoading ? 'AI 보조 진단 실행 중...' : 'AI 보조 진단 실행'}
        </button>
      </div>
    );
  }

  if (aiSecurityAudit.findings.length === 0) {
    return (
      <div>
        <AiUsageMeta usage={aiSecurityAudit.usage} />
        <div className="empty-state">AI가 제안한 추가 검토 항목이 없습니다.</div>
      </div>
    );
  }

  return (
    <div>
      <div className="section-heading ai-review-heading">
        <div>
          <h2>AI 보조 진단</h2>
          <p>확정 취약점이 아닌, AI가 제안하는 추가 검토 의견입니다.</p>
        </div>
        <span>{aiSecurityAudit.findings.length}건</span>
      </div>
      <AiUsageMeta usage={aiSecurityAudit.usage} />
      <ReferencedFiles files={aiSecurityAudit.referencedFiles} />
      <div className="ai-review-list">
        {aiSecurityAudit.findings.map((finding, index) => (
          <article className="ai-review-card ai-audit-card" key={`${finding.title}-${index}`}>
            <div className="ai-review-card-header">
              <div>
                <span className="rule-id">{finding.riskArea}</span>
                <p className="ai-file-ref">AI 추가 검토 의견 · confidence {finding.confidence}</p>
              </div>
              <SeverityBadge severity={finding.severity} />
            </div>
            <h3>{finding.title}</h3>
            <dl className="ai-review-detail">
              <div>
                <dt>reasoning</dt>
                <dd>{finding.reasoning}</dd>
              </div>
              <div>
                <dt>possible impact</dt>
                <dd>{finding.possibleImpact}</dd>
              </div>
              <div>
                <dt>recommendation</dt>
                <dd>{finding.recommendation}</dd>
              </div>
            </dl>
          </article>
        ))}
      </div>
    </div>
  );
}



function AiPrioritiesSection({ aiPriorities, isLoading, onGenerate }: { aiPriorities: AiPriorityResponse | null; isLoading: boolean; onGenerate: () => void }) {
  if (!aiPriorities) {
    return (
      <div className="ai-review-empty">
        <h2>AI 수정 우선순위가 아직 생성되지 않았습니다.</h2>
        <p>위험도, 배포 영향, 공격 가능성, 수정 난이도를 함께 고려해 무엇을 먼저 고칠지 정리합니다.</p>
        <button className="primary-button" type="button" onClick={onGenerate} disabled={isLoading}>
          {isLoading ? 'AI 수정 우선순위 생성 중...' : 'AI 수정 우선순위 생성'}
        </button>
      </div>
    );
  }

  return (
    <div>
      <div className="section-heading ai-review-heading">
        <div>
          <h2>AI 수정 우선순위</h2>
          <p>수정 효과와 실무 난이도를 함께 고려한 조치 순서입니다.</p>
        </div>
        <span>{aiPriorities.priorities.length}건</span>
      </div>
      <AiUsageMeta usage={aiPriorities.usage} />
      <div className="ai-review-list">
        {aiPriorities.priorities.map((item) => (
          <article className="ai-review-card ai-strategy-card" key={`${item.rank}-${item.ruleId}`}>
            <div className="ai-review-card-header">
              <span className="priority-badge">{item.rank}순위</span>
              <SeverityBadge severity={item.severity} />
            </div>
            <h3>{item.title}</h3>
            <dl className="ai-review-detail">
              <div>
                <dt>ruleId</dt>
                <dd>{item.ruleId}</dd>
              </div>
              <div>
                <dt>reason</dt>
                <dd>{item.reason}</dd>
              </div>
              <div>
                <dt>expected impact</dt>
                <dd>{item.expectedImpact}</dd>
              </div>
              <div>
                <dt>difficulty / urgency</dt>
                <dd>{item.fixDifficulty} · {item.urgency}</dd>
              </div>
              <div>
                <dt>recommended action</dt>
                <dd>{item.recommendedAction}</dd>
              </div>
            </dl>
          </article>
        ))}
      </div>
    </div>
  );
}

function AiRoadmapSection({ aiRoadmap, isLoading, onGenerate }: { aiRoadmap: AiSecurityRoadmapResponse | null; isLoading: boolean; onGenerate: () => void }) {
  if (!aiRoadmap) {
    return (
      <div className="ai-review-empty">
        <h2>AI 보안 개선 로드맵이 아직 생성되지 않았습니다.</h2>
        <p>오늘, 이번 주, 배포 전, 장기 개선으로 나눠 실무형 개선 계획을 생성합니다.</p>
        <button className="primary-button" type="button" onClick={onGenerate} disabled={isLoading}>
          {isLoading ? 'AI 보안 개선 로드맵 생성 중...' : 'AI 보안 개선 로드맵 생성'}
        </button>
      </div>
    );
  }

  return (
    <div>
      <div className="section-heading ai-review-heading">
        <div>
          <h2>AI 보안 개선 로드맵</h2>
          <p>분석 결과를 실제 개선 일정으로 바꾼 실행 계획입니다.</p>
        </div>
      </div>
      <AiUsageMeta usage={aiRoadmap.usage} />
      <div className="roadmap-grid">
        <RoadmapGroup title="오늘 바로 조치" items={aiRoadmap.immediateActions} />
        <RoadmapGroup title="이번 주 조치" items={aiRoadmap.thisWeekActions} />
        <RoadmapGroup title="배포 전 체크" items={aiRoadmap.beforeDeploymentChecklist} />
        <RoadmapGroup title="장기 개선" items={aiRoadmap.longTermImprovements} />
      </div>
    </div>
  );
}

function RoadmapGroup({ title, items }: { title: string; items: AiSecurityRoadmapResponse['immediateActions'] }) {
  return (
    <section className="roadmap-group">
      <h3>{title}</h3>
      {items.length === 0 ? (
        <p>제안된 항목이 없습니다.</p>
      ) : items.map((item, index) => (
        <article key={`${title}-${index}`}>
          <strong>{item.title}</strong>
          <p>{item.description}</p>
          <dl>
            <div>
              <dt>reason</dt>
              <dd>{item.reason}</dd>
            </div>
            <div>
              <dt>benefit</dt>
              <dd>{item.expectedBenefit}</dd>
            </div>
          </dl>
          {item.relatedRuleIds.length > 0 && <code>{item.relatedRuleIds.join(', ')}</code>}
        </article>
      ))}
    </section>
  );
}

function ReferencedFiles({ files }: { files: string[] }) {
  if (!files.length) {
    return null;
  }

  return (
    <div className="referenced-files">
      <span>AI가 참고한 파일 영역</span>
      <div>
        {files.map((file) => (
          <code key={file}>{file}</code>
        ))}
      </div>
    </div>
  );
}

function AiUsageMeta({ usage }: { usage?: AiUsageResponse }) {
  if (!usage) {
    return null;
  }

  return (
    <div className="ai-usage-meta">
      <span>provider {usage.provider}</span>
      <span>tokens {usage.totalTokens.toLocaleString()}</span>
      <span>cost ${Number(usage.estimatedCostUsd).toFixed(4)}</span>
      <span>{usage.billable ? 'billable' : 'no charge'}</span>
    </div>
  );
}

function AiListCard({ title, items }: { title: string; items: string[] }) {
  return (
    <article className="ai-list-card">
      <h3>{title}</h3>
      <ul>
        {items.map((item, index) => (
          <li key={`${title}-${index}`}>{item}</li>
        ))}
      </ul>
    </article>
  );
}

interface MetricProps {
  label: string;
  value: string | number;
  tone?: string;
}

function Metric({ label, value, tone = 'neutral' }: MetricProps) {
  return (
    <div className={`metric metric-${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity severity-${severity.toLowerCase()}`}>{severity}</span>;
}

function downloadBlob(blob: Blob, fileName: string) {
  const downloadUrl = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = downloadUrl;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(downloadUrl);
}

function formatDateTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat('ko-KR', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}

export default App;
