import { ChangeEvent, FormEvent, useEffect, useState } from 'react';
import { ReviewResultWorkspace } from './components/ReviewResultWorkspace';
import { RescanForm } from './components/RescanForm';
import { ZipUploadGuidance } from './components/ZipUploadGuidance';
import { validateZipUpload } from './components/zipUploadValidation';
import type { UploadPolicy } from './types/uploadPolicy';
import { ReviewProgressPanel } from './components/ReviewProgressPanel';
import { deploymentLabels } from './components/reviewPresentation';
import type { ResultView } from './components/reviewPresentation';
import {
  deleteProject,
  deleteReview,
  downloadAiReviewReport,
  downloadReviewReport,
  fetchLatestReviewComparison,
  fetchProjectDashboard,
  fetchReviewDetail,
  fetchReviewHistory,
  fetchUploadPolicy,
  fetchVulnerabilityStatusSummary,
  login as loginRequest,
  reviewGithubRepository,
  signup as signupRequest,
  updateVulnerabilityStatus,
  uploadZipForReview,
} from './api/securityReviewApi';
import type {
  AuthResponse,
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

const severityFilters: SeverityFilter[] = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const vulnerabilityStatuses: VulnerabilityStatus[] = ['UNCHECKED', 'ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED', 'IGNORED'];

const vulnerabilityStatusLabels: Record<VulnerabilityStatus, string> = {
  UNCHECKED: '미확인',
  ACKNOWLEDGED: '확인 완료',
  IN_PROGRESS: '수정 중',
  RESOLVED: '수정 완료',
  IGNORED: '무시',
};

const falsePositiveRiskLabels: Record<'LOW' | 'MEDIUM' | 'HIGH', string> = {
  LOW: '낮음',
  MEDIUM: '보통',
  HIGH: '높음',
};

const confidenceLabels: Record<'LOW' | 'MEDIUM' | 'HIGH', string> = {
  LOW: '낮음',
  MEDIUM: '보통',
  HIGH: '높음',
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
  const [scanMode, setScanMode] = useState<'STANDARD' | 'AI_ENHANCED'>('STANDARD');
  const [activeResultTab, setActiveResultTab] = useState<ResultView>('SUMMARY');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadPolicy, setUploadPolicy] = useState<UploadPolicy | null>(null);
  const [uploadPolicyError, setUploadPolicyError] = useState('');
  const [policyReload, setPolicyReload] = useState(0);
  const [repositoryUrl, setRepositoryUrl] = useState('');
  const [result, setResult] = useState<SecurityReviewResponse | null>(null);
  const [rescanOpen, setRescanOpen] = useState(false);
  const [reviewHistory, setReviewHistory] = useState<ReviewHistoryResponse[]>([]);
  const [reviewComparison, setReviewComparison] = useState<ReviewComparisonResponse | null>(null);
  const [projectDashboard, setProjectDashboard] = useState<ProjectSecurityDashboardResponse | null>(null);
  const [statusSummary, setStatusSummary] = useState<VulnerabilityStatusSummaryResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isHistoryLoading, setIsHistoryLoading] = useState(false);
  const [isComparisonLoading, setIsComparisonLoading] = useState(false);
  const [isDashboardLoading, setIsDashboardLoading] = useState(false);
  const [deletingReviewId, setDeletingReviewId] = useState<number | null>(null);
  const [deletingProjectId, setDeletingProjectId] = useState<number | null>(null);
  const [isReportDownloading, setIsReportDownloading] = useState(false);
  const [isAiReportDownloading, setIsAiReportDownloading] = useState(false);
  const [statusUpdatingId, setStatusUpdatingId] = useState<number | null>(null);
  const [selectedReviewId, setSelectedReviewId] = useState<number | null>(null);
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [historyErrorMessage, setHistoryErrorMessage] = useState('');
  const [comparisonErrorMessage, setComparisonErrorMessage] = useState('');
  const [dashboardErrorMessage, setDashboardErrorMessage] = useState('');
  const [statusSummaryErrorMessage, setStatusSummaryErrorMessage] = useState('');
  const [statusComments, setStatusComments] = useState<Record<number, string>>({});

  useEffect(() => {
    if (authSession) {
      void loadReviewHistory();
    }
  }, [authSession?.accessToken]);

  useEffect(() => {
    let active = true;
    setUploadPolicy(null);
    setUploadPolicyError('');
    if (authSession) {
      void fetchUploadPolicy().then(policy => { if (active) setUploadPolicy(policy); })
        .catch(error => { if (active) setUploadPolicyError(error instanceof Error ? error.message : '업로드 제한을 불러오지 못했습니다.'); });
    }
    return () => { active = false; };
  }, [authSession?.accessToken, policyReload]);

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

  const resetCurrentResult = () => {
    setRescanOpen(false);
    setResult(null);
    setSelectedReviewId(null);
    setActiveResultTab('SUMMARY');
    setReviewComparison(null);
    setProjectDashboard(null);
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
    setErrorMessage(file ? validateZipUpload(file, uploadPolicy) : '');
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
        ? await uploadZipForReview(selectedFile as File, scanMode)
        : await reviewGithubRepository(repositoryUrl.trim(), scanMode);
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

  const handleHistoryClick = async (reviewId: number, view: ResultView = 'SUMMARY') => {
    setIsLoading(true);
    setErrorMessage('');
    setSuccessMessage('');
    setActiveResultTab(view);
    setRescanOpen(false);

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

    try {
      const comparison = await fetchLatestReviewComparison(projectId);
      setReviewComparison(comparison);
    } catch (error) {
      setComparisonErrorMessage(error instanceof Error ? error.message : '최근 분석 비교 결과를 불러오지 못했습니다.');
    } finally {
      setIsComparisonLoading(false);
    }
  };

  const handleRescan = async (file: File | null, mode: 'STANDARD' | 'AI_ENHANCED') => {
    if (!result?.projectId || !result.sourceType) return;
    if (result.sourceType === 'ZIP') {
      const error = validateZipUpload(file, uploadPolicy);
      if (error) { setErrorMessage(error); return; }
    }
    setIsLoading(true);
    setErrorMessage('');
    setSuccessMessage('');
    try {
      const updated = result.sourceType === 'ZIP'
        ? await uploadZipForReview(file as File, mode, result.projectId)
        : await reviewGithubRepository(result.repositoryUrl ?? '', mode, result.projectId);
      resetCurrentResult();
      setResult(updated);
      setSelectedReviewId(updated.reviewId ?? null);
      setActiveResultTab('PROGRESS');
      setSuccessMessage('재검사가 완료되었습니다. 저장된 이전 분석과의 변화를 확인하세요.');
      await loadReviewHistory();
      await loadStatusSummary(updated.projectId);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : '재검사에 실패했습니다. 이전 결과는 유지됩니다.');
    } finally { setIsLoading(false); }
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
      }
      await loadReviewHistory();
      setSuccessMessage(response.message);
    } catch (error) {
      setDashboardErrorMessage(error instanceof Error ? error.message : '프로젝트를 삭제하지 못했습니다.');
    } finally {
      setDeletingProjectId(null);
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

    if (!window.confirm('이 PDF는 기존 AI 리뷰를 새로 생성합니다. OpenAI 설정에 따라 외부 API 호출과 비용이 발생할 수 있으며, 저장된 해결 가이드를 그대로 내보내는 기능은 아닙니다. 계속할까요?')) return;

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
    setScanMode('STANDARD');
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
      return validateZipUpload(selectedFile, uploadPolicy);
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
            <p className="eyebrow">프로젝트 보안 관리</p>
            <h1>SecureDeploy</h1>
          </div>
          <div className="session-box">
            <span className="status-pill">{authSession.user.name}</span>
            <button className="secondary-button logout-button" type="button" onClick={handleLogout}>로그아웃</button>
          </div>
        </div>

        <details className="analysis-entry" open={!result || undefined}>
          <summary>새 프로젝트 분석</summary>
        <form className="upload-panel review-panel" onSubmit={handleSubmit}>
          <div className="upload-copy">
            <h2>{analysisMode === 'ZIP' ? '프로젝트 ZIP 업로드' : 'GitHub Repository 분석'}</h2>
            <p>
              {analysisMode === 'ZIP'
                ? '프로젝트 압축 파일로 배포 전 보안 위험을 점검합니다.'
                : '공개 GitHub 저장소의 코드와 배포 설정을 점검합니다.'}
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
            <label className="semantic-opt-in">
              <input type="checkbox" checked={scanMode === 'AI_ENHANCED'} disabled={isLoading}
                onChange={event => setScanMode(event.target.checked ? 'AI_ENHANCED' : 'STANDARD')} />
              AI 강화 분석 · 기존 검사에 더해 제한된 코드 영역을 추가 검토합니다. 선택하면 마스킹된 코드 일부가 외부 AI로 전송될 수 있으며 사용량이 발생할 수 있습니다.
            </label>
          </div>

          {analysisMode === 'ZIP' && <ZipUploadGuidance policy={uploadPolicy} error={uploadPolicyError} onRetry={() => setPolicyReload(value => value + 1)} />}
          <button className="primary-button" type="submit" disabled={isLoading || (analysisMode === 'ZIP' && !uploadPolicy)}>
            {isLoading ? '분석 중...' : '분석 시작'}
          </button>
        </form>
        </details>
        {errorMessage && <div role="alert" className="feedback-message feedback-error">{errorMessage}</div>}
        {successMessage && <div role="status" className="feedback-message feedback-success">{successMessage}</div>}

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

        {result && !isLoading && (
          <ReviewResultWorkspace key={result.reviewId ?? 'current'} result={result} view={activeResultTab}
            onViewChange={setActiveResultTab}
            rescanActions={result.projectId && result.sourceType ? <>
              <div className="result-actions"><button className="secondary-button" type="button" onClick={() => setRescanOpen(!rescanOpen)} aria-expanded={rescanOpen}>다시 검사</button></div>
              {rescanOpen && <RescanForm result={result} uploadPolicy={uploadPolicy} policyError={uploadPolicyError}
                onRetryPolicy={() => setPolicyReload(value => value + 1)} onCancel={() => setRescanOpen(false)} onScan={(file, mode) => void handleRescan(file, mode)} />}
            </> : undefined}
            statusActions={{
              updatingId: statusUpdatingId, comments: statusComments, onComment: handleStatusCommentChange,
              onStatus: (vulnerability, status) => void handleVulnerabilityStatusChange(vulnerability, status),
            }}
            progress={<>
              {statusSummary && <VulnerabilityProgressPanel summary={statusSummary} />}
              {statusSummaryErrorMessage && <p role="alert" className="error-message">{statusSummaryErrorMessage}</p>}
            </>}
            reportActions={result.reviewId ? <>
              <button className="secondary-button" type="button" onClick={() => void handleReportDownload()} disabled={isReportDownloading}>
                {isReportDownloading ? 'PDF 생성 중...' : '기본 리포트 다운로드'}
              </button>
              <button className="secondary-button" type="button" onClick={() => void handleAiReportDownload()} disabled={isAiReportDownloading}>
                {isAiReportDownloading ? 'AI PDF 생성 중...' : 'AI 리뷰 PDF 생성·다운로드'}
              </button>
            </> : <p>분석을 저장한 후 다운로드할 수 있습니다.</p>}
          />
        )}

        <details className="history-panel" open={!result || undefined}>
          <summary>분석 이력 ({reviewHistory.length})</summary>
          <div className="section-heading history-heading">
            <div>
              <h2>분석 이력</h2>
              <p>저장된 분석 결과를 확인하거나, 새 프로젝트 분석에서 수정한 코드를 다시 검사하세요.</p>
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
                      <span>코드 탐지 {history.vulnerabilityCount}건</span>
                      <span>참고 점수 {history.securityScore}점</span>
                      <span>{history.riskSummary ? deploymentLabels[history.riskSummary.deploymentAssessment] : '위험 평가 미저장'}</span>
                      {history.riskSummary && <span>반드시 처리 {history.riskSummary.prioritySummary.BLOCKING}건</span>}
                      <time dateTime={history.createdAt}>{formatDateTime(history.createdAt)}</time>
                    </div>
                  </button>
                  <div className="history-actions">
                    {history.comparisonAvailable && <button className="compare-button" type="button" onClick={() => void handleHistoryClick(history.reviewId, 'PROGRESS')} disabled={isLoading}>변화 보기</button>}
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

          {reviewComparison && <ReviewComparisonPanel comparison={reviewComparison} />}
        </details>
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
          {comparison?.latestReviewId && <p className="dashboard-note">{comparison.message}</p>}
          {comparison?.latestReviewId ? (
            <div className="comparison-summary-grid">
              <Metric label="참고 점수 변화" value={signedNumber(comparison.scoreDiff)} tone={comparison.scoreDiff >= 0 ? 'safe' : 'danger'} />
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

function ReviewComparisonPanel({ comparison }: { comparison: ReviewComparisonResponse }) {
  const isComparable = comparison.latestReviewId && comparison.previousReviewId;

  if (!isComparable) {
    return <div className="comparison-panel empty-state">{comparison.message}</div>;
  }

  if (comparison.progress) return <section className="comparison-panel">
    <ReviewProgressPanel result={{ comparison: comparison.progress }} />
  </section>;

  return <section className="comparison-panel"><h2>비교 근거 미저장</h2><p>{comparison.message}</p>
    <p>룰 기반 참고 점수 변화: {signedNumber(comparison.scoreDiff)}. 해결 여부는 판단하지 않습니다.</p></section>;
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
              {(item.falsePositiveRisk || item.confidence || item.analysisNote) && (
                <p className="comparison-fp-note">
                  {item.falsePositiveRisk && `오탐 가능성 ${falsePositiveRiskLabels[item.falsePositiveRisk]}`}
                  {item.falsePositiveRisk && item.confidence && ' · '}
                  {item.confidence && `신뢰도 ${confidenceLabels[item.confidence]}`}
                  {item.analysisNote && ` · 판단 근거: ${item.analysisNote}`}
                </p>
              )}
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
