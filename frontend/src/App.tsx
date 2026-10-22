import { useEffect, useState, type FormEvent } from 'react';
import { login, signup } from './api/securityReviewApi';
import type { AuthResponse } from './types/securityReview';
import { Workspace } from './components/Workspace';
import { GitHubCallback, hasGitHubCallback } from './components/GitHubCallback';

const ACCESS_TOKEN_STORAGE_KEY = 'securedeploy.accessToken';
const AUTH_USER_STORAGE_KEY = 'securedeploy.authUser';
type AuthMode = 'LOGIN' | 'SIGNUP';

function loadSession(): AuthResponse | null {
  try {
    const accessToken = localStorage.getItem(ACCESS_TOKEN_STORAGE_KEY);
    const user = JSON.parse(localStorage.getItem(AUTH_USER_STORAGE_KEY) ?? 'null');
    return accessToken && user && typeof user.id === 'number' && typeof user.name === 'string' && typeof user.email === 'string'
      ? { accessToken, tokenType: 'Bearer', user } : null;
  } catch { return null; }
}

export default function App() {
  const [session, setSession] = useState(loadSession);
  const [githubCallback, setGithubCallback] = useState(hasGitHubCallback);
  const [mode, setMode] = useState<AuthMode>('LOGIN');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    const changed = (event: StorageEvent) => {
      if (event.key === ACCESS_TOKEN_STORAGE_KEY || event.key === AUTH_USER_STORAGE_KEY || event.key === null) setSession(loadSession());
    };
    window.addEventListener('storage', changed);
    return () => window.removeEventListener('storage', changed);
  }, []);
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const next = mode === 'SIGNUP' ? await signup(email.trim(), password, name.trim()) : await login(email.trim(), password);
      localStorage.setItem(AUTH_USER_STORAGE_KEY, JSON.stringify(next.user));
      localStorage.setItem(ACCESS_TOKEN_STORAGE_KEY, next.accessToken);
      window.location.hash = '#/dashboard';
      setPassword(''); setName(''); setSession(next);
    } catch (e) { setError(e instanceof Error ? e.message : '인증에 실패했습니다.'); }
    finally { setBusy(false); }
  };
  const logout = () => {
    localStorage.removeItem(ACCESS_TOKEN_STORAGE_KEY); localStorage.removeItem(AUTH_USER_STORAGE_KEY);
    setSession(null); setPassword(''); setName(''); setEmail(''); setError('');
    window.location.hash = '#/dashboard';
  };
  if (githubCallback) return <GitHubCallback loggedIn={session != null} onDone={() => setGithubCallback(false)} />;
  if (session) return <Workspace key={session.accessToken} session={session} onLogout={logout} />;
  return <AuthScreen mode={mode} email={email} password={password} name={name} errorMessage={error} isLoading={busy}
    onModeChange={value => { setMode(value); setError(''); }} onEmailChange={setEmail} onPasswordChange={setPassword}
    onNameChange={setName} onSubmit={event => void submit(event)} />;
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
          <p className="auth-brand">SecureDeploy</p>
          <h1>{isSignup ? '계정 생성' : '로그인'}</h1>
        </div>

        <form className="auth-form" onSubmit={onSubmit} aria-busy={isLoading}>
          <div className="mode-switch auth-mode-switch" aria-label="인증 방식 선택">
            <button className={mode === 'LOGIN' ? 'mode-button mode-button-active' : 'mode-button'} aria-pressed={mode==='LOGIN'} type="button" disabled={isLoading} onClick={() => onModeChange('LOGIN')}>
              로그인
            </button>
            <button className={mode === 'SIGNUP' ? 'mode-button mode-button-active' : 'mode-button'} aria-pressed={mode==='SIGNUP'} type="button" disabled={isLoading} onClick={() => onModeChange('SIGNUP')}>
              회원가입
            </button>
          </div>

          {isSignup && (
            <label>
              <span>이름</span>
              <input type="text" autoComplete="name" value={name} placeholder="이름" onChange={(event) => onNameChange(event.target.value)} disabled={isLoading} required />
            </label>
          )}

          <label>
            <span>이메일</span>
            <input type="email" autoComplete="email" value={email} placeholder="user@test.com" onChange={(event) => onEmailChange(event.target.value)} disabled={isLoading} required />
          </label>

          <label>
            <span>비밀번호</span>
            <input type="password" autoComplete={isSignup?'new-password':'current-password'} value={password} placeholder="비밀번호" onChange={(event) => onPasswordChange(event.target.value)} disabled={isLoading} minLength={8} required />
          </label>

          {errorMessage && <div role="alert" className="feedback-message feedback-error">{errorMessage}</div>}

          <button className="primary-button auth-submit" type="submit" disabled={isLoading}>
            {isLoading ? '처리 중...' : isSignup ? '회원가입' : '로그인'}
          </button>
        </form>
      </section>
    </main>
  );
}
