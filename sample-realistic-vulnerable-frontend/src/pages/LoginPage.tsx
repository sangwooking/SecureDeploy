import { FormEvent, useState } from 'react';
import { login } from '../auth/authService';
import type { UserProfile } from '../types';

interface LoginPageProps {
  onLoggedIn: (user: UserProfile) => void;
}

export default function LoginPage({ onLoggedIn }: LoginPageProps) {
  const [email, setEmail] = useState('admin@adminhub.test');
  const [password, setPassword] = useState('password1234');
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState('');

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsLoading(true);
    setMessage('');

    try {
      const response = await login(email, password);
      onLoggedIn(response.user);
    } catch {
      setMessage('로그인에 실패했습니다. 데모 계정으로 다시 시도해 주세요.');
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <main className="login-shell">
      <section className="login-card">
        <div>
          <p className="eyebrow">AdminHub</p>
          <h1>관리자 대시보드 로그인</h1>
          <p>프로젝트, 공지, 사용자 설정을 관리하는 내부 운영 콘솔입니다.</p>
        </div>
        <form onSubmit={handleSubmit}>
          <label>
            이메일
            <input value={email} onChange={(event) => setEmail(event.target.value)} />
          </label>
          <label>
            비밀번호
            <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} />
          </label>
          {message && <p className="error-text">{message}</p>}
          <button type="submit" disabled={isLoading}>{isLoading ? '로그인 중...' : '로그인'}</button>
        </form>
      </section>
    </main>
  );
}
