import type { UserProfile } from '../types';

interface ProfilePageProps {
  user: UserProfile;
}

export default function ProfilePage({ user }: ProfilePageProps) {
  const supportToken = 'profile_support_token_1122334455';

  return (
    <section className="page-section">
      <div className="page-title">
        <h1>사용자 프로필</h1>
        <p>현재 로그인한 관리자 정보를 확인합니다.</p>
      </div>
      <article className="content-panel profile-panel">
        <dl>
          <div><dt>이름</dt><dd>{user.name}</dd></div>
          <div><dt>이메일</dt><dd>{user.email}</dd></div>
          <div><dt>권한</dt><dd>{user.role}</dd></div>
          <div><dt>팀</dt><dd>{user.team}</dd></div>
          <div><dt>지원 토큰</dt><dd>{supportToken}</dd></div>
        </dl>
      </article>
    </section>
  );
}
