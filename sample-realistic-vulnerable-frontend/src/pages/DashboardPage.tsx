import StatCard from '../components/StatCard';
import { dashboardStats, notices } from '../data/mockData';

export default function DashboardPage() {
  return (
    <section className="page-section">
      <div className="page-title">
        <h1>운영 대시보드</h1>
        <p>오늘의 프로젝트 운영 상태와 최근 공지를 확인합니다.</p>
      </div>
      <div className="stats-grid">
        <StatCard label="활성 프로젝트" value={dashboardStats.activeProjects} tone="blue" />
        <StatCard label="열린 티켓" value={dashboardStats.openTickets} tone="orange" />
        <StatCard label="배포 가능" value={dashboardStats.deploymentReady} tone="green" />
        <StatCard label="주간 방문자" value={dashboardStats.weeklyVisitors.toLocaleString()} tone="red" />
      </div>
      <article className="content-panel">
        <h2>최근 공지</h2>
        <ul className="notice-list compact">
          {notices.map((notice) => (
            <li key={notice.id}>
              <strong>{notice.title}</strong>
              <span>{notice.category} / {notice.publishedAt}</span>
            </li>
          ))}
        </ul>
      </article>
    </section>
  );
}
