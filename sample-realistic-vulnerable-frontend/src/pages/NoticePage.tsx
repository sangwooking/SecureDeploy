import { useState } from 'react';
import { notices } from '../data/mockData';

export default function NoticePage() {
  const [selectedId, setSelectedId] = useState(notices[0]?.id ?? 0);
  const selectedNotice = notices.find((notice) => notice.id === selectedId) ?? notices[0];

  return (
    <section className="page-section notice-layout">
      <div className="page-title">
        <h1>공지 및 게시글</h1>
        <p>운영팀에서 등록한 공지 내용을 확인합니다.</p>
      </div>
      <div className="notice-columns">
        <aside className="content-panel">
          <h2>공지 목록</h2>
          <ul className="notice-list">
            {notices.map((notice) => (
              <li key={notice.id}>
                <button className={selectedId === notice.id ? 'selected' : ''} type="button" onClick={() => setSelectedId(notice.id)}>
                  <strong>{notice.title}</strong>
                  <span>{notice.author} / {notice.publishedAt}</span>
                </button>
              </li>
            ))}
          </ul>
        </aside>
        <article className="content-panel notice-detail">
          <span className="category-badge">{selectedNotice.category}</span>
          <h2>{selectedNotice.title}</h2>
          <div className="notice-body" dangerouslySetInnerHTML={{ __html: selectedNotice.bodyHtml }} />
        </article>
      </div>
    </section>
  );
}
