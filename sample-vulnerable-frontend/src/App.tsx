import DangerousPreview from './components/DangerousPreview';
import { login } from './services/api';

export default function App() {
  const htmlFromQuery = new URLSearchParams(window.location.search).get('html') ?? '<b>hello</b>';
  const next = new URLSearchParams(window.location.search).get('next');

  async function handleLogin() {
    const response = await login('demo@test.com', 'password1234');
    localStorage.setItem('accessToken', response.accessToken);
    localStorage.setItem('refreshToken', response.refreshToken);
  }

  function moveNext() {
    if (next) {
      window.location.href = next;
    }
  }

  return (
    <main>
      <h1>Vulnerable Frontend Sample</h1>
      <button onClick={handleLogin}>login</button>
      <button onClick={moveNext}>go next</button>
      <DangerousPreview html={htmlFromQuery} />
    </main>
  );
}
