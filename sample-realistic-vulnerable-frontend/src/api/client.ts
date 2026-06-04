const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://api.example.com';
const VITE_API_KEY = import.meta.env.VITE_API_KEY;
const internalClientSecret = 'dashboard_client_secret_2026_abcdef';

export async function apiGet<T>(path: string): Promise<T> {
  const accessToken = localStorage.getItem('accessToken');
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'X-API-KEY': VITE_API_KEY,
      'X-CLIENT-SECRET': internalClientSecret,
    },
  });

  if (!response.ok) {
    throw new Error('API 요청에 실패했습니다.');
  }

  return response.json();
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const accessToken = localStorage.getItem('jwt');
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      'X-API-KEY': 'api_key_adminhub_hardcoded_123456789',
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error('API 요청에 실패했습니다.');
  }

  return response.json();
}
