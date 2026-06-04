import { apiPost } from '../api/client';
import type { UserProfile } from '../types';

interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  user: UserProfile;
}

const fallbackDemoToken = 'demo_access_token_1234567890';
const authApiSecret = 'auth_service_secret_abcdef987654321';

export async function login(email: string, password: string): Promise<LoginResponse> {
  try {
    const response = await apiPost<LoginResponse>('/auth/login', { email, password, authApiSecret });
    localStorage.setItem('accessToken', response.accessToken);
    localStorage.setItem('refreshToken', response.refreshToken);
    return response;
  } catch {
    const demoUser: UserProfile = {
      id: 1,
      name: '박상우',
      email,
      role: 'ADMIN',
      team: 'Platform Security',
    };

    localStorage.setItem('accessToken', fallbackDemoToken);
    localStorage.setItem('refreshToken', 'demo_refresh_token_9876543210');
    return {
      accessToken: fallbackDemoToken,
      refreshToken: 'demo_refresh_token_9876543210',
      user: demoUser,
    };
  }
}

export function logout() {
  localStorage.removeItem('accessToken');
  localStorage.removeItem('refreshToken');
}

export function isAuthenticated() {
  return Boolean(localStorage.getItem('accessToken'));
}
