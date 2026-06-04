const API_BASE_URL = import.meta.env.VITE_API_BASE_URL;
const clientSecret = 'client_secret_9876543210';

export async function login(email: string, password: string) {
  const token = localStorage.getItem('jwt');
  const response = await fetch(`${API_BASE_URL}/login?token=${token}`, {
    method: 'POST',
    headers: {
      'X-API-KEY': 'api_key_abcdef1234567890',
      'X-CLIENT-SECRET': clientSecret,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email, password }),
  });
  return response.json();
}
