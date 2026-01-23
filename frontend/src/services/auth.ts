import api from './api';
import type { RegisterRequest, AuthResponse, User } from '../types/auth';

const TOKEN_KEY = 'token';

export const login = async (email: string, password: string): Promise<string> => {
  const formData = new URLSearchParams();
  formData.append('username', email);
  formData.append('password', password);

  const response = await api.post<AuthResponse>('/auth/login', formData, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  });

  const token = response.data.access_token;
  localStorage.setItem(TOKEN_KEY, token);
  return token;
};

export const register = async (email: string, password: string): Promise<void> => {
  const data: RegisterRequest = { email, password };
  await api.post('/auth/register', data);
};

export const logout = (): void => {
  localStorage.removeItem(TOKEN_KEY);
};

export const getToken = (): string | null => {
  return localStorage.getItem(TOKEN_KEY);
};

export const isAuthenticated = (): boolean => {
  return getToken() !== null;
};

export const getCurrentUser = async (): Promise<User> => {
  const response = await api.get<User>('/auth/me');
  return response.data;
};
