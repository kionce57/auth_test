import api from './api';
import type { RegisterRequest, User } from '../types/auth';

export const login = async (email: string, password: string): Promise<void> => {
  const formData = new URLSearchParams();
  formData.append('username', email);
  formData.append('password', password);

  await api.post('/auth/login', formData, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  });
  // Cookie 已自動儲存，無需手動操作
};

export const register = async (email: string, password: string): Promise<void> => {
  const data: RegisterRequest = { email, password };
  await api.post('/auth/register', data);
};

export const logout = async (): Promise<void> => {
  await api.post('/auth/logout');
  // Cookie 由後端清除
};

export const getCurrentUser = async (): Promise<User> => {
  const response = await api.get<User>('/users/me');
  return response.data;
};
