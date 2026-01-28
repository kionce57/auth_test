import React, { createContext, useContext, useState, useEffect } from 'react';
import * as authService from '../services/auth';
import type { User, AuthContextType } from '../types/auth';

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const initAuth = async () => {
      try {
        // 嘗試從 Cookie 取得當前使用者
        const currentUser = await authService.getCurrentUser();
        setUser(currentUser);
      } catch (error) {
        // 如果失敗（401），代表未登入或 token 過期
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    initAuth();
  }, []);

  // OAuth 錯誤處理
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const error = params.get('error');

    const errorMessages: Record<string, string> = {
      'oauth_failed': 'Google 登入失敗，請稍後再試',
      'invalid_state': '登入請求已過期，請重新嘗試',
      'email_not_verified': '請先在 Google 驗證您的 email',
      'access_denied': '您已取消 Google 登入',
      'account_disabled': '您的帳號已被停用'
    };

    if (error && errorMessages[error]) {
      // 顯示錯誤訊息
      alert(errorMessages[error]);

      // 清除 URL 參數
      window.history.replaceState({}, '', window.location.pathname);
    }
  }, []);

  const login = async (email: string, password: string): Promise<void> => {
    try {
      await authService.login(email, password);
      const currentUser = await authService.getCurrentUser();
      setUser(currentUser);
    } catch (error) {
      throw error;
    }
  };

  const register = async (email: string, password: string): Promise<void> => {
    try {
      await authService.register(email, password);
    } catch (error) {
      throw error;
    }
  };

  const logout = async (): Promise<void> => {
    try {
      await authService.logout();
    } catch (error) {
      // 即使後端登出失敗，仍然清除前端狀態
      console.error('Logout error:', error);
    } finally {
      setUser(null);
    }
  };

  const value: AuthContextType = {
    user,
    loading,
    login,
    register,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
