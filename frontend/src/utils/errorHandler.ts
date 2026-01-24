import { AxiosError } from 'axios';

export interface ErrorDetails {
  message: string;
  isRateLimited: boolean;
  retryAfter?: number; // seconds
}

/**
 * 解析 API 錯誤並返回使用者友善的錯誤訊息
 */
export function parseError(error: unknown, context: 'login' | 'register' | 'general' = 'general'): ErrorDetails {
  // 預設錯誤訊息
  const defaultMessages = {
    login: '登入失敗，請檢查您的帳號密碼',
    register: '註冊失敗，請稍後再試',
    general: '操作失敗，請稍後再試',
  };

  // 網路錯誤
  if (error instanceof Error && error.message === 'Network Error') {
    return {
      message: '網路連線失敗，請檢查您的網路連線',
      isRateLimited: false,
    };
  }

  // Axios 錯誤
  if (error && typeof error === 'object' && 'isAxiosError' in error) {
    const axiosError = error as AxiosError<{ detail: string }>;
    const status = axiosError.response?.status;
    const detail = axiosError.response?.data?.detail;

    // Rate Limiting (429)
    if (status === 429) {
      const retryAfter = parseInt(axiosError.response?.headers['retry-after'] || '60', 10);
      return {
        message: `操作過於頻繁，請在 ${retryAfter} 秒後重試`,
        isRateLimited: true,
        retryAfter,
      };
    }

    // 認證失敗 (401)
    if (status === 401) {
      if (context === 'login') {
        return {
          message: detail || '帳號或密碼錯誤，請重新輸入',
          isRateLimited: false,
        };
      }
      return {
        message: detail || '認證失敗，請重新登入',
        isRateLimited: false,
      };
    }

    // Email 已存在 (400 - 註冊時)
    if (status === 400 && context === 'register' && detail?.includes('already registered')) {
      return {
        message: '此 Email 已被註冊，請使用其他 Email 或直接登入',
        isRateLimited: false,
      };
    }

    // 驗證錯誤 (422)
    if (status === 422) {
      return {
        message: '輸入格式錯誤，請檢查 Email 和密碼格式',
        isRateLimited: false,
      };
    }

    // 伺服器錯誤 (500+)
    if (status && status >= 500) {
      return {
        message: '伺服器錯誤，請稍後再試',
        isRateLimited: false,
      };
    }

    // 有 detail 訊息就使用
    if (detail) {
      return {
        message: detail,
        isRateLimited: false,
      };
    }
  }

  // 預設訊息
  return {
    message: defaultMessages[context],
    isRateLimited: false,
  };
}
