import { describe, it, expect } from 'vitest';
import { parseError, ErrorDetails } from './errorHandler';
import { AxiosError } from 'axios';

describe('errorHandler', () => {
  describe('parseError', () => {
    it('should handle network errors', () => {
      const error = new Error('Network Error');
      const result = parseError(error);

      expect(result).toEqual({
        message: '網路連線失敗，請檢查您的網路連線',
        isRateLimited: false,
      });
    });

    it('should handle rate limiting (429) with retry-after', () => {
      const error: Partial<AxiosError> = {
        isAxiosError: true,
        response: {
          status: 429,
          data: { detail: 'Too Many Requests' },
          headers: { 'retry-after': '120' },
          statusText: 'Too Many Requests',
          config: {} as any,
        },
      };
      const result = parseError(error);

      expect(result.message).toBe('操作過於頻繁，請在 120 秒後重試');
      expect(result.isRateLimited).toBe(true);
      expect(result.retryAfter).toBe(120);
    });

    it('should handle 401 login errors', () => {
      const error: Partial<AxiosError> = {
        isAxiosError: true,
        response: {
          status: 401,
          data: { detail: 'Incorrect email or password' },
          statusText: 'Unauthorized',
          headers: {},
          config: {} as any,
        },
      };
      const result = parseError(error, 'login');

      expect(result).toEqual({
        message: 'Incorrect email or password',
        isRateLimited: false,
      });
    });

    it('should handle 400 duplicate email registration', () => {
      const error: Partial<AxiosError> = {
        isAxiosError: true,
        response: {
          status: 400,
          data: { detail: 'Email already registered' },
          statusText: 'Bad Request',
          headers: {},
          config: {} as any,
        },
      };
      const result = parseError(error, 'register');

      expect(result).toEqual({
        message: '此 Email 已被註冊，請使用其他 Email 或直接登入',
        isRateLimited: false,
      });
    });

    it('should handle 422 validation errors', () => {
      const error: Partial<AxiosError> = {
        isAxiosError: true,
        response: {
          status: 422,
          data: { detail: 'Validation error' },
          statusText: 'Unprocessable Entity',
          headers: {},
          config: {} as any,
        },
      };
      const result = parseError(error);

      expect(result).toEqual({
        message: '輸入格式錯誤，請檢查 Email 和密碼格式',
        isRateLimited: false,
      });
    });

    it('should handle 500 server errors', () => {
      const error: Partial<AxiosError> = {
        isAxiosError: true,
        response: {
          status: 500,
          data: { detail: 'Internal Server Error' },
          statusText: 'Internal Server Error',
          headers: {},
          config: {} as any,
        },
      };
      const result = parseError(error);

      expect(result).toEqual({
        message: '伺服器錯誤，請稍後再試',
        isRateLimited: false,
      });
    });

    it('should return default message for unknown errors', () => {
      const error = new Error('Something went wrong');
      const result = parseError(error, 'general');

      expect(result).toEqual({
        message: '操作失敗，請稍後再試',
        isRateLimited: false,
      });
    });

    it('should use custom detail message when available', () => {
      const error: Partial<AxiosError> = {
        isAxiosError: true,
        response: {
          status: 403,
          data: { detail: 'Custom error message from server' },
          statusText: 'Forbidden',
          headers: {},
          config: {} as any,
        },
      };
      const result = parseError(error);

      expect(result).toEqual({
        message: 'Custom error message from server',
        isRateLimited: false,
      });
    });
  });
});
