import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,  // 啟用 Cookie 傳遞
});

// Token 刷新狀態管理
let isRefreshing = false;
let failedQueue: Array<{
  resolve: (value?: unknown) => void;
  reject: (reason?: unknown) => void;
}> = [];

const processQueue = (error: Error | null, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });

  failedQueue = [];
};

// BroadcastChannel for cross-tab token refresh synchronization
const refreshChannel = typeof BroadcastChannel !== 'undefined'
  ? new BroadcastChannel('auth-refresh')
  : null;

if (refreshChannel) {
  refreshChannel.onmessage = (event) => {
    const { type } = event.data;

    switch (type) {
      case 'REFRESH_START':
        // 其他 tab 開始刷新，本 tab 進入等待模式
        if (!isRefreshing) {
          isRefreshing = true;
        }
        break;

      case 'REFRESH_SUCCESS':
        // 其他 tab 刷新成功，本 tab 的 pending 請求可以重試
        processQueue(null, 'success');
        isRefreshing = false;
        break;

      case 'REFRESH_FAILED':
        // 其他 tab 刷新失敗，本 tab 也需要重導向
        processQueue(new Error('Token refresh failed'), null);
        isRefreshing = false;
        window.location.href = '/login';
        break;
    }
  };
}

// Response interceptor: 自動刷新 Access Token
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // 如果是 401 且不是 refresh 端點，嘗試刷新 token
    if (
      error.response?.status === 401 &&
      !originalRequest._retry &&
      !originalRequest.url?.includes('/auth/refresh') &&
      !originalRequest.url?.includes('/auth/login')
    ) {
      if (isRefreshing) {
        // 等待 token 刷新完成
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then(() => {
            return api(originalRequest);
          })
          .catch((err) => {
            return Promise.reject(err);
          });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      // 廣播刷新開始事件
      refreshChannel?.postMessage({ type: 'REFRESH_START' });

      try {
        await api.post('/auth/refresh');
        processQueue(null, 'success');

        // 廣播刷新成功事件
        refreshChannel?.postMessage({ type: 'REFRESH_SUCCESS' });

        return api(originalRequest); // 重試原請求
      } catch (refreshError) {
        processQueue(refreshError as Error, null);

        // 廣播刷新失敗事件
        refreshChannel?.postMessage({ type: 'REFRESH_FAILED' });

        // 刷新失敗，重導向至登入頁
        window.location.href = '/login';
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export default api;
