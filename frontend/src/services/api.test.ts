import { describe, it, expect, beforeEach, vi } from 'vitest';
import MockAdapter from 'axios-mock-adapter';

// Mock BroadcastChannel globally
class MockBroadcastChannel {
  name: string;
  onmessage: ((event: MessageEvent) => void) | null = null;

  constructor(name: string) {
    this.name = name;
  }

  postMessage(message: any) {
    // Mock implementation - does nothing
  }

  close() {
    // Mock implementation
  }
}

global.BroadcastChannel = MockBroadcastChannel as any;

// Now import api after mocking BroadcastChannel
const { default: api } = await import('./api');

describe('API Service', () => {
  let mock: MockAdapter;

  beforeEach(() => {
    // Create a fresh mock adapter for each test
    mock = new MockAdapter(api);

    // Reset module-level state
    vi.clearAllMocks();
  });

  it('should create axios instance with correct config', () => {
    expect(api.defaults.baseURL).toBe('/api/v1');
    expect(api.defaults.headers['Content-Type']).toBe('application/json');
    expect(api.defaults.withCredentials).toBe(true);
  });

  it('should successfully make GET request', async () => {
    const mockData = { id: 1, name: 'Test User' };
    mock.onGet('/users/me').reply(200, mockData);

    const response = await api.get('/users/me');

    expect(response.status).toBe(200);
    expect(response.data).toEqual(mockData);
  });

  it('should trigger token refresh on 401 and retry original request', async () => {
    const mockUserData = { id: 1, email: 'test@example.com' };

    // First call to /users/me returns 401
    mock.onGet('/users/me').replyOnce(401);

    // Refresh endpoint returns 200
    mock.onPost('/auth/refresh').reply(200);

    // Retry of /users/me returns 200 with data
    mock.onGet('/users/me').replyOnce(200, mockUserData);

    const response = await api.get('/users/me');

    expect(response.status).toBe(200);
    expect(response.data).toEqual(mockUserData);

    // Verify that /auth/refresh was called
    const refreshHistory = mock.history.post.filter(req => req.url === '/auth/refresh');
    expect(refreshHistory).toHaveLength(1);
  });

  it('should NOT retry on 401 from /auth/refresh endpoint', async () => {
    // Mock window.location.href
    delete (window as any).location;
    window.location = { href: '' } as any;

    // Simulate a scenario where a regular request triggers refresh, but refresh fails
    // First call to /users/me returns 401 (triggers refresh)
    mock.onGet('/users/me').replyOnce(401);

    // /auth/refresh returns 401 (refresh fails)
    mock.onPost('/auth/refresh').reply(401);

    await expect(api.get('/users/me')).rejects.toThrow();

    // Should redirect to /login
    expect(window.location.href).toBe('/login');

    // Should call /auth/refresh once (no retry on refresh endpoint)
    const refreshHistory = mock.history.post.filter(req => req.url === '/auth/refresh');
    expect(refreshHistory).toHaveLength(1);
  });

  it('should NOT retry on 401 from /auth/login endpoint', async () => {
    // /auth/login returns 401 (wrong credentials)
    mock.onPost('/auth/login').reply(401, { detail: 'Invalid credentials' });

    await expect(
      api.post('/auth/login', { username: 'test@example.com', password: 'wrong' })
    ).rejects.toThrow();

    // Should only call /auth/login once (no retry)
    expect(mock.history.post).toHaveLength(1);

    // Should NOT call /auth/refresh
    const refreshHistory = mock.history.post.filter(req => req.url === '/auth/refresh');
    expect(refreshHistory).toHaveLength(0);
  });

  it('should queue multiple requests while refreshing token', async () => {
    const mockUserData = { id: 1, email: 'test@example.com' };
    const mockPostData = { id: 2, title: 'Test Post' };

    // Both initial requests return 401
    mock.onGet('/users/me').replyOnce(401);
    mock.onGet('/posts').replyOnce(401);

    // Refresh endpoint returns 200
    mock.onPost('/auth/refresh').reply(200);

    // Retry requests return success
    mock.onGet('/users/me').replyOnce(200, mockUserData);
    mock.onGet('/posts').replyOnce(200, mockPostData);

    // Fire both requests simultaneously
    const [response1, response2] = await Promise.all([
      api.get('/users/me'),
      api.get('/posts'),
    ]);

    expect(response1.status).toBe(200);
    expect(response1.data).toEqual(mockUserData);
    expect(response2.status).toBe(200);
    expect(response2.data).toEqual(mockPostData);

    // Should only call /auth/refresh once (not twice)
    const refreshHistory = mock.history.post.filter(req => req.url === '/auth/refresh');
    expect(refreshHistory).toHaveLength(1);
  });
});
