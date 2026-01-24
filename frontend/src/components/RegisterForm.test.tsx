import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserRouter } from 'react-router-dom';
import { RegisterForm } from './RegisterForm';
import { AuthProvider } from '../context/AuthContext';
import * as authService from '../services/auth';

// Mock auth service
vi.mock('../services/auth', () => ({
  register: vi.fn(),
  login: vi.fn(),
  getCurrentUser: vi.fn(),
}));

// Mock useNavigate
const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

describe('RegisterForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const renderRegisterForm = () => {
    return render(
      <BrowserRouter>
        <AuthProvider>
          <RegisterForm />
        </AuthProvider>
      </BrowserRouter>
    );
  };

  it('should render registration form', () => {
    renderRegisterForm();

    expect(screen.getByLabelText(/電子郵件/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/密碼/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /註冊/i })).toBeInTheDocument();
  });

  it('should handle successful registration', async () => {
    const user = userEvent.setup();
    vi.mocked(authService.register).mockResolvedValue(undefined);
    vi.mocked(authService.login).mockResolvedValue(undefined);
    vi.mocked(authService.getCurrentUser).mockResolvedValue({
      id: 1,
      email: 'newuser@example.com',
    });

    renderRegisterForm();

    const emailInput = screen.getByLabelText(/電子郵件/i);
    const passwordInput = screen.getByLabelText(/密碼/i);
    const submitButton = screen.getByRole('button', { name: /註冊/i });

    await user.type(emailInput, 'newuser@example.com');
    await user.type(passwordInput, 'password123');
    await user.click(submitButton);

    await waitFor(() => {
      expect(authService.register).toHaveBeenCalledWith('newuser@example.com', 'password123');
      expect(authService.login).toHaveBeenCalledWith('newuser@example.com', 'password123');
      expect(mockNavigate).toHaveBeenCalledWith('/dashboard');
    });
  });

  it('should display error when email already exists', async () => {
    const user = userEvent.setup();
    vi.mocked(authService.register).mockRejectedValue({
      isAxiosError: true,
      response: {
        status: 400,
        data: { detail: 'Email already registered' },
      },
    });

    renderRegisterForm();

    const emailInput = screen.getByLabelText(/電子郵件/i);
    const passwordInput = screen.getByLabelText(/密碼/i);
    const submitButton = screen.getByRole('button', { name: /註冊/i });

    await user.type(emailInput, 'existing@example.com');
    await user.type(passwordInput, 'password123');
    await user.click(submitButton);

    await waitFor(() => {
      expect(screen.getByText('此 Email 已被註冊，請使用其他 Email 或直接登入')).toBeInTheDocument();
    });

    // 驗證沒有嘗試登入
    expect(authService.login).not.toHaveBeenCalled();
  });

  it('should display validation error for invalid email', async () => {
    const user = userEvent.setup();
    vi.mocked(authService.register).mockRejectedValue({
      isAxiosError: true,
      response: {
        status: 422,
        data: {
          detail: [
            {
              loc: ['body', 'email'],
              msg: 'value is not a valid email address',
              type: 'value_error.email',
            },
          ],
        },
      },
    });

    renderRegisterForm();

    const emailInput = screen.getByLabelText(/電子郵件/i);
    const passwordInput = screen.getByLabelText(/密碼/i);
    const submitButton = screen.getByRole('button', { name: /註冊/i });

    // 使用有效的 email 格式讓 HTML5 驗證通過，但伺服器會返回 422
    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'short');
    await user.click(submitButton);

    await waitFor(() => {
      expect(screen.getByText('輸入格式錯誤，請檢查 Email 和密碼格式')).toBeInTheDocument();
    });
  });

  it('should handle rate limiting error', async () => {
    const user = userEvent.setup();
    vi.mocked(authService.register).mockRejectedValue({
      isAxiosError: true,
      response: {
        status: 429,
        data: { detail: 'Too Many Requests' },
        headers: { 'retry-after': '60' },
      },
    });

    renderRegisterForm();

    const emailInput = screen.getByLabelText(/電子郵件/i);
    const passwordInput = screen.getByLabelText(/密碼/i);
    const submitButton = screen.getByRole('button', { name: /註冊/i });

    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'password123');
    await user.click(submitButton);

    await waitFor(() => {
      expect(screen.getByText(/操作過於頻繁，請在 60 秒後重試/i)).toBeInTheDocument();
    });

    // 驗證按鈕顯示倒數計時
    await waitFor(() => {
      const button = screen.getByRole('button');
      expect(button).toHaveTextContent(/請等待 \d+ 秒/);
      expect(button).toBeDisabled();
    });
  });

  it('should disable submit while loading', async () => {
    const user = userEvent.setup();
    vi.mocked(authService.register).mockImplementation(
      () => new Promise((resolve) => setTimeout(resolve, 100))
    );
    vi.mocked(authService.login).mockResolvedValue(undefined);
    vi.mocked(authService.getCurrentUser).mockResolvedValue({
      id: 1,
      email: 'test@example.com',
    });

    renderRegisterForm();

    const emailInput = screen.getByLabelText(/電子郵件/i);
    const passwordInput = screen.getByLabelText(/密碼/i);
    const submitButton = screen.getByRole('button', { name: /註冊/i });

    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'password123');
    await user.click(submitButton);

    // 驗證按鈕在 loading 時被禁用
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /註冊中/i })).toBeDisabled();
    });
  });
});
