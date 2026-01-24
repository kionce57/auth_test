import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserRouter } from 'react-router-dom';
import { LoginForm } from './LoginForm';
import { AuthProvider } from '../context/AuthContext';
import * as authService from '../services/auth';

// Mock auth service
vi.mock('../services/auth', () => ({
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

describe('LoginForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const renderLoginForm = () => {
    return render(
      <BrowserRouter>
        <AuthProvider>
          <LoginForm />
        </AuthProvider>
      </BrowserRouter>
    );
  };

  it('should render form fields', () => {
    renderLoginForm();

    expect(screen.getByLabelText(/電子郵件/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/密碼/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /登入/i })).toBeInTheDocument();
  });

  it('should handle successful login', async () => {
    const user = userEvent.setup();
    vi.mocked(authService.login).mockResolvedValue(undefined);
    vi.mocked(authService.getCurrentUser).mockResolvedValue({
      id: 1,
      email: 'test@example.com',
    });

    renderLoginForm();

    const emailInput = screen.getByLabelText(/電子郵件/i);
    const passwordInput = screen.getByLabelText(/密碼/i);
    const submitButton = screen.getByRole('button', { name: /登入/i });

    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'password123');
    await user.click(submitButton);

    await waitFor(() => {
      expect(authService.login).toHaveBeenCalledWith('test@example.com', 'password123');
      expect(mockNavigate).toHaveBeenCalledWith('/dashboard');
    });
  });

  it('should display error on login failure', async () => {
    const user = userEvent.setup();
    vi.mocked(authService.login).mockRejectedValue({
      isAxiosError: true,
      response: {
        status: 401,
        data: { detail: 'Incorrect email or password' },
      },
    });

    renderLoginForm();

    const emailInput = screen.getByLabelText(/電子郵件/i);
    const passwordInput = screen.getByLabelText(/密碼/i);
    const submitButton = screen.getByRole('button', { name: /登入/i });

    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'wrongpassword');
    await user.click(submitButton);

    await waitFor(() => {
      expect(screen.getByText('Incorrect email or password')).toBeInTheDocument();
    });
  });

  it('should display rate limit error with countdown', async () => {
    const user = userEvent.setup();
    vi.mocked(authService.login).mockRejectedValue({
      isAxiosError: true,
      response: {
        status: 429,
        data: { detail: 'Too Many Requests' },
        headers: { 'retry-after': '60' },
      },
    });

    renderLoginForm();

    const emailInput = screen.getByLabelText(/電子郵件/i);
    const passwordInput = screen.getByLabelText(/密碼/i);
    const submitButton = screen.getByRole('button', { name: /登入/i });

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
    vi.mocked(authService.login).mockImplementation(
      () => new Promise((resolve) => setTimeout(resolve, 100))
    );
    vi.mocked(authService.getCurrentUser).mockResolvedValue({
      id: 1,
      email: 'test@example.com',
    });

    renderLoginForm();

    const emailInput = screen.getByLabelText(/電子郵件/i);
    const passwordInput = screen.getByLabelText(/密碼/i);
    const submitButton = screen.getByRole('button', { name: /登入/i });

    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'password123');
    await user.click(submitButton);

    // 驗證按鈕在 loading 時被禁用
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /登入中/i })).toBeDisabled();
    });
  });

  it('should validate email format', async () => {
    const user = userEvent.setup();
    renderLoginForm();

    const emailInput = screen.getByLabelText(/電子郵件/i) as HTMLInputElement;
    const passwordInput = screen.getByLabelText(/密碼/i);
    const submitButton = screen.getByRole('button', { name: /登入/i });

    await user.type(emailInput, 'invalid-email');
    await user.type(passwordInput, 'password123');
    await user.click(submitButton);

    // HTML5 驗證會阻止表單提交
    expect(emailInput.validity.valid).toBe(false);
    expect(authService.login).not.toHaveBeenCalled();
  });

  it('should require password field', async () => {
    const user = userEvent.setup();
    renderLoginForm();

    const emailInput = screen.getByLabelText(/電子郵件/i);
    const passwordInput = screen.getByLabelText(/密碼/i) as HTMLInputElement;
    const submitButton = screen.getByRole('button', { name: /登入/i });

    await user.type(emailInput, 'test@example.com');
    await user.click(submitButton);

    // HTML5 驗證會阻止表單提交
    expect(passwordInput.validity.valid).toBe(false);
    expect(authService.login).not.toHaveBeenCalled();
  });
});
