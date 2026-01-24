import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { parseError } from '../utils/errorHandler';

export const RegisterForm: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [rateLimitCountdown, setRateLimitCountdown] = useState<number>(0);

  const { register, login } = useAuth();
  const navigate = useNavigate();

  // Rate Limit 倒數計時
  useEffect(() => {
    if (rateLimitCountdown <= 0) return;

    const timer = setInterval(() => {
      setRateLimitCountdown((prev) => {
        if (prev <= 1) {
          setError(null);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [rateLimitCountdown]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setPasswordError(null);

    // 前端密碼驗證
    if (password.length < 8 || password.length > 72) {
      setPasswordError('密碼需為 8-72 個字元');
      return;
    }

    setLoading(true);

    try {
      await register(email, password);
      // 註冊成功後自動登入
      await login(email, password);
      navigate('/dashboard');
    } catch (err: unknown) {
      const errorDetails = parseError(err, 'register');
      setError(errorDetails.message);

      // 如果是 Rate Limit 錯誤，啟動倒數計時
      if (errorDetails.isRateLimited && errorDetails.retryAfter) {
        setRateLimitCountdown(errorDetails.retryAfter);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} style={{ maxWidth: '400px', margin: '0 auto' }}>
      <div style={{ marginBottom: '15px' }}>
        <label htmlFor="email" style={{ display: 'block', marginBottom: '5px' }}>
          電子郵件：
        </label>
        <input
          type="email"
          id="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          style={{ width: '100%', padding: '8px', fontSize: '14px' }}
        />
      </div>

      <div style={{ marginBottom: '15px' }}>
        <label htmlFor="password" style={{ display: 'block', marginBottom: '5px' }}>
          密碼：
        </label>
        <input
          type="password"
          id="password"
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
            setPasswordError(null);  // 清除錯誤提示
          }}
          required
          maxLength={72}
          style={{ width: '100%', padding: '8px', fontSize: '14px' }}
        />
        {passwordError && (
          <div style={{ color: 'red', fontSize: '12px', marginTop: '4px' }}>
            {passwordError}
          </div>
        )}
        {!passwordError && (
          <small style={{ color: '#666', fontSize: '12px' }}>
            密碼需為 8-72 個字元
          </small>
        )}
      </div>

      {error && (
        <div style={{ color: 'red', marginBottom: '15px', fontSize: '14px' }}>
          {error}
        </div>
      )}

      <button
        type="submit"
        disabled={loading || rateLimitCountdown > 0}
        style={{
          width: '100%',
          padding: '10px',
          backgroundColor: rateLimitCountdown > 0 ? '#6c757d' : '#28a745',
          color: 'white',
          border: 'none',
          cursor: loading || rateLimitCountdown > 0 ? 'not-allowed' : 'pointer',
          fontSize: '16px',
        }}
      >
        {loading ? '註冊中...' : rateLimitCountdown > 0 ? `請等待 ${rateLimitCountdown} 秒` : '註冊'}
      </button>
    </form>
  );
};
