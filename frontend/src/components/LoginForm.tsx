import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { parseError } from '../utils/errorHandler';

export const LoginForm: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [rateLimitCountdown, setRateLimitCountdown] = useState<number>(0);

  const { login } = useAuth();
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
    setLoading(true);

    try {
      await login(email, password);
      navigate('/dashboard');
    } catch (err: unknown) {
      const errorDetails = parseError(err, 'login');
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
          onChange={(e) => setPassword(e.target.value)}
          required
          style={{ width: '100%', padding: '8px', fontSize: '14px' }}
        />
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
          backgroundColor: rateLimitCountdown > 0 ? '#6c757d' : '#007bff',
          color: 'white',
          border: 'none',
          cursor: loading || rateLimitCountdown > 0 ? 'not-allowed' : 'pointer',
          fontSize: '16px',
        }}
      >
        {loading ? '登入中...' : rateLimitCountdown > 0 ? `請等待 ${rateLimitCountdown} 秒` : '登入'}
      </button>
    </form>
  );
};
