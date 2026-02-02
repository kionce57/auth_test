import { Link, Navigate } from 'react-router-dom';
import { LoginForm } from '../components/LoginForm';
import { GoogleLoginButton } from '../components/GoogleLoginButton';
import { useAuth } from '../context/AuthContext';
import './LoginPage.css';

export const LoginPage: React.FC = () => {
  const { user, loading } = useAuth();

  // 已登入則重導向到 Dashboard
  if (loading) {
    return <div style={{ textAlign: 'center', marginTop: '50px' }}>載入中...</div>;
  }

  if (user) {
    return <Navigate to="/dashboard" replace />;
  }

  return (
    <div style={{ maxWidth: '500px', margin: '50px auto', padding: '20px' }}>
      <h1 style={{ textAlign: 'center', marginBottom: '30px' }}>登入</h1>
      <LoginForm />

      <div className="divider">
        <span>或</span>
      </div>

      <GoogleLoginButton />

      <p style={{ textAlign: 'center', marginTop: '20px', fontSize: '14px' }}>
        還沒有帳號？{' '}
        <Link to="/register" style={{ color: '#007bff' }}>
          立即註冊
        </Link>
      </p>
    </div>
  );
};
