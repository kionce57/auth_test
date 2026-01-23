import { Link } from 'react-router-dom';
import { LoginForm } from '../components/LoginForm';

export const LoginPage: React.FC = () => {
  return (
    <div style={{ maxWidth: '500px', margin: '50px auto', padding: '20px' }}>
      <h1 style={{ textAlign: 'center', marginBottom: '30px' }}>登入</h1>
      <LoginForm />
      <p style={{ textAlign: 'center', marginTop: '20px', fontSize: '14px' }}>
        還沒有帳號？{' '}
        <Link to="/register" style={{ color: '#007bff' }}>
          立即註冊
        </Link>
      </p>
    </div>
  );
};
