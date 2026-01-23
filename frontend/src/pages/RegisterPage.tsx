import { Link } from 'react-router-dom';
import { RegisterForm } from '../components/RegisterForm';

export const RegisterPage: React.FC = () => {
  return (
    <div style={{ maxWidth: '500px', margin: '50px auto', padding: '20px' }}>
      <h1 style={{ textAlign: 'center', marginBottom: '30px' }}>註冊</h1>
      <RegisterForm />
      <p style={{ textAlign: 'center', marginTop: '20px', fontSize: '14px' }}>
        已經有帳號？{' '}
        <Link to="/login" style={{ color: '#007bff' }}>
          立即登入
        </Link>
      </p>
    </div>
  );
};
