import { Link } from 'react-router-dom';

export const HomePage: React.FC = () => {
  return (
    <div style={{ textAlign: 'center', marginTop: '50px' }}>
      <h1>歡迎來到 Auth Test</h1>
      <p style={{ fontSize: '18px', marginTop: '20px' }}>
        這是一個簡單的身份驗證範例應用程式
      </p>
      <div style={{ marginTop: '30px', display: 'flex', gap: '15px', justifyContent: 'center' }}>
        <Link
          to="/login"
          style={{
            padding: '10px 20px',
            backgroundColor: '#007bff',
            color: 'white',
            textDecoration: 'none',
            fontSize: '16px',
          }}
        >
          登入
        </Link>
        <Link
          to="/register"
          style={{
            padding: '10px 20px',
            backgroundColor: '#28a745',
            color: 'white',
            textDecoration: 'none',
            fontSize: '16px',
          }}
        >
          註冊
        </Link>
      </div>
    </div>
  );
};
