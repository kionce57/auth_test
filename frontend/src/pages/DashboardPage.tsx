import { useAuth } from '../context/AuthContext';

export const DashboardPage: React.FC = () => {
  const { user } = useAuth();

  return (
    <div style={{ maxWidth: '800px', margin: '50px auto', padding: '20px' }}>
      <h1>儀表板</h1>
      <div style={{ marginTop: '30px', padding: '20px', backgroundColor: '#f5f5f5', borderRadius: '4px' }}>
        <h2>歡迎，{user?.email}</h2>
        <p style={{ marginTop: '15px', fontSize: '14px', color: '#666' }}>
          這是受保護的頁面，只有登入的使用者才能存取。
        </p>
        <div style={{ marginTop: '20px' }}>
          <p><strong>使用者資訊：</strong></p>
          <ul style={{ marginTop: '10px', fontSize: '14px' }}>
            <li>電子郵件：{user?.email}</li>
            <li>使用者 ID：{user?.id}</li>
          </ul>
        </div>
      </div>
    </div>
  );
};
