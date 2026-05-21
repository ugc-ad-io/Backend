import { LogOut } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import AdminSidebar from './AdminSidebar';

function AdminLayout({ children }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const currentPath = window.location.pathname;
  const isApplicationsPage = currentPath === '/dashboard/admin/applications';

  const handleTabClick = (tab) => {
    if (tab.id === 'applications') {
      navigate('/dashboard/admin/applications');
    } else if (tab.id === 'stats') {
      navigate('/dashboard/admin');
    } else if (tab.id === 'allcampaigns') {
      navigate('/dashboard/admin/all-campaigns');
    } else {
      navigate(`/dashboard/admin/${tab.slug}`);
    }
  };

  const activeTab = isApplicationsPage ? 'applications' : 'stats';

  return (
    <div className="admin-dashboard">
      <AdminSidebar activeTab={activeTab} onTabClick={handleTabClick} user={user} />

      <main className="admin-main">
        <div className="dashboard-header">
          <div className="header-content">
            <div>
              {isApplicationsPage ? (
                <>
                  <h1>Applications Management</h1>
                  <p>Manage creator and brand applications</p>
                </>
              ) : (
                <>
                  <h1>Admin Dashboard</h1>
                  <p>Welcome, {user?.nickname} - {user?.role}</p>
                </>
              )}
            </div>
            <button className="btn-secondary" onClick={handleLogout}>
              <LogOut size={20} /> Logout
            </button>
          </div>
        </div>

        <div className="dashboard-content">
          <div className="tab-content">
            {children}
          </div>
        </div>
      </main>
    </div>
  );
}

export default AdminLayout;
