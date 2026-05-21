import { TrendingUp, FileText, Users, Briefcase, DollarSign, Download, UserPlus, BarChart } from 'lucide-react';

function AdminSidebar({ activeTab, onTabClick, user }) {
  const adminTabs = [
    { id: 'stats', label: 'Admin Dashboard', icon: TrendingUp, testId: 'tab-stats', slug: 'overview' },
    { id: 'applications', label: 'Applications', icon: FileText, testId: 'tab-applications', slug: 'applications' },
    { id: 'profiles', label: 'Profiles', icon: Users, testId: 'tab-profiles', slug: 'profiles' },
    { id: 'campaigns', label: 'Campaigns', icon: Briefcase, testId: 'tab-campaigns', slug: 'campaigns' },
    { id: 'gigs', label: 'Gig Management', icon: Briefcase, testId: 'tab-gigs', slug: 'gigs' },
    { id: 'withdrawals', label: 'Withdrawals', icon: DollarSign, testId: 'tab-withdrawals', slug: 'withdrawals' },
    { id: 'allcampaigns', label: 'All Campaigns', icon: Briefcase, testId: 'tab-allcampaigns', slug: 'all-campaigns' },
    { id: 'users', label: 'Users', icon: Users, testId: 'tab-users', slug: 'users' },
    { id: 'assignments', label: 'Assignments', icon: UserPlus, testId: 'tab-assignments', slug: 'assignments' },
    { id: 'analytics', label: 'Analytics', icon: BarChart, testId: 'tab-analytics', slug: 'analytics' },
  ];

  return (
    <aside className="admin-sidebar">
      <div>
        <div className="admin-sidebar-brand">
          <div className="admin-sidebar-mark">A</div>
          <span>UGCad.io</span>
        </div>
        <nav className="admin-sidebar-nav" aria-label="Admin dashboard">
          <span className="admin-nav-label">Admin</span>
          {adminTabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                type="button"
                className={`admin-nav-item ${activeTab === tab.id ? 'active' : ''}`}
                onClick={() => onTabClick(tab)}
                data-testid={tab.testId}
              >
                <Icon size={20} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </nav>
      </div>
      <div className="admin-sidebar-profile">
        <div className="admin-avatar">
          {(user?.nickname || user?.full_name || 'A').trim().charAt(0).toUpperCase()}
        </div>
        <div>
          <strong>{user?.nickname || 'Admin'}</strong>
          <span>{user?.role}</span>
        </div>
      </div>
    </aside>
  );
}

export default AdminSidebar;
