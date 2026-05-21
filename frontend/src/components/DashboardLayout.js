import { useAuth } from '../App';
import { useNavigate } from 'react-router-dom';
import { useEffect, useState } from 'react';
import axios from 'axios';
import { Bell, ChevronDown, LogOut, Search, Menu } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const getInitial = (name) => (name || 'U').trim().charAt(0).toUpperCase();

export default function DashboardLayout({
  navItems,
  title,
  description,
  children,
  topbarExtra,
  sidebarExtra,
  sidebarVariant,
  sidebarLabel = 'Menu'
}) {
  const { user, setUser, logout } = useAuth();
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => {
    if (user?.id) {
      axios.get(`${API}/auth/me`)
        .then(res => setUser(res.data))
        .catch(() => {});
    }
  }, []);

  const displayName = user?.nickname || user?.full_name || user?.email || 'Creator';
  const roleLabel = user?.role === 'business' ? 'Approved Business' : 'Approved Creator';

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const handleShellClick = (e) => {
    if (sidebarOpen && e.target === e.currentTarget) {
      setSidebarOpen(false);
    }
  };

  return (
    <div
      className={`pcd-shell ${sidebarVariant ? `pcd-${sidebarVariant}-sidebar` : ''} ${sidebarOpen ? 'has-mobile-sidebar' : ''}`}
      onClick={handleShellClick}
    >
      <aside className={`pcd-sidebar ${sidebarOpen ? 'is-mobile-open' : ''}`}>
        <div>
          <div className="pcd-brand">
            <div className="pcd-brand-mark">U</div>
            <span>UGCad.io</span>
          </div>
          <nav className="pcd-nav" aria-label="Creator dashboard">
            <span className="pcd-nav-label">{sidebarLabel}</span>
            {navItems.map((item) => (
              <button
                key={item.name}
                type="button"
                className={`pcd-nav-item ${item.active ? 'is-active' : ''}`}
                onClick={() => {
                  item.action();
                  setSidebarOpen(false);
                }}
              >
                <item.icon size={20} />
                <span>{item.name}</span>
                {item.badge ? <b className={`pcd-nav-badge ${item.badgeTone || ''}`}>{item.badge}</b> : null}
              </button>
            ))}
          </nav>
        </div>
        <div className="pcd-sidebar-profile">
          <div className="pcd-avatar">
            {user?.profile_photo ? (
              <img src={`${BACKEND_URL}${user.profile_photo}`} alt={displayName} style={{ width: '100%', height: '100%', objectFit: 'cover', borderRadius: '50%' }} />
            ) : (
              getInitial(displayName)
            )}
          </div>
          <div>
            <strong>{displayName}</strong>
            <span>{roleLabel}</span>
          </div>
        </div>
        {sidebarExtra}
      </aside>

      <div className="pcd-main">
        <header className="pcd-topbar">
          <button
            type="button"
            className="pcd-hamburger"
            aria-label="Toggle menu"
            onClick={() => setSidebarOpen(true)}
          >
            <Menu size={20} />
          </button>
          <div>
            <h1>{title}</h1>
            {description && <p>{description}</p>}
          </div>
          {sidebarVariant === 'business-match' && (
            <div className="pcd-business-header-search" role="search">
              <Search size={20} />
              <input type="search" placeholder="Search campaigns, deals, creators, status, briefs..." aria-label="Search dashboard" />
            </div>
          )}
          <div className="pcd-top-actions">
            {sidebarVariant === 'business-match' ? (
              <>
                <button type="button" className="pcd-business-round-action pcd-bell" aria-label="Notifications">
                  <Bell size={18} />
                  <span />
                </button>
                <button type="button" className="pcd-business-profile-photo" onClick={() => navigate('/settings')} aria-label="Profile">
                  {user?.profile_photo ? (
                    <img src={`${BACKEND_URL}${user.profile_photo}`} alt={displayName} style={{ width: '100%', height: '100%', objectFit: 'cover', borderRadius: '50%' }} />
                  ) : (
                    getInitial(displayName)
                  )}
                </button>
                <button type="button" className="pcd-business-round-action" onClick={handleLogout} aria-label="Logout">
                  <LogOut size={18} />
                </button>
                {topbarExtra}
              </>
            ) : (
            <>
            <button type="button" className="pcd-icon-btn" aria-label="Search">
              <Search size={18} />
            </button>
            <button type="button" className="pcd-icon-btn pcd-bell" aria-label="Notifications">
              <Bell size={18} />
              <span />
            </button>
            <button type="button" className="pcd-profile-chip" onClick={() => navigate('/settings')}>
              <span className="pcd-avatar small">
                {user?.profile_photo ? (
                  <img src={`${BACKEND_URL}${user.profile_photo}`} alt={displayName} style={{ width: '100%', height: '100%', objectFit: 'cover', borderRadius: '50%' }} />
                ) : (
                  <span title={user?.profile_photo || 'no photo'}>{getInitial(displayName)}</span>
                )}
              </span>
              <ChevronDown size={16} />
            </button>
            <button type="button" className="pcd-logout" onClick={handleLogout}>
              <LogOut size={18} />
              Logout
            </button>
            {topbarExtra}
            </>
            )}
          </div>
        </header>

        <main className="pcd-content">
          {children}
        </main>
      </div>
    </div>
  );
}
