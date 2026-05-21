import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import {
  User,
  Lock,
  Shield,
  Camera,
  Save,
  LayoutDashboard,
  Zap,
  Bookmark,
  Star,
  Briefcase,
  FileCheck,
  MessageSquare,
  IndianRupee,
  Settings,
  Search,
  Bell,
  HelpCircle,
  Building2,
  Users,
  CreditCard,
  Wallet,
  Globe,
  CheckCircle,
  ChevronRight,
  MoreVertical,
  UserPlus,
  Upload,
  Trash2,
  RefreshCw,
  BarChart3,
  LifeBuoy,
  Bolt,
  FileText,
  Package
} from 'lucide-react';
import DashboardLayout from '../components/DashboardLayout';
import './CreatorDashboard.css';
import './ProfileSettings.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const getInitial = (name) => (name || 'U').trim().charAt(0).toUpperCase();
const money = (value) => `₹${Number(value || 0).toLocaleString('en-IN')}`;

const getLevelInfo = (completedWorks) => {
  if (completedWorks >= 20) {
    return {
      badge: 'L2 (Pro)',
      level: 'L2 Professional',
      color: '#7387ff',
      subtitle: 'Promo Eligible',
      nextLevel: null,
      currentWorks: completedWorks,
      nextWorks: null,
      benefits: '10% Higher Base Rates & Premium Support'
    };
  }
  if (completedWorks >= 10) {
    return {
      badge: 'L1 (Rising)',
      level: 'L1 Rising Star',
      color: '#27ae60',
      subtitle: 'Verified',
      nextLevel: 'L2 Professional',
      currentWorks: completedWorks,
      nextWorks: 20,
      benefits: 'Verified badge & Priority support'
    };
  }
  return {
    badge: 'New Creator',
    level: 'New Creator',
    color: '#999',
    subtitle: 'Not Verified',
    nextLevel: 'L1 Rising Star',
    currentWorks: completedWorks,
    nextWorks: 10,
    benefits: 'Complete 10 works to reach L1 Rising Star'
  };
};

const BRAND_TABS = [
  { id: 'profile', label: 'Profile', icon: User },
  { id: 'company', label: 'Company', icon: Building2 },
  { id: 'team', label: 'Team Members', icon: Users },
  { id: 'billing', label: 'Billing', icon: CreditCard },
  { id: 'notifications', label: 'Notifications', icon: Bell },
  { id: 'security', label: 'Security', icon: Lock }
];

const defaultBrandProfile = {
  brand_name: '',
  contact_person: '',
  work_email: '',
  phone_number: '',
  website_url: '',
  logo_url: ''
};

const defaultCompany = {
  business_type: '',
  gst_number: '',
  business_category: '',
  country: 'India',
  billing_address: '',
  city: '',
  state: '',
  kyb_status: 'pending'
};

const defaultTeam = { members: [], seat_limit: 10, seats_used: 0 };
const defaultBilling = {
  plan_name: 'Brand Pro',
  commission_rate: 20,
  next_billing_date: '',
  monthly_budget_used: 0,
  monthly_budget_limit: 0,
  billing_history: [],
  payment_methods: []
};
const defaultNotifications = {
  new_creator_applications: true,
  deal_status_updates: true,
  payment_escrow_alerts: true,
  direct_messages: true,
  weekly_workspace_reports: false
};
const defaultSummary = { active_plan: 'Pro', wallet_balance: 0, team_count: 0 };

export default function ProfileSettings() {
  const { user, logout, setUser } = useAuth();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('profile');
  const [brandTab, setBrandTab] = useState('profile');
  const [loading, setLoading] = useState(false);
  const [brandLoading, setBrandLoading] = useState(false);
  const [brandProfile, setBrandProfile] = useState(defaultBrandProfile);
  const [company, setCompany] = useState(defaultCompany);
  const [team, setTeam] = useState(defaultTeam);
  const [billing, setBilling] = useState(defaultBilling);
  const [notificationPrefs, setNotificationPrefs] = useState(defaultNotifications);
  const [summary, setSummary] = useState(defaultSummary);
  const [logoUploading, setLogoUploading] = useState(false);
  
  // Profile states
  const [bio, setBio] = useState('');
  const [description, setDescription] = useState('');
  const [profilePhoto, setProfilePhoto] = useState(null);
  const [uploadingPhoto, setUploadingPhoto] = useState(false);
  
  // Password states
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  
  // 2FA states
  const [twoFAEnabled, setTwoFAEnabled] = useState(false);
  const [qrCode, setQrCode] = useState('');
  const [secret, setSecret] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [disablePassword, setDisablePassword] = useState('');
  const [showQR, setShowQR] = useState(false);

  // Creator level states
  const [completedWorks, setCompletedWorks] = useState(0);

  useEffect(() => {
    fetchUserData();
    check2FAStatus();
    if (user?.role === 'creator') {
      fetchCreatorStats();
    }
  }, [user?.role]);

  useEffect(() => {
    if (user?.role === 'business') {
      fetchBrandSettings();
    }
  }, [user?.role]);

  const fetchCreatorStats = async () => {
    try {
      const res = await axios.get(`${API}/campaigns?status=completed&creator_id=${user.id}`);
      const completedCampaigns = res.data || [];
      setCompletedWorks(completedCampaigns.length);
    } catch (error) {
      console.error('Failed to fetch creator stats:', error);
    }
  };

  const fetchBrandSettings = async () => {
    setBrandLoading(true);
    try {
      const [profileRes, companyRes, teamRes, billingRes, notificationsRes, summaryRes] = await Promise.all([
        axios.get(`${API}/business/settings/profile`),
        axios.get(`${API}/business/settings/company`),
        axios.get(`${API}/business/settings/team`),
        axios.get(`${API}/business/settings/billing`),
        axios.get(`${API}/business/settings/notifications`),
        axios.get(`${API}/business/settings/summary`)
      ]);
      setBrandProfile({ ...defaultBrandProfile, ...(profileRes.data || {}) });
      setCompany({ ...defaultCompany, ...(companyRes.data || {}) });
      setTeam({ ...defaultTeam, ...(teamRes.data || {}) });
      setBilling({ ...defaultBilling, ...(billingRes.data || {}) });
      setNotificationPrefs({ ...defaultNotifications, ...(notificationsRes.data || {}) });
      setSummary({ ...defaultSummary, ...(summaryRes.data || {}) });
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to load brand settings');
    } finally {
      setBrandLoading(false);
    }
  };

  const saveBrandProfile = async () => {
    setLoading(true);
    try {
      const res = await axios.put(`${API}/business/settings/profile`, brandProfile);
      setBrandProfile({ ...brandProfile, ...(res.data || {}) });
      toast.success('Profile settings saved');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to save profile settings');
    } finally {
      setLoading(false);
    }
  };

  const saveCompany = async () => {
    setLoading(true);
    try {
      const res = await axios.put(`${API}/business/settings/company`, company);
      setCompany({ ...company, ...(res.data || {}) });
      toast.success('Company details saved');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to save company details');
    } finally {
      setLoading(false);
    }
  };

  const saveNotifications = async () => {
    setLoading(true);
    try {
      const res = await axios.put(`${API}/business/settings/notifications`, notificationPrefs);
      setNotificationPrefs({ ...notificationPrefs, ...(res.data || {}) });
      toast.success('Notification preferences saved');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to save notifications');
    } finally {
      setLoading(false);
    }
  };

  const handleLogoUpload = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setLogoUploading(true);
    const formData = new FormData();
    formData.append('file', file);
    try {
      const res = await axios.post(`${API}/business/settings/logo`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setBrandProfile(current => ({ ...current, logo_url: res.data.logo_url || res.data.photo_url || res.data.url || current.logo_url }));
      toast.success('Logo updated');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to upload logo');
    } finally {
      setLogoUploading(false);
      event.target.value = '';
    }
  };

  const removeLogo = async () => {
    try {
      await axios.delete(`${API}/business/settings/logo`);
      setBrandProfile(current => ({ ...current, logo_url: '' }));
      toast.success('Logo removed');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to remove logo');
    }
  };

  const inviteMember = async () => {
    const email = window.prompt('Enter team member email');
    if (!email) return;
    try {
      await axios.post(`${API}/business/settings/team/invite`, { email, role: 'viewer' });
      toast.success('Invitation sent');
      const res = await axios.get(`${API}/business/settings/team`);
      setTeam({ ...defaultTeam, ...(res.data || {}) });
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to invite member');
    }
  };

  const fetchUserData = async () => {
    try {
      const response = await axios.get(`${API}/auth/me`);
      setBio(response.data.bio || '');
      setDescription(response.data.description || '');
      setProfilePhoto(response.data.profile_photo || null);
    } catch (error) {
      toast.error('Failed to load profile data');
    }
  };

  const check2FAStatus = async () => {
    try {
      const response = await axios.get(`${API}/profile/2fa/status`);
      setTwoFAEnabled(response.data.enabled);
    } catch (error) {
      console.error('Failed to check 2FA status');
    }
  };

  const handlePhotoUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Validate file size (max 2MB)
    if (file.size > 2 * 1024 * 1024) {
      toast.error('Image too large. Maximum 2MB allowed.');
      return;
    }

    setUploadingPhoto(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await axios.post(`${API}/profile/upload-photo`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setProfilePhoto(response.data.photo_url);
      setUser({ ...user, profile_photo: response.data.photo_url });
      toast.success('Profile photo updated!');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to upload photo');
    } finally {
      setUploadingPhoto(false);
    }
  };

  const handleUpdateProfile = async () => {
    setLoading(true);
    try {
      await axios.put(`${API}/profile/update-info?bio=${encodeURIComponent(bio)}&description=${encodeURIComponent(description)}`);
      setUser({ ...user, bio, description });
      toast.success('Profile updated successfully!');
    } catch (error) {
      toast.error('Failed to update profile');
    } finally {
      setLoading(false);
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    
    if (newPassword !== confirmPassword) {
      toast.error('New passwords do not match');
      return;
    }

    if (newPassword.length < 8) {
      toast.error('Password must be at least 8 characters');
      return;
    }

    setLoading(true);
    try {
      await axios.post(`${API}/profile/change-password?old_password=${encodeURIComponent(oldPassword)}&new_password=${encodeURIComponent(newPassword)}`);
      toast.success('Password changed successfully!');
      setOldPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to change password');
    } finally {
      setLoading(false);
    }
  };

  const handleSetup2FA = async () => {
    setLoading(true);
    try {
      const response = await axios.post(`${API}/profile/2fa/setup`);
      setQrCode(response.data.qr_code);
      setSecret(response.data.secret);
      setShowQR(true);
      toast.success('Scan the QR code with Google Authenticator');
    } catch (error) {
      toast.error('Failed to setup 2FA');
    } finally {
      setLoading(false);
    }
  };

  const handleVerify2FA = async () => {
    if (!verificationCode || verificationCode.length !== 6) {
      toast.error('Please enter a valid 6-digit code');
      return;
    }

    setLoading(true);
    try {
      await axios.post(`${API}/profile/2fa/verify?token=${verificationCode}`);
      toast.success('2FA enabled successfully!');
      setTwoFAEnabled(true);
      setShowQR(false);
      setVerificationCode('');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Invalid verification code');
    } finally {
      setLoading(false);
    }
  };

  const handleDisable2FA = async () => {
    if (!disablePassword) {
      toast.error('Please enter your password');
      return;
    }

    setLoading(true);
    try {
      await axios.post(`${API}/profile/2fa/disable?password=${encodeURIComponent(disablePassword)}`);
      toast.success('2FA disabled successfully');
      setTwoFAEnabled(false);
      setDisablePassword('');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to disable 2FA');
    } finally {
      setLoading(false);
    }
  };

  const displayName = user?.nickname || user?.full_name || user?.email || 'Settings';

  const navItems = user?.role === 'business'
    ? [
      { name: 'Brand Dashboard', icon: LayoutDashboard, action: () => navigate('/dashboard/business') },
      { name: 'Post a Brief', icon: FileCheck, action: () => navigate('/dashboard/business/post-brief') },
      { name: 'All Campaigns', icon: Briefcase, action: () => navigate('/dashboard/business/all-campaigns') },
      { name: 'Creator Bids', icon: User, action: () => navigate('/dashboard/business/pending-bids') },
      { name: 'Browse Creator', icon: Search, action: () => navigate('/dashboard/business/browse-creator') },
      { name: 'Work Review', icon: FileCheck, action: () => navigate('/dashboard/business/work-review') },
      { name: 'Messages', icon: MessageSquare, action: () => navigate('/messages') },
      { name: 'Manage Shipment', icon: Package, action: () => navigate('/dashboard/business/shipments') },
      { name: 'Wallet', icon: Wallet, action: () => navigate('/dashboard/business/wallet') },
      { name: 'Settings', icon: Settings, action: () => navigate('/settings'), active: true }
    ]
    : [
      { name: 'Dashboard', icon: LayoutDashboard, action: () => navigate('/dashboard/creator') },
      { name: 'My Active Work', icon: Zap, action: () => navigate('/my-active-work') },
      { name: 'My Bids', icon: Bookmark, action: () => navigate('/my-bids') },
      { name: 'Reviews', icon: Star, action: () => navigate('/reviews') },
      { name: 'Portfolio', icon: User, action: () => navigate('/portfolio') },
      { name: 'Browse Briefs', icon: Briefcase, action: () => navigate('/browse-briefs') },
      { name: 'My Deals', icon: FileCheck, action: () => navigate('/my-deals') },
      { name: 'Messages', icon: MessageSquare, action: () => navigate('/messages') },
      { name: 'Payout', icon: IndianRupee, action: () => navigate('/withdrawal') },
      { name: 'Settings', icon: Settings, action: () => navigate('/settings'), active: true }
    ];

  const brandNav = [
    { label: 'Brand Dashboard', icon: LayoutDashboard, path: '/dashboard/business' },
    { label: 'Post a Brief', icon: FileCheck, path: '/dashboard/business/post-brief' },
    { label: 'Creator Bids', icon: Users, path: '/dashboard/business/pending-bids', badge: 3, tone: 'orange' },
    { label: 'Browse Creator', icon: Search, path: '/dashboard/business/browse-creator' },
    { label: 'All Campaigns', icon: Briefcase, path: '/dashboard/business/all-campaigns' },
    { label: 'Work Review', icon: FileCheck, path: '/dashboard/business/work-review' },
    { label: 'Messages', icon: MessageSquare, path: '/messages', badge: 2, tone: 'green' },
    { label: 'Manage Shipment', icon: Package, path: '/dashboard/business/shipments' },
    { label: 'Wallet', icon: Wallet, path: '/dashboard/business/wallet' },
    { label: 'Settings', icon: Settings, path: '/settings', active: true }
  ];

  const logoSrc = brandProfile.logo_url?.startsWith('http')
    ? brandProfile.logo_url
    : brandProfile.logo_url
      ? `${BACKEND_URL}${brandProfile.logo_url}`
      : '';

  const renderBrandField = (label, value, onChange, props = {}) => (
    <label className={props.full ? 'bs-field bs-full' : 'bs-field'}>
      <span>{label}</span>
      {props.textarea ? (
        <textarea value={value || ''} onChange={(event) => onChange(event.target.value)} rows={props.rows || 3} />
      ) : (
        <input
          type={props.type || 'text'}
          value={value || ''}
          onChange={(event) => onChange(event.target.value)}
          disabled={props.disabled}
          placeholder={props.placeholder}
        />
      )}
    </label>
  );

  const renderBrandPanel = () => {
    if (brandLoading) {
      return <div className="bs-card bs-loading"><RefreshCw size={20} /> Loading settings...</div>;
    }

    if (brandTab === 'profile') {
      return (
        <section className="bs-card">
          <div className="bs-card-head">
            <span><User size={20} /></span>
            <div>
              <h2>Profile Settings</h2>
              <p>Update your basic brand information and workspace presence</p>
            </div>
          </div>
          <div className="bs-card-body bs-profile-grid">
            <div className="bs-logo-block">
              <label className="bs-logo-box">
                {logoSrc ? <img src={logoSrc} alt="Brand logo" /> : <strong>{getInitial(brandProfile.brand_name || displayName)}</strong>}
                <input type="file" accept="image/*" onChange={handleLogoUpload} />
              </label>
              <button type="button" onClick={removeLogo} disabled={!brandProfile.logo_url || logoUploading}>
                {logoUploading ? 'Uploading...' : 'Remove Logo'}
              </button>
            </div>
            <div className="bs-form-grid">
              {renderBrandField('Brand Name', brandProfile.brand_name, value => setBrandProfile(current => ({ ...current, brand_name: value })))}
              {renderBrandField('Contact Person', brandProfile.contact_person, value => setBrandProfile(current => ({ ...current, contact_person: value })))}
              {renderBrandField('Work Email', brandProfile.work_email, value => setBrandProfile(current => ({ ...current, work_email: value })), { type: 'email' })}
              {renderBrandField('Phone Number', brandProfile.phone_number, value => setBrandProfile(current => ({ ...current, phone_number: value })))}
              {renderBrandField('Website URL', brandProfile.website_url, value => setBrandProfile(current => ({ ...current, website_url: value })), { full: true, placeholder: 'https://yourbrand.com' })}
            </div>
          </div>
          <div className="bs-card-actions">
            <button type="button" className="bs-ghost">Cancel</button>
            <button type="button" className="bs-primary" onClick={saveBrandProfile} disabled={loading}>{loading ? 'Saving...' : 'Save Changes'}</button>
          </div>
        </section>
      );
    }

    if (brandTab === 'company') {
      return (
        <section className="bs-card">
          <div className="bs-card-head">
            <span><Building2 size={20} /></span>
            <div>
              <h2>Company Details</h2>
              <p>Official information for billing, verification, and legal compliance</p>
            </div>
            <em className={`bs-kyb ${company.kyb_status}`}>KYB {company.kyb_status || 'pending'}</em>
          </div>
          <div className="bs-card-body bs-form-grid">
            {renderBrandField('Business Type', company.business_type, value => setCompany(current => ({ ...current, business_type: value })))}
            {renderBrandField('GST Number', company.gst_number, value => setCompany(current => ({ ...current, gst_number: value })))}
            {renderBrandField('Business Category', company.business_category, value => setCompany(current => ({ ...current, business_category: value })))}
            {renderBrandField('Country', company.country, value => setCompany(current => ({ ...current, country: value })))}
            {renderBrandField('Billing Address', company.billing_address, value => setCompany(current => ({ ...current, billing_address: value })), { full: true, textarea: true })}
            {renderBrandField('City', company.city, value => setCompany(current => ({ ...current, city: value })))}
            {renderBrandField('State', company.state, value => setCompany(current => ({ ...current, state: value })))}
          </div>
          <div className="bs-card-actions">
            <button type="button" className="bs-primary dark" onClick={saveCompany} disabled={loading}>{loading ? 'Saving...' : 'Save Company Details'}</button>
          </div>
        </section>
      );
    }

    if (brandTab === 'team') {
      return (
        <section className="bs-card">
          <div className="bs-card-head">
            <span><Users size={20} /></span>
            <div>
              <h2>Team Members</h2>
              <p>Invite and manage workspace collaborators and their permissions</p>
            </div>
            <button type="button" className="bs-primary small" onClick={inviteMember}><UserPlus size={16} /> Invite Member</button>
          </div>
          <div className="bs-team-table">
            <div className="bs-team-row bs-team-head"><span>Member</span><span>Role</span><span>Status</span><span>Actions</span></div>
            {(team.members || []).map(member => (
              <div className="bs-team-row" key={member.id || member.email}>
                <div className="bs-member">
                  {member.avatar_url ? <img src={member.avatar_url.startsWith('http') ? member.avatar_url : `${BACKEND_URL}${member.avatar_url}`} alt={member.name} /> : <i>{getInitial(member.name || member.email)}</i>}
                  <div><strong>{member.name || member.email}</strong><small>{member.email}</small></div>
                </div>
                <span className="bs-role">{member.role}</span>
                <span className={`bs-status ${member.status}`}><b /> {member.status}</span>
                <button type="button" className="bs-icon-only"><MoreVertical size={18} /></button>
              </div>
            ))}
          </div>
          <p className="bs-seat-note">Workspace limit: <strong>{team.seats_used || team.members?.length || 0} / {team.seat_limit || 10} seats used.</strong> Pro plan allows up to {team.seat_limit || 10} members.</p>
        </section>
      );
    }

    if (brandTab === 'billing') {
      const used = Number(billing.monthly_budget_used || 0);
      const limit = Number(billing.monthly_budget_limit || 0);
      const percent = limit ? Math.min(100, Math.round((used / limit) * 100)) : 0;
      return (
        <section className="bs-card">
          <div className="bs-card-head">
            <span><CreditCard size={20} /></span>
            <div>
              <h2>Billing & Subscription</h2>
              <p>Manage your current plan, payment methods, and view billing history</p>
            </div>
          </div>
          <div className="bs-card-body">
            <div className="bs-plan-card">
              <div><small>Current Plan</small><h3>{billing.plan_name || 'Brand Pro'}</h3><p>Next billing: <strong>{billing.next_billing_date ? new Date(billing.next_billing_date).toLocaleDateString('en-IN', { month: 'long', day: 'numeric', year: 'numeric' }) : 'Not scheduled'}</strong></p></div>
              <div><small>Commission Rate</small><h4>{billing.commission_rate || 0}%</h4><button type="button">Upgrade to Enterprise</button></div>
            </div>
            <div className="bs-budget-card">
              <div><strong>Monthly Campaign Budget Progress</strong><b>{money(used)} / {money(limit)}</b></div>
              <span><i style={{ width: `${percent}%` }} /></span>
              <p>{percent}% of budget used this month <em><CheckCircle size={14} /> Normal usage</em></p>
            </div>
            <div className="bs-billing-tabs">
              <button type="button"><RefreshCw size={16} /> Billing History</button>
              <button type="button"><CreditCard size={16} /> Payment Methods</button>
            </div>
          </div>
        </section>
      );
    }

    if (brandTab === 'notifications') {
      const rows = [
        ['new_creator_applications', 'New Creator Applications', 'Alert when a creator applies to your brief', Users],
        ['deal_status_updates', 'Deal Status Updates', 'Milestone changes and content delivery alerts', RefreshCw],
        ['payment_escrow_alerts', 'Payment & Escrow Alerts', 'Wallet recharges and escrow lock notifications', IndianRupee],
        ['direct_messages', 'Direct Messages', 'Instant alerts for new chat messages from creators', MessageSquare],
        ['weekly_workspace_reports', 'Weekly Workspace Reports', 'Summarized digest of your campaign performance', FileText]
      ];
      return (
        <section className="bs-card">
          <div className="bs-card-head">
            <span><Bell size={20} /></span>
            <div>
              <h2>Notification Settings</h2>
              <p>Configure how and when you want to be notified about workspace activities</p>
            </div>
          </div>
          <div className="bs-toggle-list">
            {rows.map(([key, title, desc, Icon]) => (
              <div className="bs-toggle-row" key={key}>
                <span><Icon size={20} /></span>
                <div><strong>{title}</strong><p>{desc}</p></div>
                <button
                  type="button"
                  className={notificationPrefs[key] ? 'is-on' : ''}
                  onClick={() => setNotificationPrefs(current => ({ ...current, [key]: !current[key] }))}
                  aria-label={`Toggle ${title}`}
                />
              </div>
            ))}
          </div>
          <div className="bs-card-actions">
            <button type="button" className="bs-primary" onClick={saveNotifications} disabled={loading}>{loading ? 'Saving...' : 'Save Preferences'}</button>
          </div>
        </section>
      );
    }

    return (
      <section className="bs-card">
        <div className="bs-card-head">
          <span><Lock size={20} /></span>
          <div>
            <h2>Security Settings</h2>
            <p>Manage password and two-factor authentication for your workspace</p>
          </div>
        </div>
        <div className="bs-security-grid">
          <form onSubmit={handleChangePassword} className="bs-security-box">
            <h3>Change Password</h3>
            <input type="password" value={oldPassword} onChange={(e) => setOldPassword(e.target.value)} placeholder="Current password" required />
            <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="New password" required />
            <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} placeholder="Confirm password" required />
            <button type="submit" className="bs-primary" disabled={loading}>{loading ? 'Saving...' : 'Update Password'}</button>
          </form>
          <div className="bs-security-box">
            <h3>Two-Factor Authentication</h3>
            <p>{twoFAEnabled ? '2FA is enabled for this account.' : 'Add an extra layer of security with an authenticator app.'}</p>
            {!twoFAEnabled ? (
              <button type="button" className="bs-primary" onClick={handleSetup2FA} disabled={loading}>Setup 2FA</button>
            ) : (
              <>
                <input type="password" value={disablePassword} onChange={(e) => setDisablePassword(e.target.value)} placeholder="Password to disable" />
                <button type="button" className="bs-ghost danger" onClick={handleDisable2FA} disabled={loading}>Disable 2FA</button>
              </>
            )}
            {showQR && <div className="bs-qr"><img src={qrCode} alt="2FA QR code" /><input value={verificationCode} onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))} placeholder="000000" /><button type="button" className="bs-primary" onClick={handleVerify2FA}>Verify</button></div>}
          </div>
        </div>
      </section>
    );
  };

  if (user?.role === 'business') {
    return (
      <div className="dashboard-page">
        <aside className="business-sidebar">
          <div>
            <div className="business-sidebar-brand">
              <div className="business-sidebar-mark">U</div>
              <span>UGCad.io</span>
            </div>
            <nav className="business-sidebar-nav" aria-label="Business dashboard">
              <span className="business-nav-label">Business</span>
              {brandNav.map(({ label, icon: Icon, path, badge, tone, active }) => (
                <button
                  key={label}
                  type="button"
                  className={`business-nav-item ${active ? 'active' : ''}`}
                  onClick={() => navigate(path)}
                >
                  <Icon size={20} />
                  <span>{label}</span>
                  {badge ? <b className={`business-nav-badge ${tone || ''}`}>{badge}</b> : null}
                </button>
              ))}
            </nav>
          </div>
          <div className="business-sidebar-profile">
            <div className="business-avatar">{getInitial(displayName)}</div>
            <div>
              <strong>{displayName}</strong>
              <span>Approved Business</span>
            </div>
          </div>
        </aside>
        <main className="business-main">
          <div className="dashboard-header settings-main-header">
            <div className="header-content">
              <div className="brand-page-title">
                <div className="brand-breadcrumb">
                  <span>Brand</span>
                  <span>›</span>
                  <strong>Settings</strong>
                </div>
                <h1>Settings</h1>
                <p>Manage preferences, profile, billing, and notifications</p>
              </div>
              <div className="brand-search">
                <Search size={20} />
                <input type="search" placeholder="Search deals, creators, briefs..." aria-label="Search dashboard" />
              </div>
              <div className="header-actions">
                <button className="brand-round-action" type="button" aria-label="Notifications">
                  <Bell size={18} />
                  <i />
                </button>
                <button className="brand-round-action" type="button" aria-label="Help">
                  <HelpCircle size={18} />
                </button>
                <button className="brand-profile-photo" type="button" aria-label="Profile">
                  {getInitial(displayName)}
                </button>
              </div>
            </div>
          </div>
          <div className="bs-page bs-dashboard-page">
            <section className="bs-left">
              <div className="bs-tabs">
                {BRAND_TABS.map(tab => (
                  <button key={tab.id} type="button" className={brandTab === tab.id ? 'active' : ''} onClick={() => setBrandTab(tab.id)}>
                    <tab.icon size={18} /> {tab.label}
                  </button>
                ))}
              </div>
              {renderBrandPanel()}
            </section>
            <aside className="bs-rail">
              <section className="bs-status-card">
                <Shield size={16} />
                <h3>Workspace Status</h3>
                <dl>
                  <div><dt>Active Plan</dt><dd>{summary.active_plan || 'Pro'}</dd></div>
                  <div><dt>Wallet</dt><dd>{money(summary.wallet_balance)}</dd></div>
                  <div><dt>Team Count</dt><dd>{summary.team_count || team.members?.length || 0} Members</dd></div>
                </dl>
                <button type="button"><BarChart3 size={16} /> View Workspace Analytics</button>
              </section>
              <section className="bs-quick-card">
                <h3>Quick Actions</h3>
                <button type="button" onClick={inviteMember}><span><UserPlus size={18} /></span>Invite Team<ChevronRight size={17} /></button>
                <button type="button"><span className="warm"><Bolt size={18} /></span>Upgrade Plan<ChevronRight size={17} /></button>
                <button type="button"><span className="green"><LifeBuoy size={18} /></span>Contact Support<ChevronRight size={17} /></button>
              </section>
              <section className="bs-help-card">
                <span><HelpCircle size={20} /></span>
                <h3>Need Help?</h3>
                <p>Our support team is here to help you optimize your workspace.</p>
                <button type="button">Visit Help Center</button>
              </section>
            </aside>
          </div>
        </main>
      </div>
    );
  }

  return (
    <DashboardLayout
      navItems={navItems}
      title="Profile Settings"
      description="Manage your account information and security"
      topbarExtra={null}
      sidebarExtra={null}
    >
      <div className="ps-content">
          <div className="ps-container">
            <div className="ps-tab-sidebar">
              <button
                className={`ps-tab-btn ${activeTab === 'profile' ? 'is-active' : ''}`}
                onClick={() => setActiveTab('profile')}
              >
                <User size={20} /> Profile
              </button>
              <button
                className={`ps-tab-btn ${activeTab === 'password' ? 'is-active' : ''}`}
                onClick={() => setActiveTab('password')}
              >
                <Lock size={20} /> Password
              </button>
              <button
                className={`ps-tab-btn ${activeTab === '2fa' ? 'is-active' : ''}`}
                onClick={() => setActiveTab('2fa')}
              >
                <Shield size={20} /> Two-Factor Auth
              </button>
            </div>

            <div className="ps-panel">
              {activeTab === 'profile' && (
                <>
                  {user?.role === 'creator' && (
                    <div style={{
                      background: '#f9f9f9',
                      border: '1px solid #e0e0e0',
                      borderRadius: '8px',
                      padding: '20px',
                      marginBottom: '24px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between'
                    }}>
                      <div>
                        <p style={{ margin: '0 0 8px 0', fontSize: '14px', color: '#666' }}>Creator Level</p>
                        <h3 style={{ margin: '0 0 8px 0', fontSize: '18px', color: '#07074e' }}>
                          {getLevelInfo(completedWorks).level}
                        </h3>
                        <p style={{ margin: '0', fontSize: '13px', color: '#999' }}>
                          {completedWorks} completed {completedWorks === 1 ? 'work' : 'works'}
                        </p>
                      </div>
                      <span style={{
                        background: getLevelInfo(completedWorks).color,
                        color: 'white',
                        padding: '8px 16px',
                        borderRadius: '24px',
                        fontSize: '13px',
                        fontWeight: '600'
                      }}>
                        {getLevelInfo(completedWorks).badge}
                      </span>
                    </div>
                  )}
                  <h2>Profile Information</h2>

                  <div className="ps-form-group">
                    <label>Profile Photo</label>
                    <div className="ps-photo-upload">
                      <div className="ps-photo-preview">
                        {profilePhoto ? (
                          <img src={`${BACKEND_URL}${profilePhoto}`} alt="Profile" />
                        ) : (
                          <div className="ps-photo-placeholder">
                            <Camera size={48} />
                          </div>
                        )}
                      </div>
                      <div className="ps-photo-actions">
                        <input
                          type="file"
                          accept="image/*"
                          onChange={handlePhotoUpload}
                          id="photo-upload"
                        />
                        <label htmlFor="photo-upload">
                          {uploadingPhoto ? 'Uploading...' : 'Change Photo'}
                        </label>
                        <p className="ps-hint">JPG, PNG or WebP. Max 2MB.</p>
                      </div>
                    </div>
                  </div>

                  <div className="ps-form-group">
                    <label>Bio</label>
                    <textarea
                      value={bio}
                      onChange={(e) => setBio(e.target.value)}
                      placeholder="Tell us about yourself..."
                      rows={4}
                      maxLength={500}
                    />
                    <span className="ps-char-count">{bio.length}/500</span>
                  </div>

                  <div className="ps-form-group">
                    <label>Description</label>
                    <textarea
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                      placeholder="Add a detailed description..."
                      rows={6}
                      maxLength={1000}
                    />
                    <span className="ps-char-count">{description.length}/1000</span>
                  </div>

                  <button
                    className="ps-btn-primary"
                    onClick={handleUpdateProfile}
                    disabled={loading}
                  >
                    <Save size={20} /> {loading ? 'Saving...' : 'Save Changes'}
                  </button>
                </>
              )}

              {activeTab === 'password' && (
                <>
                  <h2>Change Password</h2>
                  <form onSubmit={handleChangePassword}>
                    <div className="ps-form-group">
                      <label>Current Password</label>
                      <input
                        type="password"
                        value={oldPassword}
                        onChange={(e) => setOldPassword(e.target.value)}
                        placeholder="Enter current password"
                        required
                      />
                    </div>

                    <div className="ps-form-group">
                      <label>New Password</label>
                      <input
                        type="password"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        placeholder="Enter new password (min 8 characters)"
                        required
                      />
                    </div>

                    <div className="ps-form-group">
                      <label>Confirm New Password</label>
                      <input
                        type="password"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        placeholder="Confirm new password"
                        required
                      />
                    </div>

                    <button type="submit" className="ps-btn-primary" disabled={loading}>
                      <Lock size={20} /> {loading ? 'Changing...' : 'Change Password'}
                    </button>
                  </form>
                </>
              )}

              {activeTab === '2fa' && (
                <>
                  <h2>Two-Factor Authentication</h2>
                  <p className="ps-panel-desc">
                    Add an extra layer of security to your account with 2FA using Google Authenticator.
                  </p>

                  {!twoFAEnabled ? (
                    <>
                      {!showQR ? (
                        <div className="ps-2fa-setup">
                          <div className="ps-info-box">
                            <Shield size={48} />
                            <h3>Enable Two-Factor Authentication</h3>
                            <p>Protect your account with an additional security layer</p>
                          </div>
                          <button
                            className="ps-btn-primary"
                            onClick={handleSetup2FA}
                            disabled={loading}
                          >
                            <Shield size={20} /> {loading ? 'Setting up...' : 'Setup 2FA'}
                          </button>
                        </div>
                      ) : (
                        <div className="ps-2fa-verification">
                          <h3>Scan QR Code</h3>
                          <p>Open Google Authenticator and scan this QR code:</p>
                          <div className="ps-qr-code">
                            <img src={qrCode} alt="QR Code" />
                          </div>
                          <div className="ps-secret-key">
                            <p><strong>Manual Entry Key:</strong></p>
                            <code>{secret}</code>
                          </div>
                          <div className="ps-form-group">
                            <label>Enter 6-digit code from Google Authenticator</label>
                            <input
                              type="text"
                              value={verificationCode}
                              onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                              placeholder="000000"
                              maxLength={6}
                            />
                          </div>
                          <button
                            className="ps-btn-primary"
                            onClick={handleVerify2FA}
                            disabled={loading}
                          >
                            {loading ? 'Verifying...' : 'Verify & Enable'}
                          </button>
                        </div>
                      )}
                    </>
                  ) : (
                    <div className="ps-2fa-enabled">
                      <div className="ps-success-box">
                        <Shield size={48} />
                        <h3>2FA is Enabled</h3>
                        <p>Your account is protected with two-factor authentication</p>
                      </div>
                      <div className="ps-form-group">
                        <label>Enter your password to disable 2FA</label>
                        <input
                          type="password"
                          value={disablePassword}
                          onChange={(e) => setDisablePassword(e.target.value)}
                          placeholder="Enter your password"
                        />
                      </div>
                      <button
                        className="ps-btn-danger"
                        onClick={handleDisable2FA}
                        disabled={loading}
                      >
                        {loading ? 'Disabling...' : 'Disable 2FA'}
                      </button>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
      </div>
    </DashboardLayout>
  );
}
