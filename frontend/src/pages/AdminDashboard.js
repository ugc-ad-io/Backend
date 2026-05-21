import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import { Users, Briefcase, LogOut, CheckCircle, XCircle, TrendingUp, MessageSquare, CreditCard, DollarSign, Bell, Mail, Phone, UserPlus, BarChart, Download } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export default function AdminDashboard() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('stats');
  const [stats, setStats] = useState(null);
  const [pendingProfiles, setPendingProfiles] = useState([]);
  const [pendingCampaigns, setPendingCampaigns] = useState([]);
  const [allUsers, setAllUsers] = useState([]);
  const [pendingWithdrawals, setPendingWithdrawals] = useState([]);
  const [allCampaigns, setAllCampaigns] = useState([]);
  const [campaignAssignments, setCampaignAssignments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedUser, setSelectedUser] = useState(null);
  const [showUserModal, setShowUserModal] = useState(false);
  const [showEditUserModal, setShowEditUserModal] = useState(false);
  const [showAssignModal, setShowAssignModal] = useState(false);
  const [selectedCampaignForAssign, setSelectedCampaignForAssign] = useState(null);
  const [selectedManagerForAssign, setSelectedManagerForAssign] = useState('');
  const [editUserData, setEditUserData] = useState({
    nickname: '',
    email: '',
    role: '',
    balance: 0
  });
  const [allChats, setAllChats] = useState([]);
  const [selectedChat, setSelectedChat] = useState(null);
  const [chatMessages, setChatMessages] = useState([]);
  const [paymentGateways, setPaymentGateways] = useState([]);
  const [showGatewayModal, setShowGatewayModal] = useState(false);
  const [selectedGateway, setSelectedGateway] = useState(null);
  const [gatewayFormData, setGatewayFormData] = useState({
    gateway_name: 'razorpay',
    key_id: '',
    key_secret: '',
    enabled: true,
    is_default: false
  });
  const [paymentTransactions, setPaymentTransactions] = useState([]);
  const [notificationGateways, setNotificationGateways] = useState([]);
  const [showNotificationModal, setShowNotificationModal] = useState(false);
  const [notificationFormData, setNotificationFormData] = useState({
    gateway_type: 'email',
    provider: 'aws_ses',
    config: {},
    enabled: true,
    is_default: false
  });
  const [notificationLogs, setNotificationLogs] = useState([]);
  const [broadcastFormData, setBroadcastFormData] = useState({
    title: '',
    message: '',
    type: 'info',
    target_type: 'all',
    target_roles: [],
    link: ''
  });
  const [analytics, setAnalytics] = useState(null);
  const [staff, setStaff] = useState([]);
  const [showStaffModal, setShowStaffModal] = useState(false);
  const [staffFormData, setStaffFormData] = useState({
    email: '',
    nickname: '',
    role: 'campaign_manager',
    password: '',
    invite_mode: 'direct',
    permissions: []
  });

  useEffect(() => {
    fetchStats();
    fetchPendingProfiles();
    fetchPendingCampaigns();
    fetchPendingWithdrawals();
    fetchAllCampaigns();
    fetchCampaignAssignments();
    if (user?.role === 'admin') {
      fetchAllUsers();
      fetchAnalytics();
    }
  }, []);

  const fetchPendingWithdrawals = async () => {
    try {
      const response = await axios.get(`${API}/admin/withdrawals?status=pending`);
      setPendingWithdrawals(response.data);
    } catch (error) {
      console.error('Failed to load withdrawals');
    }
  };

  const fetchAllCampaigns = async () => {
    try {
      const response = await axios.get(`${API}/campaigns`);
      setAllCampaigns(response.data);
    } catch (error) {
      console.error('Failed to load all campaigns');
    }
  };

  const fetchCampaignAssignments = async () => {
    try {
      const response = await axios.get(`${API}/admin/campaign-assignments`);
      setCampaignAssignments(response.data);
    } catch (error) {
      console.error('Failed to load campaign assignments');
    }
  };

  const fetchStats = async () => {
    try {
      const response = await axios.get(`${API}/admin/stats`);
      setStats(response.data);
    } catch (error) {
      toast.error('Failed to load stats');
    }
  };

  const fetchPendingProfiles = async () => {
    try {
      const response = await axios.get(`${API}/admin/pending-profiles`);
      setPendingProfiles(response.data);
    } catch (error) {
      toast.error('Failed to load pending profiles');
    } finally {
      setLoading(false);
    }
  };

  const fetchPendingCampaigns = async () => {
    try {
      const response = await axios.get(`${API}/admin/pending-campaigns`);
      setPendingCampaigns(response.data);
    } catch (error) {
      toast.error('Failed to load pending campaigns');
    }
  };

  const fetchAllUsers = async () => {
    try {
      const response = await axios.get(`${API}/admin/users`);
      setAllUsers(response.data);
    } catch (error) {
      toast.error('Failed to load users');
    }
  };

  const fetchAllChats = async () => {
    try {
      const response = await axios.get(`${API}/admin/chats`);
      setAllChats(response.data);
    } catch (error) {
      toast.error('Failed to load chats');
    }
  };

  const fetchChatMessages = async (user1Id, user2Id) => {
    try {
      const response = await axios.get(`${API}/admin/chat/${user1Id}/${user2Id}`);
      setChatMessages(response.data);
    } catch (error) {
      toast.error('Failed to load chat messages');
    }
  };

  const fetchPaymentGateways = async () => {
    try {
      const response = await axios.get(`${API}/admin/payment-gateways`);
      setPaymentGateways(response.data);
    } catch (error) {
      toast.error('Failed to load payment gateways');
    }
  };

  const fetchPaymentTransactions = async () => {
    try {
      const response = await axios.get(`${API}/admin/payment-transactions`);
      setPaymentTransactions(response.data);
    } catch (error) {
      toast.error('Failed to load transactions');
    }
  };

  const fetchNotificationGateways = async () => {
    try {
      const response = await axios.get(`${API}/admin/notification-gateways`);
      setNotificationGateways(response.data);
    } catch (error) {
      toast.error('Failed to load notification gateways');
    }
  };

  const fetchNotificationLogs = async () => {
    try {
      const response = await axios.get(`${API}/admin/notification-logs`);
      setNotificationLogs(response.data);
    } catch (error) {
      toast.error('Failed to load notification logs');
    }
  };

  const handleCreateNotificationGateway = () => {
    setNotificationFormData({
      gateway_type: 'email',
      provider: 'aws_ses',
      config: {},
      enabled: true,
      is_default: false
    });
    setShowNotificationModal(true);
  };

  const handleSaveNotificationGateway = async () => {
    try {
      await axios.post(`${API}/admin/notification-gateway`, notificationFormData);
      toast.success('Notification gateway saved successfully');
      setShowNotificationModal(false);
      fetchNotificationGateways();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to save gateway');
    }
  };

  const handleToggleNotificationGateway = async (gatewayId, currentlyEnabled) => {
    try {
      await axios.patch(`${API}/admin/notification-gateway/${gatewayId}?enabled=${!currentlyEnabled}`);
      toast.success(`Gateway ${currentlyEnabled ? 'disabled' : 'enabled'}`);
      fetchNotificationGateways();
    } catch (error) {
      toast.error('Failed to update gateway');
    }
  };

  const handleDeleteNotificationGateway = async (gatewayId) => {
    if (!window.confirm('Are you sure you want to delete this gateway?')) return;
    
    try {
      await axios.delete(`${API}/admin/notification-gateway/${gatewayId}`);
      toast.success('Gateway deleted');
      fetchNotificationGateways();
    } catch (error) {
      toast.error('Failed to delete gateway');
    }
  };

  const handleBroadcastNotification = async () => {
    if (!broadcastFormData.title || !broadcastFormData.message) {
      toast.error('Title and message are required');
      return;
    }

    try {
      const payload = {
        title: broadcastFormData.title,
        message: broadcastFormData.message,
        type: broadcastFormData.type,
        link: broadcastFormData.link || null
      };

      if (broadcastFormData.target_type === 'roles') {
        payload.target_roles = broadcastFormData.target_roles;
      }

      const response = await axios.post(`${API}/admin/broadcast-notification`, payload);
      toast.success(response.data.message);
      setBroadcastFormData({
        title: '',
        message: '',
        type: 'info',
        target_type: 'all',
        target_roles: [],
        link: ''
      });
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to send broadcast');
    }
  };

  const fetchAnalytics = async () => {
    try {
      const response = await axios.get(`${API}/admin/analytics`);
      setAnalytics(response.data);
    } catch (error) {
      toast.error('Failed to load analytics');
    }
  };

  const fetchStaff = async () => {
    try {
      const response = await axios.get(`${API}/admin/staff`);
      setStaff(response.data);
    } catch (error) {
      toast.error('Failed to load staff');
    }
  };

  const handleCreateStaff = async () => {
    if (!staffFormData.email || !staffFormData.nickname) {
      toast.error('Email and nickname are required');
      return;
    }

    if (staffFormData.invite_mode === 'direct' && !staffFormData.password) {
      toast.error('Password is required for direct creation');
      return;
    }

    try {
      const payload = {
        email: staffFormData.email,
        nickname: staffFormData.nickname,
        role: staffFormData.role,
        permissions: staffFormData.permissions
      };

      if (staffFormData.invite_mode === 'direct') {
        payload.password = staffFormData.password;
      }

      const response = await axios.post(`${API}/admin/staff/create`, payload);
      toast.success(response.data.message);
      
      if (response.data.invite_link) {
        alert(`Invite link: ${window.location.origin}${response.data.invite_link}`);
      }
      
      setShowStaffModal(false);
      fetchStaff();
      setStaffFormData({
        email: '',
        nickname: '',
        role: 'campaign_manager',
        password: '',
        invite_mode: 'direct',
        permissions: []
      });
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to create staff');
    }
  };

  const handleExportWithdrawals = async () => {
    try {
      const response = await axios.get(`${API}/admin/withdrawals/export`, {
        responseType: 'blob'
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `withdrawals_${new Date().toISOString().split('T')[0]}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      toast.success('CSV exported successfully');
    } catch (error) {
      toast.error('Failed to export CSV');
    }
  };

  const handleApproveProfile = async (userId) => {
    try {
      await axios.post(`${API}/admin/approve-profile`, {
        item_id: userId,
        action: 'approve'
      });
      toast.success('Profile approved successfully');
      fetchPendingProfiles();
      fetchStats();
    } catch (error) {
      toast.error('Failed to approve profile');
    }
  };

  const handleRejectProfile = async (userId) => {
    try {
      await axios.post(`${API}/admin/approve-profile`, {
        item_id: userId,
        action: 'reject',
        reason: 'Profile does not meet requirements'
      });
      toast.success('Profile rejected');
      fetchPendingProfiles();
      fetchStats();
    } catch (error) {
      toast.error('Failed to reject profile');
    }
  };

  const handleApproveCampaign = async (campaignId) => {
    try {
      await axios.post(`${API}/admin/approve-campaign`, {
        item_id: campaignId,
        action: 'approve'
      });
      toast.success('Campaign approved successfully');
      fetchPendingCampaigns();
      fetchStats();
    } catch (error) {
      toast.error('Failed to approve campaign');
    }
  };

  const handleRejectCampaign = async (campaignId) => {
    try {
      await axios.post(`${API}/admin/approve-campaign`, {
        item_id: campaignId,
        action: 'reject',
        reason: 'Campaign does not meet guidelines'
      });
      toast.success('Campaign rejected');
      fetchPendingCampaigns();
      fetchStats();
    } catch (error) {
      toast.error('Failed to reject campaign');
    }
  };

  const handleApproveWithdrawal = async (withdrawalId) => {
    try {
      await axios.post(`${API}/admin/withdrawals/${withdrawalId}/approve`);
      toast.success('Withdrawal approved successfully!');
      fetchPendingWithdrawals();
      fetchStats();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to approve withdrawal');
    }
  };

  const handleRejectWithdrawal = async (withdrawalId) => {
    const reason = prompt('Enter rejection reason:');
    if (!reason) return;
    
    try {
      await axios.post(`${API}/admin/withdrawals/${withdrawalId}/reject?reason=${encodeURIComponent(reason)}`);
      toast.success('Withdrawal rejected and amount refunded to user');
      fetchPendingWithdrawals();
      fetchStats();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to reject withdrawal');
    }
  };

  const handleViewUser = (userId) => {
    const userDetails = allUsers.find(u => u.id === userId);
    setSelectedUser(userDetails);
    setShowUserModal(true);
  };

  const handleAssignCampaign = async () => {
    if (!selectedCampaignForAssign || !selectedManagerForAssign) {
      toast.error('Please select a manager');
      return;
    }

    try {
      const response = await axios.post(
        `${API}/admin/assign-campaign?campaign_id=${selectedCampaignForAssign.id}&manager_id=${selectedManagerForAssign}`
      );
      toast.success(response.data.message);
      setShowAssignModal(false);
      fetchCampaignAssignments();
      fetchAllCampaigns();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to assign campaign');
    }
  };

  const handleEditUser = (user) => {
    setSelectedUser(user);
    setEditUserData({
      nickname: user.nickname,
      email: user.email,
      role: user.role,
      balance: user.balance || 0
    });
    setShowEditUserModal(true);
  };

  const handleUpdateUser = async () => {
    try {
      await axios.post(`${API}/admin/user/update`, {
        user_id: selectedUser.id,
        ...editUserData
      });
      toast.success('User updated successfully');
      setShowEditUserModal(false);
      fetchAllUsers();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to update user');
    }
  };

  const handleBanUser = async (userId, currentlyBanned) => {
    const action = currentlyBanned ? 'unban' : 'ban';
    const confirmMessage = currentlyBanned 
      ? 'Are you sure you want to unban this user?'
      : 'Are you sure you want to ban this user? They will not be able to log in.';
    
    if (!window.confirm(confirmMessage)) return;

    let banReason = null;
    if (!currentlyBanned) {
      banReason = prompt('Enter ban reason:');
      if (!banReason) return;
    }

    try {
      await axios.post(`${API}/admin/user/ban`, {
        user_id: userId,
        banned: !currentlyBanned,
        ban_reason: banReason
      });
      toast.success(`User ${action}ned successfully`);
      fetchAllUsers();
    } catch (error) {
      toast.error(error.response?.data?.detail || `Failed to ${action} user`);
    }
  };

  const handleCreateGateway = () => {
    setSelectedGateway(null);
    setGatewayFormData({
      gateway_name: 'razorpay',
      key_id: '',
      key_secret: '',
      enabled: true,
      is_default: false
    });
    setShowGatewayModal(true);
  };

  const handleEditGateway = (gateway) => {
    setSelectedGateway(gateway);
    setGatewayFormData({
      gateway_name: gateway.gateway_name,
      key_id: gateway.key_id || '',
      key_secret: '',
      enabled: gateway.enabled,
      is_default: gateway.is_default
    });
    setShowGatewayModal(true);
  };

  const handleSaveGateway = async () => {
    try {
      await axios.post(`${API}/admin/payment-gateway`, gatewayFormData);
      toast.success('Payment gateway saved successfully');
      setShowGatewayModal(false);
      fetchPaymentGateways();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to save gateway');
    }
  };

  const handleToggleGateway = async (gatewayName, currentlyEnabled) => {
    try {
      await axios.patch(`${API}/admin/payment-gateway/${gatewayName}`, {
        enabled: !currentlyEnabled
      });
      toast.success(`Gateway ${currentlyEnabled ? 'disabled' : 'enabled'} successfully`);
      fetchPaymentGateways();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to update gateway');
    }
  };

  const handleSetDefault = async (gatewayName) => {
    try {
      await axios.patch(`${API}/admin/payment-gateway/${gatewayName}`, {
        is_default: true
      });
      toast.success('Default gateway updated');
      fetchPaymentGateways();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to set default');
    }
  };

  const handleDeleteGateway = async (gatewayName) => {
    if (!window.confirm(`Are you sure you want to delete ${gatewayName} gateway?`)) return;
    
    try {
      await axios.delete(`${API}/admin/payment-gateway/${gatewayName}`);
      toast.success('Gateway deleted successfully');
      fetchPaymentGateways();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to delete gateway');
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  return (
    <div className="admin-dashboard">
      <div className="dashboard-header">
        <div className="header-content">
          <div>
            <h1>Admin Dashboard</h1>
            <p>Welcome, {user?.nickname} - {user?.role}</p>
          </div>
          <button className="btn-secondary" onClick={handleLogout} data-testid="logout-btn">
            <LogOut size={20} /> Logout
          </button>
        </div>
      </div>

      <div className="dashboard-content">
        {analytics && user?.role === 'admin' && (
          <div className="analytics-cards">
            <div className="analytics-card">
              <div className="card-icon" style={{background: '#dbeafe'}}>
                <DollarSign size={24} color="#2563eb" />
              </div>
              <div className="card-content">
                <p className="card-label">Platform Earnings</p>
                <h3 className="card-value">${analytics.platform_commission.toLocaleString()}</h3>
                <p className="card-sub">20% commission</p>
              </div>
            </div>
            <div className="analytics-card">
              <div className="card-icon" style={{background: '#d1fae5'}}>
                <Users size={24} color="#059669" />
              </div>
              <div className="card-content">
                <p className="card-label">New Creators</p>
                <h3 className="card-value">{analytics.new_creators}</h3>
                <p className="card-sub">Last 30 days</p>
              </div>
            </div>
            <div className="analytics-card">
              <div className="card-icon" style={{background: '#fef3c7'}}>
                <Briefcase size={24} color="#d97706" />
              </div>
              <div className="card-content">
                <p className="card-label">New Businesses</p>
                <h3 className="card-value">{analytics.new_businesses}</h3>
                <p className="card-sub">Last 30 days</p>
              </div>
            </div>
            <div className="analytics-card">
              <div className="card-icon" style={{background: '#e0e7ff'}}>
                <TrendingUp size={24} color="#667eea" />
              </div>
              <div className="card-content">
                <p className="card-label">Active Campaigns</p>
                <h3 className="card-value">{analytics.active_campaigns}</h3>
                <p className="card-sub">of {analytics.total_campaigns} total</p>
              </div>
            </div>
          </div>
        )}
        
        <div className="tabs">
          <button
            className={`tab ${activeTab === 'stats' ? 'active' : ''}`}
            onClick={() => setActiveTab('stats')}
            data-testid="tab-stats"
          >
            <TrendingUp size={20} /> Overview
          </button>
          <button
            className={`tab ${activeTab === 'profiles' ? 'active' : ''}`}
            onClick={() => setActiveTab('profiles')}
            data-testid="tab-profiles"
          >
            <Users size={20} /> Profiles ({pendingProfiles.length})
          </button>
          <button
            className={`tab ${activeTab === 'campaigns' ? 'active' : ''}`}
            onClick={() => setActiveTab('campaigns')}
            data-testid="tab-campaigns"
          >
            <Briefcase size={20} /> Campaigns ({pendingCampaigns.length})
          </button>
          <button
            className={`tab ${activeTab === 'withdrawals' ? 'active' : ''}`}
            onClick={() => setActiveTab('withdrawals')}
            data-testid="tab-withdrawals"
          >
            <Briefcase size={20} /> Withdrawals ({pendingWithdrawals.length})
          </button>
          <button
            className={`tab ${activeTab === 'allcampaigns' ? 'active' : ''}`}
            onClick={() => setActiveTab('allcampaigns')}
            data-testid="tab-allcampaigns"
          >
            <Briefcase size={20} /> All Campaigns
          </button>
          {user?.role === 'admin' && (
            <>
              <button
                className={`tab ${activeTab === 'users' ? 'active' : ''}`}
                onClick={() => setActiveTab('users')}
                data-testid="tab-users"
              >
                <Users size={20} /> All Users
              </button>
              <button
                className={`tab ${activeTab === 'assignments' ? 'active' : ''}`}
                onClick={() => setActiveTab('assignments')}
                data-testid="tab-assignments"
              >
                <Briefcase size={20} /> Campaign Assignments
              </button>
              <button
                className={`tab ${activeTab === 'chats' ? 'active' : ''}`}
                onClick={() => {
                  setActiveTab('chats');
                  fetchAllChats();
                }}
                data-testid="tab-chats"
              >
                <MessageSquare size={20} /> Chat Monitoring
              </button>
              <button
                className={`tab ${activeTab === 'payments' ? 'active' : ''}`}
                onClick={() => {
                  setActiveTab('payments');
                  fetchPaymentGateways();
                  fetchPaymentTransactions();
                }}
                data-testid="tab-payments"
              >
                <CreditCard size={20} /> Payment Gateways
              </button>
              <button
                className={`tab ${activeTab === 'notifications' ? 'active' : ''}`}
                onClick={() => {
                  setActiveTab('notifications');
                  fetchNotificationGateways();
                  fetchNotificationLogs();
                }}
                data-testid="tab-notifications"
              >
                <Bell size={20} /> Notifications
              </button>
              <button
                className={`tab ${activeTab === 'broadcast' ? 'active' : ''}`}
                onClick={() => setActiveTab('broadcast')}
                data-testid="tab-broadcast"
              >
                <MessageSquare size={20} /> Broadcast
              </button>
              <button
                className={`tab ${activeTab === 'staff' ? 'active' : ''}`}
                onClick={() => {
                  setActiveTab('staff');
                  fetchStaff();
                }}
                data-testid="tab-staff"
              >
                <UserPlus size={20} /> Staff Management
              </button>
              <button
                className={`tab ${activeTab === 'analytics' ? 'active' : ''}`}
                onClick={() => {
                  setActiveTab('analytics');
                  fetchAnalytics();
                }}
                data-testid="tab-analytics"
              >
                <BarChart size={20} /> Analytics
              </button>
            </>
          )}
        </div>

        <div className="tab-content">
          {activeTab === 'stats' && stats && (
            <div className="stats-section fade-in">
              <h2>Platform Statistics</h2>
              <div className="stats-grid">
                <div className="stat-card">
                  <div className="stat-icon">
                    <Users size={32} />
                  </div>
                  <div>
                    <p className="stat-label">Total Users</p>
                    <p className="stat-value">{stats.total_users}</p>
                  </div>
                </div>
                <div className="stat-card">
                  <div className="stat-icon">
                    <Users size={32} />
                  </div>
                  <div>
                    <p className="stat-label">Pending Profiles</p>
                    <p className="stat-value">{stats.pending_profiles}</p>
                  </div>
                </div>
                <div className="stat-card">
                  <div className="stat-icon">
                    <Briefcase size={32} />
                  </div>
                  <div>
                    <p className="stat-label">Pending Campaigns</p>
                    <p className="stat-value">{stats.pending_campaigns}</p>
                  </div>
                </div>
                <div className="stat-card">
                  <div className="stat-icon">
                    <Briefcase size={32} />
                  </div>
                  <div>
                    <p className="stat-label">Active Campaigns</p>
                    <p className="stat-value">{stats.active_campaigns}</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'profiles' && (
            <div className="profiles-section fade-in">
              <h2>Pending Profile Approvals</h2>
              {loading ? (
                <div className="loading">Loading...</div>
              ) : pendingProfiles.length === 0 ? (
                <div className="empty-state">
                  <CheckCircle size={64} />
                  <p>No pending profile approvals</p>
                </div>
              ) : (
                <div className="items-grid">
                  {pendingProfiles.map(profile => (
                    <div key={profile.id} className="profile-card" data-testid={`profile-${profile.id}`}>
                      <div className="profile-header">
                        <div>
                          <h3>{profile.nickname}</h3>
                          <span className="badge badge-pending">{profile.role}</span>
                        </div>
                      </div>
                      <div className="profile-details">
                        <p><strong>Email:</strong> {profile.email}</p>
                        {profile.profile && (
                          <>
                            {profile.role === 'creator' && (
                              <>
                                <p><strong>Bio:</strong> {profile.profile.bio?.substring(0, 100)}...</p>
                                <p><strong>Tags:</strong> {profile.profile.tags?.join(', ')}</p>
                                <p><strong>Rate Card:</strong></p>
                                <ul className="rate-list">
                                  <li>30s Video: ${profile.profile.rate_card?.video_30s}</li>
                                  <li>60s Video: ${profile.profile.rate_card?.video_60s}</li>
                                  <li>Photo: ${profile.profile.rate_card?.photo_post}</li>
                                </ul>
                              </>
                            )}
                            {profile.role === 'business' && (
                              <>
                                <p><strong>Description:</strong> {profile.profile.business_description?.substring(0, 100)}...</p>
                                <p><strong>Industry:</strong> {profile.profile.industry_category}</p>
                                <p><strong>Product Type:</strong> {profile.profile.product_type}</p>
                              </>
                            )}
                          </>
                        )}
                      </div>
                      <div className="profile-actions">
                        <button
                          className="btn-approve"
                          onClick={() => handleApproveProfile(profile.id)}
                          data-testid={`approve-profile-${profile.id}`}
                        >
                          <CheckCircle size={18} /> Approve
                        </button>
                        <button
                          className="btn-reject"
                          onClick={() => handleRejectProfile(profile.id)}
                          data-testid={`reject-profile-${profile.id}`}
                        >
                          <XCircle size={18} /> Reject
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'campaigns' && (
            <div className="campaigns-section fade-in">
              <h2>Pending Campaign Approvals</h2>
              {pendingCampaigns.length === 0 ? (
                <div className="empty-state">
                  <CheckCircle size={64} />
                  <p>No pending campaign approvals</p>
                </div>
              ) : (
                <div className="items-grid">
                  {pendingCampaigns.map(campaign => (
                    <div key={campaign.id} className="campaign-card" data-testid={`campaign-${campaign.id}`}>
                      <div className="campaign-header">
                        <h3>{campaign.title}</h3>
                        <span className="badge badge-pending">{campaign.status.replace('_', ' ')}</span>
                      </div>
                      <div className="campaign-details">
                        <p><strong>Business:</strong> {campaign.business_nickname}</p>
                        <p><strong>Budget:</strong> ${campaign.budget_min} - ${campaign.budget_max}</p>
                        <p><strong>Brief:</strong> {campaign.brief_text.substring(0, 150)}...</p>
                        <p><strong>Objectives:</strong></p>
                        <ul className="objectives-list">
                          {campaign.objectives.map((obj, idx) => (
                            <li key={idx}>{obj}</li>
                          ))}
                        </ul>
                        <p><strong>Requires Shipment:</strong> {campaign.requires_shipment ? 'Yes' : 'No'}</p>
                      </div>
                      <div className="campaign-actions">
                        <button
                          className="btn-approve"
                          onClick={() => handleApproveCampaign(campaign.id)}
                          data-testid={`approve-campaign-${campaign.id}`}
                        >
                          <CheckCircle size={18} /> Approve
                        </button>
                        <button
                          className="btn-reject"
                          onClick={() => handleRejectCampaign(campaign.id)}
                          data-testid={`reject-campaign-${campaign.id}`}
                        >
                          <XCircle size={18} /> Reject
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'withdrawals' && (
            <div className="withdrawals-section fade-in">
              <div className="section-header">
                <h2>Pending Withdrawals</h2>
                <button className="btn-secondary" onClick={handleExportWithdrawals}>
                  <Download size={18} /> Export CSV
                </button>
              </div>
              {pendingWithdrawals.length === 0 ? (
                <div className="empty-state">
                  <CheckCircle size={64} />
                  <p>No pending withdrawals</p>
                </div>
              ) : (
                <div className="items-grid">
                  {pendingWithdrawals.map(withdrawal => (
                    <div key={withdrawal.id} className="withdrawal-card" data-testid={`withdrawal-${withdrawal.id}`}>
                      <div className="withdrawal-header">
                        <h3>Withdrawal Request</h3>
                        <span className="badge badge-pending">{withdrawal.status}</span>
                      </div>
                      <div className="withdrawal-details">
                        <p><strong>User ID:</strong> {withdrawal.user_id}</p>
                        <p><strong>Amount:</strong> ${withdrawal.amount.toFixed(2)}</p>
                        <p><strong>Payment Method:</strong> {withdrawal.payment_method}</p>
                        <p><strong>Requested:</strong> {new Date(withdrawal.requested_at).toLocaleDateString()}</p>
                      </div>
                      <div className="withdrawal-actions">
                        <button
                          className="btn-approve"
                          onClick={() => handleApproveWithdrawal(withdrawal.id)}
                          data-testid={`approve-withdrawal-${withdrawal.id}`}
                        >
                          <CheckCircle size={18} /> Approve
                        </button>
                        <button
                          className="btn-reject"
                          onClick={() => handleRejectWithdrawal(withdrawal.id)}
                          data-testid={`reject-withdrawal-${withdrawal.id}`}
                        >
                          <XCircle size={18} /> Reject
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'allcampaigns' && (
            <div className="allcampaigns-section fade-in">
              <h2>All Campaigns</h2>
              {allCampaigns.length === 0 ? (
                <div className="empty-state">
                  <Briefcase size={64} />
                  <p>No campaigns found</p>
                </div>
              ) : (
                <div className="items-grid">
                  {allCampaigns.map(campaign => (
                    <div key={campaign.id} className="campaign-card" data-testid={`allcampaign-${campaign.id}`}>
                      <div className="campaign-header">
                        <h3>{campaign.title}</h3>
                        <span className={`badge badge-${campaign.status.replace('_', '-')}`}>{campaign.status.replace('_', ' ')}</span>
                      </div>
                      <div className="campaign-details">
                        <p><strong>Business:</strong> {campaign.business_nickname}</p>
                        <p><strong>Budget:</strong> ${campaign.budget_min} - ${campaign.budget_max}</p>
                        <p><strong>Brief:</strong> {campaign.brief_text.substring(0, 150)}...</p>
                        <p><strong>Status:</strong> {campaign.status.replace('_', ' ')}</p>
                        <p><strong>Created:</strong> {new Date(campaign.created_at).toLocaleDateString()}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'users' && user?.role === 'admin' && (
            <div className="users-section fade-in">
              <h2>All Users</h2>
              <div className="users-table">
                <table>
                  <thead>
                    <tr>
                      <th>Nickname</th>
                      <th>Email</th>
                      <th>Role</th>
                      <th>Status</th>
                      <th>Balance</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {allUsers.map(u => (
                      <tr key={u.id} data-testid={`user-row-${u.id}`} className={u.banned ? 'banned-row' : ''}>
                        <td>
                          {u.nickname}
                          {u.banned && <span className="banned-badge">BANNED</span>}
                        </td>
                        <td>{u.email}</td>
                        <td><span className="badge badge-active">{u.role}</span></td>
                        <td><span className={`badge badge-${u.approval_status}`}>{u.approval_status}</span></td>
                        <td>${u.balance?.toFixed(2) || '0.00'}</td>
                        <td>
                          <div className="action-buttons">
                            <button
                              className="btn-edit-small"
                              onClick={() => handleEditUser(u)}
                              title="Edit user"
                            >
                              Edit
                            </button>
                            <button
                              className={u.banned ? 'btn-unban-small' : 'btn-ban-small'}
                              onClick={() => handleBanUser(u.id, u.banned)}
                              title={u.banned ? 'Unban user' : 'Ban user'}
                            >
                              {u.banned ? 'Unban' : 'Ban'}
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === 'assignments' && user?.role === 'admin' && (
            <div className="assignments-section fade-in">
              <h2>Campaign Manager Assignments</h2>
              <p className="section-description">Auto-assigns 10 campaigns per manager. Manually reassign as needed.</p>
              
              {campaignAssignments.length === 0 ? (
                <div className="empty-state">
                  <p>No campaign managers found. Create campaign manager accounts first.</p>
                </div>
              ) : (
                <div className="assignments-grid">
                  {campaignAssignments.map((assignment, idx) => (
                    <div key={idx} className="assignment-card">
                      <div className="assignment-header">
                        <div>
                          <h3>{assignment.manager_nickname}</h3>
                          <p className="manager-email">{assignment.manager_email}</p>
                        </div>
                        <span className="campaign-count-badge">
                          {assignment.campaign_count} Campaigns
                        </span>
                      </div>
                      
                      {assignment.campaigns.length > 0 ? (
                        <div className="campaigns-list">
                          {assignment.campaigns.map((campaign) => (
                            <div key={campaign.id} className="campaign-item-small">
                              <div className="campaign-info-small">
                                <span className="campaign-title-small">{campaign.title}</span>
                                <span className={`status-badge-small ${campaign.status}`}>{campaign.status}</span>
                              </div>
                              <button
                                className="btn-reassign"
                                onClick={() => {
                                  setSelectedCampaignForAssign(campaign);
                                  setShowAssignModal(true);
                                }}
                              >
                                Reassign
                              </button>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="no-campaigns-text">No campaigns assigned yet</p>
                      )}
                    </div>
                  ))}
                </div>
              )}
              
              <div className="unassigned-section">
                <h3>Unassigned Campaigns</h3>
                {allCampaigns.filter(c => !c.assigned_manager && c.status === 'active').length > 0 ? (
                  <div className="unassigned-list">
                    {allCampaigns.filter(c => !c.assigned_manager && c.status === 'active').map((campaign) => (
                      <div key={campaign.id} className="campaign-item-small">
                        <div className="campaign-info-small">
                          <span className="campaign-title-small">{campaign.title}</span>
                          <span className={`status-badge-small ${campaign.status}`}>{campaign.status}</span>
                        </div>
                        <button
                          className="btn-assign"
                          onClick={() => {
                            setSelectedCampaignForAssign(campaign);
                            setShowAssignModal(true);
                          }}
                        >
                          Assign
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="no-campaigns-text">All campaigns are assigned</p>
                )}
              </div>
            </div>
          )}

          {activeTab === 'chats' && user?.role === 'admin' && (
            <div className="chats-section fade-in">
              <h2>Chat Monitoring</h2>
              <p className="section-description">View and monitor all user conversations on the platform</p>
              
              {selectedChat ? (
                <div className="chat-view">
                  <div className="chat-header">
                    <button className="btn-back" onClick={() => setSelectedChat(null)}>
                      ← Back to Conversations
                    </button>
                    <div className="chat-participants">
                      <span className="participant-name">{selectedChat.user1.nickname}</span>
                      <span className="chat-separator">↔</span>
                      <span className="participant-name">{selectedChat.user2.nickname}</span>
                    </div>
                  </div>
                  
                  <div className="chat-messages">
                    {chatMessages.length === 0 ? (
                      <p className="no-messages">No messages in this conversation</p>
                    ) : (
                      chatMessages.map((msg, idx) => (
                        <div 
                          key={idx} 
                          className={`message-item ${msg.filtered ? 'filtered-message' : ''}`}
                        >
                          <div className="message-header">
                            <span className="message-sender">{msg.sender_nickname}</span>
                            <span className="message-time">
                              {new Date(msg.timestamp).toLocaleString()}
                            </span>
                          </div>
                          <div className="message-content">{msg.message}</div>
                          {msg.filtered && (
                            <div className="filtered-badge">⚠️ Content Filtered</div>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                </div>
              ) : (
                <div className="conversations-list">
                  {allChats.length === 0 ? (
                    <div className="empty-state">
                      <MessageSquare size={64} />
                      <p>No conversations found</p>
                    </div>
                  ) : (
                    <div className="conversations-grid">
                      {allChats.map((chat, idx) => (
                        <div 
                          key={idx} 
                          className={`conversation-card ${chat.has_violations ? 'has-violations' : ''}`}
                          onClick={() => {
                            setSelectedChat(chat);
                            fetchChatMessages(chat.user1.id, chat.user2.id);
                          }}
                        >
                          <div className="conversation-participants">
                            <div className="participant">
                              <span className="participant-nickname">{chat.user1.nickname}</span>
                              <span className="participant-role badge badge-active">{chat.user1.role}</span>
                            </div>
                            <div className="conversation-arrow">↔</div>
                            <div className="participant">
                              <span className="participant-nickname">{chat.user2.nickname}</span>
                              <span className="participant-role badge badge-active">{chat.user2.role}</span>
                            </div>
                          </div>
                          
                          <div className="conversation-preview">
                            <p className="last-message">{chat.last_message}</p>
                            <span className="last-message-time">
                              {new Date(chat.last_message_at).toLocaleString()}
                            </span>
                          </div>
                          
                          {chat.has_violations && (
                            <div className="violation-indicator">
                              ⚠️ {chat.violation_count} violation(s) detected
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {activeTab === 'payments' && user?.role === 'admin' && (
            <div className="payments-section fade-in">
              <div className="section-header">
                <h2>Payment Gateway Management</h2>
                <button className="btn-primary" onClick={handleCreateGateway}>
                  <CreditCard size={18} /> Add Gateway
                </button>
              </div>

              <div className="gateways-grid">
                {paymentGateways.length === 0 ? (
                  <div className="empty-state">
                    <CreditCard size={64} />
                    <p>No payment gateways configured</p>
                    <button className="btn-primary" onClick={handleCreateGateway}>
                      Add Your First Gateway
                    </button>
                  </div>
                ) : (
                  paymentGateways.map((gateway) => (
                    <div key={gateway.gateway_name} className="gateway-card">
                      <div className="gateway-header">
                        <div className="gateway-name-section">
                          <h3>{gateway.gateway_name.toUpperCase()}</h3>
                          {gateway.is_default && <span className="default-badge">DEFAULT</span>}
                        </div>
                        <div className="gateway-toggle">
                          <label className="switch">
                            <input
                              type="checkbox"
                              checked={gateway.enabled}
                              onChange={() => handleToggleGateway(gateway.gateway_name, gateway.enabled)}
                            />
                            <span className="slider"></span>
                          </label>
                        </div>
                      </div>

                      <div className="gateway-details">
                        <p><strong>Key ID:</strong> {gateway.key_id}</p>
                        <p><strong>Status:</strong> 
                          <span className={`status-badge ${gateway.enabled ? 'active' : 'inactive'}`}>
                            {gateway.enabled ? 'Active' : 'Inactive'}
                          </span>
                        </p>
                      </div>

                      <div className="gateway-actions">
                        <button className="btn-edit-small" onClick={() => handleEditGateway(gateway)}>
                          Edit
                        </button>
                        {!gateway.is_default && (
                          <button className="btn-default-small" onClick={() => handleSetDefault(gateway.gateway_name)}>
                            Set Default
                          </button>
                        )}
                        <button className="btn-delete-small" onClick={() => handleDeleteGateway(gateway.gateway_name)}>
                          Delete
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </div>

              <div className="transactions-section">
                <h3><DollarSign size={20} /> Payment Transactions</h3>
                {paymentTransactions.length === 0 ? (
                  <p className="no-transactions">No transactions yet</p>
                ) : (
                  <div className="transactions-table">
                    <table>
                      <thead>
                        <tr>
                          <th>Transaction ID</th>
                          <th>Gateway</th>
                          <th>Amount</th>
                          <th>Customer</th>
                          <th>Status</th>
                          <th>Date</th>
                        </tr>
                      </thead>
                      <tbody>
                        {paymentTransactions.map((txn) => (
                          <tr key={txn.id}>
                            <td className="txn-id">{txn.id.substring(0, 8)}...</td>
                            <td>
                              <span className="gateway-badge">{txn.gateway.toUpperCase()}</span>
                            </td>
                            <td className="txn-amount">
                              {txn.currency} {txn.amount.toFixed(2)}
                            </td>
                            <td>{txn.customer_name}</td>
                            <td>
                              <span className={`status-badge ${txn.status}`}>
                                {txn.status}
                              </span>
                            </td>
                            <td>{new Date(txn.created_at).toLocaleString()}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'notifications' && user?.role === 'admin' && (
            <div className="notifications-section fade-in">
              <div className="section-header">
                <h2>Notification Gateways</h2>
                <button className="btn-primary" onClick={handleCreateNotificationGateway}>
                  <Bell size={18} /> Add Gateway
                </button>
              </div>

              <div className="gateways-grid">
                {notificationGateways.length === 0 ? (
                  <div className="empty-state">
                    <Bell size={64} />
                    <p>No notification gateways configured</p>
                    <button className="btn-primary" onClick={handleCreateNotificationGateway}>
                      Add Your First Gateway
                    </button>
                  </div>
                ) : (
                  notificationGateways.map((gateway) => (
                    <div key={gateway.id} className="gateway-card">
                      <div className="gateway-header">
                        <div className="gateway-name-section">
                          {gateway.gateway_type === 'email' ? <Mail size={24} /> : <Phone size={24} />}
                          <div>
                            <h3>{gateway.provider.toUpperCase()}</h3>
                            <p className="gateway-type-label">{gateway.gateway_type.toUpperCase()}</p>
                          </div>
                          {gateway.is_default && <span className="default-badge">DEFAULT</span>}
                        </div>
                        <div className="gateway-toggle">
                          <label className="switch">
                            <input
                              type="checkbox"
                              checked={gateway.enabled}
                              onChange={() => handleToggleNotificationGateway(gateway.id, gateway.enabled)}
                            />
                            <span className="slider"></span>
                          </label>
                        </div>
                      </div>

                      <div className="gateway-details">
                        {gateway.config_masked && Object.entries(gateway.config_masked).map(([key, value]) => (
                          <p key={key}><strong>{key}:</strong> {value}</p>
                        ))}
                        <p><strong>Status:</strong>
                          <span className={`status-badge ${gateway.enabled ? 'active' : 'inactive'}`}>
                            {gateway.enabled ? 'Active' : 'Inactive'}
                          </span>
                        </p>
                      </div>

                      <div className="gateway-actions">
                        <button className="btn-delete-small" onClick={() => handleDeleteNotificationGateway(gateway.id)}>
                          Delete
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </div>

              <div className="logs-section">
                <h3><Bell size={20} /> Notification Logs</h3>
                {notificationLogs.length === 0 ? (
                  <p className="no-transactions">No notifications sent yet</p>
                ) : (
                  <div className="transactions-table">
                    <table>
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>Type</th>
                          <th>Provider</th>
                          <th>Recipient</th>
                          <th>Status</th>
                          <th>Date</th>
                        </tr>
                      </thead>
                      <tbody>
                        {notificationLogs.map((log) => (
                          <tr key={log.id}>
                            <td className="txn-id">{log.id.substring(0, 8)}...</td>
                            <td>{log.type === 'email' ? <Mail size={16} /> : <Phone size={16} />}</td>
                            <td>
                              <span className="gateway-badge">{log.provider.toUpperCase()}</span>
                            </td>
                            <td>{log.recipient}</td>
                            <td>
                              <span className={`status-badge ${log.status}`}>
                                {log.status}
                              </span>
                            </td>
                            <td>{new Date(log.created_at).toLocaleString()}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'staff' && user?.role === 'admin' && (
            <div className="staff-section fade-in">
              <div className="section-header">
                <h2>Staff Management</h2>
                <button className="btn-primary" onClick={() => setShowStaffModal(true)}>
                  <UserPlus size={18} /> Add Staff Member
                </button>
              </div>

              <div className="staff-table">
                {staff.length === 0 ? (
                  <div className="empty-state">
                    <UserPlus size={64} />
                    <p>No staff members yet</p>
                  </div>
                ) : (
                  <table>
                    <thead>
                      <tr>
                        <th>Name</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Joined</th>
                        <th>Permissions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {staff.map((member) => (
                        <tr key={member.id}>
                          <td>{member.nickname}</td>
                          <td>{member.email}</td>
                          <td><span className="badge badge-active">{member.role.replace('_', ' ')}</span></td>
                          <td><span className={`status-badge ${member.approval_status === 'approved' ? 'active' : 'inactive'}`}>
                            {member.approval_status}
                          </span></td>
                          <td>{new Date(member.created_at).toLocaleDateString()}</td>
                          <td>
                            {member.permissions && member.permissions.length > 0 ? (
                              <span className="permission-count">{member.permissions.length} permissions</span>
                            ) : (
                              <span className="no-permissions">Default</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          )}

          {activeTab === 'analytics' && user?.role === 'admin' && analytics && (
            <div className="analytics-detailed-section fade-in">
              <h2>Detailed Analytics</h2>
              
              <div className="analytics-metrics-grid">
                <div className="metric-card">
                  <h4>Total Creators</h4>
                  <p className="big-number">{analytics.total_creators}</p>
                  <span className="metric-change positive">+{analytics.new_creators} this month</span>
                </div>
                <div className="metric-card">
                  <h4>Total Businesses</h4>
                  <p className="big-number">{analytics.total_businesses}</p>
                  <span className="metric-change positive">+{analytics.new_businesses} this month</span>
                </div>
                <div className="metric-card">
                  <h4>Creator Earnings</h4>
                  <p className="big-number">${analytics.total_creator_earnings.toLocaleString()}</p>
                  <span className="metric-info">Total paid to creators</span>
                </div>
                <div className="metric-card highlight">
                  <h4>Platform Commission</h4>
                  <p className="big-number">${analytics.platform_commission.toLocaleString()}</p>
                  <span className="metric-info">20% of {analytics.total_creator_earnings.toLocaleString()}</span>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'broadcast' && user?.role === 'admin' && (
            <div className="broadcast-section fade-in">
              <h2>Broadcast In-App Notification</h2>
              <p className="section-description">Send push notifications to users that appear in their notification bell</p>

              <div className="broadcast-form">
                <div className="form-group">
                  <label>Notification Title *</label>
                  <input
                    type="text"
                    className="input-field"
                    value={broadcastFormData.title}
                    onChange={(e) => setBroadcastFormData({...broadcastFormData, title: e.target.value})}
                    placeholder="Enter notification title"
                  />
                </div>

                <div className="form-group">
                  <label>Message *</label>
                  <textarea
                    className="textarea-field"
                    value={broadcastFormData.message}
                    onChange={(e) => setBroadcastFormData({...broadcastFormData, message: e.target.value})}
                    placeholder="Enter notification message"
                    rows="4"
                  />
                </div>

                <div className="form-row">
                  <div className="form-group">
                    <label>Type</label>
                    <select
                      className="select-input"
                      value={broadcastFormData.type}
                      onChange={(e) => setBroadcastFormData({...broadcastFormData, type: e.target.value})}
                    >
                      <option value="info">Info</option>
                      <option value="success">Success</option>
                      <option value="warning">Warning</option>
                      <option value="error">Error</option>
                    </select>
                  </div>

                  <div className="form-group">
                    <label>Target Audience</label>
                    <select
                      className="select-input"
                      value={broadcastFormData.target_type}
                      onChange={(e) => setBroadcastFormData({...broadcastFormData, target_type: e.target.value, target_roles: []})}
                    >
                      <option value="all">All Users</option>
                      <option value="roles">Specific Roles</option>
                    </select>
                  </div>
                </div>

                {broadcastFormData.target_type === 'roles' && (
                  <div className="form-group">
                    <label>Select Roles</label>
                    <div className="checkbox-group">
                      {['creator', 'business', 'campaign_manager', 'support_staff'].map((role) => (
                        <label key={role} className="checkbox-label">
                          <input
                            type="checkbox"
                            checked={broadcastFormData.target_roles.includes(role)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setBroadcastFormData({
                                  ...broadcastFormData,
                                  target_roles: [...broadcastFormData.target_roles, role]
                                });
                              } else {
                                setBroadcastFormData({
                                  ...broadcastFormData,
                                  target_roles: broadcastFormData.target_roles.filter(r => r !== role)
                                });
                              }
                            }}
                          />
                          <span>{role.replace('_', ' ').toUpperCase()}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                )}

                <div className="form-group">
                  <label>Link (Optional)</label>
                  <input
                    type="text"
                    className="input-field"
                    value={broadcastFormData.link}
                    onChange={(e) => setBroadcastFormData({...broadcastFormData, link: e.target.value})}
                    placeholder="/dashboard or /campaign/123"
                  />
                </div>

                <button className="btn-primary btn-large" onClick={handleBroadcastNotification}>
                  <MessageSquare size={20} /> Send Broadcast
                </button>
              </div>
            </div>
          )}

          {activeTab === 'staff' && user?.role === 'admin' && (
            <div className="staff-section fade-in">
              <div className="section-header">
                <h2>Staff Management</h2>
                <button className="btn-primary" onClick={() => setShowStaffModal(true)}>
                  <UserPlus size={18} /> Add Staff Member
                </button>
              </div>

              <div className="staff-grid">
                {staff.length === 0 ? (
                  <div className="empty-state">
                    <UserPlus size={64} />
                    <p>No staff members yet</p>
                    <button className="btn-primary" onClick={() => setShowStaffModal(true)}>
                      Add Your First Staff Member
                    </button>
                  </div>
                ) : (
                  staff.map((member) => (
                    <div key={member.id} className="staff-card">
                      <div className="staff-header">
                        <div className="staff-info">
                          <h3>{member.nickname}</h3>
                          <p className="staff-email">{member.email}</p>
                        </div>
                        <span className={`role-badge ${member.role}`}>
                          {member.role.replace('_', ' ').toUpperCase()}
                        </span>
                      </div>

                      <div className="staff-details">
                        <p><strong>Status:</strong> 
                          <span className={`status-badge ${member.is_active ? 'active' : 'inactive'}`}>
                            {member.is_active ? 'Active' : 'Inactive'}
                          </span>
                        </p>
                        <p><strong>Joined:</strong> {new Date(member.created_at).toLocaleDateString()}</p>
                        {member.last_login && (
                          <p><strong>Last Login:</strong> {new Date(member.last_login).toLocaleDateString()}</p>
                        )}
                      </div>

                      <div className="staff-permissions">
                        <p><strong>Permissions:</strong></p>
                        <div className="permissions-list">
                          {member.permissions && member.permissions.length > 0 ? (
                            member.permissions.map((perm, idx) => (
                              <span key={idx} className="permission-tag">{perm}</span>
                            ))
                          ) : (
                            <span className="no-permissions">Default permissions</span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {activeTab === 'analytics' && user?.role === 'admin' && analytics && (
            <div className="analytics-section fade-in">
              <h2>Platform Analytics</h2>
              
              <div className="analytics-overview">
                <div className="analytics-row">
                  <div className="analytics-metric">
                    <div className="metric-header">
                      <DollarSign size={20} />
                      <h3>Revenue Metrics</h3>
                    </div>
                    <div className="metric-grid">
                      <div className="metric-item">
                        <span className="metric-label">Total Revenue</span>
                        <span className="metric-value">${analytics.total_revenue?.toLocaleString() || '0'}</span>
                      </div>
                      <div className="metric-item">
                        <span className="metric-label">Platform Commission</span>
                        <span className="metric-value">${analytics.platform_commission?.toLocaleString() || '0'}</span>
                      </div>
                      <div className="metric-item">
                        <span className="metric-label">Creator Earnings</span>
                        <span className="metric-value">${analytics.creator_earnings?.toLocaleString() || '0'}</span>
                      </div>
                    </div>
                  </div>

                  <div className="analytics-metric">
                    <div className="metric-header">
                      <Users size={20} />
                      <h3>User Growth</h3>
                    </div>
                    <div className="metric-grid">
                      <div className="metric-item">
                        <span className="metric-label">Total Users</span>
                        <span className="metric-value">{analytics.total_users || 0}</span>
                      </div>
                      <div className="metric-item">
                        <span className="metric-label">New Creators (30d)</span>
                        <span className="metric-value">{analytics.new_creators || 0}</span>
                      </div>
                      <div className="metric-item">
                        <span className="metric-label">New Businesses (30d)</span>
                        <span className="metric-value">{analytics.new_businesses || 0}</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="analytics-row">
                  <div className="analytics-metric">
                    <div className="metric-header">
                      <Briefcase size={20} />
                      <h3>Campaign Metrics</h3>
                    </div>
                    <div className="metric-grid">
                      <div className="metric-item">
                        <span className="metric-label">Total Campaigns</span>
                        <span className="metric-value">{analytics.total_campaigns || 0}</span>
                      </div>
                      <div className="metric-item">
                        <span className="metric-label">Active Campaigns</span>
                        <span className="metric-value">{analytics.active_campaigns || 0}</span>
                      </div>
                      <div className="metric-item">
                        <span className="metric-label">Completed Campaigns</span>
                        <span className="metric-value">{analytics.completed_campaigns || 0}</span>
                      </div>
                    </div>
                  </div>

                  <div className="analytics-metric">
                    <div className="metric-header">
                      <TrendingUp size={20} />
                      <h3>Performance</h3>
                    </div>
                    <div className="metric-grid">
                      <div className="metric-item">
                        <span className="metric-label">Avg Campaign Value</span>
                        <span className="metric-value">${analytics.avg_campaign_value?.toFixed(0) || '0'}</span>
                      </div>
                      <div className="metric-item">
                        <span className="metric-label">Success Rate</span>
                        <span className="metric-value">{analytics.success_rate?.toFixed(1) || '0'}%</span>
                      </div>
                      <div className="metric-item">
                        <span className="metric-label">Monthly Growth</span>
                        <span className="metric-value">{analytics.monthly_growth?.toFixed(1) || '0'}%</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="export-section">
                <h3>Export Data</h3>
                <div className="export-buttons">
                  <button className="btn-secondary" onClick={handleExportWithdrawals}>
                    <Download size={18} /> Export Withdrawals CSV
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {showAssignModal && selectedCampaignForAssign && (
        <div className="modal-overlay" onClick={() => setShowAssignModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Assign Campaign</h2>
            <p><strong>Campaign:</strong> {selectedCampaignForAssign.title}</p>
            
            <div className="form-group">
              <label>Select Campaign Manager</label>
              <select
                value={selectedManagerForAssign}
                onChange={(e) => setSelectedManagerForAssign(e.target.value)}
                className="select-input"
              >
                <option value="">Choose manager...</option>
                {campaignAssignments.map((assignment) => (
                  <option key={assignment.manager_id} value={assignment.manager_id}>
                    {assignment.manager_nickname} ({assignment.campaign_count} campaigns)
                  </option>
                ))}
              </select>
            </div>
            
            <div className="modal-actions">
              <button className="btn-primary" onClick={handleAssignCampaign}>
                Assign Campaign
              </button>
              <button className="btn-secondary" onClick={() => setShowAssignModal(false)}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {showUserModal && selectedUser && (
        <div className="modal-overlay" onClick={() => setShowUserModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>User Details</h2>
            <div className="user-details-grid">
              <div className="detail-row">
                <span className="detail-label">Nickname:</span>
                <span className="detail-value">{selectedUser.nickname}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Email:</span>
                <span className="detail-value">{selectedUser.email}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Role:</span>
                <span className="badge badge-active">{selectedUser.role}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Status:</span>
                <span className={`badge badge-${selectedUser.approval_status}`}>{selectedUser.approval_status}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Balance:</span>
                <span className="detail-value">${selectedUser.balance?.toFixed(2) || '0.00'}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Joined:</span>
                <span className="detail-value">{new Date(selectedUser.created_at).toLocaleDateString()}</span>
              </div>
            </div>
            <button className="btn-secondary" onClick={() => setShowUserModal(false)}>
              Close
            </button>
          </div>
        </div>
      )}

      {showEditUserModal && selectedUser && (
        <div className="modal-overlay" onClick={() => setShowEditUserModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Edit User</h2>
            <div className="form-group">
              <label>Nickname</label>
              <input
                type="text"
                className="input-field"
                value={editUserData.nickname}
                onChange={(e) => setEditUserData({...editUserData, nickname: e.target.value})}
              />
            </div>
            <div className="form-group">
              <label>Email</label>
              <input
                type="email"
                className="input-field"
                value={editUserData.email}
                onChange={(e) => setEditUserData({...editUserData, email: e.target.value})}
              />
            </div>
            <div className="form-group">
              <label>Role</label>
              <select
                className="select-input"
                value={editUserData.role}
                onChange={(e) => setEditUserData({...editUserData, role: e.target.value})}
              >
                <option value="creator">Creator</option>
                <option value="business">Business</option>
                <option value="admin">Admin</option>
                <option value="campaign_manager">Campaign Manager</option>
                <option value="support_staff">Support Staff</option>
              </select>
            </div>
            <div className="form-group">
              <label>Balance ($)</label>
              <input
                type="number"
                step="0.01"
                className="input-field"
                value={editUserData.balance}
                onChange={(e) => setEditUserData({...editUserData, balance: parseFloat(e.target.value)})}
              />
            </div>
            <div className="modal-actions">
              <button className="btn-primary" onClick={handleUpdateUser}>
                Update User
              </button>
              <button className="btn-secondary" onClick={() => setShowEditUserModal(false)}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {showStaffModal && (
        <div className="modal-overlay" onClick={() => setShowStaffModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Add Staff Member</h2>
            
            <div className="form-group">
              <label>Email *</label>
              <input
                type="email"
                className="input-field"
                value={staffFormData.email}
                onChange={(e) => setStaffFormData({...staffFormData, email: e.target.value})}
                placeholder="staff@example.com"
              />
            </div>

            <div className="form-group">
              <label>Nickname *</label>
              <input
                type="text"
                className="input-field"
                value={staffFormData.nickname}
                onChange={(e) => setStaffFormData({...staffFormData, nickname: e.target.value})}
                placeholder="John Doe"
              />
            </div>

            <div className="form-group">
              <label>Role</label>
              <select
                className="select-input"
                value={staffFormData.role}
                onChange={(e) => setStaffFormData({...staffFormData, role: e.target.value})}
              >
                <option value="campaign_manager">Campaign Manager</option>
                <option value="support_staff">Support Staff</option>
              </select>
            </div>

            <div className="form-group">
              <label>Creation Mode</label>
              <select
                className="select-input"
                value={staffFormData.invite_mode}
                onChange={(e) => setStaffFormData({...staffFormData, invite_mode: e.target.value, password: ''})}
              >
                <option value="direct">Direct (Create with Password)</option>
                <option value="invite">Invite (Send Email Link)</option>
              </select>
            </div>

            {staffFormData.invite_mode === 'direct' && (
              <div className="form-group">
                <label>Password *</label>
                <input
                  type="password"
                  className="input-field"
                  value={staffFormData.password}
                  onChange={(e) => setStaffFormData({...staffFormData, password: e.target.value})}
                  placeholder="Enter password"
                />
              </div>
            )}

            <div className="form-group">
              <label>Permissions (Optional)</label>
              <div className="checkbox-group">
                {['view_campaigns', 'edit_campaigns', 'view_users', 'edit_users', 'view_withdrawals', 'approve_withdrawals', 'view_analytics'].map((perm) => (
                  <label key={perm} className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={staffFormData.permissions.includes(perm)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setStaffFormData({
                            ...staffFormData,
                            permissions: [...staffFormData.permissions, perm]
                          });
                        } else {
                          setStaffFormData({
                            ...staffFormData,
                            permissions: staffFormData.permissions.filter(p => p !== perm)
                          });
                        }
                      }}
                    />
                    <span>{perm.replace(/_/g, ' ').toUpperCase()}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="modal-actions">
              <button className="btn-primary" onClick={handleCreateStaff}>
                Create Staff Member
              </button>
              <button className="btn-secondary" onClick={() => setShowStaffModal(false)}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {showNotificationModal && (
        <div className="modal-overlay" onClick={() => setShowNotificationModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Add Notification Gateway</h2>
            
            <div className="form-group">
              <label>Gateway Type</label>
              <select
                className="select-input"
                value={notificationFormData.gateway_type}
                onChange={(e) => setNotificationFormData({...notificationFormData, gateway_type: e.target.value})}
              >
                <option value="email">Email</option>
                <option value="sms">SMS</option>
              </select>
            </div>

            <div className="form-group">
              <label>Provider</label>
              <select
                className="select-input"
                value={notificationFormData.provider}
                onChange={(e) => setNotificationFormData({...notificationFormData, provider: e.target.value})}
              >
                {notificationFormData.gateway_type === 'email' ? (
                  <option value="aws_ses">AWS SES</option>
                ) : (
                  <option value="twilio">Twilio</option>
                )}
              </select>
            </div>

            {notificationFormData.gateway_type === 'email' && notificationFormData.provider === 'aws_ses' && (
              <>
                <div className="form-group">
                  <label>AWS Region</label>
                  <input
                    type="text"
                    className="input-field"
                    placeholder="us-east-1"
                    onChange={(e) => setNotificationFormData({
                      ...notificationFormData,
                      config: {...notificationFormData.config, region: e.target.value}
                    })}
                  />
                </div>
                <div className="form-group">
                  <label>Access Key ID</label>
                  <input
                    type="text"
                    className="input-field"
                    onChange={(e) => setNotificationFormData({
                      ...notificationFormData,
                      config: {...notificationFormData.config, access_key_id: e.target.value}
                    })}
                  />
                </div>
                <div className="form-group">
                  <label>Secret Access Key</label>
                  <input
                    type="password"
                    className="input-field"
                    onChange={(e) => setNotificationFormData({
                      ...notificationFormData,
                      config: {...notificationFormData.config, secret_access_key: e.target.value}
                    })}
                  />
                </div>
                <div className="form-group">
                  <label>Sender Email</label>
                  <input
                    type="email"
                    className="input-field"
                    placeholder="noreply@yourdomain.com"
                    onChange={(e) => setNotificationFormData({
                      ...notificationFormData,
                      config: {...notificationFormData.config, sender_email: e.target.value}
                    })}
                  />
                </div>
              </>
            )}

            {notificationFormData.gateway_type === 'sms' && notificationFormData.provider === 'twilio' && (
              <>
                <div className="form-group">
                  <label>Account SID</label>
                  <input
                    type="text"
                    className="input-field"
                    onChange={(e) => setNotificationFormData({
                      ...notificationFormData,
                      config: {...notificationFormData.config, account_sid: e.target.value}
                    })}
                  />
                </div>
                <div className="form-group">
                  <label>Auth Token</label>
                  <input
                    type="password"
                    className="input-field"
                    onChange={(e) => setNotificationFormData({
                      ...notificationFormData,
                      config: {...notificationFormData.config, auth_token: e.target.value}
                    })}
                  />
                </div>
                <div className="form-group">
                  <label>Phone Number</label>
                  <input
                    type="tel"
                    className="input-field"
                    placeholder="+1234567890"
                    onChange={(e) => setNotificationFormData({
                      ...notificationFormData,
                      config: {...notificationFormData.config, phone_number: e.target.value}
                    })}
                  />
                </div>
              </>
            )}

            <div className="form-group-checkbox">
              <label>
                <input
                  type="checkbox"
                  checked={notificationFormData.enabled}
                  onChange={(e) => setNotificationFormData({...notificationFormData, enabled: e.target.checked})}
                />
                <span>Enable Gateway</span>
              </label>
            </div>

            <div className="form-group-checkbox">
              <label>
                <input
                  type="checkbox"
                  checked={notificationFormData.is_default}
                  onChange={(e) => setNotificationFormData({...notificationFormData, is_default: e.target.checked})}
                />
                <span>Set as Default</span>
              </label>
            </div>

            <div className="modal-actions">
              <button className="btn-primary" onClick={handleSaveNotificationGateway}>
                Save Gateway
              </button>
              <button className="btn-secondary" onClick={() => setShowNotificationModal(false)}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {showGatewayModal && (
        <div className="modal-overlay" onClick={() => setShowGatewayModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>{selectedGateway ? 'Edit Gateway' : 'Add Payment Gateway'}</h2>
            
            <div className="form-group">
              <label>Gateway Provider</label>
              <select
                className="select-input"
                value={gatewayFormData.gateway_name}
                onChange={(e) => setGatewayFormData({...gatewayFormData, gateway_name: e.target.value})}
                disabled={selectedGateway !== null}
              >
                <option value="razorpay">Razorpay</option>
                <option value="cashfree">Cashfree</option>
              </select>
            </div>

            <div className="form-group">
              <label>Key ID / Client ID</label>
              <input
                type="text"
                className="input-field"
                value={gatewayFormData.key_id}
                onChange={(e) => setGatewayFormData({...gatewayFormData, key_id: e.target.value})}
                placeholder="Enter your Key ID"
              />
            </div>

            <div className="form-group">
              <label>Key Secret / Client Secret</label>
              <input
                type="password"
                className="input-field"
                value={gatewayFormData.key_secret}
                onChange={(e) => setGatewayFormData({...gatewayFormData, key_secret: e.target.value})}
                placeholder="Enter your Key Secret"
              />
            </div>

            <div className="form-group-checkbox">
              <label>
                <input
                  type="checkbox"
                  checked={gatewayFormData.enabled}
                  onChange={(e) => setGatewayFormData({...gatewayFormData, enabled: e.target.checked})}
                />
                <span>Enable Gateway</span>
              </label>
            </div>

            <div className="form-group-checkbox">
              <label>
                <input
                  type="checkbox"
                  checked={gatewayFormData.is_default}
                  onChange={(e) => setGatewayFormData({...gatewayFormData, is_default: e.target.checked})}
                />
                <span>Set as Default Gateway</span>
              </label>
            </div>

            <div className="modal-actions">
              <button className="btn-primary" onClick={handleSaveGateway}>
                Save Gateway
              </button>
              <button className="btn-secondary" onClick={() => setShowGatewayModal(false)}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {showStaffModal && (
        <div className="modal-overlay" onClick={() => setShowStaffModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Add Staff Member</h2>
            
            <div className="form-group">
              <label>Email *</label>
              <input
                type="email"
                className="input-field"
                value={staffFormData.email}
                onChange={(e) => setStaffFormData({...staffFormData, email: e.target.value})}
                placeholder="Enter email address"
              />
            </div>

            <div className="form-group">
              <label>Nickname *</label>
              <input
                type="text"
                className="input-field"
                value={staffFormData.nickname}
                onChange={(e) => setStaffFormData({...staffFormData, nickname: e.target.value})}
                placeholder="Enter display name"
              />
            </div>

            <div className="form-group">
              <label>Role</label>
              <select
                className="select-input"
                value={staffFormData.role}
                onChange={(e) => setStaffFormData({...staffFormData, role: e.target.value})}
              >
                <option value="campaign_manager">Campaign Manager</option>
                <option value="support_staff">Support Staff</option>
                <option value="admin">Admin</option>
              </select>
            </div>

            <div className="form-group">
              <label>Creation Mode</label>
              <select
                className="select-input"
                value={staffFormData.invite_mode}
                onChange={(e) => setStaffFormData({...staffFormData, invite_mode: e.target.value})}
              >
                <option value="direct">Direct Creation (with password)</option>
                <option value="invite">Send Invite Link</option>
              </select>
            </div>

            {staffFormData.invite_mode === 'direct' && (
              <div className="form-group">
                <label>Password *</label>
                <input
                  type="password"
                  className="input-field"
                  value={staffFormData.password}
                  onChange={(e) => setStaffFormData({...staffFormData, password: e.target.value})}
                  placeholder="Enter password"
                />
              </div>
            )}

            <div className="form-group">
              <label>Permissions (Optional)</label>
              <div className="checkbox-group">
                {['manage_campaigns', 'manage_users', 'view_analytics', 'manage_payments'].map((perm) => (
                  <label key={perm} className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={staffFormData.permissions.includes(perm)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setStaffFormData({
                            ...staffFormData,
                            permissions: [...staffFormData.permissions, perm]
                          });
                        } else {
                          setStaffFormData({
                            ...staffFormData,
                            permissions: staffFormData.permissions.filter(p => p !== perm)
                          });
                        }
                      }}
                    />
                    <span>{perm.replace('_', ' ').toUpperCase()}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="modal-actions">
              <button className="btn-primary" onClick={handleCreateStaff}>
                {staffFormData.invite_mode === 'direct' ? 'Create Staff' : 'Send Invite'}
              </button>
              <button className="btn-secondary" onClick={() => setShowStaffModal(false)}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      <style jsx>{`
        .admin-dashboard {
          min-height: 100vh;
          background: linear-gradient(135deg, #f8f9ff 0%, #e8ecff 100%);
        }

        .dashboard-header {
          background: white;
          border-bottom: 2px solid #e2e8f0;
          padding: 24px 8%;
        }

        .header-content {
          display: flex;
          justify-content: space-between;
          align-items: center;
          max-width: 1400px;
          margin: 0 auto;
        }

        .dashboard-header h1 {
          font-size: 2rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 4px;
        }

        .dashboard-header p {
          color: #718096;
          text-transform: capitalize;
        }

        .dashboard-header button {
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .dashboard-content {
          padding: 40px 8%;
          max-width: 1400px;
          margin: 0 auto;
        }

        .analytics-cards {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
          gap: 24px;
          margin-bottom: 40px;
        }

        .analytics-card {
          background: white;
          padding: 24px;
          border-radius: 16px;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
          display: flex;
          align-items: center;
          gap: 20px;
          transition: all 0.3s ease;
        }

        .analytics-card:hover {
          transform: translateY(-4px);
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.12);
        }

        .card-icon {
          width: 64px;
          height: 64px;
          border-radius: 16px;
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .card-content {
          flex: 1;
        }

        .card-label {
          font-size: 0.875rem;
          color: #718096;
          margin: 0 0 8px 0;
          font-weight: 500;
        }

        .card-value {
          font-size: 2rem;
          font-weight: 700;
          color: #1a202c;
          margin: 0 0 4px 0;
        }

        .card-sub {
          font-size: 0.75rem;
          color: #a0aec0;
          margin: 0;
        }

        .tabs {
          display: flex;
          gap: 12px;
          margin-bottom: 32px;
          border-bottom: 2px solid #e2e8f0;
          overflow-x: auto;
          padding-bottom: 2px;
        }

        .tab {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 12px 24px;
          background: none;
          border: none;
          border-bottom: 3px solid transparent;
          color: #718096;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
          white-space: nowrap;
        }

        .tab:hover {
          color: #667eea;
        }

        .tab.active {
          color: #667eea;
          border-bottom-color: #667eea;
        }

        .tab-content {
          background: white;
          padding: 32px;
          border-radius: 24px;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
        }

        .tab-content h2 {
          font-size: 1.75rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 32px;
        }

        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
          gap: 24px;
        }

        .stat-card {
          background: #f8f9ff;
          padding: 24px;
          border-radius: 16px;
          display: flex;
          align-items: center;
          gap: 20px;
          border: 2px solid #e2e8f0;
        }

        .stat-icon {
          width: 64px;
          height: 64px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          border-radius: 16px;
          display: flex;
          align-items: center;
          justify-content: center;
          color: white;
        }

        .stat-label {
          font-size: 0.875rem;
          color: #718096;
          margin-bottom: 4px;
        }

        .stat-value {
          font-size: 1.75rem;
          font-weight: 700;
          color: #1a202c;
        }

        .loading,
        .empty-state {
          text-align: center;
          padding: 60px 20px;
          color: #718096;
        }

        .empty-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 16px;
        }

        .items-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
          gap: 24px;
        }

        .profile-card,
        .campaign-card,
        .withdrawal-card {
          background: #f8f9ff;
          padding: 24px;
          border-radius: 16px;
          border: 2px solid #e2e8f0;
        }

        .profile-header,
        .campaign-header,
        .withdrawal-header {
          display: flex;
          justify-content: space-between;
          align-items: start;
          margin-bottom: 16px;
        }

        .profile-header h3,
        .campaign-header h3,
        .withdrawal-header h3 {
          font-size: 1.25rem;
          font-weight: 600;
          color: #1a202c;
          margin-bottom: 8px;
        }

        .profile-details,
        .campaign-details,
        .withdrawal-details {
          margin-bottom: 20px;
          color: #4a5568;
          line-height: 1.8;
        }

        .profile-details p,
        .campaign-details p,
        .withdrawal-details p {
          margin-bottom: 8px;
        }

        .rate-list,
        .objectives-list {
          margin: 8px 0;
          padding-left: 20px;
          color: #4a5568;
        }

        .profile-actions,
        .campaign-actions,
        .withdrawal-actions {
          display: flex;
          gap: 12px;
        }

        .btn-approve,
        .btn-reject {
          flex: 1;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          padding: 12px;
          border-radius: 12px;
          border: none;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
        }

        .btn-approve {
          background: #d4edda;
          color: #155724;
        }

        .btn-approve:hover {
          background: #c3e6cb;
          transform: translateY(-2px);
        }

        .btn-reject {
          background: #f8d7da;
          color: #721c24;
        }

        .btn-reject:hover {
          background: #f5c6cb;
          transform: translateY(-2px);
        }

        .action-buttons {
          display: flex;
          gap: 8px;
        }

        .btn-edit-small,
        .btn-ban-small,
        .btn-unban-small {
          padding: 6px 12px;
          border-radius: 8px;
          border: none;
          font-size: 0.875rem;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s ease;
        }

        .btn-edit-small {
          background: #d1ecf1;
          color: #0c5460;
        }

        .btn-edit-small:hover {
          background: #bee5eb;
        }

        .btn-ban-small {
          background: #f8d7da;
          color: #721c24;
        }

        .btn-ban-small:hover {
          background: #f5c6cb;
        }

        .btn-unban-small {
          background: #d4edda;
          color: #155724;
        }

        .btn-unban-small:hover {
          background: #c3e6cb;
        }

        .banned-row {
          background: #fff3cd;
          opacity: 0.8;
        }

        .banned-badge {
          display: inline-block;
          margin-left: 8px;
          padding: 2px 8px;
          background: #dc3545;
          color: white;
          font-size: 0.7rem;
          font-weight: 700;
          border-radius: 4px;
        }

        .input-field {
          width: 100%;
          padding: 12px 16px;
          border: 2px solid #e2e8f0;
          border-radius: 12px;
          font-size: 1rem;
          color: #1a202c;
          transition: all 0.3s ease;
        }

        .input-field:focus {
          outline: none;
          border-color: #667eea;
          box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .users-table {
          overflow-x: auto;
        }

        table {
          width: 100%;
          border-collapse: collapse;
        }

        th,
        td {
          padding: 16px;
          text-align: left;
          border-bottom: 1px solid #e2e8f0;
        }

        th {
          background: #f8f9ff;
          font-weight: 600;
          color: #2d3748;
        }

        td {
          color: #4a5568;
        }

        .chats-section {
          padding: 32px;
        }

        .conversations-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
          gap: 20px;
        }

        .conversation-card {
          background: #f8f9ff;
          padding: 20px;
          border-radius: 16px;
          border: 2px solid #e2e8f0;
          cursor: pointer;
          transition: all 0.3s ease;
        }

        .conversation-card:hover {
          border-color: #667eea;
          box-shadow: 0 4px 12px rgba(102, 126, 234, 0.2);
          transform: translateY(-2px);
        }

        .conversation-card.has-violations {
          border-left: 4px solid #f59e0b;
          background: #fffbeb;
        }

        .conversation-participants {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 16px;
          gap: 12px;
        }

        .participant {
          display: flex;
          flex-direction: column;
          gap: 6px;
          flex: 1;
        }

        .participant-nickname {
          font-weight: 600;
          color: #1a202c;
          font-size: 1rem;
        }

        .participant-role {
          font-size: 0.75rem;
          width: fit-content;
        }

        .conversation-arrow {
          font-size: 1.25rem;
          color: #718096;
        }

        .conversation-preview {
          margin-top: 12px;
          padding-top: 12px;
          border-top: 1px solid #e2e8f0;
        }

        .last-message {
          color: #4a5568;
          margin-bottom: 8px;
          font-size: 0.9rem;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }

        .last-message-time {
          color: #a0aec0;
          font-size: 0.8rem;
        }

        .violation-indicator {
          margin-top: 12px;
          padding: 8px 12px;
          background: #fef3c7;
          border-radius: 8px;
          color: #92400e;
          font-size: 0.85rem;
          font-weight: 600;
        }

        .chat-view {
          background: white;
          border-radius: 16px;
          overflow: hidden;
        }

        .chat-header {
          background: #f8f9ff;
          padding: 20px;
          border-bottom: 2px solid #e2e8f0;
          display: flex;
          align-items: center;
          gap: 20px;
        }

        .btn-back {
          padding: 8px 16px;
          background: white;
          border: 2px solid #e2e8f0;
          border-radius: 8px;
          font-weight: 600;
          color: #4a5568;
          cursor: pointer;
          transition: all 0.2s ease;
        }

        .btn-back:hover {
          border-color: #667eea;
          color: #667eea;
        }

        .chat-participants {
          display: flex;
          align-items: center;
          gap: 12px;
          font-size: 1.1rem;
        }

        .participant-name {
          font-weight: 600;
          color: #1a202c;
        }

        .chat-separator {
          color: #718096;
          font-size: 1.25rem;
        }

        .chat-messages {
          padding: 24px;
          max-height: 600px;
          overflow-y: auto;
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .no-messages {
          text-align: center;
          color: #718096;
          padding: 40px;
        }

        .message-item {
          background: #f8f9ff;
          padding: 16px;
          border-radius: 12px;
          border: 2px solid #e2e8f0;
        }

        .message-item.filtered-message {
          border-color: #f59e0b;
          background: #fffbeb;
        }

        .message-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 8px;
        }

        .message-sender {
          font-weight: 600;
          color: #1a202c;
          font-size: 0.95rem;
        }

        .message-time {
          color: #a0aec0;
          font-size: 0.8rem;
        }

        .message-content {
          color: #4a5568;
          line-height: 1.6;
          word-wrap: break-word;
        }

        .filtered-badge {
          margin-top: 8px;
          padding: 4px 8px;
          background: #fef3c7;
          border-radius: 6px;
          color: #92400e;
          font-size: 0.75rem;
          font-weight: 600;
          display: inline-block;
        }

        .modal-overlay {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0, 0, 0, 0.6);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 1000;
          padding: 20px;
        }

        .modal-content {
          background: white;
          padding: 40px;
          border-radius: 24px;
          max-width: 600px;
          width: 100%;
          max-height: 90vh;
          overflow-y: auto;
        }

        .modal-content h2 {
          font-size: 1.75rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 32px;
        }

        .user-details-grid {
          display: flex;
          flex-direction: column;
          gap: 20px;
          margin-bottom: 32px;
        }

        .detail-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 16px;
          background: #f8f9ff;
          border-radius: 12px;
        }

        .detail-label {
          font-weight: 600;
          color: #4a5568;
        }

        .detail-value {
          color: #1a202c;
          font-weight: 500;
        }

        .assignments-section {
          padding: 32px;
        }

        .section-description {
          color: #718096;
          margin-bottom: 24px;
          font-size: 0.95rem;
        }

        .assignments-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
          gap: 24px;
          margin-bottom: 40px;
        }

        .assignment-card {
          background: #f8f9ff;
          padding: 24px;
          border-radius: 16px;
          border: 2px solid #e2e8f0;
          transition: all 0.3s ease;
        }

        .assignment-card:hover {
          box-shadow: 0 8px 24px rgba(0, 0, 0, 0.1);
          transform: translateY(-2px);
        }

        .assignment-header {
          display: flex;
          justify-content: space-between;
          align-items: start;
          margin-bottom: 20px;
          padding-bottom: 16px;
          border-bottom: 2px solid #e2e8f0;
        }

        .assignment-header h3 {
          font-size: 1.25rem;
          font-weight: 600;
          color: #1a202c;
          margin-bottom: 4px;
        }

        .manager-email {
          font-size: 0.875rem;
          color: #718096;
        }

        .campaign-count-badge {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          padding: 6px 16px;
          border-radius: 20px;
          font-size: 0.875rem;
          font-weight: 600;
        }

        .campaigns-list {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }

        .campaign-item-small {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 12px;
          background: white;
          border-radius: 12px;
          border: 1px solid #e2e8f0;
          transition: all 0.2s ease;
        }

        .campaign-item-small:hover {
          border-color: #667eea;
          box-shadow: 0 2px 8px rgba(102, 126, 234, 0.2);
        }

        .campaign-info-small {
          display: flex;
          flex-direction: column;
          gap: 6px;
          flex: 1;
        }

        .campaign-title-small {
          font-weight: 600;
          color: #1a202c;
          font-size: 0.95rem;
        }

        .status-badge-small {
          display: inline-block;
          padding: 4px 10px;
          border-radius: 12px;
          font-size: 0.75rem;
          font-weight: 600;
          text-transform: uppercase;
          width: fit-content;
        }

        .status-badge-small.active {
          background: #d4edda;
          color: #155724;
        }

        .status-badge-small.pending_approval {
          background: #fff3cd;
          color: #856404;
        }

        .status-badge-small.in_progress {
          background: #d1ecf1;
          color: #0c5460;
        }

        .status-badge-small.completed {
          background: #d4edda;
          color: #155724;
        }

        .btn-reassign,
        .btn-assign {
          padding: 8px 16px;
          border-radius: 10px;
          border: none;
          font-weight: 600;
          font-size: 0.875rem;
          cursor: pointer;
          transition: all 0.3s ease;
          white-space: nowrap;
        }

        .btn-reassign {
          background: #fff3cd;
          color: #856404;
        }

        .btn-reassign:hover {
          background: #ffeeba;
          transform: translateY(-2px);
        }

        .btn-assign {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
        }

        .btn-assign:hover {
          opacity: 0.9;
          transform: translateY(-2px);
        }

        .unassigned-section {
          margin-top: 40px;
          padding-top: 32px;
          border-top: 2px solid #e2e8f0;
        }

        .unassigned-section h3 {
          font-size: 1.5rem;
          font-weight: 600;
          color: #1a202c;
          margin-bottom: 20px;
        }

        .unassigned-list {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }

        .no-campaigns-text {
          color: #718096;
          font-style: italic;
          padding: 20px;
          text-align: center;
        }

        .form-group {
          margin-bottom: 24px;
        }

        .form-group label {
          display: block;
          font-weight: 600;
          color: #4a5568;
          margin-bottom: 8px;
        }

        .select-input {
          width: 100%;
          padding: 12px 16px;
          border: 2px solid #e2e8f0;
          border-radius: 12px;
          font-size: 1rem;
          color: #1a202c;
          background: white;
          cursor: pointer;
          transition: all 0.3s ease;
        }

        .select-input:focus {
          outline: none;
          border-color: #667eea;
          box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .modal-actions {
          display: flex;
          gap: 12px;
          margin-top: 32px;
        }

        .modal-actions button {
          flex: 1;
          padding: 12px;
          border-radius: 12px;
          border: none;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
        }

        .payments-section {
          padding: 32px;
        }

        .section-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 32px;
        }

        .section-header h2 {
          margin: 0;
        }

        .gateways-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
          gap: 24px;
          margin-bottom: 48px;
        }

        .gateway-card {
          background: #f8f9ff;
          padding: 24px;
          border-radius: 16px;
          border: 2px solid #e2e8f0;
          transition: all 0.3s ease;
        }

        .gateway-card:hover {
          box-shadow: 0 8px 24px rgba(0, 0, 0, 0.1);
          transform: translateY(-2px);
        }

        .gateway-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 20px;
          padding-bottom: 16px;
          border-bottom: 2px solid #e2e8f0;
        }

        .gateway-name-section {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .gateway-name-section h3 {
          margin: 0;
          font-size: 1.25rem;
          font-weight: 700;
          color: #1a202c;
        }

        .default-badge {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          padding: 4px 12px;
          border-radius: 12px;
          font-size: 0.75rem;
          font-weight: 600;
        }

        .gateway-toggle .switch {
          position: relative;
          display: inline-block;
          width: 50px;
          height: 24px;
        }

        .gateway-toggle .switch input {
          opacity: 0;
          width: 0;
          height: 0;
        }

        .gateway-toggle .slider {
          position: absolute;
          cursor: pointer;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background-color: #ccc;
          transition: 0.4s;
          border-radius: 24px;
        }

        .gateway-toggle .slider:before {
          position: absolute;
          content: "";
          height: 18px;
          width: 18px;
          left: 3px;
          bottom: 3px;
          background-color: white;
          transition: 0.4s;
          border-radius: 50%;
        }

        .gateway-toggle input:checked + .slider {
          background-color: #667eea;
        }

        .gateway-toggle input:checked + .slider:before {
          transform: translateX(26px);
        }

        .gateway-details {
          margin-bottom: 20px;
        }

        .gateway-details p {
          margin-bottom: 8px;
          color: #4a5568;
        }

        .status-badge {
          display: inline-block;
          padding: 4px 12px;
          border-radius: 12px;
          font-size: 0.85rem;
          font-weight: 600;
          margin-left: 8px;
        }

        .status-badge.active {
          background: #d4edda;
          color: #155724;
        }

        .status-badge.inactive {
          background: #f8d7da;
          color: #721c24;
        }

        .status-badge.created {
          background: #fff3cd;
          color: #856404;
        }

        .status-badge.success {
          background: #d4edda;
          color: #155724;
        }

        .status-badge.failed {
          background: #f8d7da;
          color: #721c24;
        }

        .gateway-actions {
          display: flex;
          gap: 8px;
        }

        .btn-default-small {
          padding: 6px 12px;
          border-radius: 8px;
          border: none;
          font-size: 0.875rem;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s ease;
          background: #fff3cd;
          color: #856404;
        }

        .btn-default-small:hover {
          background: #ffeeba;
        }

        .btn-delete-small {
          padding: 6px 12px;
          border-radius: 8px;
          border: none;
          font-size: 0.875rem;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s ease;
          background: #f8d7da;
          color: #721c24;
        }

        .btn-delete-small:hover {
          background: #f5c6cb;
        }

        .transactions-section {
          margin-top: 48px;
          padding-top: 32px;
          border-top: 2px solid #e2e8f0;
        }

        .transactions-section h3 {
          display: flex;
          align-items: center;
          gap: 8px;
          font-size: 1.5rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 24px;
        }

        .no-transactions {
          text-align: center;
          padding: 40px;
          color: #718096;
        }

        .transactions-table {
          overflow-x: auto;
          background: white;
          border-radius: 12px;
          padding: 16px;
        }

        .transactions-table table {
          width: 100%;
        }

        .txn-id {
          font-family: monospace;
          font-size: 0.9rem;
          color: #667eea;
        }

        .gateway-badge {
          display: inline-block;
          padding: 4px 8px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          border-radius: 8px;
          font-size: 0.75rem;
          font-weight: 600;
        }

        .txn-amount {
          font-weight: 700;
          color: #1a202c;
        }

        .form-group-checkbox {
          margin-bottom: 16px;
        }

        .form-group-checkbox label {
          display: flex;
          align-items: center;
          gap: 8px;
          cursor: pointer;
        }

        .form-group-checkbox input[type="checkbox"] {
          width: 20px;
          height: 20px;
          cursor: pointer;
        }

        .form-group-checkbox span {
          font-weight: 500;
          color: #4a5568;
        }

        .notifications-section {
          padding: 32px;
        }

        .logs-section {
          margin-top: 48px;
          padding-top: 32px;
          border-top: 2px solid #e2e8f0;
        }

        .logs-section h3 {
          display: flex;
          align-items: center;
          gap: 8px;
          font-size: 1.5rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 24px;
        }

        .gateway-type-label {
          font-size: 0.75rem;
          color: #718096;
          margin: 0;
        }

        .broadcast-section {
          padding: 32px;
          max-width: 800px;
          margin: 0 auto;
        }

        .broadcast-form {
          background: white;
          padding: 32px;
          border-radius: 16px;
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
        }

        .textarea-field {
          width: 100%;
          padding: 12px 16px;
          border: 2px solid #e2e8f0;
          border-radius: 12px;
          font-size: 1rem;
          font-family: inherit;
          color: #1a202c;
          transition: all 0.3s ease;
          resize: vertical;
        }

        .textarea-field:focus {
          outline: none;
          border-color: #667eea;
          box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .form-row {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 20px;
        }

        .checkbox-group {
          display: flex;
          flex-direction: column;
          gap: 12px;
          padding: 16px;
          background: #f8f9ff;
          border-radius: 12px;
        }

        .checkbox-label {
          display: flex;
          align-items: center;
          gap: 8px;
          cursor: pointer;
        }

        .checkbox-label input[type="checkbox"] {
          width: 18px;
          height: 18px;
          cursor: pointer;
        }

        .checkbox-label span {
          font-weight: 500;
          color: #4a5568;
        }

        .btn-large {
          width: 100%;
          padding: 14px 24px;
          font-size: 1rem;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
        }

        .analytics-cards {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
          gap: 20px;
          margin-bottom: 32px;
          padding: 0 32px;
        }

        .analytics-card {
          display: flex;
          align-items: center;
          gap: 16px;
          background: white;
          padding: 24px;
          border-radius: 16px;
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
          transition: all 0.3s ease;
        }

        .analytics-card:hover {
          transform: translateY(-4px);
          box-shadow: 0 8px 24px rgba(0, 0, 0, 0.1);
        }

        .card-icon {
          width: 56px;
          height: 56px;
          border-radius: 12px;
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .card-content {
          flex: 1;
        }

        .card-label {
          margin: 0 0 8px 0;
          font-size: 0.875rem;
          color: #718096;
        }

        .card-value {
          margin: 0 0 4px 0;
          font-size: 1.75rem;
          font-weight: 700;
          color: #1a202c;
        }

        .card-sub {
          margin: 0;
          font-size: 0.75rem;
          color: #a0aec0;
        }

        .staff-section,
        .analytics-detailed-section {
          padding: 32px;
        }

        .staff-table {
          background: white;
          border-radius: 12px;
          overflow: hidden;
        }

        .permission-count {
          color: #667eea;
          font-weight: 600;
        }

        .no-permissions {
          color: #a0aec0;
          font-style: italic;
        }

        .analytics-metrics-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
          gap: 24px;
        }

        .metric-card {
          background: white;
          padding: 24px;
          border-radius: 16px;
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
          transition: all 0.3s ease;
        }

        .metric-card:hover {
          box-shadow: 0 8px 24px rgba(0, 0, 0, 0.1);
        }

        .metric-card.highlight {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
        }

        .metric-card h4 {
          margin: 0 0 12px 0;
          font-size: 0.875rem;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          opacity: 0.8;
        }

        .metric-card.highlight h4,
        .metric-card.highlight .metric-info {
          color: white;
          opacity: 0.9;
        }

        .big-number {
          margin: 0 0 8px 0;
          font-size: 2.5rem;
          font-weight: 700;
        }

        .metric-change {
          font-size: 0.875rem;
          font-weight: 600;
        }

        .metric-change.positive {
          color: #059669;
        }

        .metric-info {
          font-size: 0.875rem;
          color: #718096;
        }

        .role-badge {
          display: inline-block;
          padding: 4px 12px;
          border-radius: 12px;
          font-size: 0.75rem;
          font-weight: 600;
          text-transform: uppercase;
        }

        .role-badge.campaign_manager {
          background: #dbeafe;
          color: #1e40af;
        }

        .role-badge.support_staff {
          background: #fef3c7;
          color: #92400e;
        }

        .staff-section {
          padding: 32px;
        }

        .staff-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
          gap: 24px;
        }

        .staff-card {
          background: #f8f9ff;
          padding: 24px;
          border-radius: 16px;
          border: 2px solid #e2e8f0;
          transition: all 0.3s ease;
        }

        .staff-card:hover {
          box-shadow: 0 8px 24px rgba(0, 0, 0, 0.1);
          transform: translateY(-2px);
        }

        .staff-header {
          display: flex;
          justify-content: space-between;
          align-items: start;
          margin-bottom: 20px;
          padding-bottom: 16px;
          border-bottom: 2px solid #e2e8f0;
        }

        .staff-info h3 {
          font-size: 1.25rem;
          font-weight: 600;
          color: #1a202c;
          margin: 0 0 4px 0;
        }

        .staff-email {
          font-size: 0.875rem;
          color: #718096;
          margin: 0;
        }

        .role-badge {
          padding: 6px 16px;
          border-radius: 20px;
          font-size: 0.75rem;
          font-weight: 600;
          text-transform: uppercase;
        }

        .role-badge.campaign_manager {
          background: #dbeafe;
          color: #2563eb;
        }

        .role-badge.support_staff {
          background: #d1fae5;
          color: #059669;
        }

        .role-badge.admin {
          background: #fef3c7;
          color: #d97706;
        }

        .staff-details {
          margin-bottom: 20px;
        }

        .staff-details p {
          margin-bottom: 8px;
          color: #4a5568;
        }

        .staff-permissions {
          margin-top: 16px;
        }

        .staff-permissions p {
          font-weight: 600;
          color: #4a5568;
          margin-bottom: 8px;
        }

        .permissions-list {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
        }

        .permission-tag {
          background: #e0e7ff;
          color: #667eea;
          padding: 4px 8px;
          border-radius: 8px;
          font-size: 0.75rem;
          font-weight: 500;
        }

        .no-permissions {
          color: #a0aec0;
          font-style: italic;
          font-size: 0.875rem;
        }

        .analytics-section {
          padding: 32px;
        }

        .analytics-overview {
          display: flex;
          flex-direction: column;
          gap: 32px;
          margin-bottom: 48px;
        }

        .analytics-row {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
          gap: 32px;
        }

        .analytics-metric {
          background: white;
          padding: 32px;
          border-radius: 16px;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
        }

        .metric-header {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-bottom: 24px;
          padding-bottom: 16px;
          border-bottom: 2px solid #e2e8f0;
        }

        .metric-header h3 {
          font-size: 1.25rem;
          font-weight: 600;
          color: #1a202c;
          margin: 0;
        }

        .metric-grid {
          display: grid;
          gap: 16px;
        }

        .metric-item {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 16px;
          background: #f8f9ff;
          border-radius: 12px;
        }

        .metric-label {
          font-weight: 500;
          color: #4a5568;
        }

        .metric-value {
          font-size: 1.5rem;
          font-weight: 700;
          color: #1a202c;
        }

        .export-section {
          margin-top: 48px;
          padding-top: 32px;
          border-top: 2px solid #e2e8f0;
        }

        .export-section h3 {
          font-size: 1.5rem;
          font-weight: 600;
          color: #1a202c;
          margin-bottom: 20px;
        }

        .export-buttons {
          display: flex;
          gap: 16px;
        }

        @media (max-width: 768px) {
          .header-content {
            flex-direction: column;
            gap: 20px;
            align-items: flex-start;
          }

          .items-grid {
            grid-template-columns: 1fr;
          }

          .tabs {
            gap: 8px;
          }

          .tab {
            padding: 12px 16px;
            font-size: 0.9rem;
          }

          .modal-content {
            padding: 24px;
          }

          .assignments-grid {
            grid-template-columns: 1fr;
          }

          .assignment-header {
            flex-direction: column;
            gap: 12px;
          }

          .campaign-count-badge {
            align-self: flex-start;
          }
        }
      `}</style>
    </div>
  );
}