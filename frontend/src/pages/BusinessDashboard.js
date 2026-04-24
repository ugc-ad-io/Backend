import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import { Plus, Briefcase, LogOut, MessageSquare, CheckCircle, Eye, Package, FileCheck, TrendingUp, DollarSign, Users } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export default function BusinessDashboard() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [campaigns, setCampaigns] = useState([]);
  const [activeCampaigns, setActiveCampaigns] = useState([]);
  const [pendingCampaigns, setPendingCampaigns] = useState([]);
  const [completedCampaigns, setCompletedCampaigns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [formData, setFormData] = useState({
    title: '',
    objectives: [],
    budget_min: '',
    budget_max: '',
    brief_text: '',
    requires_shipment: false,
    shipment_option: 'no'
  });
  const [objectiveInput, setObjectiveInput] = useState('');

  useEffect(() => {
    if (user?.approval_status === 'approved') {
      fetchCampaigns();
    }
  }, [user]);

  const fetchCampaigns = async () => {
    try {
      const response = await axios.get(`${API}/campaigns`);
      const allCampaigns = response.data;
      
      // Filter to only show this business's campaigns
      const myCampaigns = allCampaigns.filter(c => c.business_id === user.id);
      setCampaigns(myCampaigns);
      
      // Categorize campaigns
      setActiveCampaigns(myCampaigns.filter(c => c.status === 'active' || c.status === 'in_progress'));
      setPendingCampaigns(myCampaigns.filter(c => c.status === 'pending_approval'));
      setCompletedCampaigns(myCampaigns.filter(c => c.status === 'completed'));
    } catch (error) {
      toast.error('Failed to load campaigns');
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const addObjective = () => {
    if (objectiveInput.trim() && !formData.objectives.includes(objectiveInput.trim())) {
      setFormData(prev => ({
        ...prev,
        objectives: [...prev.objectives, objectiveInput.trim()]
      }));
      setObjectiveInput('');
    }
  };

  const removeObjective = (obj) => {
    setFormData(prev => ({
      ...prev,
      objectives: prev.objectives.filter(o => o !== obj)
    }));
  };

  const handleCreateCampaign = async (e) => {
    e.preventDefault();
    
    if (formData.objectives.length === 0) {
      toast.error('Please add at least one objective');
      return;
    }

    try {
      await axios.post(`${API}/campaigns`, {
        ...formData,
        budget_min: parseFloat(formData.budget_min),
        budget_max: parseFloat(formData.budget_max),
        requires_shipment: formData.shipment_option === 'yes'
      });
      toast.success('Campaign created and submitted for approval!');
      setShowCreateModal(false);
      setFormData({
        title: '',
        objectives: [],
        budget_min: '',
        budget_max: '',
        brief_text: '',
        requires_shipment: false,
        shipment_option: 'no'
      });
      fetchCampaigns();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to create campaign');
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const handleViewCampaign = (campaignId) => {
    navigate(`/campaign/${campaignId}`);
  };

  // Calculate stats
  const totalSpent = completedCampaigns.reduce((sum, c) => sum + (c.budget_max || 0), 0);
  const totalBidsReceived = campaigns.reduce((sum, c) => sum + (c.bids?.length || 0), 0);

  if (user?.approval_status === 'pending') {
    return (
      <div className="approval-page">
        <header className="approval-header">
          <div className="header-container">
            <div className="logo-section">
              <div className="logo-icon">UGC</div>
              <span className="logo-text">Business Platform</span>
            </div>
            <button className="header-logout-btn" onClick={handleLogout} data-testid="logout-btn">
              <LogOut size={18} /> Logout
            </button>
          </div>
        </header>

        <div className="approval-content">
          <div className="approval-card">
            <div className="icon-wrapper">
              <CheckCircle size={80} className="pending-icon" />
            </div>
            <h1>Business Profile Under Review</h1>
            <p className="subtitle">Thank you for joining our platform!</p>
            
            <div className="info-box">
              <div className="info-item">
                <div className="info-icon">⏱️</div>
                <div>
                  <h3>Review Time</h3>
                  <p>Typically 24-48 hours</p>
                </div>
              </div>
              <div className="info-item">
                <div className="info-icon">✉️</div>
                <div>
                  <h3>We'll Notify You</h3>
                  <p>Via email once approved</p>
                </div>
              </div>
              <div className="info-item">
                <div className="info-icon">🚀</div>
                <div>
                  <h3>What's Next?</h3>
                  <p>Create your first campaign</p>
                </div>
              </div>
            </div>

            <div className="status-message">
              <p>Your business profile is being verified by our team. We review all business accounts to maintain quality standards and protect our creator community.</p>
            </div>

            <button className="btn-primary" onClick={handleLogout} data-testid="home-btn">
              Back to Home
            </button>
          </div>
        </div>

        <footer className="approval-footer">
          <div className="footer-container">
            <div className="footer-section">
              <h4>UGC Platform</h4>
              <p>Connecting creators with brands worldwide</p>
            </div>
            <div className="footer-section">
              <h4>Support</h4>
              <p>help@ugcplatform.com</p>
              <p>Mon-Fri, 9AM-6PM EST</p>
            </div>
            <div className="footer-section">
              <h4>Quick Links</h4>
              <p>Terms of Service</p>
              <p>Privacy Policy</p>
            </div>
          </div>
          <div className="footer-bottom">
            <p>© 2025 UGC Platform. All rights reserved.</p>
          </div>
        </footer>

        <style jsx>{`
          .approval-page {
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            background: linear-gradient(135deg, #f8f9ff 0%, #e8ecff 100%);
          }

          .approval-header {
            background: white;
            border-bottom: 2px solid #e2e8f0;
            padding: 20px 8%;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
          }

          .header-container {
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
          }

          .logo-section {
            display: flex;
            align-items: center;
            gap: 12px;
          }

          .logo-icon {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 1rem;
          }

          .logo-text {
            font-size: 1.25rem;
            font-weight: 700;
            color: #1a202c;
          }

          .header-logout-btn {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px 20px;
            background: white;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            color: #4a5568;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
          }

          .header-logout-btn:hover {
            border-color: #667eea;
            color: #667eea;
          }

          .approval-content {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 60px 20px;
          }

          .approval-card {
            background: white;
            padding: 60px 48px;
            border-radius: 24px;
            max-width: 800px;
            width: 100%;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.1);
            text-align: center;
          }

          .icon-wrapper {
            margin-bottom: 24px;
          }

          .pending-icon {
            color: #667eea;
            animation: pulse 2s ease-in-out infinite;
          }

          @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.8; transform: scale(1.05); }
          }

          .approval-card h1 {
            font-size: 2.5rem;
            font-weight: 700;
            color: #1a202c;
            margin-bottom: 12px;
          }

          .subtitle {
            font-size: 1.125rem;
            color: #718096;
            margin-bottom: 40px;
          }

          .info-box {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 24px;
            margin-bottom: 40px;
            padding: 32px;
            background: #f8f9ff;
            border-radius: 16px;
          }

          .info-item {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 12px;
            text-align: center;
          }

          .info-icon {
            width: 56px;
            height: 56px;
            background: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.75rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
          }

          .info-item h3 {
            font-size: 1rem;
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 4px;
          }

          .info-item p {
            font-size: 0.875rem;
            color: #718096;
          }

          .status-message {
            padding: 24px;
            background: #e0e7ff;
            border-radius: 12px;
            margin-bottom: 32px;
            border-left: 4px solid #667eea;
          }

          .status-message p {
            color: #3730a3;
            line-height: 1.6;
            margin: 0;
          }

          .approval-footer {
            background: white;
            border-top: 2px solid #e2e8f0;
            padding: 48px 8% 24px;
            margin-top: auto;
          }

          .footer-container {
            max-width: 1400px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 40px;
            margin-bottom: 32px;
          }

          .footer-section h4 {
            font-size: 1.125rem;
            font-weight: 700;
            color: #1a202c;
            margin-bottom: 16px;
          }

          .footer-section p {
            color: #718096;
            line-height: 1.8;
            margin-bottom: 8px;
          }

          .footer-bottom {
            max-width: 1400px;
            margin: 0 auto;
            padding-top: 24px;
            border-top: 1px solid #e2e8f0;
            text-align: center;
            color: #a0aec0;
            font-size: 0.875rem;
          }

          @media (max-width: 768px) {
            .approval-header {
              padding: 16px 5%;
            }

            .logo-text {
              font-size: 1rem;
            }

            .logo-icon {
              width: 40px;
              height: 40px;
              font-size: 0.875rem;
            }

            .approval-card {
              padding: 40px 24px;
            }

            .approval-card h1 {
              font-size: 2rem;
            }

            .info-box {
              grid-template-columns: 1fr;
              padding: 24px;
            }

            .footer-container {
              grid-template-columns: 1fr;
              gap: 32px;
            }
          }
        `}</style>
      </div>
    );
  }

  if (user?.approval_status === 'rejected') {
    return (
      <div className="dashboard-container">
        <div className="approval-pending">
          <h2>Profile Not Approved</h2>
          <p>Unfortunately, your profile was not approved. Please contact support.</p>
          <button className="btn-primary" onClick={handleLogout}>Back to Home</button>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-page">
      <div className="dashboard-header">
        <div className="header-content">
          <div>
            <h1>Business Dashboard</h1>
            <p>Welcome back, {user?.nickname}!</p>
          </div>
          <div className="header-actions">
            <button className="btn-primary" onClick={() => setShowCreateModal(true)} data-testid="create-campaign-btn">
              <Plus size={20} /> Create Campaign
            </button>
            <button className="btn-secondary" onClick={() => navigate('/chat/conversations')} data-testid="messages-btn">
              <MessageSquare size={20} /> Messages
            </button>
            <button className="btn-secondary" onClick={() => navigate('/settings')} data-testid="settings-btn">
              <Users size={20} /> Settings
            </button>
            <button className="btn-secondary" onClick={handleLogout} data-testid="logout-btn">
              <LogOut size={20} /> Logout
            </button>
          </div>
        </div>
      </div>

      <div className="dashboard-content">
        {/* Stats Cards */}
        <div className="stats-grid">
          <div className="stat-card" data-testid="total-campaigns-card">
            <div className="stat-icon">
              <Briefcase size={32} />
            </div>
            <div>
              <p className="stat-label">Total Campaigns</p>
              <p className="stat-value">{campaigns.length}</p>
            </div>
          </div>
          <div className="stat-card" data-testid="active-campaigns-card">
            <div className="stat-icon active">
              <TrendingUp size={32} />
            </div>
            <div>
              <p className="stat-label">Active Campaigns</p>
              <p className="stat-value">{activeCampaigns.length}</p>
            </div>
          </div>
          <div className="stat-card" data-testid="bids-received-card">
            <div className="stat-icon bids">
              <Users size={32} />
            </div>
            <div>
              <p className="stat-label">Bids Received</p>
              <p className="stat-value">{totalBidsReceived}</p>
            </div>
          </div>
          <div className="stat-card" data-testid="total-spent-card">
            <div className="stat-icon spent">
              <DollarSign size={32} />
            </div>
            <div>
              <p className="stat-label">Total Spent</p>
              <p className="stat-value">${totalSpent.toFixed(0)}</p>
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="quick-actions">
          <h3>Quick Actions</h3>
          <div className="actions-grid">
            <button className="action-btn" onClick={() => setShowCreateModal(true)} data-testid="new-campaign-btn">
              <Plus size={24} />
              <span>New Campaign</span>
            </button>
            <button className="action-btn" onClick={() => setActiveTab('pending-bids')} data-testid="view-bids-btn">
              <Users size={24} />
              <span>View Bids</span>
            </button>
            <button className="action-btn" onClick={() => setActiveTab('work-review')} data-testid="review-work-btn">
              <FileCheck size={24} />
              <span>Review Work</span>
            </button>
            <button className="action-btn" onClick={() => setActiveTab('shipments')} data-testid="manage-shipments-btn">
              <Package size={24} />
              <span>Manage Shipments</span>
            </button>
          </div>
        </div>

        {/* Tabs Navigation */}
        <div className="tabs-container">
          <div className="tabs">
            <button
              className={`tab ${activeTab === 'overview' ? 'active' : ''}`}
              onClick={() => setActiveTab('overview')}
              data-testid="tab-overview"
            >
              Overview
            </button>
            <button
              className={`tab ${activeTab === 'all-campaigns' ? 'active' : ''}`}
              onClick={() => setActiveTab('all-campaigns')}
              data-testid="tab-all-campaigns"
            >
              All Campaigns ({campaigns.length})
            </button>
            <button
              className={`tab ${activeTab === 'pending-bids' ? 'active' : ''}`}
              onClick={() => setActiveTab('pending-bids')}
              data-testid="tab-pending-bids"
            >
              Pending Bids ({totalBidsReceived})
            </button>
            <button
              className={`tab ${activeTab === 'work-review' ? 'active' : ''}`}
              onClick={() => setActiveTab('work-review')}
              data-testid="tab-work-review"
            >
              Work Review
            </button>
            <button
              className={`tab ${activeTab === 'shipments' ? 'active' : ''}`}
              onClick={() => setActiveTab('shipments')}
              data-testid="tab-shipments"
            >
              Shipments
            </button>
          </div>
        </div>

        {/* Tab Content */}
        <div className="tab-content">
          {activeTab === 'overview' && (
            <div className="overview-section">
              <div className="section-group">
                <h2>Active Campaigns</h2>
                {activeCampaigns.length === 0 ? (
                  <div className="empty-state">
                    <Briefcase size={64} />
                    <p>No active campaigns. Create your first campaign!</p>
                    <button className="btn-primary" onClick={() => setShowCreateModal(true)}>Create Campaign</button>
                  </div>
                ) : (
                  <div className="campaigns-grid">
                    {activeCampaigns.slice(0, 3).map(campaign => (
                      <div key={campaign.id} className="campaign-card" data-testid={`campaign-${campaign.id}`}>
                        <div className="campaign-header">
                          <h3>{campaign.title}</h3>
                          <span className="badge badge-active">{campaign.status.replace('_', ' ')}</span>
                        </div>
                        <p className="campaign-brief">{campaign.brief_text.substring(0, 100)}...</p>
                        <div className="campaign-stats">
                          <span><strong>Bids:</strong> {campaign.bids?.length || 0}</span>
                          <span><strong>Budget:</strong> ${campaign.budget_min} - ${campaign.budget_max}</span>
                        </div>
                        <button className="btn-secondary" onClick={() => handleViewCampaign(campaign.id)}>
                          <Eye size={18} /> View Details
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="section-group">
                <h2>Pending Approval</h2>
                {pendingCampaigns.length === 0 ? (
                  <div className="empty-state-small">
                    <p>No campaigns pending approval</p>
                  </div>
                ) : (
                  <div className="pending-list">
                    {pendingCampaigns.map(campaign => (
                      <div key={campaign.id} className="pending-item" data-testid={`pending-${campaign.id}`}>
                        <div className="pending-info">
                          <h4>{campaign.title}</h4>
                          <span className="badge badge-pending">Pending Admin Approval</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'all-campaigns' && (
            <div className="all-campaigns-section">
              <h2>All Your Campaigns</h2>
              {loading ? (
                <div className="loading">Loading campaigns...</div>
              ) : campaigns.length === 0 ? (
                <div className="empty-state">
                  <Briefcase size={64} />
                  <p>No campaigns yet. Create your first campaign to get started!</p>
                  <button className="btn-primary" onClick={() => setShowCreateModal(true)}>Create Campaign</button>
                </div>
              ) : (
                <div className="campaigns-grid">
                  {campaigns.map(campaign => (
                    <div key={campaign.id} className="campaign-card-detailed" data-testid={`campaign-${campaign.id}`}>
                      <div className="campaign-header">
                        <h3>{campaign.title}</h3>
                        <span className={`badge badge-${campaign.status.replace('_', '-')}`}>{campaign.status.replace('_', ' ')}</span>
                      </div>
                      <p className="campaign-description">{campaign.brief_text.substring(0, 120)}...</p>
                      <div className="campaign-stats">
                        <div className="stat">
                          <span className="stat-label">Budget</span>
                          <span className="stat-value">${campaign.budget_min} - ${campaign.budget_max}</span>
                        </div>
                        <div className="stat">
                          <span className="stat-label">Bids</span>
                          <span className="stat-value">{campaign.bids?.length || 0}</span>
                        </div>
                        <div className="stat">
                          <span className="stat-label">Status</span>
                          <span className="stat-value">{campaign.status.replace('_', ' ')}</span>
                        </div>
                      </div>
                      <div className="campaign-actions-row">
                        <button
                          className="btn-secondary"
                          onClick={() => handleViewCampaign(campaign.id)}
                          data-testid={`view-campaign-${campaign.id}`}
                        >
                          <Eye size={18} /> View Details
                        </button>
                        {campaign.selected_creator && (
                          <button
                            className="btn-secondary"
                            onClick={() => navigate(`/chat/${campaign.selected_creator}`)}
                            data-testid={`chat-creator-${campaign.id}`}
                          >
                            <MessageSquare size={18} /> Chat
                          </button>
                        )}
                        {campaign.requires_shipment && campaign.selected_creator && (
                          <button
                            className="btn-secondary"
                            onClick={() => navigate(`/shipment?campaign=${campaign.id}`)}
                            data-testid={`shipment-${campaign.id}`}
                          >
                            <Package size={18} /> Shipment
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'pending-bids' && (
            <div className="bids-section">
              <h2>Campaigns with Pending Bids</h2>
              {campaigns.filter(c => c.bids && c.bids.length > 0 && !c.selected_creator).length === 0 ? (
                <div className="empty-state">
                  <Users size={64} />
                  <p>No pending bids at the moment</p>
                </div>
              ) : (
                <div className="bids-grid">
                  {campaigns.filter(c => c.bids && c.bids.length > 0 && !c.selected_creator).map(campaign => (
                    <div key={campaign.id} className="bid-campaign-card" data-testid={`bid-campaign-${campaign.id}`}>
                      <div className="bid-campaign-header">
                        <h3>{campaign.title}</h3>
                        <span className="bid-count">{campaign.bids.length} Bids</span>
                      </div>
                      <p className="campaign-budget">Budget: ${campaign.budget_min} - ${campaign.budget_max}</p>
                      <div className="bids-preview">
                        {campaign.bids.slice(0, 2).map((bid, idx) => (
                          <div key={idx} className="bid-preview-item">
                            <span className="creator-name">{bid.creator_nickname}</span>
                            <span className="bid-amount">${bid.amount}</span>
                          </div>
                        ))}
                      </div>
                      <button
                        className="btn-primary"
                        onClick={() => handleViewCampaign(campaign.id)}
                        data-testid={`review-bids-${campaign.id}`}
                      >
                        Review All Bids
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'work-review' && (
            <div className="work-review-section">
              <h2>Work Submissions to Review</h2>
              <div className="empty-state">
                <FileCheck size={64} />
                <p>No work submissions pending review</p>
                <p className="hint">Work submissions from creators will appear here</p>
              </div>
            </div>
          )}

          {activeTab === 'shipments' && (
            <div className="shipments-section">
              <h2>Campaign Shipments</h2>
              {campaigns.filter(c => c.requires_shipment || c.shipment_option === 'yes').length === 0 ? (
                <div className="empty-state">
                  <Package size={64} />
                  <p>No campaigns requiring shipment</p>
                  <p className="hint">Campaigns with shipment requirements will appear here</p>
                </div>
              ) : (
                <div className="shipments-grid">
                  {campaigns.filter(c => c.requires_shipment || c.shipment_option === 'yes').map(campaign => (
                    <div key={campaign.id} className="shipment-card" data-testid={`shipment-${campaign.id}`}>
                      <div className="shipment-header">
                        <h3>{campaign.title}</h3>
                        <span className={`badge ${campaign.selected_creator ? 'badge-active' : 'badge-pending'}`}>
                          {campaign.selected_creator ? 'Ready to Ship' : 'Awaiting Creator Selection'}
                        </span>
                      </div>
                      <div className="shipment-details">
                        <p className="shipment-info">
                          <strong>Status:</strong> {campaign.status.replace('_', ' ')}
                        </p>
                        <p className="shipment-info">
                          <strong>Creator:</strong> {campaign.selected_creator ? campaign.selected_creator : 'Not yet selected'}
                        </p>
                        <p className="shipment-info">
                          <strong>Budget:</strong> ${campaign.budget_min} - ${campaign.budget_max}
                        </p>
                      </div>
                      {campaign.selected_creator ? (
                        <button
                          className="btn-primary"
                          onClick={() => navigate(`/shipment?campaign=${campaign.id}`)}
                          data-testid={`manage-shipment-${campaign.id}`}
                        >
                          <Package size={18} /> Manage Shipment
                        </button>
                      ) : (
                        <button
                          className="btn-secondary"
                          onClick={() => navigate(`/campaign/${campaign.id}`)}
                          data-testid={`view-campaign-${campaign.id}`}
                        >
                          <Eye size={18} /> View Campaign & Select Creator
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Create Campaign Modal */}
      {showCreateModal && (
        <div className="modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Create New Campaign</h2>
            <form onSubmit={handleCreateCampaign} className="campaign-form">
              <div className="form-group">
                <label htmlFor="title">Campaign Title</label>
                <input
                  id="title"
                  type="text"
                  value={formData.title}
                  onChange={(e) => handleInputChange('title', e.target.value)}
                  className="input-field"
                  placeholder="e.g., T-Shirt UGC Campaign"
                  required
                  data-testid="campaign-title-input"
                />
              </div>

              <div className="form-group">
                <label htmlFor="objectives">Campaign Objectives</label>
                <div className="objective-input-wrapper">
                  <input
                    id="objectives"
                    type="text"
                    value={objectiveInput}
                    onChange={(e) => setObjectiveInput(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), addObjective())}
                    className="input-field"
                    placeholder="e.g., Increase brand awareness"
                    data-testid="objective-input"
                  />
                  <button type="button" onClick={addObjective} className="btn-secondary" data-testid="add-objective-btn">
                    Add
                  </button>
                </div>
                <div className="objectives-list">
                  {formData.objectives.map((obj, idx) => (
                    <span key={idx} className="objective-tag" data-testid={`objective-${idx}`}>
                      {obj}
                      <button type="button" onClick={() => removeObjective(obj)} data-testid={`remove-objective-${idx}`}>×</button>
                    </span>
                  ))}
                </div>
              </div>

              <div className="budget-row">
                <div className="form-group">
                  <label htmlFor="budget_min">Min Budget ($)</label>
                  <input
                    id="budget_min"
                    type="number"
                    value={formData.budget_min}
                    onChange={(e) => handleInputChange('budget_min', e.target.value)}
                    className="input-field"
                    placeholder="100"
                    required
                    data-testid="budget-min-input"
                  />
                </div>
                <div className="form-group">
                  <label htmlFor="budget_max">Max Budget ($)</label>
                  <input
                    id="budget_max"
                    type="number"
                    value={formData.budget_max}
                    onChange={(e) => handleInputChange('budget_max', e.target.value)}
                    className="input-field"
                    placeholder="500"
                    required
                    data-testid="budget-max-input"
                  />
                </div>
              </div>

              <div className="form-group">
                <label htmlFor="brief_text">Campaign Brief</label>
                <textarea
                  id="brief_text"
                  value={formData.brief_text}
                  onChange={(e) => handleInputChange('brief_text', e.target.value)}
                  className="textarea-field"
                  placeholder="Describe your campaign requirements, target audience, content style, etc."
                  required
                  data-testid="brief-text-input"
                />
              </div>

              <div className="form-group">
                <label htmlFor="shipment_option">Will you ship your product to creator for the video?</label>
                <select
                  id="shipment_option"
                  value={formData.shipment_option}
                  onChange={(e) => handleInputChange('shipment_option', e.target.value)}
                  className="input-field"
                  data-testid="shipment-option-select"
                >
                  <option value="no">No - Creator uses their own</option>
                  <option value="yes">Yes - I will ship the product</option>
                  <option value="not_sure">Not Sure - Discuss with creator</option>
                </select>
              </div>

              <div className="modal-actions">
                <button type="button" className="btn-secondary" onClick={() => setShowCreateModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-primary" data-testid="submit-campaign-btn">
                  Create Campaign
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <style jsx>{`
        .dashboard-page {
          min-height: 100vh;
          background: linear-gradient(135deg, #f8f9ff 0%, #e8ecff 100%);
        }

        .dashboard-container {
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 40px 20px;
        }

        .approval-pending {
          text-align: center;
          background: white;
          padding: 60px 40px;
          border-radius: 24px;
          max-width: 600px;
          box-shadow: 0 10px 40px rgba(0, 0, 0, 0.08);
        }

        .approval-pending h2 {
          font-size: 2rem;
          margin-bottom: 16px;
          color: #1a202c;
        }

        .approval-pending p {
          color: #718096;
          margin-bottom: 12px;
          line-height: 1.6;
        }

        .approval-pending button {
          margin-top: 24px;
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
        }

        .header-actions {
          display: flex;
          gap: 12px;
        }

        .header-actions button {
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .dashboard-content {
          padding: 40px 8%;
          max-width: 1400px;
          margin: 0 auto;
        }

        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
          gap: 24px;
          margin-bottom: 32px;
        }

        .stat-card {
          background: white;
          padding: 24px;
          border-radius: 16px;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
          display: flex;
          align-items: center;
          gap: 20px;
          transition: all 0.3s ease;
        }

        .stat-card:hover {
          transform: translateY(-4px);
          box-shadow: 0 8px 30px rgba(0, 0, 0, 0.12);
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

        .stat-icon.active {
          background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        }

        .stat-icon.bids {
          background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
        }

        .stat-icon.spent {
          background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
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

        .quick-actions {
          background: white;
          padding: 32px;
          border-radius: 24px;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
          margin-bottom: 32px;
        }

        .quick-actions h3 {
          font-size: 1.5rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 24px;
        }

        .actions-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 16px;
        }

        .action-btn {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 12px;
          padding: 24px;
          background: linear-gradient(135deg, #f8f9ff 0%, #e8ecff 100%);
          border: 2px solid #e2e8f0;
          border-radius: 16px;
          cursor: pointer;
          transition: all 0.3s ease;
          font-weight: 600;
          color: #4a5568;
        }

        .action-btn:hover {
          border-color: #667eea;
          transform: translateY(-4px);
          box-shadow: 0 8px 24px rgba(102, 126, 234, 0.2);
        }

        .tabs-container {
          background: white;
          padding: 0;
          border-radius: 24px 24px 0 0;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
          margin-bottom: -1px;
        }

        .tabs {
          display: flex;
          gap: 8px;
          padding: 16px 24px 0;
          overflow-x: auto;
          border-bottom: 2px solid #e2e8f0;
        }

        .tab {
          padding: 12px 24px;
          background: none;
          border: none;
          border-bottom: 3px solid transparent;
          color: #718096;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
          white-space: nowrap;
          margin-bottom: -2px;
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
          border-radius: 0 0 24px 24px;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
          min-height: 400px;
        }

        .section-group {
          margin-bottom: 48px;
        }

        .section-group:last-child {
          margin-bottom: 0;
        }

        .section-group h2 {
          font-size: 1.5rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 24px;
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

        .empty-state-small {
          text-align: center;
          padding: 30px;
          color: #718096;
        }

        .hint {
          font-size: 0.9rem;
          color: #a0aec0;
          font-style: italic;
        }

        .campaigns-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
          gap: 24px;
        }

        .campaign-card,
        .campaign-card-detailed {
          background: #f8f9ff;
          padding: 24px;
          border-radius: 16px;
          border: 2px solid #e2e8f0;
          transition: all 0.3s ease;
        }

        .campaign-card:hover,
        .campaign-card-detailed:hover {
          border-color: #667eea;
          transform: translateY(-4px);
          box-shadow: 0 8px 24px rgba(102, 126, 234, 0.2);
        }

        .campaign-header {
          display: flex;
          justify-content: space-between;
          align-items: start;
          margin-bottom: 12px;
        }

        .campaign-header h3 {
          font-size: 1.25rem;
          font-weight: 600;
          color: #1a202c;
          flex: 1;
        }

        .campaign-brief,
        .campaign-description {
          color: #4a5568;
          line-height: 1.6;
          margin-bottom: 16px;
        }

        .campaign-stats {
          display: flex;
          gap: 24px;
          margin-bottom: 20px;
        }

        .stat {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .stat-label {
          font-size: 0.875rem;
          color: #718096;
        }

        .stat-value {
          font-weight: 600;
          color: #1a202c;
        }

        .campaign-actions-row {
          display: flex;
          gap: 12px;
          flex-wrap: wrap;
        }

        .campaign-actions-row button {
          flex: 1;
          min-width: 140px;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
        }

        .pending-list {
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .pending-item {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 20px;
          background: #f8f9ff;
          border-radius: 12px;
          border: 2px solid #e2e8f0;
        }

        .pending-info h4 {
          font-size: 1.1rem;
          font-weight: 600;
          color: #1a202c;
          margin-bottom: 8px;
        }

        .bids-grid,
        .shipments-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
          gap: 24px;
        }

        .bid-campaign-card,
        .shipment-card {
          background: #f8f9ff;
          padding: 24px;
          border-radius: 16px;
          border: 2px solid #e2e8f0;
        }

        .bid-campaign-header,
        .shipment-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 16px;
        }

        .bid-campaign-header h3,
        .shipment-header h3 {
          font-size: 1.1rem;
          font-weight: 600;
          color: #1a202c;
          flex: 1;
        }

        .bid-count {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          padding: 6px 12px;
          border-radius: 20px;
          font-size: 0.875rem;
          font-weight: 600;
        }

        .campaign-budget,
        .shipment-info {
          color: #4a5568;
          margin-bottom: 16px;
        }

        .bids-preview {
          display: flex;
          flex-direction: column;
          gap: 8px;
          margin-bottom: 20px;
          padding: 12px;
          background: white;
          border-radius: 8px;
        }

        .bid-preview-item {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 8px 0;
        }

        .creator-name {
          color: #667eea;
          font-weight: 600;
        }

        .bid-amount {
          font-weight: 700;
          color: #1a202c;
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
          max-width: 700px;
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

        .campaign-form {
          display: flex;
          flex-direction: column;
          gap: 20px;
        }

        .objective-input-wrapper {
          display: flex;
          gap: 12px;
        }

        .objective-input-wrapper .input-field {
          flex: 1;
        }

        .objectives-list {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
          margin-top: 12px;
        }

        .objective-tag {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 6px 12px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          border-radius: 20px;
          font-size: 0.875rem;
          font-weight: 500;
        }

        .objective-tag button {
          background: none;
          border: none;
          color: white;
          font-size: 1.25rem;
          cursor: pointer;
          padding: 0;
          line-height: 1;
        }

        .budget-row {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 16px;
        }

        .checkbox-label {
          display: flex;
          align-items: center;
          gap: 12px;
          font-size: 0.95rem;
          color: #2d3748;
          cursor: pointer;
        }

        .checkbox-label input[type="checkbox"] {
          width: 20px;
          height: 20px;
          cursor: pointer;
        }

        .modal-actions {
          display: flex;
          gap: 12px;
          margin-top: 8px;
        }

        .modal-actions button {
          flex: 1;
        }

        /* Approval Page Styles */
        .approval-page {
          min-height: 100vh;
          display: flex;
          flex-direction: column;
          background: linear-gradient(135deg, #f8f9ff 0%, #e8ecff 100%);
        }

        .approval-header {
          background: white;
          border-bottom: 2px solid #e2e8f0;
          padding: 20px 8%;
          position: sticky;
          top: 0;
          z-index: 100;
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
        }

        .header-container {
          max-width: 1400px;
          margin: 0 auto;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .logo-section {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .logo-icon {
          width: 48px;
          height: 48px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          border-radius: 12px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-weight: 700;
          font-size: 1rem;
        }

        .logo-text {
          font-size: 1.25rem;
          font-weight: 700;
          color: #1a202c;
        }

        .header-logout-btn {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 10px 20px;
          background: white;
          border: 2px solid #e2e8f0;
          border-radius: 8px;
          color: #4a5568;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
        }

        .header-logout-btn:hover {
          border-color: #667eea;
          color: #667eea;
        }

        .approval-content {
          flex: 1;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 60px 20px;
        }

        .approval-card {
          background: white;
          padding: 60px 48px;
          border-radius: 24px;
          max-width: 800px;
          width: 100%;
          box-shadow: 0 20px 60px rgba(0, 0, 0, 0.1);
          text-align: center;
        }

        .icon-wrapper {
          margin-bottom: 24px;
        }

        .pending-icon {
          color: #667eea;
          animation: pulse 2s ease-in-out infinite;
        }

        @keyframes pulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.8; transform: scale(1.05); }
        }

        .approval-card h1 {
          font-size: 2.5rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 12px;
        }

        .subtitle {
          font-size: 1.125rem;
          color: #718096;
          margin-bottom: 40px;
        }

        .info-box {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 24px;
          margin-bottom: 40px;
          padding: 32px;
          background: #f8f9ff;
          border-radius: 16px;
        }

        .info-item {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 12px;
          text-align: center;
        }

        .info-icon {
          width: 56px;
          height: 56px;
          background: white;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 1.75rem;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }

        .info-item h3 {
          font-size: 1rem;
          font-weight: 600;
          color: #2d3748;
          margin-bottom: 4px;
        }

        .info-item p {
          font-size: 0.875rem;
          color: #718096;
        }

        .status-message {
          padding: 24px;
          background: #e0e7ff;
          border-radius: 12px;
          margin-bottom: 32px;
          border-left: 4px solid #667eea;
        }

        .status-message p {
          color: #3730a3;
          line-height: 1.6;
          margin: 0;
        }

        .approval-footer {
          background: white;
          border-top: 2px solid #e2e8f0;
          padding: 48px 8% 24px;
          margin-top: auto;
        }

        .footer-container {
          max-width: 1400px;
          margin: 0 auto;
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
          gap: 40px;
          margin-bottom: 32px;
        }

        .footer-section h4 {
          font-size: 1.125rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 16px;
        }

        .footer-section p {
          color: #718096;
          line-height: 1.8;
          margin-bottom: 8px;
        }

        .footer-bottom {
          max-width: 1400px;
          margin: 0 auto;
          padding-top: 24px;
          border-top: 1px solid #e2e8f0;
          text-align: center;
          color: #a0aec0;
          font-size: 0.875rem;
        }

        @media (max-width: 768px) {
          .header-content {
            flex-direction: column;
            gap: 20px;
            align-items: flex-start;
          }

          .header-actions {
            width: 100%;
            flex-wrap: wrap;
          }

          .header-actions button {
            flex: 1;
          }

          .stats-grid {
            grid-template-columns: 1fr;
          }

          .campaigns-grid {
            grid-template-columns: 1fr;
          }

          .actions-grid {
            grid-template-columns: 1fr 1fr;
          }

          .budget-row {
            grid-template-columns: 1fr;
          }

          .tabs {
            gap: 4px;
            padding: 16px 16px 0;
          }

          .tab {
            padding: 10px 16px;
            font-size: 0.9rem;
          }

          .tab-content {
            padding: 24px 16px;
          }
        }
      `}</style>
    </div>
  );
}
