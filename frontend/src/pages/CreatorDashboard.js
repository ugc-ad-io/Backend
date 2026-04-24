import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import { Briefcase, DollarSign, LogOut, MessageSquare, Star, CheckCircle, Package, Upload, FileText, TrendingUp, Eye, User } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export default function CreatorDashboard() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [activeCampaigns, setActiveCampaigns] = useState([]);
  const [availableCampaigns, setAvailableCampaigns] = useState([]);
  const [myBids, setMyBids] = useState([]);
  const [reviews, setReviews] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedCampaign, setSelectedCampaign] = useState(null);
  const [bidAmount, setBidAmount] = useState('');
  const [proposal, setProposal] = useState('');
  const [deliveryDays, setDeliveryDays] = useState('');
  const [activeTab, setActiveTab] = useState('overview');
  const [portfolio, setPortfolio] = useState([]);
  const [uploadingPortfolio, setUploadingPortfolio] = useState(false);

  useEffect(() => {
    if (user?.approval_status === 'approved') {
      fetchAllData();
      
      // Poll for updates every 10 seconds
      const interval = setInterval(() => {
        fetchAllData();
      }, 10000);
      
      return () => clearInterval(interval);
    }
  }, [user]);

  const fetchAllData = async () => {
    try {
      const [campaignsRes, reviewsRes] = await Promise.all([
        axios.get(`${API}/campaigns?t=${Date.now()}`),
        axios.get(`${API}/reviews/creator/${user.id}`)
      ]);
      
      const allCampaigns = campaignsRes.data;
      
      // Active work (campaigns where I've been selected)
      const activeWork = allCampaigns.filter(c => 
        c.selected_creator === user.id && 
        (c.status === 'in_progress' || c.status === 'active')
      );
      setActiveCampaigns(activeWork);
      
      // Available campaigns (active and not yet selected)
      const available = allCampaigns.filter(c => c.status === 'active' && !c.selected_creator);
      setAvailableCampaigns(available);
      
      // My bids (campaigns where I've bid)
      const bidsData = allCampaigns.filter(c => 
        c.bids?.some(bid => bid.creator_id === user.id)
      ).map(c => ({
        ...c,
        myBid: c.bids.find(bid => bid.creator_id === user.id)
      }));
      setMyBids(bidsData);
      
      setReviews(reviewsRes.data);
      
      // Set portfolio from user data
      if (user?.portfolio) {
        setPortfolio(user.portfolio);
      }
    } catch (error) {
      toast.error('Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const handleBidSubmit = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${API}/campaigns/${selectedCampaign.id}/bid`, {
        campaign_id: selectedCampaign.id,
        amount: parseFloat(bidAmount),
        proposal,
        estimated_delivery_days: parseInt(deliveryDays)
      });
      toast.success('Bid submitted successfully!');
      setSelectedCampaign(null);
      setBidAmount('');
      setProposal('');
      setDeliveryDays('');
      fetchAllData();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to submit bid');
    }
  };

  const handlePortfolioUpload = async (e) => {
    const files = Array.from(e.target.files || []);
    if (files.length === 0) return;

    setUploadingPortfolio(true);

    try {
      const uploadPromises = files.map(async (file) => {
        if (file.size > 10 * 1024 * 1024) {
          throw new Error(`${file.name} is too large. Maximum 10MB per file.`);
        }
        
        const formDataUpload = new FormData();
        formDataUpload.append('file', file);
        const response = await axios.post(`${API}/upload/file`, formDataUpload, {
          headers: { 'Content-Type': 'multipart/form-data' }
        });
        return response.data.file_url;
      });

      const uploadedUrls = await Promise.all(uploadPromises);
      const newPortfolio = [...portfolio, ...uploadedUrls];
      setPortfolio(newPortfolio);
      
      // Update user portfolio without affecting approval status
      await axios.patch(`${API}/profile/portfolio`, newPortfolio);
      
      toast.success(`${uploadedUrls.length} file(s) added to portfolio!`);
    } catch (error) {
      console.error('Portfolio upload error:', error);
      toast.error(error.response?.data?.detail || error.message || 'Failed to upload portfolio items');
    } finally {
      setUploadingPortfolio(false);
    }
  };

  const handleRemovePortfolioItem = async (url) => {
    try {
      const newPortfolio = portfolio.filter(item => item !== url);
      setPortfolio(newPortfolio);
      
      // Update user portfolio without affecting approval status
      await axios.patch(`${API}/profile/portfolio`, newPortfolio);
      
      toast.success('Portfolio item removed');
    } catch (error) {
      toast.error('Failed to remove portfolio item');
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  if (user?.approval_status === 'pending') {
    return (
      <div className="approval-page">
        <header className="approval-header">
          <div className="header-container">
            <div className="logo-section">
              <div className="logo-icon">UGC</div>
              <span className="logo-text">Creator Platform</span>
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
            <h1>Profile Under Review</h1>
            <p className="subtitle">Thank you for completing your profile!</p>
            
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
                <div className="info-icon">✓</div>
                <div>
                  <h3>What's Next?</h3>
                  <p>Start browsing campaigns</p>
                </div>
              </div>
            </div>

            <div className="status-message">
              <p>Your profile is currently being reviewed by our verification team. We carefully review each profile to ensure quality and authenticity on our platform.</p>
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
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 12px;
            font-weight: 700;
            font-size: 1.25rem;
          }

          .logo-text {
            font-size: 1.5rem;
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
            background: #1a202c;
            color: white;
            padding: 48px 8%;
          }

          .footer-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 32px;
            margin-bottom: 24px;
          }

          .footer-section h4 {
            font-size: 1.125rem;
            font-weight: 700;
            margin-bottom: 16px;
          }

          .footer-section p {
            color: #a0aec0;
            font-size: 0.875rem;
            margin-bottom: 8px;
          }

          .footer-bottom {
            padding-top: 24px;
            border-top: 1px solid #4a5568;
            text-align: center;
          }

          .footer-bottom p {
            color: #a0aec0;
            font-size: 0.875rem;
          }

          .btn-primary {
            padding: 14px 32px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 12px;
            font-weight: 600;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.3s ease;
          }

          .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4);
          }

          @media (max-width: 768px) {
            .approval-card {
              padding: 40px 24px;
            }

            .approval-card h1 {
              font-size: 2rem;
            }

            .info-box {
              grid-template-columns: 1fr;
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
          <p>Unfortunately, your profile was not approved. Please contact support for more information.</p>
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
            <h1>Creator Dashboard</h1>
            <p>Welcome back, {user?.nickname}!</p>
          </div>
          <div className="header-actions">
            <button className="btn-secondary" onClick={() => navigate('/chat/conversations')} data-testid="messages-btn">
              <MessageSquare size={20} /> Messages
            </button>
            <button className="btn-secondary" onClick={() => navigate('/settings')} data-testid="settings-btn">
              <User size={20} /> Settings
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
          <div className="stat-card" onClick={() => navigate('/withdrawal')} style={{cursor: 'pointer'}} data-testid="balance-card">
            <div className="stat-icon">
              <DollarSign size={32} />
            </div>
            <div>
              <p className="stat-label">Available Balance</p>
              <p className="stat-value">${user?.balance?.toFixed(2) || '0.00'}</p>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon">
              <Briefcase size={32} />
            </div>
            <div>
              <p className="stat-label">Active Campaigns</p>
              <p className="stat-value">{activeCampaigns.length}</p>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon">
              <Star size={32} />
            </div>
            <div>
              <p className="stat-label">Average Rating</p>
              <p className="stat-value">{user?.average_rating?.toFixed(1) || 'N/A'}</p>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon">
              <TrendingUp size={32} />
            </div>
            <div>
              <p className="stat-label">Total Reviews</p>
              <p className="stat-value">{user?.total_reviews || 0}</p>
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="quick-actions">
          <h3>Quick Actions</h3>
          <div className="actions-grid">
            <button className="action-btn" onClick={() => setActiveTab('browse')} data-testid="browse-campaigns-btn">
              <Briefcase size={24} />
              <span>Browse Campaigns</span>
            </button>
            <button className="action-btn" onClick={() => navigate('/withdrawal')} data-testid="withdraw-btn">
              <DollarSign size={24} />
              <span>Withdraw Earnings</span>
            </button>
            <button className="action-btn" onClick={() => setActiveTab('portfolio')} data-testid="portfolio-btn">
              <FileText size={24} />
              <span>My Portfolio</span>
            </button>
            <button className="action-btn" onClick={() => setActiveTab('reviews')} data-testid="reviews-btn">
              <Star size={24} />
              <span>My Reviews</span>
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
              className={`tab ${activeTab === 'active' ? 'active' : ''}`}
              onClick={() => setActiveTab('active')}
              data-testid="tab-active"
            >
              My Active Work ({activeCampaigns.length})
            </button>
            <button
              className={`tab ${activeTab === 'bids' ? 'active' : ''}`}
              onClick={() => setActiveTab('bids')}
              data-testid="tab-bids"
            >
              My Bids ({myBids.length})
            </button>
            <button
              className={`tab ${activeTab === 'browse' ? 'active' : ''}`}
              onClick={() => setActiveTab('browse')}
              data-testid="tab-browse"
            >
              Browse Campaigns ({availableCampaigns.length})
            </button>
            <button
              className={`tab ${activeTab === 'reviews' ? 'active' : ''}`}
              onClick={() => setActiveTab('reviews')}
              data-testid="tab-reviews"
            >
              Reviews ({reviews.length})
            </button>
          </div>
        </div>

        {/* Tab Content */}
        <div className="tab-content">
          {activeTab === 'overview' && (
            <div className="overview-section">
              <div className="section-group">
                <h2>Active Work</h2>
                {activeCampaigns.length === 0 ? (
                  <div className="empty-state">
                    <Briefcase size={64} />
                    <p>No active campaigns</p>
                    <button className="btn-primary" onClick={() => setActiveTab('browse')}>Browse Campaigns</button>
                  </div>
                ) : (
                  <div className="campaigns-grid">
                    {activeCampaigns.slice(0, 3).map(campaign => (
                      <div key={campaign.id} className="campaign-card" data-testid={`active-campaign-${campaign.id}`}>
                        <h3>{campaign.title}</h3>
                        <p className="campaign-status">Status: {campaign.status}</p>
                        <div className="campaign-actions">
                          <button className="btn-secondary" onClick={() => navigate(`/work/submit?campaign=${campaign.id}`)} data-testid="submit-work-btn">
                            <Upload size={18} /> Submit Work
                          </button>
                          {campaign.requires_shipment && (
                            <button className="btn-secondary" onClick={() => navigate(`/shipment?campaign=${campaign.id}`)} data-testid="track-shipment-btn">
                              <Package size={18} /> Track Shipment
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="section-group">
                <h2>Recent Bids</h2>
                {myBids.length === 0 ? (
                  <div className="empty-state-small">
                    <p>No bids submitted yet</p>
                  </div>
                ) : (
                  <div className="bids-list">
                    {myBids.slice(0, 3).map(campaign => (
                      <div key={campaign.id} className="bid-item" data-testid={`bid-${campaign.id}`}>
                        <div className="bid-info">
                          <h4>{campaign.title}</h4>
                          <p>Your Bid: ${campaign.myBid.amount}</p>
                          <span className="badge badge-pending">Pending</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'active' && (
            <div className="active-section">
              <h2>My Active Work</h2>
              {activeCampaigns.length === 0 ? (
                <div className="empty-state">
                  <Briefcase size={64} />
                  <p>No active campaigns. Browse and bid on campaigns to get started!</p>
                </div>
              ) : (
                <div className="campaigns-grid">
                  {activeCampaigns.map(campaign => {
                    const myBid = campaign.bids?.find(bid => bid.creator_id === user.id);
                    return (
                      <div key={campaign.id} className="campaign-card-detailed selected-campaign" data-testid={`campaign-${campaign.id}`}>
                        <div className="selected-badge-top">
                          ✓ You've been selected for this campaign!
                        </div>
                        <div className="campaign-header">
                          <h3>{campaign.title}</h3>
                          <span className="badge badge-active">{campaign.status}</span>
                        </div>
                        <p className="campaign-brief">{campaign.brief_text?.substring(0, 100)}...</p>
                        <div className="campaign-meta">
                          <span><strong>Your Bid:</strong> ${myBid?.amount || 'N/A'}</span>
                          <span><strong>Delivery:</strong> {myBid?.estimated_delivery_days || 0} days</span>
                        </div>
                        <div className="campaign-meta">
                          <span><strong>Budget:</strong> ${campaign.budget_min} - ${campaign.budget_max}</span>
                        <span><strong>Business:</strong> {campaign.business_nickname}</span>
                      </div>
                      <div className="campaign-actions-row">
                        <button className="btn-primary" onClick={() => navigate(`/work/submit?campaign=${campaign.id}`)}>
                          <Upload size={18} /> Submit Work
                        </button>
                        <button className="btn-secondary" onClick={() => navigate(`/chat/${campaign.business_id}`)}>
                          <MessageSquare size={18} /> Chat
                        </button>
                        {campaign.requires_shipment && (
                          <button className="btn-secondary" onClick={() => navigate(`/shipment?campaign=${campaign.id}`)}>
                            <Package size={18} /> Shipment
                          </button>
                        )}
                      </div>
                    </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {activeTab === 'bids' && (
            <div className="bids-section">
              <h2>My Submitted Bids</h2>
              {myBids.length === 0 ? (
                <div className="empty-state">
                  <FileText size={64} />
                  <p>No bids submitted yet</p>
                  <button className="btn-primary" onClick={() => setActiveTab('browse')}>Browse Campaigns</button>
                </div>
              ) : (
                <div className="bids-grid">
                  {myBids.map(campaign => (
                    <div key={campaign.id} className="bid-card" data-testid={`mybid-${campaign.id}`}>
                      <div className="bid-header">
                        <h3>{campaign.title}</h3>
                        <span className="badge badge-pending">Bid Pending</span>
                      </div>
                      <div className="bid-details">
                        <p><strong>Your Bid:</strong> ${campaign.myBid.amount}</p>
                        <p><strong>Delivery:</strong> {campaign.myBid.estimated_delivery_days} days</p>
                        <p><strong>Proposal:</strong> {campaign.myBid.proposal.substring(0, 80)}...</p>
                      </div>
                      <button className="btn-secondary" onClick={() => navigate(`/campaign/${campaign.id}`)}>View Campaign</button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'browse' && (
            <div className="browse-section">
              <div className="browse-header">
                <h2>Available Campaigns ({availableCampaigns.length})</h2>
                <p className="browse-subtitle">Browse and bid on campaigns that match your expertise</p>
              </div>
              {loading ? (
                <div className="loading">Loading campaigns...</div>
              ) : availableCampaigns.length === 0 ? (
                <div className="empty-state">
                  <Briefcase size={64} />
                  <p>No active campaigns available at the moment</p>
                </div>
              ) : (
                <div className="campaigns-list-view">
                  {availableCampaigns.map((campaign, idx) => (
                    <div key={campaign.id} className="campaign-list-item" data-testid={`campaign-${campaign.id}`}>
                      <div className="list-item-number">{idx + 1}</div>
                      <div className="list-item-content">
                        <div className="list-item-header">
                          <h3>{campaign.title}</h3>
                          <span className="badge badge-active">{campaign.status}</span>
                        </div>
                        <p className="list-item-brief">{campaign.brief_text.substring(0, 120)}...</p>
                        <div className="list-item-meta">
                          <span className="meta-badge">
                            <DollarSign size={16} /> ${campaign.budget_min} - ${campaign.budget_max}
                          </span>
                          <span className="meta-badge">
                            <Briefcase size={16} /> {campaign.objectives.length} Objectives
                          </span>
                          {campaign.requires_shipment && (
                            <span className="meta-badge shipment">
                              <Package size={16} /> Shipment Included
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="list-item-actions">
                        <button
                          className="btn-details"
                          onClick={() => navigate(`/campaign/${campaign.id}`)}
                          data-testid={`view-details-${campaign.id}`}
                        >
                          <Eye size={18} /> View Details
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'reviews' && (
            <div className="reviews-section">
              <h2>My Reviews & Ratings</h2>
              {reviews.length === 0 ? (
                <div className="empty-state">
                  <Star size={64} />
                  <p>No reviews yet. Complete campaigns to receive reviews!</p>
                </div>
              ) : (
                <div className="reviews-grid">
                  {reviews.map((review, idx) => (
                    <div key={review.id || idx} className="review-card" data-testid={`review-${idx}`}>
                      <div className="review-header">
                        <div className="stars">
                          {[...Array(5)].map((_, i) => (
                            <Star key={i} size={20} fill={i < review.rating ? '#fbbf24' : 'none'} color="#fbbf24" />
                          ))}
                        </div>
                        <span className="review-date">{new Date(review.created_at).toLocaleDateString()}</span>
                      </div>
                      <p className="review-text">{review.review}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'portfolio' && (
            <div className="portfolio-section">
              <div className="portfolio-header">
                <h2>My Portfolio</h2>
                <input
                  type="file"
                  accept="image/*,video/*"
                  multiple
                  onChange={handlePortfolioUpload}
                  style={{ display: 'none' }}
                  id="portfolio-upload-dashboard"
                />
                <label htmlFor="portfolio-upload-dashboard" className="btn-primary" style={{ cursor: 'pointer' }}>
                  <Upload size={20} /> {uploadingPortfolio ? 'Uploading...' : 'Add Items'}
                </label>
              </div>
              {portfolio.length === 0 ? (
                <div className="empty-state">
                  <FileText size={64} />
                  <p>No portfolio items yet. Upload images or videos to showcase your work!</p>
                </div>
              ) : (
                <div className="portfolio-grid">
                  {portfolio.map((url, idx) => {
                    const isVideo = url.match(/\.(mp4|mov|webm|avi)$/i);
                    return (
                      <div key={idx} className="portfolio-item-card" data-testid={`portfolio-${idx}`}>
                        <div className="portfolio-media">
                          {isVideo ? (
                            <video src={`${BACKEND_URL}${url}`} controls />
                          ) : (
                            <img src={`${BACKEND_URL}${url}`} alt={`Portfolio ${idx + 1}`} />
                          )}
                        </div>
                        <button
                          className="btn-remove"
                          onClick={() => handleRemovePortfolioItem(url)}
                          data-testid={`remove-portfolio-${idx}`}
                        >
                          Remove
                        </button>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Bid Modal */}
      {selectedCampaign && (
        <div className="modal-overlay" onClick={() => setSelectedCampaign(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Submit Your Bid</h2>
            <p className="modal-subtitle">Campaign: {selectedCampaign.title}</p>
            <form onSubmit={handleBidSubmit} className="bid-form">
              <div className="form-group">
                <label htmlFor="bidAmount">Your Bid Amount ($)</label>
                <input
                  id="bidAmount"
                  type="number"
                  value={bidAmount}
                  onChange={(e) => setBidAmount(e.target.value)}
                  className="input-field"
                  placeholder="Enter your bid"
                  min={selectedCampaign.budget_min}
                  max={selectedCampaign.budget_max}
                  required
                  data-testid="bid-amount-input"
                />
              </div>
              <div className="form-group">
                <label htmlFor="deliveryDays">Estimated Delivery (days)</label>
                <input
                  id="deliveryDays"
                  type="number"
                  value={deliveryDays}
                  onChange={(e) => setDeliveryDays(e.target.value)}
                  className="input-field"
                  placeholder="Number of days"
                  required
                  data-testid="delivery-days-input"
                />
              </div>
              <div className="form-group">
                <label htmlFor="proposal">Proposal</label>
                <textarea
                  id="proposal"
                  value={proposal}
                  onChange={(e) => setProposal(e.target.value)}
                  className="textarea-field"
                  placeholder="Explain why you're the best fit for this campaign..."
                  required
                  data-testid="proposal-input"
                />
              </div>
              <div className="modal-actions">
                <button type="button" className="btn-secondary" onClick={() => setSelectedCampaign(null)}>
                  Cancel
                </button>
                <button type="submit" className="btn-primary" data-testid="submit-bid-btn">Submit Bid</button>
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

        .browse-header {
          margin-bottom: 32px;
        }

        .browse-header h2 {
          font-size: 1.75rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 8px;
        }

        .browse-subtitle {
          color: #718096;
          font-size: 1rem;
        }

        .campaigns-list-view {
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .campaign-list-item {
          display: flex;
          align-items: center;
          gap: 20px;
          padding: 20px;
          background: white;
          border-radius: 12px;
          border: 2px solid #e2e8f0;
          transition: all 0.3s ease;
        }

        .campaign-list-item:hover {
          border-color: #667eea;
          box-shadow: 0 4px 12px rgba(102, 126, 234, 0.15);
        }

        .list-item-number {
          width: 48px;
          height: 48px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          border-radius: 12px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-weight: 700;
          font-size: 1.25rem;
          flex-shrink: 0;
        }

        .list-item-content {
          flex: 1;
          min-width: 0;
        }

        .list-item-header {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-bottom: 8px;
        }

        .list-item-header h3 {
          font-size: 1.125rem;
          font-weight: 600;
          color: #1a202c;
          margin: 0;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }

        .list-item-brief {
          color: #4a5568;
          font-size: 0.9rem;
          line-height: 1.5;
          margin-bottom: 12px;
        }

        .list-item-meta {
          display: flex;
          flex-wrap: wrap;
          gap: 12px;
        }

        .meta-badge {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 6px 12px;
          background: #f8f9ff;
          border-radius: 8px;
          font-size: 0.875rem;
          font-weight: 500;
          color: #4a5568;
        }

        .meta-badge.shipment {
          background: #fff3cd;
          color: #856404;
        }

        .list-item-actions {
          display: flex;
          gap: 12px;
          flex-shrink: 0;
        }

        .btn-details {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 12px 24px;
          background: white;
          border: 2px solid #667eea;
          border-radius: 12px;
          color: #667eea;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
          white-space: nowrap;
        }

        .btn-details:hover {
          background: #667eea;
          color: white;
          transform: translateY(-2px);
          box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
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
          position: relative;
        }

        .campaign-card-detailed.selected-campaign {
          background: linear-gradient(135deg, #e6f7ff 0%, #f0f9ff 100%);
          border: 2px solid #48bb78;
        }

        .selected-badge-top {
          background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
          color: white;
          padding: 8px 16px;
          border-radius: 8px;
          font-weight: 600;
          font-size: 0.875rem;
          margin-bottom: 16px;
          display: flex;
          align-items: center;
          gap: 6px;
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

        .campaign-status {
          color: #667eea;
          font-weight: 600;
          margin-bottom: 16px;
        }

        .campaign-brief {
          color: #4a5568;
          line-height: 1.6;
          margin-bottom: 16px;
        }

        .campaign-meta {
          display: flex;
          flex-direction: column;
          gap: 8px;
          margin-bottom: 16px;
          padding: 12px;
          background: white;
          border-radius: 8px;
          font-size: 0.9rem;
        }

        .campaign-actions {
          display: flex;
          gap: 12px;
        }

        .campaign-actions button {
          flex: 1;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
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

        .campaign-description {
          color: #4a5568;
          line-height: 1.6;
          margin-bottom: 16px;
        }

        .campaign-details {
          display: flex;
          flex-direction: column;
          gap: 12px;
          margin-bottom: 20px;
        }

        .detail-item {
          display: flex;
          flex-direction: column;
          gap: 6px;
        }

        .detail-item .label {
          font-size: 0.875rem;
          color: #718096;
          font-weight: 600;
        }

        .detail-item .value {
          color: #1a202c;
          font-weight: 600;
        }

        .objectives {
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
        }

        .objective-tag {
          padding: 4px 10px;
          background: white;
          border-radius: 12px;
          font-size: 0.8rem;
          color: #667eea;
          font-weight: 500;
        }

        .bids-list {
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .bid-item {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 20px;
          background: #f8f9ff;
          border-radius: 12px;
          border: 2px solid #e2e8f0;
        }

        .bid-info h4 {
          font-size: 1.1rem;
          font-weight: 600;
          color: #1a202c;
          margin-bottom: 8px;
        }

        .bids-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
          gap: 24px;
        }

        .bid-card {
          background: #f8f9ff;
          padding: 24px;
          border-radius: 16px;
          border: 2px solid #e2e8f0;
        }

        .bid-header {
          display: flex;
          justify-content: space-between;
          align-items: start;
          margin-bottom: 16px;
        }

        .bid-header h3 {
          font-size: 1.1rem;
          font-weight: 600;
          color: #1a202c;
          flex: 1;
        }

        .bid-details {
          margin-bottom: 16px;
        }

        .bid-details p {
          margin-bottom: 8px;
          color: #4a5568;
        }

        .reviews-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
          gap: 24px;
        }

        .review-card {
          background: #f8f9ff;
          padding: 24px;
          border-radius: 16px;
          border: 2px solid #e2e8f0;
        }

        .review-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 16px;
        }

        .stars {
          display: flex;
          gap: 4px;
        }

        .review-date {
          color: #a0aec0;
          font-size: 0.875rem;
        }

        .review-text {
          color: #4a5568;
          line-height: 1.6;
        }

        .portfolio-section {
          padding: 20px 0;
        }

        .portfolio-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 32px;
        }

        .portfolio-header h2 {
          font-size: 1.75rem;
          font-weight: 700;
          color: #1a202c;
        }

        .portfolio-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
          gap: 24px;
        }

        .portfolio-item-card {
          background: white;
          border-radius: 16px;
          overflow: hidden;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
          transition: transform 0.3s ease;
        }

        .portfolio-item-card:hover {
          transform: translateY(-4px);
          box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
        }

        .portfolio-media {
          width: 100%;
          aspect-ratio: 16/9;
          background: #f8f9ff;
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .portfolio-media img,
        .portfolio-media video {
          width: 100%;
          height: 100%;
          object-fit: cover;
        }

        .btn-remove {
          width: 100%;
          padding: 12px;
          background: #fee;
          color: #c53030;
          border: none;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.3s ease;
        }

        .btn-remove:hover {
          background: #fdd;
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
          margin-bottom: 8px;
        }

        .modal-subtitle {
          color: #718096;
          margin-bottom: 32px;
        }

        .bid-form {
          display: flex;
          flex-direction: column;
          gap: 20px;
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
