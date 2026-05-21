import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import DashboardLayout from '../components/DashboardLayout';
import {
  ArrowRight,
  ArrowUpRight,
  Bell,
  Bookmark,
  Briefcase,
  CheckCircle,
  CheckCircle2,
  ChevronDown,
  Clock,
  Eye,
  Filter,
  FileCheck,
  IndianRupee,
  LayoutDashboard,
  LayoutGrid,
  List,
  LogOut,
  MapPin,
  MessageCircle,
  MessageSquare,
  Package,
  Search,
  Settings,
  ShieldCheck,
  Sparkles,
  Star,
  TrendingUp,
  Trophy,
  Upload,
  User,
  Zap
} from 'lucide-react';
import './CreatorDashboard.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const earningsData = [
  { label: 'Jan', value: 12000 },
  { label: 'Feb', value: 19000 },
  { label: 'Mar', value: 15000 },
  { label: 'Apr', value: 28000 },
  { label: 'May', value: 22000 },
  { label: 'Jun', value: 34000 }
];

const browseCovers = [
  'https://images.unsplash.com/photo-1581182800629-7d90925ad072?auto=format&fit=crop&q=80&w=800&h=520',
  'https://images.unsplash.com/photo-1558002038-1055907df827?auto=format&fit=crop&q=80&w=800&h=520',
  'https://images.unsplash.com/photo-1645318801217-143533cb559f?auto=format&fit=crop&q=80&w=800&h=520',
  'https://images.unsplash.com/photo-1663958749441-926bbef7cd0c?auto=format&fit=crop&q=80&w=800&h=520',
  'https://images.unsplash.com/photo-1491637639811-60e2756cc1c7?auto=format&fit=crop&q=80&w=800&h=520',
  'https://images.unsplash.com/photo-1580635766551-5e3a8ca8b21d?auto=format&fit=crop&q=80&w=800&h=520'
];

const browseLogos = [
  'https://images.unsplash.com/photo-1556228578-0d85b1a4d571?auto=format&fit=crop&q=80&w=128&h=128',
  'https://images.unsplash.com/photo-1546868871-7041f2a55e12?auto=format&fit=crop&q=80&w=128&h=128',
  'https://images.unsplash.com/photo-1517836357463-d25dfeac3438?auto=format&fit=crop&q=80&w=128&h=128',
  'https://images.unsplash.com/photo-1559525839-b184a4d698c7?auto=format&fit=crop&q=80&w=128&h=128'
];

const formatMoney = (value) => {
  const amount = Number(value || 0);
  return `Rs. ${amount.toLocaleString('en-IN', { maximumFractionDigits: 0 })}`;
};

const getCampaignBudget = (campaign) => {
  if (!campaign) return 'Rs. 0';
  const min = campaign.budget_min ?? campaign.budget ?? campaign.myBid?.amount ?? 0;
  const max = campaign.budget_max ?? min;
  return min === max ? formatMoney(min) : `${formatMoney(min)} - ${formatMoney(max)}`;
};

const getInitial = (name) => (name || 'U').trim().charAt(0).toUpperCase();

function MiniAreaChart({ data }) {
  const width = 640;
  const height = 230;
  const padding = 26;
  const max = Math.max(...data.map((point) => point.value));
  const min = Math.min(...data.map((point) => point.value));
  const range = max - min || 1;
  const points = data.map((point, index) => {
    const x = padding + (index * (width - padding * 2)) / (data.length - 1);
    const y = height - padding - ((point.value - min) / range) * (height - padding * 2);
    return { ...point, x, y };
  });
  const line = points.map((point) => `${point.x},${point.y}`).join(' ');
  const area = `${padding},${height - padding} ${line} ${width - padding},${height - padding}`;

  return (
    <svg className="pcd-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Earnings chart">
      <defs>
        <linearGradient id="pcdChartFill" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor="#7387ff" stopOpacity="0.28" />
          <stop offset="100%" stopColor="#7387ff" stopOpacity="0" />
        </linearGradient>
      </defs>
      {[0, 1, 2, 3].map((lineIndex) => {
        const y = padding + (lineIndex * (height - padding * 2)) / 3;
        return <line key={lineIndex} x1={padding} x2={width - padding} y1={y} y2={y} className="pcd-chart-grid" />;
      })}
      <polygon points={area} fill="url(#pcdChartFill)" />
      <polyline points={line} fill="none" stroke="#7387ff" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
      {points.map((point) => (
        <g key={point.label}>
          <circle cx={point.x} cy={point.y} r="5" className="pcd-chart-dot" />
          <text x={point.x} y={height - 3} textAnchor="middle" className="pcd-chart-label">
            {point.label}
          </text>
        </g>
      ))}
    </svg>
  );
}

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

export default function CreatorDashboard() {
  const { user, logout, setUser } = useAuth();
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
  const [portfolio, setPortfolio] = useState([]);
  const [uploadingPortfolio, setUploadingPortfolio] = useState(false);
  const [completedWorks, setCompletedWorks] = useState(0);

  useEffect(() => {
    // Only skip if approval_status is explicitly set and not 'approved'
    if (user && user.approval_status && user.approval_status !== 'approved') {
      return;
    }

    if (user?.id) {
      fetchAllData();
      const interval = setInterval(fetchAllData, 10000);
      return () => clearInterval(interval);
    }
  }, [user?.approval_status, user?.id]);

  useEffect(() => {
    const refreshUserData = async () => {
      try {
        const response = await axios.get(`${API}/auth/me`);
        setUser(response.data);
      } catch (error) {
        console.error('Failed to refresh user data');
      }
    };
    refreshUserData();
  }, [setUser]);

  const fetchAllData = async () => {
    try {
      const [campaignsRes, reviewsRes, worksRes] = await Promise.all([
        axios.get(`${API}/campaigns?t=${Date.now()}`),
        axios.get(`${API}/reviews/creator/${user.id}`),
        axios.get(`${API}/campaigns?status=completed&creator_id=${user.id}`)
      ]);

      const allCampaigns = campaignsRes.data;
      const completedCampaigns = worksRes.data || [];

      setActiveCampaigns(allCampaigns.filter((campaign) =>
        campaign.selected_creator === user.id &&
        (campaign.status === 'in_progress' || campaign.status === 'active')
      ));
      setAvailableCampaigns(allCampaigns.filter((campaign) => campaign.status === 'active' && !campaign.selected_creator));
      setMyBids(
        allCampaigns
          .filter((campaign) => campaign.bids?.some((bid) => bid.creator_id === user.id))
          .map((campaign) => ({
            ...campaign,
            myBid: campaign.bids.find((bid) => bid.creator_id === user.id)
          }))
      );
      setReviews(reviewsRes.data);
      setPortfolio(user?.portfolio || []);
      setCompletedWorks(completedCampaigns.length);
    } catch (error) {
      toast.error('Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const handleBidSubmit = async (event) => {
    event.preventDefault();
    try {
      await axios.post(`${API}/campaigns/${selectedCampaign.id}/bid`, {
        campaign_id: selectedCampaign.id,
        amount: parseFloat(bidAmount),
        proposal,
        estimated_delivery_days: parseInt(deliveryDays, 10)
      });
      toast.success('Bid submitted successfully');
      setSelectedCampaign(null);
      setBidAmount('');
      setProposal('');
      setDeliveryDays('');
      fetchAllData();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to submit bid');
    }
  };

  const handlePortfolioUpload = async (event) => {
    const files = Array.from(event.target.files || []);
    if (!files.length) return;

    setUploadingPortfolio(true);
    try {
      const uploadedUrls = await Promise.all(files.map(async (file) => {
        if (file.size > 10 * 1024 * 1024) {
          throw new Error(`${file.name} is too large. Maximum 10MB per file.`);
        }
        const formDataUpload = new FormData();
        formDataUpload.append('file', file);
        const response = await axios.post(`${API}/upload/file`, formDataUpload, {
          headers: { 'Content-Type': 'multipart/form-data' }
        });
        return response.data.file_url;
      }));

      const nextPortfolio = [...portfolio, ...uploadedUrls];
      setPortfolio(nextPortfolio);
      await axios.patch(`${API}/profile/portfolio`, nextPortfolio);
      toast.success(`${uploadedUrls.length} file(s) added to portfolio`);
    } catch (error) {
      toast.error(error.response?.data?.detail || error.message || 'Failed to upload portfolio items');
    } finally {
      setUploadingPortfolio(false);
      event.target.value = '';
    }
  };

  const handleRemovePortfolioItem = async (url) => {
    try {
      const nextPortfolio = portfolio.filter((item) => item !== url);
      setPortfolio(nextPortfolio);
      await axios.patch(`${API}/profile/portfolio`, nextPortfolio);
      toast.success('Portfolio item removed');
    } catch (error) {
      toast.error('Failed to remove portfolio item');
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const displayName = user?.nickname || user?.full_name || user?.email || 'Creator';
  const rating = Number(user?.average_rating || 0);
  const totalEarned = useMemo(() => {
    const bidsTotal = myBids.reduce((sum, campaign) => sum + Number(campaign.myBid?.amount || 0), 0);
    return Math.max(Number(user?.balance || 0), bidsTotal);
  }, [myBids, user?.balance]);

  const levelInfo = getLevelInfo(completedWorks);
  const progressPercentage = levelInfo.nextWorks
    ? Math.min(100, Math.max(0, (levelInfo.currentWorks / levelInfo.nextWorks) * 100))
    : 100;
  const worksRemaining = levelInfo.nextWorks ? Math.max(0, levelInfo.nextWorks - levelInfo.currentWorks) : 0;

  const navItems = [
    { name: 'Dashboard', icon: LayoutDashboard, action: () => navigate('/dashboard/creator'), active: true },
    { name: 'Create a Gig', icon: Upload, action: () => navigate('/create-gig') },
    { name: 'My Active Work', icon: Zap, action: () => navigate('/my-active-work') },
    { name: 'My Bids', icon: Bookmark, action: () => navigate('/my-bids') },
    { name: 'Reviews', icon: Star, action: () => navigate('/reviews') },
    { name: 'Portfolio', icon: User, action: () => navigate('/portfolio') },
    { name: 'Browse Briefs', icon: Briefcase, action: () => navigate('/browse-briefs') },
    { name: 'My Deals', icon: FileCheck, action: () => navigate('/my-deals') },
    { name: 'Messages', icon: MessageSquare, action: () => navigate('/messages') },
    { name: 'Payout', icon: IndianRupee, action: () => navigate('/withdrawal') },
    { name: 'Settings', icon: Settings, action: () => navigate('/settings') }
  ];

  const stats = [
    { title: 'Active Deals', value: activeCampaigns.length, icon: Briefcase, trend: `${availableCampaigns.length} open briefs`, color: '#7387ff' },
    { title: 'Pending Payout', value: formatMoney(user?.balance), icon: IndianRupee, trend: 'Processing', color: '#f59e0b' },
    { title: 'Total Earned', value: formatMoney(totalEarned), icon: IndianRupee, trend: '+18% vs last mo', color: '#27ae60' },
    { title: 'Creator Rating', value: rating ? rating.toFixed(1) : 'N/A', icon: Star, trend: `${user?.total_reviews || reviews.length} reviews`, color: '#f59e0b' }
  ];

  if (user?.approval_status === 'pending') {
    return (
      <div className="pcd-status-page">
        <section className="pcd-status-card">
          <CheckCircle size={68} />
          <p className="pcd-eyebrow">Creator verification</p>
          <h1>Profile Under Review</h1>
          <p>Your profile is being reviewed. Most creator approvals are completed within 24-48 hours.</p>
          <button type="button" onClick={handleLogout}>Back to Home</button>
        </section>
      </div>
    );
  }

  if (user?.approval_status === 'rejected') {
    return (
      <div className="pcd-status-page">
        <section className="pcd-status-card">
          <User size={68} />
          <p className="pcd-eyebrow">Creator verification</p>
          <h1>Profile Not Approved</h1>
          <p>Please contact support for more information about your creator profile review.</p>
          <button type="button" onClick={handleLogout}>Back to Home</button>
        </section>
      </div>
    );
  }

  // Show pending message if user is not approved (but only if approval_status is explicitly set to something other than 'approved')
  if (user && user.approval_status && user.approval_status !== 'approved') {
    return (
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '100vh',
        background: '#f5f5f5',
        flexDirection: 'column',
        gap: '16px',
        textAlign: 'center',
        padding: '20px'
      }}>
        <div style={{ fontSize: '48px', marginBottom: '16px' }}>⏳</div>
        <h1 style={{ color: '#07074e', margin: 0, fontSize: '28px' }}>Profile Pending Review</h1>
        <p style={{ color: '#666', margin: '8px 0 0 0', fontSize: '16px' }}>
          Your creator profile is being reviewed by our team.
        </p>
        <p style={{ color: '#999', margin: '8px 0 0 0', fontSize: '14px' }}>
          You'll be able to access all features once approved.
        </p>
      </div>
    );
  }

  return (
    <DashboardLayout
      navItems={navItems}
      title="Creator Dashboard"
      description={
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span>Welcome back, {displayName}</span>
          <span style={{
            background: levelInfo.color,
            color: 'white',
            padding: '4px 12px',
            borderRadius: '20px',
            fontSize: '12px',
            fontWeight: '600'
          }}>
            {levelInfo.badge}
          </span>
        </div>
      }
      topbarExtra={null}
      sidebarExtra={null}
    >
          <section className="pcd-stat-grid">
            {stats.map((stat) => (
              <article key={stat.title} className="pcd-card pcd-stat-card">
                <div className="pcd-stat-top">
                  <span className="pcd-stat-icon" style={{ color: stat.color }}>
                    <stat.icon size={24} strokeWidth={1.6} />
                  </span>
                  <span className="pcd-trend">
                    {stat.trend.includes('+') && <TrendingUp size={14} />}
                    {stat.trend}
                  </span>
                </div>
                <p>{stat.title}</p>
                <h2>{stat.value}</h2>
              </article>
            ))}
          </section>

          <section className="pcd-level-banner">
            <div className="pcd-level-main">
              <div className="pcd-level-title">
                <span className="pcd-trophy" style={{ color: levelInfo.color }}><Trophy size={32} /></span>
                <div>
                  <p>Current Level <strong style={{ color: levelInfo.color }}>{levelInfo.subtitle}</strong></p>
                  <h2>{levelInfo.level}</h2>
                </div>
              </div>
              {levelInfo.nextLevel && (
                <div className="pcd-progress-block">
                  <div className="pcd-progress-copy">
                    <span>Progress to {levelInfo.nextLevel}</span>
                    <strong>{levelInfo.currentWorks} / {levelInfo.nextWorks} works</strong>
                  </div>
                  <div className="pcd-progress-track">
                    <span style={{ width: `${progressPercentage}%` }} />
                  </div>
                  <p><Zap size={14} /> {worksRemaining > 0 ? `${worksRemaining} more ${worksRemaining === 1 ? 'work' : 'works'} to level up!` : 'You\'ve reached this level!'}</p>
                </div>
              )}
              {!levelInfo.nextLevel && (
                <div className="pcd-progress-block">
                  <div className="pcd-progress-copy">
                    <span>You've reached the top level!</span>
                    <strong>{levelInfo.currentWorks} Completed Works</strong>
                  </div>
                  <div className="pcd-progress-track">
                    <span style={{ width: '100%' }} />
                  </div>
                  <p><Zap size={14} /> {levelInfo.benefits}</p>
                </div>
              )}
            </div>
            <div className="pcd-level-metrics">
              <div>
                <span>Rating</span>
                <strong>{rating ? rating.toFixed(1) : 'N/A'} <Star size={16} /></strong>
              </div>
              <i />
              <div>
                <span>Completed Works</span>
                <strong>{completedWorks}</strong>
              </div>
            </div>
          </section>

          <section className="pcd-card pcd-table-card">
            <div className="pcd-section-header">
              <h2>Active Campaigns</h2>
              <button type="button" onClick={() => navigate('/my-active-work')}>
                View all deals <ArrowRight size={14} />
              </button>
            </div>
            <div className="pcd-table-wrap">
              <table className="pcd-table">
                <thead>
                  <tr>
                    <th>Brief Name</th>
                    <th>Quality</th>
                    <th>Brand Handle</th>
                    <th>Stage</th>
                    <th>Due Date</th>
                    <th>Payout</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {(activeCampaigns.length ? activeCampaigns : myBids.slice(0, 4)).slice(0, 4).map((campaign, index) => (
                    <tr key={campaign.id || index}>
                      <td>{campaign.title || 'Creator Brief'}</td>
                      <td>{campaign.quality || (index % 2 ? 'Standard' : 'Premium')}</td>
                      <td>@{campaign.business_nickname || campaign.brand_handle || 'brand'}</td>
                      <td><span className={`pcd-status ${campaign.status || 'pending'}`}>{(campaign.status || 'Pending').replace('_', ' ')}</span></td>
                      <td>{campaign.due_date ? new Date(campaign.due_date).toLocaleDateString() : 'Oct 15, 2026'}</td>
                      <td>{getCampaignBudget(campaign)}</td>
                      <td>
                        <button type="button" onClick={() => navigate(`/campaign/${campaign.id}`)}>Open</button>
                      </td>
                    </tr>
                  ))}
                  {!activeCampaigns.length && !myBids.length && (
                    <tr>
                      <td colSpan="7" className="pcd-empty-row">No active campaigns yet. Browse briefs to start a deal.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <section className="pcd-dashboard-grid">
            <article className="pcd-card pcd-analytics-card">
              <div className="pcd-section-header align-start">
                <div>
                  <h2>Earnings Analytics</h2>
                  <p>Your payout performance over the last 6 months.</p>
                </div>
                <select aria-label="Earnings range">
                  <option>Last 6 Months</option>
                  <option>This Year</option>
                </select>
              </div>
              <MiniAreaChart data={earningsData} />
            </article>

            <article className="pcd-card pcd-updates-card">
              <div className="pcd-section-header">
                <h2>Updates</h2>
                <button type="button">Mark all read</button>
              </div>
              {[
                { icon: FileCheck, title: 'Brief Approved', desc: activeCampaigns[0]?.title || 'Your concept was approved.', time: '2h ago', color: '#27ae60' },
                { icon: IndianRupee, title: 'Payout Processed', desc: `${formatMoney(user?.balance)} available for withdrawal.`, time: '5h ago', color: '#7387ff' },
                { icon: MessageCircle, title: 'New Message', desc: 'You have a message from a brand.', time: '1d ago', color: '#f59e0b' },
                { icon: Trophy, title: 'Level Up Pending', desc: 'You are 250 XP away from L2.', time: '2d ago', color: '#07074e' }
              ].map((update) => (
                <div key={update.title} className="pcd-update">
                  <span style={{ color: update.color, backgroundColor: `${update.color}18` }}>
                    <update.icon size={18} />
                  </span>
                  <div>
                    <h3>{update.title}</h3>
                    <p>{update.desc}</p>
                    <small><Clock size={12} /> {update.time}</small>
                  </div>
                </div>
              ))}
            </article>
          </section>

          <section className="pcd-dashboard-grid bottom">
            <article className="pcd-card pcd-achievements-card">
              <div className="pcd-section-header align-start">
                <div>
                  <h2>Creator Achievements</h2>
                  <p>Keep completing deals to unlock new badges.</p>
                </div>
                <span>4 of 7 Unlocked</span>
              </div>
              <div className="pcd-badges">
                {[
                  { title: 'Fast Deliverer', rule: '< 48h turnaround', icon: Zap },
                  { title: 'Brief Faithful', rule: '0 revisions needed', icon: ShieldCheck },
                  { title: '5 Star Streak', rule: '5x 5-star ratings', icon: Star },
                  { title: 'Elite Creator', rule: 'Top 10% volume', icon: Trophy }
                ].map((badge) => (
                  <div key={badge.title} className="pcd-badge-card">
                    <span><badge.icon size={24} /></span>
                    <h3>{badge.title}</h3>
                    <p>{badge.rule}</p>
                  </div>
                ))}
              </div>
            </article>

            <article className="pcd-rate-card">
              <div>
                <div className="pcd-rate-head">
                  <h2>Rate Card</h2>
                  <span>Public</span>
                </div>
                <p>Current baseline figures for L1 Rising.</p>
              </div>
              <div className="pcd-rate-list">
                <div><span>Minimum Rate</span><strong>Rs. 5,000</strong></div>
                <div><span>Tier Multiplier</span><strong className="positive">1.2x</strong></div>
                <div><span>Custom Limit</span><strong>Rs. 50,000</strong></div>
                <div><span>Payout Window</span><strong>14 Days</strong></div>
              </div>
              <button type="button" onClick={() => navigate('/settings')}>
                Edit Rate Card <ArrowUpRight size={16} />
              </button>
            </article>
          </section>

      {selectedCampaign && (
        <div className="pcd-modal-overlay" role="dialog" aria-modal="true" aria-labelledby="bid-modal-title">
          <form className="pcd-modal" onSubmit={handleBidSubmit}>
            <h2 id="bid-modal-title">Submit Bid</h2>
            <p>{selectedCampaign.title}</p>
            <label>
              Bid Amount
              <input type="number" value={bidAmount} onChange={(event) => setBidAmount(event.target.value)} required min="1" />
            </label>
            <label>
              Delivery Days
              <input type="number" value={deliveryDays} onChange={(event) => setDeliveryDays(event.target.value)} required min="1" />
            </label>
            <label>
              Proposal
              <textarea value={proposal} onChange={(event) => setProposal(event.target.value)} required rows="5" />
            </label>
            <div>
              <button type="button" onClick={() => setSelectedCampaign(null)}>Cancel</button>
              <button type="submit" className="pcd-primary">Submit Bid</button>
            </div>
          </form>
        </div>
      )}
    </DashboardLayout>
  );
}

function EmptyPanel({ text }) {
  return <div className="pcd-empty-panel">{text}</div>;
}

function CompactList({ title, empty, items, render }) {
  return (
    <section>
      <h2>{title}</h2>
      {items.length ? <div className="pcd-mini-list">{items.map(render)}</div> : <EmptyPanel text={empty} />}
    </section>
  );
}

function CampaignMiniCard({ campaign, actionLabel, onAction }) {
  return (
    <article className="pcd-mini-card">
      <div>
        <h3>{campaign.title}</h3>
        <p>{campaign.business_nickname || 'Brand campaign'} - {getCampaignBudget(campaign)}</p>
      </div>
      <button type="button" onClick={onAction}>{actionLabel}</button>
    </article>
  );
}

function CampaignGrid({ items, empty, renderActions }) {
  if (!items.length) return <EmptyPanel text={empty} />;

  return (
    <div className="pcd-campaign-grid">
      {items.map((campaign) => (
        <article key={campaign.id} className="pcd-campaign-card">
          <div>
            <h3>{campaign.title}</h3>
            <span className={`pcd-status ${campaign.status}`}>{(campaign.status || 'active').replace('_', ' ')}</span>
          </div>
          <p>{campaign.brief_text ? `${campaign.brief_text.substring(0, 150)}${campaign.brief_text.length > 150 ? '...' : ''}` : 'Creator campaign brief'}</p>
          <dl>
            <div><dt>Budget</dt><dd>{getCampaignBudget(campaign)}</dd></div>
            <div><dt>Brand</dt><dd>{campaign.business_nickname || campaign.brand_handle || 'Brand'}</dd></div>
            <div><dt>Objectives</dt><dd>{campaign.objectives?.length || 0}</dd></div>
          </dl>
          <div className="pcd-card-actions">{renderActions(campaign)}</div>
        </article>
      ))}
    </div>
  );
}

function BrowseFilterSection({ title, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <section className="pcd-brief-filter-section">
      <button type="button" onClick={() => setOpen((value) => !value)}>
        <span>{title}</span>
        <ChevronDown size={16} className={open ? 'is-open' : ''} />
      </button>
      {open && <div>{children}</div>}
    </section>
  );
}

function BrowseCheck({ label, count, checked, onChange }) {
  return (
    <button type="button" className={`pcd-brief-check ${checked ? 'is-checked' : ''}`} onClick={onChange}>
      <span><i />{label}</span>
      {count ? <em>{count}</em> : null}
    </button>
  );
}

function BrowseRadio({ label, checked, onChange }) {
  return (
    <button type="button" className={`pcd-brief-radio ${checked ? 'is-checked' : ''}`} onClick={onChange}>
      <span><i />{label}</span>
    </button>
  );
}

function normalizeBrief(campaign, index, myBids) {
  const objectives = Array.isArray(campaign.objectives) ? campaign.objectives.filter(Boolean) : [];
  const hasBid = myBids.some((bidCampaign) => bidCampaign.id === campaign.id);
  const budgetMax = Number(campaign.budget_max ?? campaign.budget ?? campaign.myBid?.amount ?? 0);
  const matchScore = Math.min(98, 76 + (objectives.length * 4) + (campaign.requires_shipment ? 3 : 0) + (index % 3) * 2);
  const fallbackBrand = ['Glow & Co', 'TechNova', 'FitLife Apparel', 'BeanRoast Coffee', 'Wanderlust Gear', 'PurePlant'][index % 6];

  return {
    campaign,
    id: campaign.id,
    title: campaign.title || 'Creator Campaign Brief',
    description: campaign.brief_text || 'Review the brand brief, pitch your concept, and manage the collaboration from your creator workspace.',
    brand: campaign.business_nickname || campaign.brand_handle || fallbackBrand,
    cover: campaign.cover_image || campaign.image_url || campaign.thumbnail_url || browseCovers[index % browseCovers.length],
    logo: campaign.brand_logo || campaign.business_logo || browseLogos[index % browseLogos.length],
    tags: objectives.length ? objectives.slice(0, 3) : ['UGC', campaign.requires_shipment ? 'Product' : 'Remote', 'Creator'],
    budget: getCampaignBudget(campaign),
    budgetMax,
    location: campaign.requires_shipment ? 'Product shipment' : 'Remote',
    deadline: campaign.due_date ? `Closes ${new Date(campaign.due_date).toLocaleDateString()}` : 'Open brief',
    matchScore,
    verified: Boolean(campaign.business_nickname || index % 2 === 0),
    fastPayment: budgetMax <= 1000 || index % 2 === 0,
    repeatHirer: index % 3 !== 1,
    featured: index === 0 || matchScore >= 94,
    hasBid,
    createdAt: campaign.created_at ? new Date(campaign.created_at).getTime() : 0
  };
}

function BrowseBriefsPanel({ campaigns, myBids, loading, onView, onPitch }) {
  const [viewMode, setViewMode] = useState('grid');
  const [query, setQuery] = useState('');
  const [sortBy, setSortBy] = useState('recommended');
  const [category, setCategory] = useState('all');
  const [budgetRange, setBudgetRange] = useState('any');
  const [minMatch, setMinMatch] = useState(0);
  const [brandFlags, setBrandFlags] = useState({
    verified: true,
    repeatHirer: false,
    fastPayment: false,
    shipment: false
  });

  const briefs = useMemo(() => campaigns.map((campaign, index) => normalizeBrief(campaign, index, myBids)), [campaigns, myBids]);
  const categories = useMemo(() => {
    const counts = briefs.reduce((acc, brief) => {
      brief.tags.forEach((tag) => {
        acc[tag] = (acc[tag] || 0) + 1;
      });
      return acc;
    }, {});
    return Object.entries(counts).slice(0, 5);
  }, [briefs]);

  const filteredBriefs = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return briefs
      .filter((brief) => {
        if (normalizedQuery) {
          const haystack = `${brief.title} ${brief.brand} ${brief.description} ${brief.tags.join(' ')}`.toLowerCase();
          if (!haystack.includes(normalizedQuery)) return false;
        }
        if (category !== 'all' && !brief.tags.includes(category)) return false;
        if (budgetRange === 'under1000' && brief.budgetMax > 1000) return false;
        if (budgetRange === '1000plus' && brief.budgetMax < 1000) return false;
        if (minMatch && brief.matchScore < minMatch) return false;
        if (brandFlags.verified && !brief.verified) return false;
        if (brandFlags.repeatHirer && !brief.repeatHirer) return false;
        if (brandFlags.fastPayment && !brief.fastPayment) return false;
        if (brandFlags.shipment && !brief.campaign.requires_shipment) return false;
        return true;
      })
      .sort((a, b) => {
        if (sortBy === 'highest') return b.budgetMax - a.budgetMax;
        if (sortBy === 'newest') return b.createdAt - a.createdAt;
        if (sortBy === 'closing') return Number(Boolean(b.campaign.due_date)) - Number(Boolean(a.campaign.due_date));
        return b.matchScore - a.matchScore;
      });
  }, [briefs, query, category, budgetRange, minMatch, brandFlags, sortBy]);

  const toggleFlag = (key) => {
    setBrandFlags((current) => ({ ...current, [key]: !current[key] }));
  };

  const clearFilters = () => {
    setQuery('');
    setCategory('all');
    setBudgetRange('any');
    setMinMatch(0);
    setBrandFlags({ verified: false, repeatHirer: false, fastPayment: false, shipment: false });
  };

  return (
    <div className="pcd-briefs-panel">
      <aside className="pcd-brief-filters">
        <div className="pcd-brief-filter-head">
          <div>
            <Filter size={16} />
            <h2>Filters</h2>
          </div>
          <button type="button" onClick={clearFilters}>Clear all</button>
          <label>
            <Search size={16} />
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search opportunities..." />
          </label>
        </div>

        <div className="pcd-brief-filter-body">
          <BrowseFilterSection title="Category" defaultOpen>
            <BrowseCheck label="All Briefs" count={briefs.length} checked={category === 'all'} onChange={() => setCategory('all')} />
            {categories.map(([tag, count]) => (
              <BrowseCheck key={tag} label={tag} count={count} checked={category === tag} onChange={() => setCategory(tag)} />
            ))}
          </BrowseFilterSection>

          <BrowseFilterSection title="Payout Range" defaultOpen>
            <BrowseRadio label="Any Budget" checked={budgetRange === 'any'} onChange={() => setBudgetRange('any')} />
            <BrowseRadio label="Under Rs. 1,000" checked={budgetRange === 'under1000'} onChange={() => setBudgetRange('under1000')} />
            <BrowseRadio label="Rs. 1,000+" checked={budgetRange === '1000plus'} onChange={() => setBudgetRange('1000plus')} />
          </BrowseFilterSection>

          <BrowseFilterSection title="Match Score">
            <BrowseRadio label="Any match score" checked={minMatch === 0} onChange={() => setMinMatch(0)} />
            <BrowseRadio label="80% and above" checked={minMatch === 80} onChange={() => setMinMatch(80)} />
            <BrowseRadio label="90% and above" checked={minMatch === 90} onChange={() => setMinMatch(90)} />
          </BrowseFilterSection>

          <BrowseFilterSection title="Brand Type" defaultOpen>
            <BrowseCheck label="Verified Brands" checked={brandFlags.verified} onChange={() => toggleFlag('verified')} />
            <BrowseCheck label="Repeat Hirer" checked={brandFlags.repeatHirer} onChange={() => toggleFlag('repeatHirer')} />
            <BrowseCheck label="Fast Payment" checked={brandFlags.fastPayment} onChange={() => toggleFlag('fastPayment')} />
            <BrowseCheck label="Product Shipment" checked={brandFlags.shipment} onChange={() => toggleFlag('shipment')} />
          </BrowseFilterSection>
        </div>
      </aside>

      <section className="pcd-brief-results">
        <div className="pcd-brief-toolbar">
          <span>Showing <strong>{filteredBriefs.length}</strong> matching opportunities</span>
          <div>
            <label>
              Sort by:
              <select value={sortBy} onChange={(event) => setSortBy(event.target.value)}>
                <option value="recommended">Recommended</option>
                <option value="highest">Highest Payout</option>
                <option value="closing">Closing Soon</option>
                <option value="newest">Newest</option>
              </select>
            </label>
            <i />
            <div className="pcd-view-toggle" aria-label="View mode">
              <button type="button" className={viewMode === 'grid' ? 'is-active' : ''} onClick={() => setViewMode('grid')} aria-label="Grid view">
                <LayoutGrid size={16} />
              </button>
              <button type="button" className={viewMode === 'list' ? 'is-active' : ''} onClick={() => setViewMode('list')} aria-label="List view">
                <List size={16} />
              </button>
            </div>
          </div>
        </div>

        {filteredBriefs.length ? (
          <div className={`pcd-brief-grid ${viewMode === 'list' ? 'is-list' : ''}`}>
            {filteredBriefs.map((brief) => (
              <BriefOpportunityCard key={brief.id} brief={brief} viewMode={viewMode} onView={onView} onPitch={onPitch} />
            ))}
          </div>
        ) : (
          <EmptyPanel text={loading ? 'Loading campaigns...' : 'No matching briefs found. Try clearing filters.'} />
        )}
      </section>
    </div>
  );
}

function BriefOpportunityCard({ brief, viewMode, onView, onPitch }) {
  const handlePitch = () => {
    if (brief.hasBid) {
      onView(brief.campaign);
      return;
    }
    onPitch(brief.campaign);
  };

  return (
    <article className={`pcd-brief-card ${brief.featured ? 'is-featured' : ''} ${viewMode === 'list' ? 'is-list' : ''}`}>
      {brief.featured && <div className="pcd-feature-line" />}
      <div className="pcd-brief-media">
        <img src={brief.cover} alt={brief.title} />
        <div className="pcd-brief-media-shade" />
        <button type="button" aria-label="Save brief"><Bookmark size={15} /></button>
        {brief.featured && (
          <span className="pcd-best-match"><Sparkles size={12} /> Best Match</span>
        )}
        <div className="pcd-brief-brand">
          <img src={brief.logo} alt="" />
          <div>
            <strong>{brief.brand}</strong>
            {brief.verified && <CheckCircle2 size={15} />}
          </div>
        </div>
      </div>

      <div className="pcd-brief-content">
        <button type="button" className="pcd-brief-title" onClick={() => onView(brief.campaign)}>
          {brief.title}
        </button>
        <p>{brief.description}</p>
        <div className="pcd-brief-tags">
          <span className="match"><Star size={12} /> {brief.matchScore}%</span>
          {brief.tags.slice(0, 2).map((tag) => <span key={tag}>{tag}</span>)}
          {brief.fastPayment && <span className="fast"><Zap size={12} /> Fast</span>}
        </div>
        <div className="pcd-brief-footer">
          <div>
            <strong>{brief.budget}</strong>
            <span><MapPin size={12} /> {brief.location}</span>
          </div>
          <div>
            <small><Clock size={12} /> {brief.deadline}</small>
            <button type="button" onClick={handlePitch}>
              {brief.hasBid ? 'View Bid' : 'Pitch Now'}
            </button>
          </div>
        </div>
      </div>
    </article>
  );
}
