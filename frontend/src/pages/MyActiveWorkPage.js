import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import {
  Bookmark,
  Briefcase,
  Check,
  ChevronDown,
  FileCheck,
  IndianRupee,
  LayoutDashboard,
  MessageSquare,
  Package,
  Settings,
  Star,
  Upload,
  User,
  Zap,
} from 'lucide-react';
import { getInitial, CampaignGrid } from '../components/CreatorComponents';
import DashboardLayout from '../components/DashboardLayout';
import './CreatorDashboard.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const DEAL_PROGRESS = [
  { state: 'Accepted - Awaiting Shipment', label: 'Accepted', progress: 0 },
  { state: 'Shipped - In Transit', label: 'Shipment', progress: 20 },
  { state: 'Delivered - Awaiting Receipt Confirmation', label: 'Delivery', progress: 35 },
  { state: 'Received - Content in Progress', label: 'Content', progress: 50 },
  { state: 'Content Submitted - Awaiting Review', label: 'Review', progress: 70 },
  { state: 'Revision Requested', label: 'Revision', progress: 70 },
  { state: 'Approved - Payment Processing', label: 'Payment', progress: 88 },
  { state: 'Paid - Complete', label: 'Payout', progress: 100 },
];

const normalizeState = (value) => String(value || '')
  .replace(/\s*(?:\u2014|\u2013|-)\s*/g, ' - ')
  .toLowerCase();

function ActiveWorkProgress({ deal, campaignId }) {
  const [expanded, setExpanded] = useState(false);
  const state = deal?.current_state || deal?.campaign_status || 'Accepted - Awaiting Shipment';
  const current = DEAL_PROGRESS.find((step) => normalizeState(step.state) === normalizeState(state)) || DEAL_PROGRESS[0];
  const detailSteps = [
    { label: 'Start', progress: 0 },
    { label: 'Shipment', progress: 20 },
    { label: 'Content', progress: 50 },
    { label: 'Review', progress: 70 },
    { label: 'Payout', progress: 100 },
  ];

  return (
    <button
      type="button"
      className={`active-work-progress ${expanded ? 'is-expanded' : ''}`}
      onClick={() => setExpanded((value) => !value)}
      aria-expanded={expanded}
      aria-controls={`active-work-stages-${campaignId}`}
    >
      <span className="active-work-progress-head">
        <strong>Start</strong>
        <span className="active-work-current">{current.label}</span>
        <strong>Payout</strong>
      </span>
      <span className="active-work-track" aria-hidden="true">
        <span className="active-work-fill" style={{ width: `${current.progress}%` }} />
        <span className="active-work-marker" style={{ left: `${current.progress}%` }}>
          {current.progress === 100 ? <Check size={11} strokeWidth={3} /> : null}
        </span>
      </span>
      <span id={`active-work-stages-${campaignId}`} className="active-work-stage-list">
        {detailSteps.map((step) => (
          <span key={step.label} className={step.progress <= current.progress ? 'is-reached' : ''}>
            <i aria-hidden="true" />
            <small>{step.label}</small>
          </span>
        ))}
      </span>
      <span className="active-work-expand-copy">
        {expanded ? 'Hide progress' : 'View progress'}
        <ChevronDown size={14} aria-hidden="true" />
      </span>
    </button>
  );
}

export default function MyActiveWorkPage() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [activeCampaigns, setActiveCampaigns] = useState([]);
  const [dealsByCampaign, setDealsByCampaign] = useState({});
  const [loading, setLoading] = useState(true);

  const displayName = user?.nickname || user?.full_name || user?.email || 'Creator';

  const navItems = [
    { name: 'Dashboard', icon: LayoutDashboard, action: () => navigate('/dashboard/creator') },
    { name: 'My Active Work', icon: Zap, action: () => {}, active: true },
    { name: 'My Bids', icon: Bookmark, action: () => navigate('/my-bids') },
    { name: 'Reviews', icon: Star, action: () => navigate('/reviews') },
    { name: 'Portfolio', icon: User, action: () => navigate('/portfolio') },
    { name: 'Browse Briefs', icon: Briefcase, action: () => navigate('/browse-briefs') },
    { name: 'My Deals', icon: FileCheck, action: () => navigate('/my-deals') },
    { name: 'Messages', icon: MessageSquare, action: () => navigate('/messages') },
    { name: 'Payout', icon: IndianRupee, action: () => navigate('/withdrawal') },
    { name: 'Settings', icon: Settings, action: () => navigate('/settings') },
  ];

  useEffect(() => {
    if (user?.approval_status !== 'approved') return;
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [user?.id]);

  const fetchData = async () => {
    try {
      const [campaignRes, dealsRes] = await Promise.all([
        axios.get(`${API}/campaigns?t=${Date.now()}`),
        axios.get(`${API}/deals/my`).catch(() => ({ data: [] })),
      ]);
      const allCampaigns = campaignRes.data;
      setActiveCampaigns(allCampaigns.filter((campaign) =>
        campaign.selected_creator === user.id &&
        (campaign.status === 'in_progress' || campaign.status === 'active' || campaign.status === 'work_submitted')
      ));
      setDealsByCampaign((dealsRes.data || []).reduce((result, deal) => {
        const campaignId = deal?.campaign?.id || deal?.campaign_id;
        if (campaignId) result[String(campaignId)] = deal;
        return result;
      }, {}));
    } catch (error) {
      toast.error('Failed to load active work');
    } finally {
      setLoading(false);
    }
  };

  return (
    <DashboardLayout
      navItems={navItems}
      title="My Active Work"
      description="Manage your active campaigns"
      topbarExtra={null}
      sidebarExtra={null}
    >
      {loading ? (
        <div className="pcd-empty-panel">Loading...</div>
      ) : (
        <CampaignGrid
          items={activeCampaigns}
          empty="No active campaigns. Browse and bid on campaigns to get started."
          renderProgress={(campaign) => (
            <ActiveWorkProgress deal={dealsByCampaign[String(campaign.id)]} campaignId={campaign.id} />
          )}
          renderActions={(campaign) => (
            <>
              <button
                type="button"
                className="pcd-primary"
                onClick={() => navigate('/my-deals')}
              >
                <Upload size={16} /> Open Deal Room
              </button>
              <button type="button" onClick={() => navigate(`/chat/${campaign.business_id}`)}>
                <MessageSquare size={16} /> Message
              </button>
              {campaign.requires_shipment && (
                <button type="button" onClick={() => navigate(`/shipment?campaign=${campaign.id}`)}>
                  <Package size={16} /> Track Shipment
                </button>
              )}
            </>
          )}
        />
      )}
    </DashboardLayout>
  );
}
