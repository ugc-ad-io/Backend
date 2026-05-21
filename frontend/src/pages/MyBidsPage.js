import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import {
  Bookmark,
  Briefcase,
  Calendar,
  Eye,
  FileCheck,
  IndianRupee,
  LayoutDashboard,
  MessageSquare,
  Settings,
  Star,
  User,
  Zap,
} from 'lucide-react';
import { EmptyPanel, formatMoney, getCampaignBudget } from '../components/CreatorComponents';
import DashboardLayout from '../components/DashboardLayout';
import './CreatorDashboard.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;
const VISIBLE_BID_STATUSES = new Set(['pending', 'submitted', 'bid_submitted']);

const getBidStatus = (item) => (
  item?.bid_status ||
  item?.my_bid?.status ||
  item?.bid?.status ||
  'pending'
).toLowerCase();

const isVisiblePendingBid = (item) => {
  const campaign = item?.campaign || {};
  const isCampaignAssigned = Boolean(campaign.selected_creator || item?.selected_creator);
  return !isCampaignAssigned && VISIBLE_BID_STATUSES.has(getBidStatus(item));
};

export default function MyBidsPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [myBids, setMyBids] = useState([]);
  const [loading, setLoading] = useState(true);

  const navItems = [
    { name: 'Dashboard', icon: LayoutDashboard, action: () => navigate('/dashboard/creator') },
    { name: 'My Active Work', icon: Zap, action: () => navigate('/my-active-work') },
    { name: 'My Bids', icon: Bookmark, action: () => {}, active: true },
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
      const res = await axios.get(`${API}/bids/my?t=${Date.now()}`);
      setMyBids((res.data || []).filter(isVisiblePendingBid));
    } catch (error) {
      toast.error('Failed to load bids');
    } finally {
      setLoading(false);
    }
  };

  return (
    <DashboardLayout
      navItems={navItems}
      title="My Bids"
      description="Track your submitted bids"
      topbarExtra={null}
      sidebarExtra={null}
    >
      {loading ? (
        <div className="pcd-empty-panel">Loading...</div>
      ) : (
        <MyBidsGrid items={myBids} onView={(campaignId) => navigate(`/campaign/${campaignId}`)} />
      )}
    </DashboardLayout>
  );
}

function MyBidsGrid({ items, onView }) {
  if (!items.length) return <EmptyPanel text="No bids submitted yet." />;

  return (
    <div className="pcd-campaign-grid">
      {items.map((item) => {
        const campaign = item.campaign || {};
        const bid = item.my_bid || {};
        const bidStatus = item.bid_status || 'pending';
        const submittedAt = item.submitted_at || bid.submitted_at;

        return (
          <article key={bid.id || campaign.id} className="pcd-campaign-card pcd-bid-card">
            <div>
              <h3>{campaign.title || 'Campaign'}</h3>
              <span className={`pcd-status ${bidStatus}`}>{bidStatus}</span>
            </div>
            <p>{campaign.brief_text ? `${campaign.brief_text.substring(0, 150)}${campaign.brief_text.length > 150 ? '...' : ''}` : 'Creator campaign brief'}</p>
            <dl>
              <div><dt>Your Bid</dt><dd>{formatMoney(bid.amount)}</dd></div>
              <div><dt>Campaign Budget</dt><dd>{getCampaignBudget(campaign)}</dd></div>
              <div><dt>Brand</dt><dd>{campaign.business_nickname || campaign.brand_handle || 'Brand'}</dd></div>
              <div><dt>Delivery</dt><dd>{bid.estimated_delivery_days ? `${bid.estimated_delivery_days} days` : 'N/A'}</dd></div>
              <div><dt>Campaign Status</dt><dd>{(item.campaign_status || campaign.status || 'active').replace('_', ' ')}</dd></div>
              <div>
                <dt><Calendar size={13} /> Submitted</dt>
                <dd>{submittedAt ? new Date(submittedAt).toLocaleDateString() : 'Recent'}</dd>
              </div>
            </dl>
            {bid.proposal && <p className="pcd-bid-proposal">{bid.proposal}</p>}
            <div className="pcd-card-actions">
              <button type="button" onClick={() => onView(campaign.id)}>
                <Eye size={16} /> View Campaign
              </button>
            </div>
          </article>
        );
      })}
    </div>
  );
}
