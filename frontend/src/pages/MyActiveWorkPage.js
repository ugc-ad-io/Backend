import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import {
  Bookmark,
  Briefcase,
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

export default function MyActiveWorkPage() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [activeCampaigns, setActiveCampaigns] = useState([]);
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
      const res = await axios.get(`${API}/campaigns?t=${Date.now()}`);
      const allCampaigns = res.data;
      setActiveCampaigns(allCampaigns.filter((campaign) =>
        campaign.selected_creator === user.id &&
        (campaign.status === 'in_progress' || campaign.status === 'active' || campaign.status === 'work_submitted')
      ));
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
          renderActions={(campaign) => (
            <>
              <button
                type="button"
                className="pcd-primary"
                onClick={() => navigate(`/work/submit?campaign=${campaign.id}`)}
                disabled={campaign.status === 'work_submitted'}
              >
                <Upload size={16} /> {campaign.status === 'work_submitted' ? 'Work Submitted' : 'Submit Work'}
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
