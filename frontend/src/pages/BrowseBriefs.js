import { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import {
  Bookmark,
  Briefcase,
  CheckCircle2,
  ChevronDown,
  Clock,
  FileCheck,
  Filter,
  LayoutDashboard,
  LayoutGrid,
  List,
  MapPin,
  MessageSquare,
  Search,
  Settings,
  Sparkles,
  Star,
  IndianRupee,
  User,
  Zap,
} from 'lucide-react';
import DashboardLayout from '../components/DashboardLayout';
import './CreatorDashboard.css';
import './BrowseBriefs.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const getInitial = (name) => (name || 'U').trim().charAt(0).toUpperCase();

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

// Mock fallback images (used only if backend images are unavailable)
const browseCovers = [
  'https://images.unsplash.com/photo-1581182800629-7d90925ad072?auto=format&fit=crop&q=80&w=800&h=520',
  'https://images.unsplash.com/photo-1558002038-1055907df827?auto=format&fit=crop&q=80&w=800&h=520',
  'https://images.unsplash.com/photo-1645318801217-143533cb559f?auto=format&fit=crop&q=80&w=800&h=520',
  'https://images.unsplash.com/photo-1663958749441-926bbef7cd0c?auto=format&fit=crop&q=80&w=800&h=520',
  'https://images.unsplash.com/photo-1491637639811-60e2756cc1c7?auto=format&fit=crop&q=80&w=800&h=520',
  'https://images.unsplash.com/photo-1580635766551-5e3a8ca8b21d?auto=format&fit=crop&q=80&w=800&h=520',
];

const browseLogos = [
  'https://images.unsplash.com/photo-1556228578-0d85b1a4d571?auto=format&fit=crop&q=80&w=128&h=128',
  'https://images.unsplash.com/photo-1546868871-7041f2a55e12?auto=format&fit=crop&q=80&w=128&h=128',
  'https://images.unsplash.com/photo-1517836357463-d25dfeac3438?auto=format&fit=crop&q=80&w=128&h=128',
  'https://images.unsplash.com/photo-1559525839-b184a4d698c7?auto=format&fit=crop&q=80&w=128&h=128',
];

// Normalize campaign data from backend API
function normalizeBrief(campaign, index, myBids) {
  const objectives = Array.isArray(campaign.objectives) ? campaign.objectives.filter(Boolean) : [];
  const hasBid = myBids.some((bidCampaign) => bidCampaign.id === campaign.id);
  const budgetMax = Number(campaign.budget_max ?? campaign.budget ?? 0);
  const matchScore = Math.min(98, 76 + (objectives.length * 4) + (campaign.requires_shipment ? 3 : 0) + (index % 3) * 2);

  return {
    campaign,
    id: campaign.id,
    title: campaign.title,
    description: campaign.brief_text,
    brand: campaign.business_nickname || campaign.brand_handle,
    cover: campaign.cover_image,
    logo: campaign.brand_logo,
    tags: objectives.length ? objectives.slice(0, 3) : ['UGC', campaign.requires_shipment ? 'Product' : 'Remote', 'Creator'],
    budget: getCampaignBudget(campaign),
    budgetMax,
    location: campaign.requires_shipment ? 'Product shipment' : 'Remote',
    deadline: campaign.due_date ? `Closes ${new Date(campaign.due_date).toLocaleDateString()}` : 'Open brief',
    matchScore,
    verified: Boolean(campaign.business_verified),
    fastPayment: budgetMax <= 1000,
    repeatHirer: false,
    featured: index === 0 || matchScore >= 94,
    hasBid,
    createdAt: campaign.created_at ? new Date(campaign.created_at).getTime() : 0,
    industryType: campaign.industry_type || null,
  };
}

export default function BrowseBriefs() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const [availableCampaigns, setAvailableCampaigns] = useState([]);
  const [myBids, setMyBids] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedCampaign, setSelectedCampaign] = useState(null);
  const [bidAmount, setBidAmount] = useState('');
  const [proposal, setProposal] = useState('');
  const [deliveryDays, setDeliveryDays] = useState('');

  const displayName = user?.nickname || user?.full_name || user?.email || 'Creator';

  const navItems = [
    { name: 'Dashboard', icon: LayoutDashboard, action: () => navigate('/dashboard/creator') },
    { name: 'My Active Work', icon: Zap, action: () => navigate('/my-active-work') },
    { name: 'My Bids', icon: Bookmark, action: () => navigate('/my-bids') },
    { name: 'Reviews', icon: Star, action: () => navigate('/reviews') },
    { name: 'Portfolio', icon: User, action: () => navigate('/portfolio') },
    { name: 'Browse Briefs', icon: Briefcase, action: () => navigate('/browse-briefs'), active: true },
    { name: 'My Deals', icon: FileCheck, action: () => navigate('/my-deals') },
    { name: 'Messages', icon: MessageSquare, action: () => navigate('/messages') },
    { name: 'Payout', icon: IndianRupee, action: () => navigate('/withdrawal') },
    { name: 'Settings', icon: Settings, action: () => navigate('/settings') },
  ];

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const res = await axios.get(`${API}/campaigns?t=${Date.now()}`);
      const allCampaigns = res.data;
      setAvailableCampaigns(allCampaigns.filter((c) => c.status === 'active' && !c.selected_creator));
      setMyBids(
        allCampaigns.filter((c) => c.bids?.some((b) => b.creator_id === user?.id))
      );
    } catch {
      toast.error('Failed to load campaigns');
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
        estimated_delivery_days: parseInt(deliveryDays, 10),
      });
      toast.success('Bid submitted successfully');
      setSelectedCampaign(null);
      setBidAmount(''); setProposal(''); setDeliveryDays('');
      fetchData();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to submit bid');
    }
  };

  return (
    <DashboardLayout
      navItems={navItems}
      title="Browse Briefs"
      description="Find your next campaign"
      topbarExtra={null}
      sidebarExtra={null}
    >
      <BrowseBriefsPanel
        campaigns={availableCampaigns}
        myBids={myBids}
        loading={loading}
        onView={(campaign) => navigate(`/campaign/${campaign.id}`)}
        onPitch={(campaign) => setSelectedCampaign(campaign)}
      />

      {selectedCampaign && (
        <div className="pcd-modal-overlay" role="dialog" aria-modal="true" aria-labelledby="bid-modal-title">
          <form className="pcd-modal" onSubmit={handleBidSubmit}>
            <h2 id="bid-modal-title">Submit Bid</h2>
            <p>{selectedCampaign.title}</p>
            <label>
              Bid Amount
              <input type="number" value={bidAmount} onChange={(e) => setBidAmount(e.target.value)} required min="1" />
            </label>
            <label>
              Delivery Days
              <input type="number" value={deliveryDays} onChange={(e) => setDeliveryDays(e.target.value)} required min="1" />
            </label>
            <label>
              Proposal
              <textarea value={proposal} onChange={(e) => setProposal(e.target.value)} required rows="5" />
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

// ── Exact copy of BrowseBriefsPanel from CreatorDashboard.js ──────────────────

function BrowseBriefsPanel({ campaigns, myBids, loading, onView, onPitch }) {
  const [viewMode, setViewMode] = useState('grid');
  const [query, setQuery] = useState('');
  const [sortBy, setSortBy] = useState('recommended');
  const [category, setCategory] = useState('all');
  const [payoutRangesData, setPayoutRangesData] = useState([]);
  const [budgetRanges, setBudgetRanges] = useState({});
  const [minMatch, setMinMatch] = useState(0);
  const [industryTypes, setIndustryTypes] = useState({
    skincare: false,
    fashion: false,
    servicesBased: false,
    healthcare: false,
    electronics: false,
    foodBeverage: false,
  });

  useEffect(() => {
    fetchPayoutRanges();
  }, []);

  const fetchPayoutRanges = async () => {
    try {
      const res = await axios.get(`${API}/payout-ranges`);
      setPayoutRangesData(res.data.ranges || []);
      const initialState = {};
      (res.data.ranges || []).forEach(range => {
        initialState[range.key] = false;
      });
      setBudgetRanges(initialState);
    } catch {
      toast.error('Failed to load payout ranges');
    }
  };

  const industryTypeLabels = {
    skincare: 'Skincare & Haircare',
    fashion: 'Fashion',
    servicesBased: 'Service-based Industry',
    healthcare: 'Healthcare',
    electronics: 'Electronics',
    foodBeverage: 'Food & Beverage',
  };

  const briefs = useMemo(() => campaigns.map((campaign, index) => normalizeBrief(campaign, index, myBids)), [campaigns, myBids]);

  const categories = useMemo(() => {
    const counts = briefs.reduce((acc, brief) => {
      brief.tags.forEach((tag) => { acc[tag] = (acc[tag] || 0) + 1; });
      return acc;
    }, {});
    return Object.entries(counts).slice(0, 5);
  }, [briefs]);

  const filteredBriefs = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    const selectedIndustries = Object.keys(industryTypes).filter(key => industryTypes[key]);
    const selectedRanges = Object.keys(budgetRanges).filter(key => budgetRanges[key]);

    const isInBudgetRange = (budgetMax) => {
      if (selectedRanges.length === 0) return true;
      return selectedRanges.some(rangeKey => {
        const range = payoutRangesData.find(r => r.key === rangeKey);
        if (!range) return false;
        return budgetMax >= range.min && budgetMax <= range.max;
      });
    };

    return briefs
      .filter((brief) => {
        if (normalizedQuery) {
          const haystack = `${brief.title} ${brief.brand} ${brief.description} ${brief.tags.join(' ')}`.toLowerCase();
          if (!haystack.includes(normalizedQuery)) return false;
        }
        if (category !== 'all' && !brief.tags.includes(category)) return false;
        if (!isInBudgetRange(brief.budgetMax)) return false;
        if (minMatch && brief.matchScore < minMatch) return false;
        if (selectedIndustries.length > 0 && !selectedIndustries.includes(brief.industryType)) return false;
        return true;
      })
      .sort((a, b) => {
        if (sortBy === 'highest') return b.budgetMax - a.budgetMax;
        if (sortBy === 'newest') return b.createdAt - a.createdAt;
        if (sortBy === 'closing') return Number(Boolean(b.campaign.due_date)) - Number(Boolean(a.campaign.due_date));
        return b.matchScore - a.matchScore;
      });
  }, [briefs, query, category, budgetRanges, minMatch, industryTypes, sortBy, payoutRangesData]);

  const toggleIndustry = (key) => setIndustryTypes((cur) => ({ ...cur, [key]: !cur[key] }));

  const clearFilters = () => {
    setQuery(''); setCategory('all'); setMinMatch(0);
    const resetRanges = {};
    payoutRangesData.forEach(range => {
      resetRanges[range.key] = false;
    });
    setBudgetRanges(resetRanges);
    setIndustryTypes({ skincare: false, fashion: false, servicesBased: false, healthcare: false, electronics: false, foodBeverage: false });
  };

  return (
    <div className="pcd-briefs-panel">
      <aside className="pcd-brief-filters">
        <div className="pcd-brief-filter-head">
          <div><Filter size={16} /><h2>Filters</h2></div>
          <button type="button" onClick={clearFilters}>Clear all</button>
          <label>
            <Search size={16} />
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search opportunities..." />
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
            {payoutRangesData.map(range => (
              <BrowseCheck
                key={range.key}
                label={range.label}
                checked={budgetRanges[range.key] || false}
                onChange={() => setBudgetRanges(cur => ({ ...cur, [range.key]: !cur[range.key] }))}
              />
            ))}
          </BrowseFilterSection>

          {/* <BrowseFilterSection title="Match Score">
            <BrowseRadio label="Any match score" checked={minMatch === 0} onChange={() => setMinMatch(0)} />
            <BrowseRadio label="80% and above" checked={minMatch === 80} onChange={() => setMinMatch(80)} />
            <BrowseRadio label="90% and above" checked={minMatch === 90} onChange={() => setMinMatch(90)} />
          </BrowseFilterSection> */}

          <BrowseFilterSection title="Industry Type" defaultOpen>
            <BrowseCheck label={industryTypeLabels.skincare} checked={industryTypes.skincare} onChange={() => toggleIndustry('skincare')} />
            <BrowseCheck label={industryTypeLabels.fashion} checked={industryTypes.fashion} onChange={() => toggleIndustry('fashion')} />
            <BrowseCheck label={industryTypeLabels.servicesBased} checked={industryTypes.servicesBased} onChange={() => toggleIndustry('servicesBased')} />
            <BrowseCheck label={industryTypeLabels.healthcare} checked={industryTypes.healthcare} onChange={() => toggleIndustry('healthcare')} />
            <BrowseCheck label={industryTypeLabels.electronics} checked={industryTypes.electronics} onChange={() => toggleIndustry('electronics')} />
            <BrowseCheck label={industryTypeLabels.foodBeverage} checked={industryTypes.foodBeverage} onChange={() => toggleIndustry('foodBeverage')} />
          </BrowseFilterSection>
        </div>
      </aside>

      <section className="pcd-brief-results">
        <div className="pcd-brief-toolbar">
          <span>Showing <strong>{filteredBriefs.length}</strong> matching opportunities</span>
          <div>
            <label>
              Sort by:
              <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
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
          <div className="pcd-empty-panel">
            {loading ? 'Loading campaigns...' : 'No matching briefs found. Try clearing filters.'}
          </div>
        )}
      </section>
    </div>
  );
}

function BriefOpportunityCard({ brief, viewMode, onView, onPitch }) {
  const handlePitch = () => {
    if (brief.hasBid) { onView(brief.campaign); return; }
    onPitch(brief.campaign);
  };

  return (
    <article className={`pcd-brief-card ${brief.featured ? 'is-featured' : ''} ${viewMode === 'list' ? 'is-list' : ''}`}>
      {brief.featured && <div className="pcd-feature-line" />}
      <div className="pcd-brief-media">
        <img src={brief.cover} alt={brief.title} />
        <div className="pcd-brief-media-shade" />
        <button type="button" aria-label="Save brief"><Bookmark size={15} /></button>
        {brief.featured && <span className="pcd-best-match"><Sparkles size={12} /> Best Match</span>}
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

function BrowseFilterSection({ title, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <section className="pcd-brief-filter-section">
      <button type="button" onClick={() => setOpen((v) => !v)}>
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
