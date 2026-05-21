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
  Settings,
  Star,
  User,
  Zap,
  Award,
  Calendar,
} from 'lucide-react';
import { getInitial, EmptyPanel } from '../components/CreatorComponents';
import DashboardLayout from '../components/DashboardLayout';
import './CreatorDashboard.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export default function ReviewsPage() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [reviews, setReviews] = useState([]);
  const [campaigns, setCampaigns] = useState({});
  const [reviewers, setReviewers] = useState({});
  const [loading, setLoading] = useState(true);

  const displayName = user?.nickname || user?.full_name || user?.email || 'Creator';

  const navItems = [
    { name: 'Dashboard', icon: LayoutDashboard, action: () => navigate('/dashboard/creator') },
    { name: 'My Active Work', icon: Zap, action: () => navigate('/my-active-work') },
    { name: 'My Bids', icon: Bookmark, action: () => navigate('/my-bids') },
    { name: 'Reviews', icon: Star, action: () => {}, active: true },
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
      const reviewsRes = await axios.get(`${API}/reviews/creator/${user.id}`);
      const reviewsList = reviewsRes.data || [];

      console.log('📊 Reviews loaded:', reviewsList.length);

      // Get unique campaign IDs
      const campaignIds = [...new Set(reviewsList.map(r => r.campaign_id))];
      const reviewerIds = [...new Set(reviewsList.map(r => r.reviewer_id))];

      // Fetch campaign details individually
      const campaignsData = {};
      if (campaignIds.length > 0) {
        for (const campaignId of campaignIds) {
          try {
            const campaignRes = await axios.get(`${API}/campaigns/${campaignId}`);
            campaignsData[campaignId] = campaignRes.data;
            console.log(`✅ Campaign ${campaignId} loaded:`, campaignRes.data.title);
          } catch (err) {
            console.warn(`⚠️ Could not fetch campaign ${campaignId}:`, err.message);
          }
        }
      }

      console.log('🏆 Final Campaigns Data:', campaignsData);

      // Fetch reviewer (brand) details
      const reviewersData = {};
      for (const reviewerId of reviewerIds) {
        try {
          const profileRes = await axios.get(`${API}/profile/${reviewerId}`);
          reviewersData[reviewerId] = profileRes.data;
          console.log(`👤 Reviewer ${reviewerId} loaded`);
        } catch (err) {
          console.warn(`Could not fetch reviewer ${reviewerId}`);
        }
      }

      setCampaigns(campaignsData);
      setReviewers(reviewersData);
      setReviews(reviewsList);

    } catch (error) {
      console.error('❌ Error fetching reviews:', error);
      toast.error('Failed to load reviews');
    } finally {
      setLoading(false);
    }
  };

  return (
    <DashboardLayout
      navItems={navItems}
      title="Reviews"
      description="See what brands think about your work"
      topbarExtra={null}
      sidebarExtra={null}
    >
      {loading ? (
        <div className="pcd-empty-panel">Loading...</div>
      ) : (
        <div className="pcd-review-grid">
          {reviews.length ? reviews.map((review) => {
            const reviewText = review.review || review.review_text || review.comment || '';
            const campaign = campaigns[review.campaign_id];
            const reviewer = reviewers[review.reviewer_id];
            const campaignTitle = campaign?.title || 'Campaign';
            const businessName = reviewer?.nickname || reviewer?.full_name || 'Brand';

            return (
            <article key={review.id} className="pcd-review-card-enhanced">
              <div className="review-header-info">
                <div className="campaign-info">
                  <h4 className="campaign-title">{campaignTitle}</h4>
                  <p className="brand-name">By {businessName}</p>
                </div>
                <div className="review-stars">
                  {Array.from({ length: 5 }).map((_, index) => (
                    <Star key={index} size={16} className={index < review.rating ? 'filled' : ''} />
                  ))}
                </div>
              </div>
              {reviewText && <p className="review-text">{reviewText}</p>}
              <small className="review-date">
                <Calendar size={12} /> {review.created_at ? new Date(review.created_at).toLocaleDateString() : 'Recent review'}
              </small>
            </article>
            );
          }) : <EmptyPanel text="No reviews yet. Complete campaigns to receive reviews." />}
        </div>
      )}
    </DashboardLayout>
  );
}
