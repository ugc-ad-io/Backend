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
  Upload,
  User,
  X,
  Zap,
} from 'lucide-react';
import { getInitial, EmptyPanel } from '../components/CreatorComponents';
import DashboardLayout from '../components/DashboardLayout';
import './CreatorDashboard.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

function getPortfolioAssetUrl(url) {
  if (!url) return '';
  if (/^https?:\/\//i.test(url)) return url;
  const baseUrl = BACKEND_URL || window.location.origin;
  return `${baseUrl.replace(/\/$/, '')}/${String(url).replace(/^\//, '')}`;
}

function PortfolioMedia({ url, index }) {
  const [fallbackUrl, setFallbackUrl] = useState('');
  const [failed, setFailed] = useState(false);
  const assetUrl = getPortfolioAssetUrl(url);
  const isVideo = /\.(mp4|webm|mov)$/i.test(String(url).split('?')[0]);

  useEffect(() => {
    return () => {
      if (fallbackUrl) URL.revokeObjectURL(fallbackUrl);
    };
  }, [fallbackUrl]);

  const loadWithAuth = async () => {
    if (fallbackUrl || failed) return;
    try {
      const response = await axios.get(assetUrl, { responseType: 'blob' });
      const objectUrl = URL.createObjectURL(response.data);
      setFallbackUrl(objectUrl);
    } catch (error) {
      setFailed(true);
    }
  };

  if (failed) {
    return <div className="pcd-portfolio-fallback">Preview unavailable</div>;
  }

  if (isVideo) {
    return <video src={fallbackUrl || assetUrl} controls onError={loadWithAuth} />;
  }

  return <img src={fallbackUrl || assetUrl} alt={`Portfolio item ${index + 1}`} loading="lazy" onError={loadWithAuth} />;
}

export default function PortfolioPage() {
  const { user, logout, setUser } = useAuth();
  const navigate = useNavigate();
  const [portfolio, setPortfolio] = useState([]);
  const [uploadingPortfolio, setUploadingPortfolio] = useState(false);
  const [loading, setLoading] = useState(true);

  const displayName = user?.nickname || user?.full_name || user?.email || 'Creator';

  const navItems = [
    { name: 'Dashboard', icon: LayoutDashboard, action: () => navigate('/dashboard/creator') },
    { name: 'My Active Work', icon: Zap, action: () => navigate('/my-active-work') },
    { name: 'My Bids', icon: Bookmark, action: () => navigate('/my-bids') },
    { name: 'Reviews', icon: Star, action: () => navigate('/reviews') },
    { name: 'Portfolio', icon: User, action: () => {}, active: true },
    { name: 'Browse Briefs', icon: Briefcase, action: () => navigate('/browse-briefs') },
    { name: 'My Deals', icon: FileCheck, action: () => navigate('/my-deals') },
    { name: 'Messages', icon: MessageSquare, action: () => navigate('/messages') },
    { name: 'Payout', icon: IndianRupee, action: () => navigate('/withdrawal') },
    { name: 'Settings', icon: Settings, action: () => navigate('/settings') },
  ];

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

  useEffect(() => {
    setPortfolio(user?.portfolio || []);
    setLoading(false);
  }, [user?.portfolio]);

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

  return (
    <DashboardLayout
      navItems={navItems}
      title="Portfolio"
      description="Showcase your best work"
      topbarExtra={null}
      sidebarExtra={null}
    >
      {loading ? (
        <div className="pcd-empty-panel">Loading...</div>
      ) : (
        <div>
          <div className="pcd-portfolio-head">
            <h2>My Portfolio</h2>
            <input id="portfolio-upload-page" type="file" multiple accept="image/*,video/*" onChange={handlePortfolioUpload} />
            <label htmlFor="portfolio-upload-page">
              <Upload size={16} /> {uploadingPortfolio ? 'Uploading...' : 'Add Work'}
            </label>
          </div>
          <div className="pcd-portfolio-grid">
            {portfolio.length ? portfolio.map((url, index) => (
              <article key={url} className="pcd-portfolio-item">
                <div>
                  <PortfolioMedia url={url} index={index} />
                </div>
                <button type="button" className="pcd-remove-btn" onClick={() => handleRemovePortfolioItem(url)}>
                  <X size={16} /> Remove Portfolio
                </button>
              </article>
            )) : <EmptyPanel text="No portfolio items yet. Upload images or videos to showcase your work." />}
          </div>
        </div>
      )}
    </DashboardLayout>
  );
}
