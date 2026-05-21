import { useState, useEffect } from 'react';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import {
  Search,
  Filter,
  Star,
  Heart,
  Share2,
  MessageCircle,
  DollarSign,
  Calendar,
  Award
} from 'lucide-react';
import './BrowseApprovedGigs.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const GigCategoryIcon = ({ category }) => {
  const icons = {
    social_media: '📱',
    product_review: '⭐',
    unboxing: '🎁',
    tutorial: '📚',
    sponsorship: '🤝',
    brand_ambassador: '👑',
    content_creation: '🎬',
    photography: '📷',
    videography: '🎥',
    other: '✨'
  };
  return icons[category] || '✨';
};

const CreatorLevelBadge = ({ completedWorks = 0 }) => {
  let badge = 'New Creator';
  let color = '#999';

  if (completedWorks >= 20) {
    badge = 'L2 (Pro)';
    color = '#7387ff';
  } else if (completedWorks >= 10) {
    badge = 'L1 (Rising)';
    color = '#27ae60';
  }

  return (
    <span className="gig-creator-badge" style={{ color, borderColor: color }}>
      {badge}
    </span>
  );
};

export default function BrowseApprovedGigs() {
  const { user } = useAuth();
  const [gigs, setGigs] = useState([]);
  const [filteredGigs, setFilteredGigs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [categories, setCategories] = useState([]);

  const categoryOptions = [
    { id: 'all', label: 'All Categories' },
    { id: 'social_media', label: 'Social Media' },
    { id: 'product_review', label: 'Product Reviews' },
    { id: 'unboxing', label: 'Unboxing' },
    { id: 'tutorial', label: 'Tutorials' },
    { id: 'sponsorship', label: 'Sponsored Content' },
    { id: 'brand_ambassador', label: 'Brand Ambassador' },
    { id: 'content_creation', label: 'Content Creation' },
    { id: 'photography', label: 'Photography' },
    { id: 'videography', label: 'Videography' }
  ];

  useEffect(() => {
    fetchApprovedGigs();
  }, []);

  useEffect(() => {
    filterGigs();
  }, [gigs, searchQuery, selectedCategory]);

  const fetchApprovedGigs = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API}/gigs`, {
        params: { status: 'approved', limit: 100 }
      });
      const gigsData = res.data.data || res.data || [];
      setGigs(gigsData);
    } catch (error) {
      toast.error('Failed to load gigs');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const filterGigs = () => {
    let filtered = gigs;

    if (selectedCategory !== 'all') {
      filtered = filtered.filter(gig => gig.category === selectedCategory);
    }

    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(gig =>
        gig.title?.toLowerCase().includes(query) ||
        gig.description?.toLowerCase().includes(query) ||
        gig.skills_required?.some(skill => skill.toLowerCase().includes(query))
      );
    }

    setFilteredGigs(filtered);
  };

  const handleContactCreator = (gigId, creatorId) => {
    // TODO: Open contact/message modal or navigate to messages
    toast.info(`Messaging creator for gig ${gigId}`);
  };

  return (
    <div className="browse-gigs-container">
      <div className="browse-gigs-header">
        <div className="browse-gigs-title">
          <h1>Approved Creator Gigs</h1>
          <p>Browse vetted creators and their services</p>
        </div>
      </div>

      {/* Search and Filter */}
      <div className="browse-gigs-controls">
        <div className="search-box">
          <Search size={18} />
          <input
            type="text"
            placeholder="Search by gig title, description, or skills..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <select
          value={selectedCategory}
          onChange={(e) => setSelectedCategory(e.target.value)}
          className="category-filter"
        >
          {categoryOptions.map(cat => (
            <option key={cat.id} value={cat.id}>{cat.label}</option>
          ))}
        </select>
      </div>

      {/* Results Count */}
      <div className="browse-gigs-results">
        <p>{filteredGigs.length} gigs found</p>
      </div>

      {/* Gigs Grid */}
      {loading ? (
        <div className="loading-container">
          <p>Loading gigs...</p>
        </div>
      ) : filteredGigs.length === 0 ? (
        <div className="empty-state">
          <p>No gigs found. Try adjusting your search or filters.</p>
        </div>
      ) : (
        <div className="gigs-grid">
          {filteredGigs.map(gig => (
            <div key={gig.id} className="gig-card">
              {/* Creator Info Header */}
              <div className="gig-creator-header">
                <div className="creator-avatar">
                  {gig.creator_name?.charAt(0).toUpperCase() || 'C'}
                </div>
                <div className="creator-info">
                  <h3 className="creator-name">{gig.creator_name || 'Unknown Creator'}</h3>
                  <CreatorLevelBadge completedWorks={gig.completed_works || 0} />
                </div>
                <Heart size={20} className="gig-heart-icon" />
              </div>

              {/* Gig Category Badge */}
              <div className="gig-category-badge">
                <span>{GigCategoryIcon({ category: gig.category })}</span>
                <span>{gig.category?.replace('_', ' ').toUpperCase()}</span>
              </div>

              {/* Gig Title */}
              <h2 className="gig-title">{gig.title}</h2>

              {/* Gig Description */}
              <p className="gig-description">
                {gig.description?.substring(0, 100)}...
              </p>

              {/* Gig Details Grid */}
              <div className="gig-details-grid">
                {gig.deadline && (
                  <div className="gig-detail-item">
                    <Calendar size={14} />
                    <span>
                      {new Date(gig.deadline).toLocaleDateString('en-US', {
                        month: 'short',
                        day: 'numeric'
                      })}
                    </span>
                  </div>
                )}
                {gig.skills_required && gig.skills_required.length > 0 && (
                  <div className="gig-detail-item">
                    <Award size={14} />
                    <span>{gig.skills_required.length} skills</span>
                  </div>
                )}
              </div>

              {/* Attachments Preview */}
              {gig.attachments && gig.attachments.length > 0 && (
                <div className="gig-attachments">
                  <div className="attachment-preview">
                    {gig.attachments.slice(0, 3).map((url, idx) => (
                      <div key={idx} className="attachment-thumbnail">
                        {url.includes('.mp4') || url.includes('.webm') ? (
                          <div className="video-thumbnail">
                            <span>🎥</span>
                          </div>
                        ) : (
                          <img src={url} alt={`Attachment ${idx + 1}`} />
                        )}
                      </div>
                    ))}
                    {gig.attachments.length > 3 && (
                      <div className="attachment-more">+{gig.attachments.length - 3}</div>
                    )}
                  </div>
                </div>
              )}

              {/* Budget and CTA */}
              <div className="gig-footer">
                <div className="gig-budget">
                  <DollarSign size={16} />
                  <span className="budget-amount">{gig.budget}</span>
                </div>
                <button
                  className="gig-cta-button"
                  onClick={() => handleContactCreator(gig.id, gig.creator_id)}
                >
                  View & Contact
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
