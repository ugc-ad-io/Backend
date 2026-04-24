import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import { Upload, Tag, DollarSign } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export default function CreatorProfileSetup() {
  const navigate = useNavigate();
  const { user, setUser } = useAuth();
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    bio: '',
    tags: [],
    social_links: { instagram: '', youtube: '', tiktok: '' },
    rate_card: { video_30s: '', video_60s: '', photo_post: '' },
    payment_methods: { upi: '', bank_account: '' },
    receive_briefs: true,
    terms_agreed: false,
    intro_video: '',
    portfolio: [],
    availability_calendar: {}
  });
  const [tagInput, setTagInput] = useState('');
  const [uploadingVideo, setUploadingVideo] = useState(false);
  const [uploadingPortfolio, setUploadingPortfolio] = useState(false);

  const handleInputChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handleNestedChange = (parent, field, value) => {
    setFormData(prev => ({
      ...prev,
      [parent]: { ...prev[parent], [field]: value }
    }));
  };

  const addTag = () => {
    if (tagInput.trim() && !formData.tags.includes(tagInput.trim())) {
      setFormData(prev => ({
        ...prev,
        tags: [...prev.tags, tagInput.trim()]
      }));
      setTagInput('');
    }
  };

  const removeTag = (tag) => {
    setFormData(prev => ({
      ...prev,
      tags: prev.tags.filter(t => t !== tag)
    }));
  };

  const handleVideoUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Validate file size (max 50MB)
    if (file.size > 50 * 1024 * 1024) {
      toast.error('Video file too large. Maximum 50MB allowed.');
      return;
    }

    setUploadingVideo(true);
    const formDataUpload = new FormData();
    formDataUpload.append('file', file);

    try {
      const response = await axios.post(`${API}/upload/file`, formDataUpload, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setFormData(prev => ({ ...prev, intro_video: response.data.file_url }));
      toast.success('Intro video uploaded!');
    } catch (error) {
      console.error('Video upload error:', error);
      toast.error(error.response?.data?.detail || 'Failed to upload video');
    } finally {
      setUploadingVideo(false);
    }
  };

  const handlePortfolioUpload = async (e) => {
    const files = Array.from(e.target.files || []);
    if (files.length === 0) return;

    setUploadingPortfolio(true);

    try {
      const uploadPromises = files.map(async (file) => {
        // Validate file size (max 10MB per file for portfolio)
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
      setFormData(prev => ({ 
        ...prev, 
        portfolio: [...prev.portfolio, ...uploadedUrls]
      }));
      toast.success(`${uploadedUrls.length} file(s) uploaded to portfolio!`);
    } catch (error) {
      console.error('Portfolio upload error:', error);
      toast.error(error.response?.data?.detail || error.message || 'Failed to upload portfolio items');
    } finally {
      setUploadingPortfolio(false);
    }
  };

  const removePortfolioItem = (url) => {
    setFormData(prev => ({
      ...prev,
      portfolio: prev.portfolio.filter(item => item !== url)
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!formData.terms_agreed) {
      toast.error('Please agree to the terms and conditions');
      return;
    }

    if (formData.tags.length === 0) {
      toast.error('Please add at least one tag/niche');
      return;
    }

    setLoading(true);

    try {
      await axios.put(`${API}/profile/creator`, formData);
      toast.success('Profile submitted for review!');
      
      // Update user context
      const updatedUser = { ...user, profile_completed: true, approval_status: 'pending' };
      setUser(updatedUser);
      
      navigate('/dashboard/creator');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to update profile');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="profile-setup-page">
      <div className="profile-container fade-in">
        <div className="profile-header">
          <h1>Complete Your Creator Profile</h1>
          <p>Tell us about yourself and showcase your work</p>
        </div>

        <form onSubmit={handleSubmit} className="profile-form">
          <div className="form-section">
            <h3>About You</h3>
            <div className="form-group">
              <label htmlFor="bio">Bio (100 words max)</label>
              <textarea
                id="bio"
                value={formData.bio}
                onChange={(e) => handleInputChange('bio', e.target.value)}
                className="textarea-field"
                placeholder="Tell brands about yourself, your style, and expertise..."
                maxLength={500}
                required
                data-testid="bio-input"
              />
              <span className="char-count">{formData.bio.length}/500 characters</span>
            </div>
          </div>

          <div className="form-section">
            <h3><Upload size={20} /> Intro Video (Optional)</h3>
            <p className="hint">Upload a short introduction video to help brands get to know you</p>
            <div className="form-group">
              <input
                type="file"
                accept="video/mp4,video/quicktime,video/webm"
                onChange={handleVideoUpload}
                style={{ display: 'none' }}
                id="intro-video-upload"
              />
              <label htmlFor="intro-video-upload" className="upload-btn">
                {uploadingVideo ? 'Uploading...' : formData.intro_video ? '✓ Video Uploaded' : 'Choose Video'}
              </label>
              {formData.intro_video && (
                <button
                  type="button"
                  onClick={() => setFormData(prev => ({ ...prev, intro_video: '' }))}
                  className="btn-secondary-small"
                >
                  Remove
                </button>
              )}
            </div>
          </div>

          <div className="form-section">
            <h3><Upload size={20} /> Portfolio (Optional)</h3>
            <p className="hint">Upload images or videos showcasing your previous work (max 10MB per file)</p>
            <div className="form-group">
              <input
                type="file"
                accept="image/*,video/*"
                multiple
                onChange={handlePortfolioUpload}
                style={{ display: 'none' }}
                id="portfolio-upload"
              />
              <label htmlFor="portfolio-upload" className="upload-btn">
                {uploadingPortfolio ? 'Uploading...' : 'Add Portfolio Items'}
              </label>
              {formData.portfolio.length > 0 && (
                <div className="portfolio-preview">
                  {formData.portfolio.map((url, idx) => {
                    const isVideo = url.match(/\.(mp4|mov|webm|avi)$/i);
                    return (
                      <div key={idx} className="portfolio-item">
                        {isVideo ? (
                          <video src={`${BACKEND_URL}${url}`} controls style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                        ) : (
                          <img src={`${BACKEND_URL}${url}`} alt={`Portfolio ${idx + 1}`} />
                        )}
                        <button
                          type="button"
                          onClick={() => removePortfolioItem(url)}
                          className="remove-btn"
                        >
                          ×
                        </button>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          <div className="form-section">
            <h3><Tag size={20} /> Tags & Niche</h3>
            <div className="form-group">
              <label htmlFor="tags">Add Tags (Fashion, Beauty, Tech, etc.)</label>
              <div className="tag-input-wrapper">
                <input
                  id="tags"
                  type="text"
                  value={tagInput}
                  onChange={(e) => setTagInput(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), addTag())}
                  className="input-field"
                  placeholder="Type and press Enter"
                  data-testid="tag-input"
                />
                <button type="button" onClick={addTag} className="btn-secondary" data-testid="add-tag-btn">
                  Add
                </button>
              </div>
              <div className="tags-list">
                {formData.tags.map((tag, idx) => (
                  <span key={idx} className="tag-badge" data-testid={`tag-${idx}`}>
                    {tag}
                    <button type="button" onClick={() => removeTag(tag)} data-testid={`remove-tag-${idx}`}>×</button>
                  </span>
                ))}
              </div>
            </div>
          </div>

          <div className="form-section">
            <h3>Social Links (Private)</h3>
            <p className="hint">These will be hidden from public view</p>
            <div className="form-group">
              <label htmlFor="instagram">Instagram</label>
              <input
                id="instagram"
                type="text"
                value={formData.social_links.instagram}
                onChange={(e) => handleNestedChange('social_links', 'instagram', e.target.value)}
                className="input-field"
                placeholder="@username"
                data-testid="instagram-input"
              />
            </div>
            <div className="form-group">
              <label htmlFor="youtube">YouTube</label>
              <input
                id="youtube"
                type="text"
                value={formData.social_links.youtube}
                onChange={(e) => handleNestedChange('social_links', 'youtube', e.target.value)}
                className="input-field"
                placeholder="Channel URL"
                data-testid="youtube-input"
              />
            </div>
          </div>

          <div className="form-section">
            <h3><DollarSign size={20} /> Rate Card</h3>
            <div className="rate-grid">
              <div className="form-group">
                <label htmlFor="video_30s">30s Video ($)</label>
                <input
                  id="video_30s"
                  type="number"
                  value={formData.rate_card.video_30s}
                  onChange={(e) => handleNestedChange('rate_card', 'video_30s', e.target.value)}
                  className="input-field"
                  placeholder="100"
                  required
                  data-testid="rate-video-30s"
                />
              </div>
              <div className="form-group">
                <label htmlFor="video_60s">60s Video ($)</label>
                <input
                  id="video_60s"
                  type="number"
                  value={formData.rate_card.video_60s}
                  onChange={(e) => handleNestedChange('rate_card', 'video_60s', e.target.value)}
                  className="input-field"
                  placeholder="150"
                  required
                  data-testid="rate-video-60s"
                />
              </div>
              <div className="form-group">
                <label htmlFor="photo_post">Photo Post ($)</label>
                <input
                  id="photo_post"
                  type="number"
                  value={formData.rate_card.photo_post}
                  onChange={(e) => handleNestedChange('rate_card', 'photo_post', e.target.value)}
                  className="input-field"
                  placeholder="80"
                  required
                  data-testid="rate-photo-post"
                />
              </div>
            </div>
          </div>

          <div className="form-section">
            <h3>Payment Methods</h3>
            <div className="form-group">
              <label htmlFor="upi">UPI ID</label>
              <input
                id="upi"
                type="text"
                value={formData.payment_methods.upi}
                onChange={(e) => handleNestedChange('payment_methods', 'upi', e.target.value)}
                className="input-field"
                placeholder="yourname@upi"
                required
                data-testid="upi-input"
              />
            </div>
            <div className="form-group">
              <label htmlFor="bank_account">Bank Account (Last 4 digits)</label>
              <input
                id="bank_account"
                type="text"
                value={formData.payment_methods.bank_account}
                onChange={(e) => handleNestedChange('payment_methods', 'bank_account', e.target.value)}
                className="input-field"
                placeholder="XXXX1234"
                data-testid="bank-input"
              />
            </div>
          </div>

          <div className="form-section">
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={formData.receive_briefs}
                onChange={(e) => handleInputChange('receive_briefs', e.target.checked)}
                data-testid="receive-briefs-checkbox"
              />
              I want to receive campaign briefs
            </label>

            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={formData.terms_agreed}
                onChange={(e) => handleInputChange('terms_agreed', e.target.checked)}
                required
                data-testid="terms-checkbox"
              />
              I agree to the Terms & Conditions
            </label>
          </div>

          <button type="submit" className="btn-primary" disabled={loading} data-testid="submit-profile-btn">
            {loading ? 'Submitting...' : 'Submit for Review'}
          </button>
        </form>
      </div>

      <style jsx>{`
        .profile-setup-page {
          min-height: 100vh;
          padding: 60px 20px;
          background: linear-gradient(135deg, #f8f9ff 0%, #e8ecff 100%);
        }

        .profile-container {
          max-width: 800px;
          margin: 0 auto;
          background: white;
          border-radius: 24px;
          padding: 48px;
          box-shadow: 0 10px 40px rgba(0, 0, 0, 0.08);
        }

        .profile-header {
          text-align: center;
          margin-bottom: 48px;
        }

        .profile-header h1 {
          font-size: 2rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 8px;
        }

        .profile-header p {
          color: #718096;
        }

        .profile-form {
          display: flex;
          flex-direction: column;
          gap: 32px;
        }

        .form-section {
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .form-section h3 {
          font-size: 1.25rem;
          font-weight: 600;
          color: #2d3748;
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .hint {
          font-size: 0.875rem;
          color: #a0aec0;
          font-style: italic;
        }

        .form-group {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .form-group label {
          font-weight: 600;
          color: #2d3748;
          font-size: 0.95rem;
        }

        .char-count {
          text-align: right;
          font-size: 0.85rem;
          color: #a0aec0;
        }

        .tag-input-wrapper {
          display: flex;
          gap: 12px;
        }

        .tag-input-wrapper .input-field {
          flex: 1;
        }

        .tag-input-wrapper .btn-secondary {
          padding: 12px 24px;
        }

        .tags-list {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
          margin-top: 8px;
        }

        .tag-badge {
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

        .tag-badge button {
          background: none;
          border: none;
          color: white;
          font-size: 1.25rem;
          cursor: pointer;
          padding: 0;
          line-height: 1;
        }

        .rate-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
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

        .profile-form .btn-primary {
          margin-top: 16px;
        }

        .upload-btn {
          display: inline-block;
          padding: 12px 24px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          border-radius: 12px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
          text-align: center;
        }

        .upload-btn:hover {
          transform: translateY(-2px);
          box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }

        .btn-secondary-small {
          margin-left: 12px;
          padding: 8px 16px;
          background: white;
          color: #4a5568;
          border: 2px solid #e2e8f0;
          border-radius: 8px;
          font-weight: 600;
          cursor: pointer;
        }

        .portfolio-preview {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
          gap: 16px;
          margin-top: 16px;
        }

        .portfolio-item {
          position: relative;
          border-radius: 12px;
          overflow: hidden;
          aspect-ratio: 1;
        }

        .portfolio-item img {
          width: 100%;
          height: 100%;
          object-fit: cover;
        }

        .remove-btn {
          position: absolute;
          top: 8px;
          right: 8px;
          width: 28px;
          height: 28px;
          background: rgba(255, 0, 0, 0.8);
          color: white;
          border: none;
          border-radius: 50%;
          font-size: 20px;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          line-height: 1;
        }

        .remove-btn:hover {
          background: rgba(255, 0, 0, 1);
        }

        @media (max-width: 640px) {
          .profile-container {
            padding: 32px 24px;
          }

          .rate-grid {
            grid-template-columns: 1fr;
          }
        }
      `}</style>
    </div>
  );
}