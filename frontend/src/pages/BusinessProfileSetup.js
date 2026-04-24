import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import { Building2, Globe } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export default function BusinessProfileSetup() {
  const navigate = useNavigate();
  const { user, setUser } = useAuth();
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    business_description: '',
    website: '',
    social_links: { facebook: '', instagram: '', linkedin: '' },
    product_type: '',
    industry_category: '',
  });

  const industries = [
    'Fashion & Apparel',
    'Beauty & Cosmetics',
    'Technology & Gadgets',
    'Food & Beverage',
    'Health & Fitness',
    'Home & Lifestyle',
    'Travel & Tourism',
    'Education',
    'Entertainment',
    'Other'
  ];

  const handleInputChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handleNestedChange = (parent, field, value) => {
    setFormData(prev => ({
      ...prev,
      [parent]: { ...prev[parent], [field]: value }
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      await axios.put(`${API}/profile/business`, formData);
      toast.success('Profile submitted for review!');
      
      // Update user context
      const updatedUser = { ...user, profile_completed: true, approval_status: 'pending' };
      setUser(updatedUser);
      
      navigate('/dashboard/business');
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
          <Building2 size={48} className="header-icon" />
          <h1>Complete Your Business Profile</h1>
          <p>Tell creators about your brand and products</p>
        </div>

        <form onSubmit={handleSubmit} className="profile-form">
          <div className="form-section">
            <h3>Business Information</h3>
            <div className="form-group">
              <label htmlFor="business_description">Business Description</label>
              <textarea
                id="business_description"
                value={formData.business_description}
                onChange={(e) => handleInputChange('business_description', e.target.value)}
                className="textarea-field"
                placeholder="Describe your business, products, and what makes your brand unique..."
                required
                data-testid="business-description-input"
              />
            </div>

            <div className="form-group">
              <label htmlFor="product_type">Product Type</label>
              <input
                id="product_type"
                type="text"
                value={formData.product_type}
                onChange={(e) => handleInputChange('product_type', e.target.value)}
                className="input-field"
                placeholder="e.g., Clothing, Electronics, Skincare"
                required
                data-testid="product-type-input"
              />
            </div>

            <div className="form-group">
              <label htmlFor="industry_category">Industry Category</label>
              <select
                id="industry_category"
                value={formData.industry_category}
                onChange={(e) => handleInputChange('industry_category', e.target.value)}
                className="input-field"
                required
                data-testid="industry-category-select"
              >
                <option value="">Select an industry</option>
                {industries.map(industry => (
                  <option key={industry} value={industry}>{industry}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="form-section">
            <h3><Globe size={20} /> Online Presence</h3>
            <div className="form-group">
              <label htmlFor="website">Website URL</label>
              <input
                id="website"
                type="url"
                value={formData.website}
                onChange={(e) => handleInputChange('website', e.target.value)}
                className="input-field"
                placeholder="https://yourbrand.com"
                data-testid="website-input"
              />
            </div>

            <div className="form-group">
              <label htmlFor="facebook">Facebook</label>
              <input
                id="facebook"
                type="text"
                value={formData.social_links.facebook}
                onChange={(e) => handleNestedChange('social_links', 'facebook', e.target.value)}
                className="input-field"
                placeholder="facebook.com/yourpage"
                data-testid="facebook-input"
              />
            </div>

            <div className="form-group">
              <label htmlFor="instagram">Instagram</label>
              <input
                id="instagram"
                type="text"
                value={formData.social_links.instagram}
                onChange={(e) => handleNestedChange('social_links', 'instagram', e.target.value)}
                className="input-field"
                placeholder="@yourbrand"
                data-testid="instagram-input"
              />
            </div>

            <div className="form-group">
              <label htmlFor="linkedin">LinkedIn</label>
              <input
                id="linkedin"
                type="text"
                value={formData.social_links.linkedin}
                onChange={(e) => handleNestedChange('social_links', 'linkedin', e.target.value)}
                className="input-field"
                placeholder="linkedin.com/company/yourbrand"
                data-testid="linkedin-input"
              />
            </div>
          </div>

          <button type="submit" className="btn-primary" disabled={loading} data-testid="submit-business-profile-btn">
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

        .header-icon {
          color: #667eea;
          margin: 0 auto 16px;
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

        .profile-form .btn-primary {
          margin-top: 16px;
        }

        @media (max-width: 640px) {
          .profile-container {
            padding: 32px 24px;
          }
        }
      `}</style>
    </div>
  );
}