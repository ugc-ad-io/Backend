import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import DashboardLayout from '../components/DashboardLayout';
import {
  LayoutDashboard,
  Upload,
  Zap,
  Bookmark,
  Star,
  User,
  Briefcase,
  FileCheck,
  MessageSquare,
  IndianRupee,
  Settings,
  ArrowLeft,
  X,
  Plus
} from 'lucide-react';
import { useState } from 'react';
import './CreateGig.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export default function CreateGig() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [mediaItems, setMediaItems] = useState([]);
  const [formData, setFormData] = useState({
    title: '',
    category: '',
    description: '',
    budget: '',
    deadline: '',
    requirements: '',
    target_audience: '',
    skills_required: []
  });

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

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleMultiSelect = (name, value) => {
    setFormData(prev => {
      const current = prev[name] || [];
      if (current.includes(value)) {
        return { ...prev, [name]: current.filter(item => item !== value) };
      } else {
        return { ...prev, [name]: [...current, value] };
      }
    });
  };

  const handleMediaUpload = async (e) => {
    const files = Array.from(e.target.files || []);
    if (mediaItems.length + files.length > 5) {
      toast.error('Maximum 5 images/videos allowed');
      return;
    }

    for (const file of files) {
      if (file.size > 10 * 1024 * 1024) {
        toast.error(`${file.name} is too large. Maximum 10MB per file.`);
        continue;
      }

      const formDataUpload = new FormData();
      formDataUpload.append('file', file);

      try {
        console.log('Uploading file:', file.name);
        const response = await axios.post(`${API}/upload/file`, formDataUpload, {
          headers: { 'Content-Type': 'multipart/form-data' }
        });

        console.log('Upload response:', response.data);

        // Handle different response formats
        let fileUrl = response.data?.file_url || response.data?.url || response.data?.data?.url || response.data;

        if (!fileUrl || typeof fileUrl !== 'string') {
          console.error('Invalid file URL in response:', response.data);
          toast.error(`${file.name} uploaded but URL is invalid`);
          continue;
        }

        // Convert relative URLs to absolute backend URLs
        if (fileUrl.startsWith('/')) {
          fileUrl = `${BACKEND_URL}${fileUrl}`;
        }

        console.log('Final file URL:', fileUrl);
        setMediaItems(prev => [...prev, { id: Date.now() + Math.random(), url: fileUrl }]);
        toast.success(`${file.name} uploaded successfully`);
      } catch (error) {
        console.error('Upload error:', error);
        const errorMsg = error.response?.data?.error || error.response?.data?.detail || error.message || 'Upload failed';
        toast.error(`Failed to upload ${file.name}: ${errorMsg}`);
      }
    }
    e.target.value = '';
  };

  const removeMedia = (id) => {
    setMediaItems(prev => prev.filter(item => item.id !== id));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    // Validate required fields
    if (!formData.title?.trim()) {
      toast.error('Please enter a gig title');
      return;
    }

    if (!formData.category) {
      toast.error('Please select a category');
      return;
    }

    if (!formData.description?.trim()) {
      toast.error('Please enter a description');
      return;
    }

    if (!formData.budget || parseFloat(formData.budget) <= 0) {
      toast.error('Please enter a valid budget (greater than 0)');
      return;
    }

    if (!formData.deadline) {
      toast.error('Please set a deadline');
      return;
    }

    // Validate deadline is in future
    const deadlineDate = new Date(formData.deadline);
    const now = new Date();
    if (deadlineDate <= now) {
      toast.error('Deadline must be in the future');
      return;
    }

    setLoading(true);
    try {
      // Convert datetime-local to ISO string
      const deadlineDate = new Date(formData.deadline);
      const isoDeadline = deadlineDate.toISOString();

      const gigData = {
        title: formData.title,
        category: formData.category,
        description: formData.description,
        budget: parseFloat(formData.budget),
        deadline: isoDeadline,
        attachments: mediaItems.map(item => item.url),
        requirements: formData.requirements || '',
        target_audience: formData.target_audience || '',
        skills_required: formData.skills_required || []
      };

      console.log('Submitting gig data:', gigData);
      const response = await axios.post(`${API}/gigs`, gigData);
      console.log('Gig creation response:', response.data);

      toast.success('Gig created successfully! Sent for admin approval.');

      // Add a small delay before redirect to ensure toast is visible
      setTimeout(() => {
        navigate('/dashboard/creator');
      }, 1500);
    } catch (error) {
      console.error('Gig creation error:', error);
      const errorMsg = error.response?.data?.detail ||
                       error.response?.data?.error ||
                       error.response?.data?.message ||
                       error.message ||
                       'Failed to create gig. Please try again.';
      toast.error(errorMsg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <DashboardLayout
      navItems={navItems}
      title="Create a Gig"
      description="Offer your services and attract clients"
      topbarExtra={null}
      sidebarExtra={null}
    >
      <section className="create-gig-container">
        <div className="create-gig-card">
          <button
            type="button"
            className="create-gig-back"
            onClick={() => navigate('/dashboard/creator')}
          >
            <ArrowLeft size={18} />
            Back
          </button>

          <div className="create-gig-header">
            <h1>Create a New Gig</h1>
            <p>Set up a service offering to attract clients and grow your creator business</p>
          </div>

          <form className="create-gig-form" onSubmit={handleSubmit}>
            <div className="create-gig-section">
              <h3>Basic Information</h3>

              <fieldset>
                <legend>Gig Title *</legend>
                <input
                  type="text"
                  name="title"
                  value={formData.title}
                  onChange={handleInputChange}
                  placeholder="e.g., Create engaging social media content"
                  maxLength="100"
                  required
                />
                <small>Clear, specific title (5-100 characters)</small>
              </fieldset>

              <fieldset>
                <legend>Category *</legend>
                <select
                  name="category"
                  value={formData.category}
                  onChange={handleInputChange}
                  required
                >
                  <option value="">Select a category</option>
                  <option value="social_media">Social Media Content</option>
                  <option value="product_review">Product Reviews</option>
                  <option value="unboxing">Unboxing Videos</option>
                  <option value="tutorial">Tutorials/How-to</option>
                  <option value="sponsorship">Sponsored Content</option>
                  <option value="brand_ambassador">Brand Ambassador Work</option>
                  <option value="content_creation">General Content Creation</option>
                  <option value="photography">Photography Work</option>
                  <option value="videography">Video Production</option>
                  <option value="other">Other</option>
                </select>
              </fieldset>

              <fieldset>
                <legend>Description *</legend>
                <textarea
                  name="description"
                  value={formData.description}
                  onChange={handleInputChange}
                  placeholder="Describe what the gig is about, what's included, and your process..."
                  rows="6"
                  maxLength="5000"
                  required
                />
                <small>Detailed description (20-5000 characters)</small>
              </fieldset>

              <fieldset>
                <legend>Budget *</legend>
                <div className="price-input">
                  <span>$</span>
                  <input
                    type="number"
                    name="budget"
                    value={formData.budget}
                    onChange={handleInputChange}
                    placeholder="e.g., 500"
                    step="0.01"
                    min="0"
                    required
                  />
                </div>
                <small>Budget amount in USD (must be greater than 0)</small>
              </fieldset>

              <fieldset>
                <legend>Deadline *</legend>
                <input
                  type="datetime-local"
                  name="deadline"
                  value={formData.deadline}
                  onChange={handleInputChange}
                  required
                />
                <small>When work needs to be completed (must be in the future)</small>
              </fieldset>
            </div>

            <div className="create-gig-section">
              <h3>Additional Details</h3>

              <fieldset>
                <legend>Requirements</legend>
                <textarea
                  name="requirements"
                  value={formData.requirements}
                  onChange={handleInputChange}
                  placeholder="Specify any detailed requirements for the work..."
                  rows="4"
                  maxLength="2000"
                />
                <small>Optional - Additional requirements (max 2000 characters)</small>
              </fieldset>

              <fieldset>
                <legend>Target Audience</legend>
                <input
                  type="text"
                  name="target_audience"
                  value={formData.target_audience}
                  onChange={handleInputChange}
                  placeholder="e.g., Women 18-35, Tech enthusiasts, Fashion lovers"
                  maxLength="500"
                />
                <small>Optional - Describe your target audience (max 500 characters)</small>
              </fieldset>

              <fieldset>
                <legend>Skills Required</legend>
                <div className="skills-input">
                  {['Video Editing', 'Content Writing', 'Photography', 'Social Media', 'Design', 'Storytelling', 'Animation', 'Scripting'].map(skill => (
                    <label key={skill} className="checkbox-label">
                      <input
                        type="checkbox"
                        checked={formData.skills_required.includes(skill)}
                        onChange={() => handleMultiSelect('skills_required', skill)}
                      />
                      <span>{skill}</span>
                    </label>
                  ))}
                </div>
              </fieldset>
            </div>

            <div className="create-gig-section">
              <h3>Attachments (Add up to 5 files)</h3>

              <fieldset>
                <legend>Upload Attachments</legend>
                <div className="media-upload-area">
                  <label className="media-upload-label">
                    <Plus size={24} />
                    <span>Click to upload or drag and drop</span>
                    <small>Any file type • Max 10MB per file</small>
                    <input
                      type="file"
                      multiple
                      accept="image/*,video/*,.pdf,.doc,.docx"
                      onChange={handleMediaUpload}
                      disabled={mediaItems.length >= 5}
                      style={{ display: 'none' }}
                    />
                  </label>
                </div>

                {mediaItems.length > 0 && (
                  <div className="media-preview-grid">
                    {mediaItems.map(item => (
                      <div key={item.id} className="media-preview-item">
                        <div className="media-preview-content">
                          {item.url.includes('.mp4') || item.url.includes('.webm') ? (
                            <video
                              src={item.url}
                              controls
                              style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                              onError={() => console.error('Video load error:', item.url)}
                            />
                          ) : item.url.includes('.pdf') ? (
                            <div className="pdf-placeholder">📄 PDF File</div>
                          ) : (
                            <img
                              src={item.url}
                              alt="Preview"
                              style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                              onError={(e) => {
                                console.error('Image load error:', item.url);
                                e.target.src = 'data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%22100%22 height=%22100%22%3E%3Crect fill=%22%23f0f0f0%22 width=%22100%22 height=%22100%22/%3E%3Ctext x=%2250%25%22 y=%2250%25%22 dominant-baseline=%22middle%22 text-anchor=%22middle%22 font-family=%22Arial%22 font-size=%2214%22 fill=%22%23999%22%3EImage Load Error%3C/text%3E%3C/svg%3E';
                              }}
                            />
                          )}
                        </div>
                        <button
                          type="button"
                          className="media-remove-btn"
                          onClick={() => removeMedia(item.id)}
                        >
                          <X size={18} />
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                <small>{mediaItems.length}/5 files uploaded</small>
              </fieldset>
            </div>

            <div className="create-gig-actions">
              <button type="button" className="create-gig-cancel" onClick={() => navigate('/dashboard/creator')}>
                Cancel
              </button>
              <button type="submit" className="create-gig-submit" disabled={loading}>
                <Upload size={16} />
                {loading ? 'Creating...' : 'Create Gig'}
              </button>
            </div>
          </form>

          <div className="create-gig-tips">
            <h3>Tips for Creating Your Gig</h3>
            <ul>
              <li>Use a clear, descriptive title so creators can find your work easily</li>
              <li>Provide detailed requirements and expectations in the description</li>
              <li>Set a realistic budget based on the complexity and timeline</li>
              <li>Attach reference materials, examples, or mockups to guide the work</li>
              <li>Define the target audience clearly to get better quality submissions</li>
              <li>Be specific about required skills to attract the right creators</li>
            </ul>
          </div>
        </div>
      </section>
    </DashboardLayout>
  );
}
