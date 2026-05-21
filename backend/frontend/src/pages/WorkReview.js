import { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import { ArrowLeft, CheckCircle, MessageCircle, Star } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export default function WorkReview() {
  const { id: workId } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const [work, setWork] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showReviewModal, setShowReviewModal] = useState(false);
  const [showRevisionModal, setShowRevisionModal] = useState(false);
  const [rating, setRating] = useState(5);
  const [review, setReview] = useState('');
  const [revisionFeedback, setRevisionFeedback] = useState('');

  useEffect(() => {
    const fetchWork = async () => {
      try {
        const response = await axios.get(`${API}/work/${workId}`);
        setWork(response.data);
      } catch (error) {
        console.error('Failed to fetch work:', error);
        toast.error('Failed to load work submission');
      } finally {
        setLoading(false);
      }
    };

    if (workId) {
      fetchWork();
    }
  }, [workId]);

  const handleApprove = async () => {
    try {
      await axios.post(`${API}/work/${workId}/approve`);
      toast.success('Work approved and payment released!');
      setShowReviewModal(true);
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to approve work');
    }
  };

  const handleRequestRevision = async () => {
    if (!revisionFeedback.trim()) {
      toast.error('Please provide feedback for revision');
      return;
    }

    try {
      await axios.post(`${API}/work/${workId}/request-revision?feedback=${encodeURIComponent(revisionFeedback)}`);
      toast.success('Revision requested');
      setShowRevisionModal(false);
      navigate('/dashboard/business');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to request revision');
    }
  };

  const handleSubmitReview = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${API}/reviews`, {
        campaign_id: work.campaign_id,
        creator_id: work.creator_id,
        rating,
        review
      });
      toast.success('Review submitted!');
      navigate('/dashboard/business');
    } catch (error) {
      toast.error('Failed to submit review');
    }
  };

  if (loading) return <div className="loading-page">Loading...</div>;
  if (!work) return <div className="error-page">Work not found</div>;

  return (
    <div className="work-review-page">
      <div className="page-header">
        <button className="back-btn" onClick={() => navigate(-1)} data-testid="back-btn">
          <ArrowLeft size={20} /> Back
        </button>
      </div>

      <div className="review-container fade-in">
        <div className="review-header">
          <h1>Review Submitted Work</h1>
          <p>Campaign: {work.campaign_title}</p>
          <p className="creator-info">By {work.creator_nickname}</p>
        </div>

        <div className="work-section">
          <h3>Work Description</h3>
          <p className="work-description">{work.description}</p>
        </div>

        <div className="work-section">
          <h3>Submitted Files</h3>
          <div className="files-grid">
            {work.work_files.map((file, idx) => (
              <div key={idx} className="file-preview" data-testid={`file-${idx}`}>
                <div className="file-icon">
                  {file.includes('video') ? '🎥' : '🖼️'}
                </div>
                <p className="file-name">{file.split('/').pop()}</p>
                <a href={file.startsWith('http') ? file : `${BACKEND_URL}${file}`} target="_blank" rel="noopener noreferrer" className="view-link">
                  View File
                </a>
              </div>
            ))}
          </div>
        </div>

        <div className="action-buttons">
          <button
            className="btn-approve"
            onClick={handleApprove}
            data-testid="approve-btn"
          >
            <CheckCircle size={20} /> Approve & Release Payment
          </button>
          <button
            className="btn-revision"
            onClick={() => setShowRevisionModal(true)}
            data-testid="revision-btn"
          >
            <MessageCircle size={20} /> Request Revision
          </button>
        </div>
      </div>

      {/* Review Modal */}
      {showReviewModal && (
        <div className="modal-overlay" onClick={() => setShowReviewModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Leave a Review</h2>
            <form onSubmit={handleSubmitReview} className="review-form">
              <div className="form-group">
                <label>Rating</label>
                <div className="star-rating">
                  {[1, 2, 3, 4, 5].map((star) => (
                    <button
                      key={star}
                      type="button"
                      onClick={() => setRating(star)}
                      className={`star ${star <= rating ? 'active' : ''}`}
                      data-testid={`star-${star}`}
                    >
                      <Star size={32} fill={star <= rating ? '#fbbf24' : 'none'} />
                    </button>
                  ))}
                </div>
              </div>
              <div className="form-group">
                <label htmlFor="review">Your Review</label>
                <textarea
                  id="review"
                  value={review}
                  onChange={(e) => setReview(e.target.value)}
                  className="textarea-field"
                  placeholder="Share your experience working with this creator..."
                  required
                  data-testid="review-input"
                />
              </div>
              <div className="modal-actions">
                <button type="button" className="btn-secondary" onClick={() => setShowReviewModal(false)}>
                  Skip
                </button>
                <button type="submit" className="btn-primary" data-testid="submit-review-btn">
                  Submit Review
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Revision Modal */}
      {showRevisionModal && (
        <div className="modal-overlay" onClick={() => setShowRevisionModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Request Revision</h2>
            <div className="form-group">
              <label htmlFor="feedback">Revision Feedback</label>
              <textarea
                id="feedback"
                value={revisionFeedback}
                onChange={(e) => setRevisionFeedback(e.target.value)}
                className="textarea-field"
                placeholder="Explain what changes you'd like to see..."
                data-testid="feedback-input"
              />
            </div>
            <div className="modal-actions">
              <button className="btn-secondary" onClick={() => setShowRevisionModal(false)}>
                Cancel
              </button>
              <button className="btn-primary" onClick={handleRequestRevision} data-testid="submit-revision-btn">
                Send Revision Request
              </button>
            </div>
          </div>
        </div>
      )}

      <style jsx>{`
        .work-review-page {
          min-height: 100vh;
          background: linear-gradient(135deg, #f8f9ff 0%, #e8ecff 100%);
          padding: 40px 8%;
        }

        .loading-page,
        .error-page {
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 1.25rem;
          color: #718096;
        }

        .page-header {
          max-width: 1000px;
          margin: 0 auto 24px;
        }

        .back-btn {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 12px 24px;
          background: white;
          border: 2px solid #e2e8f0;
          border-radius: 12px;
          color: #4a5568;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
        }

        .back-btn:hover {
          border-color: #667eea;
          color: #667eea;
          transform: translateX(-4px);
        }

        .review-container {
          max-width: 1000px;
          margin: 0 auto;
          background: white;
          padding: 48px;
          border-radius: 24px;
          box-shadow: 0 10px 40px rgba(0, 0, 0, 0.08);
        }

        .review-header {
          text-align: center;
          margin-bottom: 40px;
          padding-bottom: 32px;
          border-bottom: 2px solid #e2e8f0;
        }

        .review-header h1 {
          font-size: 2rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 8px;
        }

        .review-header p {
          color: #718096;
          font-size: 1.05rem;
          margin-top: 8px;
        }

        .creator-info {
          color: #667eea !important;
          font-weight: 600;
        }

        .work-section {
          margin-bottom: 32px;
        }

        .work-section h3 {
          font-size: 1.25rem;
          font-weight: 600;
          color: #2d3748;
          margin-bottom: 16px;
        }

        .work-description {
          color: #4a5568;
          line-height: 1.8;
          padding: 20px;
          background: #f8f9ff;
          border-radius: 12px;
        }

        .files-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
          gap: 16px;
        }

        .file-preview {
          padding: 24px;
          background: #f8f9ff;
          border-radius: 12px;
          border: 2px solid #e2e8f0;
          text-align: center;
          transition: all 0.3s ease;
        }

        .file-preview:hover {
          border-color: #667eea;
          transform: translateY(-4px);
        }

        .file-icon {
          font-size: 3rem;
          margin-bottom: 12px;
        }

        .file-name {
          color: #4a5568;
          font-size: 0.9rem;
          margin-bottom: 12px;
          word-break: break-all;
        }

        .view-link {
          display: inline-block;
          padding: 8px 16px;
          background: #667eea;
          color: white;
          border-radius: 8px;
          text-decoration: none;
          font-weight: 600;
          font-size: 0.875rem;
          transition: all 0.3s ease;
        }

        .view-link:hover {
          background: #5568d3;
        }

        .action-buttons {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 16px;
          margin-top: 40px;
          padding-top: 32px;
          border-top: 2px solid #e2e8f0;
        }

        .btn-approve {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          padding: 16px;
          background: linear-gradient(135deg, #10b981 0%, #059669 100%);
          color: white;
          border: none;
          border-radius: 12px;
          font-weight: 600;
          font-size: 1.05rem;
          cursor: pointer;
          transition: all 0.3s ease;
        }

        .btn-approve:hover {
          transform: translateY(-2px);
          box-shadow: 0 8px 24px rgba(16, 185, 129, 0.4);
        }

        .btn-revision {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          padding: 16px;
          background: white;
          color: #f59e0b;
          border: 2px solid #f59e0b;
          border-radius: 12px;
          font-weight: 600;
          font-size: 1.05rem;
          cursor: pointer;
          transition: all 0.3s ease;
        }

        .btn-revision:hover {
          background: #f59e0b;
          color: white;
          transform: translateY(-2px);
        }

        .modal-overlay {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0, 0, 0, 0.6);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 1000;
          padding: 20px;
        }

        .modal-content {
          background: white;
          padding: 40px;
          border-radius: 24px;
          max-width: 600px;
          width: 100%;
        }

        .modal-content h2 {
          font-size: 1.75rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 32px;
        }

        .review-form {
          display: flex;
          flex-direction: column;
          gap: 24px;
        }

        .star-rating {
          display: flex;
          gap: 8px;
        }

        .star {
          background: none;
          border: none;
          cursor: pointer;
          padding: 4px;
          color: #cbd5e0;
          transition: all 0.3s ease;
        }

        .star:hover {
          transform: scale(1.1);
        }

        .star.active {
          color: #fbbf24;
        }

        .modal-actions {
          display: flex;
          gap: 12px;
          margin-top: 8px;
        }

        .modal-actions button {
          flex: 1;
        }

        @media (max-width: 768px) {
          .review-container {
            padding: 32px 24px;
          }

          .action-buttons {
            grid-template-columns: 1fr;
          }
        }
      `}</style>
    </div>
  );
}