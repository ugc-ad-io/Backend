import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import { ArrowLeft, Upload, FileVideo, Image as ImageIcon } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export default function WorkSubmission() {
  const [searchParams] = useSearchParams();
  const campaignId = searchParams.get('campaign');
  const navigate = useNavigate();
  const { user } = useAuth();
  const [campaign, setCampaign] = useState(null);
  const [loading, setLoading] = useState(true);
  const [description, setDescription] = useState('');
  const [files, setFiles] = useState([]);

  useEffect(() => {
    if (campaignId) {
      fetchCampaign();
    }
  }, [campaignId]);

  const fetchCampaign = async () => {
    try {
      const response = await axios.get(`${API}/campaigns/${campaignId}`);
      setCampaign(response.data);
    } catch (error) {
      toast.error('Failed to load campaign');
    } finally {
      setLoading(false);
    }
  };

  const handleFileAdd = () => {
    const mockUrl = `https://storage.example.com/work/${Date.now()}_video.mp4`;
    setFiles([...files, mockUrl]);
    toast.success('File uploaded successfully (mocked)');
  };

  const handleRemoveFile = (index) => {
    setFiles(files.filter((_, i) => i !== index));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (files.length === 0) {
      toast.error('Please upload at least one file');
      return;
    }

    try {
      await axios.post(`${API}/work/submit`, {
        campaign_id: campaignId,
        work_files: files,
        description
      });
      toast.success('Work submitted successfully!');
      navigate('/dashboard/creator');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to submit work');
    }
  };

  if (loading) return <div className="loading-page">Loading...</div>;
  if (!campaign) return <div className="error-page">Campaign not found</div>;

  return (
    <div className="work-submission-page">
      <div className="page-header">
        <button className="back-btn" onClick={() => navigate(-1)} data-testid="back-btn">
          <ArrowLeft size={20} /> Back
        </button>
      </div>

      <div className="submission-container fade-in">
        <div className="submission-header">
          <h1>Submit Your Work</h1>
          <p>Campaign: {campaign.title}</p>
        </div>

        <form onSubmit={handleSubmit} className="submission-form">
          <div className="upload-section">
            <h3><Upload size={20} /> Upload Files</h3>
            <p className="hint">Videos, images, or any deliverables</p>
            
            <button
              type="button"
              className="upload-btn"
              onClick={handleFileAdd}
              data-testid="upload-file-btn"
            >
              <FileVideo size={24} />
              Click to Upload File (Mocked)
            </button>

            {files.length > 0 && (
              <div className="files-list">
                <h4>Uploaded Files:</h4>
                {files.map((file, idx) => (
                  <div key={idx} className="file-item" data-testid={`file-${idx}`}>
                    <div className="file-info">
                      <ImageIcon size={20} />
                      <span>{file.split('/').pop()}</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleRemoveFile(idx)}
                      className="remove-btn"
                      data-testid={`remove-file-${idx}`}
                    >
                      ×
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="form-group">
            <label htmlFor="description">Work Description</label>
            <textarea
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="textarea-field"
              placeholder="Describe your work, highlight key features, mention any special considerations..."
              required
              data-testid="description-input"
            />
          </div>

          <button type="submit" className="btn-primary" data-testid="submit-work-btn">
            Submit Work for Review
          </button>
        </form>
      </div>

      <style jsx>{`
        .work-submission-page {
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
          max-width: 900px;
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

        .submission-container {
          max-width: 900px;
          margin: 0 auto;
          background: white;
          padding: 48px;
          border-radius: 24px;
          box-shadow: 0 10px 40px rgba(0, 0, 0, 0.08);
        }

        .submission-header {
          text-align: center;
          margin-bottom: 40px;
        }

        .submission-header h1 {
          font-size: 2rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 8px;
        }

        .submission-header p {
          color: #718096;
          font-size: 1.1rem;
        }

        .submission-form {
          display: flex;
          flex-direction: column;
          gap: 32px;
        }

        .upload-section {
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .upload-section h3 {
          display: flex;
          align-items: center;
          gap: 8px;
          font-size: 1.25rem;
          font-weight: 600;
          color: #2d3748;
        }

        .hint {
          font-size: 0.875rem;
          color: #a0aec0;
          font-style: italic;
        }

        .upload-btn {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 12px;
          padding: 48px 32px;
          background: #f8f9ff;
          border: 3px dashed #cbd5e0;
          border-radius: 16px;
          color: #4a5568;
          font-weight: 600;
          font-size: 1.05rem;
          cursor: pointer;
          transition: all 0.3s ease;
        }

        .upload-btn:hover {
          border-color: #667eea;
          background: white;
          color: #667eea;
        }

        .files-list {
          padding: 20px;
          background: #f8f9ff;
          border-radius: 12px;
          border: 2px solid #e2e8f0;
        }

        .files-list h4 {
          font-size: 1rem;
          font-weight: 600;
          color: #2d3748;
          margin-bottom: 12px;
        }

        .file-item {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 12px;
          background: white;
          border-radius: 8px;
          margin-bottom: 8px;
        }

        .file-info {
          display: flex;
          align-items: center;
          gap: 12px;
          color: #4a5568;
        }

        .remove-btn {
          width: 32px;
          height: 32px;
          background: #f8d7da;
          color: #721c24;
          border: none;
          border-radius: 8px;
          font-size: 1.5rem;
          cursor: pointer;
          transition: all 0.3s ease;
        }

        .remove-btn:hover {
          background: #f5c6cb;
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

        @media (max-width: 640px) {
          .submission-container {
            padding: 32px 24px;
          }
        }
      `}</style>
    </div>
  );
}