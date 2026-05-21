import { useState, useEffect } from 'react';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import {
  LayoutDashboard,
  Check,
  X,
  ChevronDown,
  Search,
  Filter,
  Eye,
  MessageCircle,
  IndianRupee
} from 'lucide-react';
import AdminLayout from '../components/AdminLayout';
import './AdminGigManagement.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export default function AdminGigManagement() {
  const { user } = useAuth();
  const [gigs, setGigs] = useState([]);
  const [filteredGigs, setFilteredGigs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedGig, setSelectedGig] = useState(null);
  const [filterStatus, setFilterStatus] = useState('pending_approval');
  const [searchQuery, setSearchQuery] = useState('');
  const [rejectReason, setRejectReason] = useState('');
  const [showRejectForm, setShowRejectForm] = useState(null);
  const [processingId, setProcessingId] = useState(null);

  useEffect(() => {
    fetchGigs();
  }, []);

  useEffect(() => {
    filterGigs();
  }, [gigs, filterStatus, searchQuery]);

  const fetchGigs = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API}/gigs`, { params: { limit: 100 } });
      const gigsData = res.data.data || res.data || [];
      console.log('Fetched gigs from API:', gigsData);
      gigsData.forEach(gig => {
        console.log(`Gig ${gig.id}: attachments =`, gig.attachments);
      });
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

    if (filterStatus) {
      filtered = filtered.filter(gig => gig.status === filterStatus);
    }

    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(gig =>
        gig.title?.toLowerCase().includes(query) ||
        gig.creator_name?.toLowerCase().includes(query) ||
        gig.category?.toLowerCase().includes(query)
      );
    }

    setFilteredGigs(filtered);
  };

  const approveGig = async (gigId) => {
    setProcessingId(gigId);
    try {
      await axios.patch(`${API}/gigs/${gigId}?action=approve`);
      toast.success('Gig approved!');
      setGigs(gigs.map(g => g.id === gigId ? { ...g, status: 'approved' } : g));
      setShowRejectForm(null);
      setSelectedGig(null);
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to approve gig');
    } finally {
      setProcessingId(null);
    }
  };

  const rejectGig = async (gigId) => {
    if (!rejectReason.trim()) {
      toast.error('Please provide a rejection reason');
      return;
    }

    setProcessingId(gigId);
    try {
      await axios.patch(`${API}/gigs/${gigId}?action=reject`, {
        rejection_reason: rejectReason
      });
      toast.success('Gig rejected');
      setGigs(gigs.map(g => g.id === gigId ? { ...g, status: 'rejected', rejection_reason: rejectReason } : g));
      setShowRejectForm(null);
      setRejectReason('');
      setSelectedGig(null);
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to reject gig');
    } finally {
      setProcessingId(null);
    }
  };

  return (
    <AdminLayout>
      <div className="agm-container">
        <div className="agm-header">
          <div>
            <h1>Gig Management</h1>
            <p>Review and approve creator gigs</p>
          </div>
          <div className="agm-stats">
            <div className="agm-stat">
              <span>Pending</span>
              <strong>{gigs.filter(g => g.status === 'pending_approval').length}</strong>
            </div>
            <div className="agm-stat">
              <span>Approved</span>
              <strong>{gigs.filter(g => g.status === 'approved').length}</strong>
            </div>
            <div className="agm-stat">
              <span>Rejected</span>
              <strong>{gigs.filter(g => g.status === 'rejected').length}</strong>
            </div>
          </div>
        </div>

        <div className="agm-controls">
          <div className="agm-search">
            <Search size={18} />
            <input
              type="text"
              placeholder="Search gigs by title, creator, or category..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="agm-filter"
          >
            <option value="pending_approval">Pending Approval</option>
            <option value="approved">Approved</option>
            <option value="rejected">Rejected</option>
            <option value="">All Gigs</option>
          </select>
        </div>

        <div className="agm-content">
          <div className="agm-list">
            {loading ? (
              <div className="agm-empty">Loading gigs...</div>
            ) : filteredGigs.length === 0 ? (
              <div className="agm-empty">No gigs found</div>
            ) : (
              filteredGigs.map(gig => (
                <div
                  key={gig.id}
                  className={`agm-gig-card ${selectedGig?.id === gig.id ? 'is-selected' : ''}`}
                  onClick={() => setSelectedGig(gig)}
                >
                  <div className="agm-gig-header">
                    <div>
                      <h3>{gig.title}</h3>
                      <p className="agm-creator">by {gig.creator_name || 'Unknown Creator'}</p>
                    </div>
                    <span className={`agm-status agm-status-${gig.status}`}>
                      {gig.status === 'pending_approval' ? 'Pending' : gig.status.charAt(0).toUpperCase() + gig.status.slice(1)}
                    </span>
                  </div>
                  <div className="agm-gig-meta">
                    <span>{gig.category}</span>
                    <span><IndianRupee size={14} /> {gig.price}</span>
                  </div>
                </div>
              ))
            )}
          </div>

          {selectedGig && (
            <div className="agm-details">
              <div className="agm-detail-header">
                <h2>{selectedGig.title}</h2>
                <span className={`agm-status agm-status-${selectedGig.status}`}>
                  {selectedGig.status === 'pending_approval' ? 'Pending Review' : selectedGig.status.charAt(0).toUpperCase() + selectedGig.status.slice(1)}
                </span>
              </div>

              <div className="agm-detail-section">
                <h3>Creator Information</h3>
                <dl>
                  <div>
                    <dt>Creator Name</dt>
                    <dd>{selectedGig.creator_name || 'Unknown'}</dd>
                  </div>
                  <div>
                    <dt>Creator Email</dt>
                    <dd>{selectedGig.creator_email || 'N/A'}</dd>
                  </div>
                </dl>
              </div>

              <div className="agm-detail-section">
                <h3>Gig Details</h3>
                <dl>
                  <div>
                    <dt>Category</dt>
                    <dd>{selectedGig.category}</dd>
                  </div>
                  <div>
                    <dt>Price</dt>
                    <dd>₹{selectedGig.price}</dd>
                  </div>
                  <div>
                    <dt>Delivery Days</dt>
                    <dd>{selectedGig.deliveryTime || 'N/A'} days</dd>
                  </div>
                  <div>
                    <dt>Niche</dt>
                    <dd>{selectedGig.niche || 'Not specified'}</dd>
                  </div>
                </dl>
              </div>

              <div className="agm-detail-section">
                <h3>Description</h3>
                <p>{selectedGig.description}</p>
              </div>

              {selectedGig.attachments && selectedGig.attachments.length > 0 && (
                <div className="agm-detail-section">
                  <h3>Attachments & Images</h3>
                  <div className="agm-attachments-grid">
                    {selectedGig.attachments.map((attachment, idx) => {
                      const isImage = /\.(jpg|jpeg|png|gif|webp)$/i.test(attachment);
                      const isVideo = /\.(mp4|webm|mov)$/i.test(attachment);
                      const isPdf = /\.pdf$/i.test(attachment);

                      return (
                        <div key={idx} className="agm-attachment-item">
                          {isImage ? (
                            <img src={attachment} alt={`Attachment ${idx + 1}`} className="agm-attachment-image" onError={(e) => {console.log(`Image failed to load: ${attachment}`); e.target.src = 'data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%22150%22 height=%22150%22%3E%3Crect fill=%22%23f0f0f0%22 width=%22150%22 height=%22150%22/%3E%3C/svg%3E';}} onLoad={(e) => {console.log(`Image loaded: ${attachment}`);}} />
                          ) : isVideo ? (
                            <div className="agm-video-placeholder">🎥 Video</div>
                          ) : isPdf ? (
                            <div className="agm-pdf-placeholder">📄 PDF</div>
                          ) : (
                            <div className="agm-file-placeholder">📎 File</div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              <div className="agm-detail-section">
                <h3>Personal Info</h3>
                <dl>
                  <div>
                    <dt>Gender</dt>
                    <dd>{selectedGig.gender || 'Not specified'}</dd>
                  </div>
                  <div>
                    <dt>Age Range</dt>
                    <dd>{selectedGig.ageRange || 'Not specified'}</dd>
                  </div>
                  <div>
                    <dt>City</dt>
                    <dd>{selectedGig.city || 'Not specified'}</dd>
                  </div>
                  <div>
                    <dt>Native Language</dt>
                    <dd>{selectedGig.nativeLanguage || 'Not specified'}</dd>
                  </div>
                </dl>
              </div>

              {selectedGig.videoStyles?.length > 0 && (
                <div className="agm-detail-section">
                  <h3>Video Styles</h3>
                  <div className="agm-tags">
                    {selectedGig.videoStyles.map(style => (
                      <span key={style} className="agm-tag">{style}</span>
                    ))}
                  </div>
                </div>
              )}

              {selectedGig.platforms?.length > 0 && (
                <div className="agm-detail-section">
                  <h3>Platforms</h3>
                  <div className="agm-tags">
                    {selectedGig.platforms.map(platform => (
                      <span key={platform} className="agm-tag">{platform}</span>
                    ))}
                  </div>
                </div>
              )}

              {selectedGig.status === 'pending_approval' && (
                <div className="agm-actions">
                  <button
                    className="agm-btn agm-btn-approve"
                    onClick={() => approveGig(selectedGig.id)}
                    disabled={processingId === selectedGig.id}
                  >
                    <Check size={18} />
                    {processingId === selectedGig.id ? 'Approving...' : 'Approve Gig'}
                  </button>

                  {!showRejectForm ? (
                    <button
                      className="agm-btn agm-btn-reject"
                      onClick={() => setShowRejectForm(selectedGig.id)}
                      disabled={processingId === selectedGig.id}
                    >
                      <X size={18} />
                      Reject Gig
                    </button>
                  ) : (
                    <div className="agm-reject-form">
                      <textarea
                        placeholder="Enter reason for rejection..."
                        value={rejectReason}
                        onChange={(e) => setRejectReason(e.target.value)}
                        rows="3"
                      />
                      <div className="agm-reject-actions">
                        <button
                          className="agm-btn agm-btn-cancel"
                          onClick={() => {
                            setShowRejectForm(null);
                            setRejectReason('');
                          }}
                          disabled={processingId === selectedGig.id}
                        >
                          Cancel
                        </button>
                        <button
                          className="agm-btn agm-btn-confirm-reject"
                          onClick={() => rejectGig(selectedGig.id)}
                          disabled={processingId === selectedGig.id}
                        >
                          {processingId === selectedGig.id ? 'Rejecting...' : 'Confirm Rejection'}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {selectedGig.status === 'rejected' && selectedGig.rejection_reason && (
                <div className="agm-rejection-reason">
                  <h3>Rejection Reason</h3>
                  <p>{selectedGig.rejection_reason}</p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </AdminLayout>
  );
}
