import { useState, useEffect } from 'react';
import { ChevronLeft, CheckCircle, XCircle } from 'lucide-react';
import axios from 'axios';
import { toast } from 'sonner';
import '../styles/ApplicationsPage.css';

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

function ApplicationsPage() {
  const [applications, setApplications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedApplication, setSelectedApplication] = useState(null);
  const [applicationType, setApplicationType] = useState('creators');
  const [filterState, setFilterState] = useState('all');
  const [filterCategory, setFilterCategory] = useState('all');
  const [showMoreInfoModal, setShowMoreInfoModal] = useState(false);
  const [rejectFormData, setRejectFormData] = useState({ reason_code: '', reason_details: '' });
  const [moreInfoFormData, setMoreInfoFormData] = useState({
    request_type: 'clarification',
    message: '',
    priority: 'medium',
    deadline_days: 7
  });

  useEffect(() => {
    fetchApplications();
  }, [applicationType]);

  const fetchApplications = async () => {
    try {
      setLoading(true);
      const endpoint = applicationType === 'creators'
        ? `${API}/admin/applications/creators`
        : `${API}/admin/applications/brands`;

      const response = await axios.get(endpoint);
      const data = Array.isArray(response.data) ? response.data : (response.data?.data || []);
      setApplications(data);
      setSelectedApplication(null);
    } catch (error) {
      console.error('Error fetching applications:', error);
      toast.error('Failed to fetch applications');
    } finally {
      setLoading(false);
    }
  };

  const handleApproveApplication = async (id, type) => {
    try {
      await axios.post(`${API}/admin/applications/${id}/approve`);
      toast.success('Application approved');
      setApplications(applications.filter(app => app.id !== id));
      setSelectedApplication(null);
    } catch (error) {
      console.error('Error approving application:', error);
      toast.error('Failed to approve application');
    }
  };

  const handleRejectApplication = async (id, type) => {
    if (!rejectFormData.reason_code) {
      toast.error('Please select a rejection reason');
      return;
    }

    try {
      await axios.post(`${API}/admin/applications/${id}/reject`, {
        reason_code: rejectFormData.reason_code,
        reason_details: rejectFormData.reason_details
      });
      toast.success('Application rejected');
      setApplications(applications.filter(app => app.id !== id));
      setSelectedApplication(null);
      setRejectFormData({ reason_code: '', reason_details: '' });
    } catch (error) {
      console.error('Error rejecting application:', error);
      toast.error('Failed to reject application');
    }
  };

  const handleRequestMoreInfo = async (id, type) => {
    if (!moreInfoFormData.message) {
      toast.error('Please enter a message');
      return;
    }

    try {
      await axios.post(`${API}/admin/applications/${id}/request-more-info`, moreInfoFormData);
      toast.success('More info request sent');
      setShowMoreInfoModal(false);
      setMoreInfoFormData({ request_type: 'clarification', message: '', priority: 'medium', deadline_days: 7 });
    } catch (error) {
      console.error('Error requesting more info:', error);
      toast.error('Failed to request more information');
    }
  };

  const filteredApplications = applications.filter(app => {
    if (filterState !== 'all' && app.status !== filterState) return false;
    const appCategory = app.category || app.business_profile?.industry;
    if (filterCategory !== 'all' && appCategory !== filterCategory) return false;
    return true;
  });

  const categories = [...new Set(applications.map(app => app.category || app.business_profile?.industry))].filter(Boolean);

  if (selectedApplication) {
    return (
      <>
        <div className="detail-view" style={{ padding: '40px', marginLeft: '-40px', marginRight: '-40px', marginTop: '-40px' }}>
          <button className="btn-back" onClick={() => setSelectedApplication(null)}>
            <ChevronLeft size={20} /> Back
          </button>

          {applicationType === 'creators' ? (
            <div className="detail-content">
              <div className="detail-header">
                <div className="detail-title">
                  <h2>{selectedApplication.nickname}</h2>
                  <p>{selectedApplication.email}</p>
                  <span className={`status-badge status-${selectedApplication.status}`}>
                    {selectedApplication.status?.replace(/_/g, ' ').toUpperCase()}
                  </span>
                  {selectedApplication.handle_flagged_as_real_name && (
                    <span className="flag-badge">⚠️ Handle flagged as real name</span>
                  )}
                </div>
                <div className="detail-meta">
                  <div className="meta-item">
                    <span className="label">Submitted</span>
                    <span className="value">{new Date(selectedApplication.submitted_date).toLocaleDateString()}</span>
                  </div>
                  <div className="meta-item">
                    <span className="label">SLA Remaining</span>
                    <span className="value">{selectedApplication.sla_remaining_days} days</span>
                  </div>
                  <div className="meta-item">
                    <span className="label">Category</span>
                    <span className="value">{selectedApplication.category}</span>
                  </div>
                </div>
              </div>

              <div className="detail-grid">
                <section className="detail-section">
                  <h3>Profile Information</h3>
                  <div className="info-grid">
                    <div className="info-item">
                      <label>Handle</label>
                      <p>{selectedApplication.nickname}</p>
                    </div>
                    <div className="info-item">
                      <label>Location</label>
                      <p>{selectedApplication.location}</p>
                    </div>
                    <div className="info-item">
                      <label>Languages</label>
                      <p>{selectedApplication.languages?.join(', ')}</p>
                    </div>
                    <div className="info-item">
                      <label>Category</label>
                      <p>{selectedApplication.category}</p>
                    </div>
                    <div className="info-item full-width">
                      <label>Bio</label>
                      <p>{selectedApplication.bio}</p>
                    </div>
                  </div>
                </section>

                <section className="detail-section">
                  <h3>Rate Card</h3>
                  <div className="rate-card-grid">
                    {Object.entries(selectedApplication.rate_card || {}).map(([key, value]) => (
                      <div key={key} className="rate-item">
                        <span className="rate-label">{key.replace(/_/g, ' ').toUpperCase()}</span>
                        <span className="rate-value">₹{Number(value).toLocaleString()}</span>
                      </div>
                    ))}
                  </div>
                </section>

                <section className="detail-section full-width">
                  <h3>Portfolio Videos</h3>
                  {selectedApplication.portfolio_videos?.length > 0 ? (
                    <div className="portfolio-grid">
                      {selectedApplication.portfolio_videos.map(video => (
                        <div key={video.id} className="video-card">
                          <div className="video-thumbnail">
                            <img src={video.thumbnail} alt={video.title} />
                            <a href={video.url} target="_blank" rel="noopener noreferrer" className="play-button">▶</a>
                          </div>
                          <p className="video-title">{video.title}</p>
                          {video.duration && <p className="video-duration">{Math.floor(video.duration / 60)}:{(video.duration % 60).toString().padStart(2, '0')}</p>}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="empty-message">No portfolio videos provided</p>
                  )}
                </section>

                <section className="detail-section full-width">
                  <h3>KYC Documents</h3>
                  <div className="kyc-grid">
                    {selectedApplication.kyc_documents ? Object.entries(selectedApplication.kyc_documents).map(([docType, doc]) => (
                      <div key={docType} className="kyc-card">
                        <div className="kyc-header">
                          <h4>{docType.replace(/_/g, ' ').toUpperCase()}</h4>
                          <span className={`verify-badge ${doc.verified ? 'verified' : 'pending'}`}>
                            {doc.verified ? '✓ Verified' : '⏳ Pending'}
                          </span>
                        </div>
                        {doc.url && (
                          <a href={doc.url} target="_blank" rel="noopener noreferrer" className="doc-link">
                            View Document
                          </a>
                        )}
                        {doc.number && <p className="doc-info"><strong>ID:</strong> {doc.number}</p>}
                        {doc.verified_at && <p className="doc-info"><strong>Verified:</strong> {new Date(doc.verified_at).toLocaleDateString()}</p>}
                      </div>
                    )) : null}
                  </div>
                </section>

                <section className="detail-section full-width">
                  <h3>Social Media Handles</h3>
                  {selectedApplication.social_handles ? (
                    <div className="social-grid">
                      {Object.entries(selectedApplication.social_handles).map(([platform, data]) => (
                        data.handle || data.profile_url ? (
                          <div key={platform} className="social-card">
                            <h4>{platform.toUpperCase()}</h4>
                            {data.profile_url ? (
                              <a href={data.profile_url} target="_blank" rel="noopener noreferrer">{data.handle || data.profile_url}</a>
                            ) : (
                              <p>{data.handle}</p>
                            )}
                            {data.followers && <p className="followers">{Number(data.followers).toLocaleString()} followers</p>}
                            {data.verified && <span className="verified-badge">✓ Verified</span>}
                          </div>
                        ) : null
                      ))}
                    </div>
                  ) : (
                    <p className="empty-message">No social handles provided</p>
                  )}
                </section>
              </div>

              <div className="decision-section">
                <h3>Application Decision</h3>
                <div className="decision-buttons">
                  <button
                    className="btn-decision btn-approve"
                    onClick={() => handleApproveApplication(selectedApplication.id, 'creator')}
                    disabled={selectedApplication.status === 'approved'}
                  >
                    ✓ Approve
                  </button>
                  <button
                    className="btn-decision btn-more-info"
                    onClick={() => setShowMoreInfoModal(true)}
                    disabled={selectedApplication.status === 'approved' || selectedApplication.status === 'rejected'}
                  >
                    ✎ Request More Info
                  </button>
                  <button
                    className="btn-decision btn-reject"
                    onClick={() => document.querySelector('.reject-form')?.classList.toggle('show')}
                    disabled={selectedApplication.status === 'approved' || selectedApplication.status === 'rejected'}
                  >
                    ✕ Reject
                  </button>
                </div>

                <div className="reject-form">
                  <div className="form-group">
                    <label>Rejection Reason</label>
                    <select
                      value={rejectFormData.reason_code}
                      onChange={(e) => setRejectFormData({...rejectFormData, reason_code: e.target.value})}
                    >
                      <option value="">Select a reason...</option>
                      <option value="invalid_documents">Invalid Documents</option>
                      <option value="incomplete_kyc">Incomplete KYC</option>
                      <option value="restricted_category">Restricted Category</option>
                      <option value="fraud_detected">Fraud Detected</option>
                      <option value="other">Other</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label>Details</label>
                    <textarea
                      value={rejectFormData.reason_details}
                      onChange={(e) => setRejectFormData({...rejectFormData, reason_details: e.target.value})}
                      placeholder="Provide details for rejection..."
                    />
                  </div>
                  <div className="form-actions">
                    <button
                      className="btn-confirm btn-reject"
                      onClick={() => handleRejectApplication(selectedApplication.id, 'creator')}
                    >
                      Confirm Rejection
                    </button>
                    <button
                      className="btn-cancel"
                      onClick={() => document.querySelector('.reject-form')?.classList.remove('show')}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="detail-content">
              <div className="detail-header">
                <div className="detail-title">
                  <h2>{selectedApplication.business_name}</h2>
                  <p>{selectedApplication.business_email}</p>
                  <span className={`status-badge status-${selectedApplication.status}`}>
                    {selectedApplication.status?.replace(/_/g, ' ').toUpperCase()}
                  </span>
                  {selectedApplication.flags?.free_email_domain && (
                    <span className="flag-badge">⚠️ Free email domain</span>
                  )}
                  {selectedApplication.flags?.restricted_category && (
                    <span className="flag-badge">⚠️ Restricted category</span>
                  )}
                </div>
                <div className="detail-meta">
                  <div className="meta-item">
                    <span className="label">Submitted</span>
                    <span className="value">{new Date(selectedApplication.submitted_date).toLocaleDateString()}</span>
                  </div>
                  <div className="meta-item">
                    <span className="label">SLA Remaining</span>
                    <span className="value">{selectedApplication.sla_remaining_days} days</span>
                  </div>
                  <div className="meta-item">
                    <span className="label">GST Status</span>
                    <span className={`gst-badge ${selectedApplication.gst_details?.verification_status}`}>
                      {selectedApplication.gst_details?.verification_status?.toUpperCase()}
                    </span>
                  </div>
                </div>
              </div>

              <div className="detail-grid">
                <section className="detail-section">
                  <h3>Business Information</h3>
                  <div className="info-grid">
                    <div className="info-item">
                      <label>Business Name</label>
                      <p>{selectedApplication.business_name}</p>
                    </div>
                    <div className="info-item">
                      <label>Business Email</label>
                      <p>{selectedApplication.business_email}</p>
                    </div>
                    <div className="info-item">
                      <label>Industry</label>
                      <p>{selectedApplication.business_profile?.industry}</p>
                    </div>
                    <div className="info-item">
                      <label>Product Type</label>
                      <p>{selectedApplication.business_profile?.product_type}</p>
                    </div>
                    <div className="info-item full-width">
                      <label>Description</label>
                      <p>{selectedApplication.business_profile?.description}</p>
                    </div>
                  </div>
                </section>

                <section className="detail-section">
                  <h3>GST Verification</h3>
                  <div className="gst-info">
                    <div className="gst-item">
                      <label>GST Number</label>
                      <p>{selectedApplication.gst_details?.gst_number}</p>
                    </div>
                    <div className="gst-item">
                      <label>Status</label>
                      <span className={`gst-badge ${selectedApplication.gst_details?.verification_status}`}>
                        {selectedApplication.gst_details?.verification_status?.toUpperCase()}
                      </span>
                    </div>
                    <div className="gst-item">
                      <label>Business Type</label>
                      <p>{selectedApplication.gst_details?.business_type}</p>
                    </div>
                    {selectedApplication.gst_details?.verified_at && (
                      <div className="gst-item">
                        <label>Verified Date</label>
                        <p>{new Date(selectedApplication.gst_details.verified_at).toLocaleDateString()}</p>
                      </div>
                    )}
                  </div>
                </section>

                {selectedApplication.business_profile?.website && (
                  <section className="detail-section full-width">
                    <h3>Website</h3>
                    <div className="website-preview">
                      <a href={selectedApplication.business_profile.website} target="_blank" rel="noopener noreferrer">
                        {selectedApplication.business_profile.website}
                      </a>
                    </div>
                  </section>
                )}

                <section className="detail-section full-width">
                  <h3>Social Media Links</h3>
                  {selectedApplication.social_media ? (
                    <div className="social-grid">
                      {Object.entries(selectedApplication.social_media).map(([platform, url]) => (
                        url ? (
                          <div key={platform} className="social-card">
                            <h4>{platform.toUpperCase()}</h4>
                            <a href={url} target="_blank" rel="noopener noreferrer">{url}</a>
                          </div>
                        ) : null
                      ))}
                    </div>
                  ) : (
                    <p className="empty-message">No social media links provided</p>
                  )}
                </section>
              </div>

              <div className="decision-section">
                <h3>Application Decision</h3>
                <div className="decision-buttons">
                  <button
                    className="btn-decision btn-approve"
                    onClick={() => handleApproveApplication(selectedApplication.id, 'brand')}
                    disabled={selectedApplication.status === 'approved'}
                  >
                    ✓ Approve
                  </button>
                  <button
                    className="btn-decision btn-more-info"
                    onClick={() => setShowMoreInfoModal(true)}
                    disabled={selectedApplication.status === 'approved' || selectedApplication.status === 'rejected'}
                  >
                    ✎ Request More Info
                  </button>
                  <button
                    className="btn-decision btn-reject"
                    onClick={() => document.querySelector('.reject-form')?.classList.toggle('show')}
                    disabled={selectedApplication.status === 'approved' || selectedApplication.status === 'rejected'}
                  >
                    ✕ Reject
                  </button>
                </div>

                <div className="reject-form">
                  <div className="form-group">
                    <label>Rejection Reason</label>
                    <select
                      value={rejectFormData.reason_code}
                      onChange={(e) => setRejectFormData({...rejectFormData, reason_code: e.target.value})}
                    >
                      <option value="">Select a reason...</option>
                      <option value="invalid_gst">Invalid GST</option>
                      <option value="restricted_category">Restricted Category</option>
                      <option value="fraud_detected">Fraud Detected</option>
                      <option value="low_trust">Low Trust Indicators</option>
                      <option value="other">Other</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label>Details</label>
                    <textarea
                      value={rejectFormData.reason_details}
                      onChange={(e) => setRejectFormData({...rejectFormData, reason_details: e.target.value})}
                      placeholder="Provide details for rejection..."
                    />
                  </div>
                  <div className="form-actions">
                    <button
                      className="btn-confirm btn-reject"
                      onClick={() => handleRejectApplication(selectedApplication.id, 'brand')}
                    >
                      Confirm Rejection
                    </button>
                    <button
                      className="btn-cancel"
                      onClick={() => document.querySelector('.reject-form')?.classList.remove('show')}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {showMoreInfoModal && (
            <div className="modal-overlay" onClick={() => setShowMoreInfoModal(false)}>
              <div className="modal-content more-info-modal" onClick={(e) => e.stopPropagation()}>
                <h3>Request More Information</h3>
                <div className="form-group">
                  <label>Request Type</label>
                  <select
                    value={moreInfoFormData.request_type}
                    onChange={(e) => setMoreInfoFormData({...moreInfoFormData, request_type: e.target.value})}
                  >
                    <option value="clarification">Clarification</option>
                    <option value="document">Document</option>
                    <option value="verification">Verification</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Message</label>
                  <textarea
                    value={moreInfoFormData.message}
                    onChange={(e) => setMoreInfoFormData({...moreInfoFormData, message: e.target.value})}
                    placeholder="Enter your request message..."
                    rows="4"
                  />
                </div>
                <div className="form-group">
                  <label>Priority</label>
                  <select
                    value={moreInfoFormData.priority}
                    onChange={(e) => setMoreInfoFormData({...moreInfoFormData, priority: e.target.value})}
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Response Deadline (Days)</label>
                  <input
                    type="number"
                    min="1"
                    max="30"
                    value={moreInfoFormData.deadline_days}
                    onChange={(e) => setMoreInfoFormData({...moreInfoFormData, deadline_days: parseInt(e.target.value)})}
                  />
                </div>
                <div className="modal-actions">
                  <button
                    className="btn-confirm"
                    onClick={() => handleRequestMoreInfo(selectedApplication.id, applicationType === 'creators' ? 'creator' : 'brand')}
                  >
                    Send Request
                  </button>
                  <button
                    className="btn-cancel"
                    onClick={() => setShowMoreInfoModal(false)}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </>
    );
  }

  return (
    <>
      <div style={{ padding: '0' }}>
        <div style={{ marginBottom: '40px', backgroundColor: 'white', padding: '30px', borderRadius: '12px' }}>
          <div style={{ marginBottom: '24px' }}>
            <h2 style={{ fontSize: '1.8rem', color: '#0f172a', margin: '0 0 12px 0', fontWeight: '700' }}>Applications List</h2>
          </div>
          <div style={{ display: 'flex', gap: '12px', borderBottom: '2px solid #e2e8f0', paddingBottom: '0' }}>
            <button
              onClick={() => setApplicationType('creators')}
              style={{
                padding: '14px 28px',
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                fontSize: '1rem',
                color: applicationType === 'creators' ? '#3b82f6' : '#64748b',
                borderBottom: applicationType === 'creators' ? '3px solid #3b82f6' : '3px solid transparent',
                fontWeight: 600,
                transition: 'all 0.3s ease'
              }}
            >
              Creator Applications
            </button>
            <button
              onClick={() => setApplicationType('brands')}
              style={{
                padding: '14px 28px',
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                fontSize: '1rem',
                color: applicationType === 'brands' ? '#3b82f6' : '#64748b',
                borderBottom: applicationType === 'brands' ? '3px solid #3b82f6' : '3px solid transparent',
                fontWeight: 600,
                transition: 'all 0.3s ease'
              }}
            >
              Brand Applications
            </button>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '20px', marginBottom: '40px', backgroundColor: 'white', padding: '25px 30px', borderRadius: '14px', boxShadow: '0 2px 16px rgba(0, 0, 0, 0.06)', flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', minWidth: '200px' }}>
            <label style={{ fontWeight: 700, color: '#0f172a', fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '0.5px', color: '#475569' }}>Status</label>
            <select value={filterState} onChange={(e) => setFilterState(e.target.value)} style={{ padding: '12px 14px', border: '2px solid #e2e8f0', borderRadius: '8px', fontSize: '0.95rem', backgroundColor: 'white', cursor: 'pointer', transition: 'all 0.3s ease', fontWeight: 500, color: '#0f172a' }}>
              <option value="all">All Statuses</option>
              <option value="pending">Pending</option>
              <option value="approved">Approved</option>
              <option value="rejected">Rejected</option>
            </select>
          </div>
          {categories.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', minWidth: '200px' }}>
              <label style={{ fontWeight: 700, color: '#0f172a', fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '0.5px', color: '#475569' }}>Category</label>
              <select value={filterCategory} onChange={(e) => setFilterCategory(e.target.value)} style={{ padding: '12px 14px', border: '2px solid #e2e8f0', borderRadius: '8px', fontSize: '0.95rem', backgroundColor: 'white', cursor: 'pointer', transition: 'all 0.3s ease', fontWeight: 500, color: '#0f172a' }}>
                <option value="all">All Categories</option>
                {categories.map(cat => (
                  <option key={cat} value={cat}>{cat}</option>
                ))}
              </select>
            </div>
          )}
        </div>

        <div style={{ padding: '0 20px' }}>

      {loading ? (
        <div className="loading">Loading applications...</div>
      ) : filteredApplications.length === 0 ? (
        <div className="empty-state">
          <CheckCircle size={64} />
          <p>No applications found</p>
        </div>
      ) : (
        <div className="applications-list">
          {filteredApplications.map(app => (
            <div key={app.id} className="application-card" onClick={() => setSelectedApplication(app)}>
              <div className="card-header">
                <h3>{applicationType === 'creators' ? app.nickname : app.business_name}</h3>
                <span className={`status-badge status-${app.status}`}>
                  {app.status?.replace(/_/g, ' ').toUpperCase()}
                </span>
              </div>
              <div className="card-body">
                <p><strong>Email:</strong> {applicationType === 'creators' ? app.email : app.business_email}</p>
                <p><strong>Category:</strong> {applicationType === 'creators' ? app.category : app.business_profile?.industry}</p>
                <p><strong>Submitted:</strong> {new Date(app.submitted_date).toLocaleDateString()}</p>
                {app.sla_remaining_days && (
                  <p><strong>SLA Remaining:</strong> {app.sla_remaining_days} days</p>
                )}
              </div>
              <div className="card-action">View Details →</div>
            </div>
          ))}
        </div>
      )}
        </div>
      </div>
    </>
  );
}

export default ApplicationsPage;
