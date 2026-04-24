import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import { ArrowLeft, Package, Truck, Upload, AlertTriangle } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export default function ShipmentTracking() {
  const [searchParams] = useSearchParams();
  const campaignId = searchParams.get('campaign');
  const navigate = useNavigate();
  const { user } = useAuth();
  const [campaign, setCampaign] = useState(null);
  const [shipment, setShipment] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showUpdateModal, setShowUpdateModal] = useState(false);
  const [showReceiveModal, setShowReceiveModal] = useState(false);
  const [shipmentData, setShipmentData] = useState({
    tracking_number: '',
    expected_delivery: '',
    shipment_checklist: {
      sealed: false,
      correct_item: false,
      working: false
    }
  });
  const [receiveData, setReceiveData] = useState({
    unboxing_video: '',
    items_damaged: false,
    dispute_reason: ''
  });

  useEffect(() => {
    if (campaignId) {
      fetchCampaign();
      fetchShipment();
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

  const fetchShipment = async () => {
    try {
      const response = await axios.get(`${API}/shipment/${campaignId}`);
      setShipment(response.data);
    } catch (error) {
      // Shipment might not exist yet
      console.log('No shipment found yet');
    }
  };

  const handleUpdateShipment = async (e) => {
    e.preventDefault();
    try {
      const courierSlip = `https://storage.example.com/courier/${Date.now()}.pdf`;
      await axios.post(`${API}/shipment/update`, {
        campaign_id: campaignId,
        tracking_number: shipmentData.tracking_number,
        courier_slip: courierSlip,
        expected_delivery: shipmentData.expected_delivery,
        shipment_checklist: shipmentData.shipment_checklist
      });
      toast.success('Shipment details updated!');
      setShowUpdateModal(false);
      fetchShipment();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to update shipment');
    }
  };

  const handleReceiveShipment = async (e) => {
    e.preventDefault();
    try {
      const unboxingVideo = `https://storage.example.com/unboxing/${Date.now()}.mp4`;
      await axios.post(`${API}/shipment/receive`, {
        campaign_id: campaignId,
        unboxing_video: unboxingVideo,
        items_damaged: receiveData.items_damaged,
        dispute_reason: receiveData.items_damaged ? receiveData.dispute_reason : undefined
      });
      toast.success('Shipment marked as received!');
      setShowReceiveModal(false);
      fetchShipment();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to mark as received');
    }
  };

  const handleChecklistChange = (field) => {
    setShipmentData({
      ...shipmentData,
      shipment_checklist: {
        ...shipmentData.shipment_checklist,
        [field]: !shipmentData.shipment_checklist[field]
      }
    });
  };

  if (loading) return <div className="loading-page">Loading...</div>;
  if (!campaign) return <div className="error-page">Campaign not found</div>;

  const isBusiness = user?.role === 'business' && campaign.business_id === user.id;
  const isCreator = user?.role === 'creator' && campaign.selected_creator === user.id;

  return (
    <div className="shipment-page">
      <div className="page-header">
        <button className="back-btn" onClick={() => navigate(-1)} data-testid="back-btn">
          <ArrowLeft size={20} /> Back
        </button>
      </div>

      <div className="shipment-container fade-in">
        <div className="shipment-header">
          <Package size={48} className="header-icon" />
          <h1>Shipment Tracking</h1>
          <p>Campaign: {campaign.title}</p>
        </div>

        {!shipment ? (
          <div className="no-shipment">
            <Package size={64} />
            <p>No shipment details available yet</p>
            {isBusiness && (
              <button
                className="btn-primary"
                onClick={() => setShowUpdateModal(true)}
                data-testid="add-shipment-btn"
              >
                Add Shipment Details
              </button>
            )}
          </div>
        ) : (
          <div className="shipment-details">
            <div className="status-card">
              <div className="status-icon">
                <Truck size={32} />
              </div>
              <div>
                <p className="status-label">Status</p>
                <p className="status-value">{shipment.status.toUpperCase()}</p>
              </div>
            </div>

            <div className="details-grid">
              <div className="detail-card">
                <h3>Tracking Information</h3>
                <div className="detail-item">
                  <span className="label">Tracking Number:</span>
                  <span className="value">{shipment.tracking_number}</span>
                </div>
                <div className="detail-item">
                  <span className="label">Expected Delivery:</span>
                  <span className="value">{new Date(shipment.expected_delivery).toLocaleDateString()}</span>
                </div>
                {shipment.courier_slip && (
                  <div className="detail-item">
                    <span className="label">Courier Slip:</span>
                    <a href={shipment.courier_slip} target="_blank" rel="noopener noreferrer" className="link">
                      View Document
                    </a>
                  </div>
                )}
              </div>

              <div className="detail-card">
                <h3>Shipment Checklist</h3>
                <div className="checklist">
                  <div className="checklist-item">
                    <input
                      type="checkbox"
                      checked={shipment.shipment_checklist?.sealed}
                      disabled
                      readOnly
                    />
                    <span>Package Sealed</span>
                  </div>
                  <div className="checklist-item">
                    <input
                      type="checkbox"
                      checked={shipment.shipment_checklist?.correct_item}
                      disabled
                      readOnly
                    />
                    <span>Correct Item</span>
                  </div>
                  <div className="checklist-item">
                    <input
                      type="checkbox"
                      checked={shipment.shipment_checklist?.working}
                      disabled
                      readOnly
                    />
                    <span>Working Condition</span>
                  </div>
                </div>
              </div>
            </div>

            {shipment.unboxing_video && (
              <div className="detail-card">
                <h3>Unboxing Video</h3>
                <a href={shipment.unboxing_video} target="_blank" rel="noopener noreferrer" className="video-link">
                  View Unboxing Video
                </a>
              </div>
            )}

            {shipment.dispute && (
              <div className="dispute-alert">
                <AlertTriangle size={24} />
                <div>
                  <strong>Dispute Reported</strong>
                  <p>{shipment.dispute.reason}</p>
                </div>
              </div>
            )}

            <div className="action-buttons">
              {isBusiness && shipment.status !== 'received' && (
                <button
                  className="btn-secondary"
                  onClick={() => setShowUpdateModal(true)}
                  data-testid="update-shipment-btn"
                >
                  Update Shipment Details
                </button>
              )}
              {isCreator && shipment.status === 'shipped' && (
                <button
                  className="btn-primary"
                  onClick={() => setShowReceiveModal(true)}
                  data-testid="mark-received-btn"
                >
                  Mark as Received
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Update Shipment Modal */}
      {showUpdateModal && (
        <div className="modal-overlay" onClick={() => setShowUpdateModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Update Shipment Details</h2>
            <form onSubmit={handleUpdateShipment} className="shipment-form">
              <div className="form-group">
                <label htmlFor="tracking">Tracking Number</label>
                <input
                  id="tracking"
                  type="text"
                  value={shipmentData.tracking_number}
                  onChange={(e) => setShipmentData({ ...shipmentData, tracking_number: e.target.value })}
                  className="input-field"
                  placeholder="ABC123456789"
                  required
                  data-testid="tracking-input"
                />
              </div>

              <div className="form-group">
                <label htmlFor="delivery">Expected Delivery Date</label>
                <input
                  id="delivery"
                  type="date"
                  value={shipmentData.expected_delivery}
                  onChange={(e) => setShipmentData({ ...shipmentData, expected_delivery: e.target.value })}
                  className="input-field"
                  required
                  data-testid="delivery-input"
                />
              </div>

              <div className="form-group">
                <label>Shipment Checklist</label>
                <div className="checklist">
                  <label className="checklist-item">
                    <input
                      type="checkbox"
                      checked={shipmentData.shipment_checklist.sealed}
                      onChange={() => handleChecklistChange('sealed')}
                      data-testid="sealed-checkbox"
                    />
                    <span>Package is sealed properly</span>
                  </label>
                  <label className="checklist-item">
                    <input
                      type="checkbox"
                      checked={shipmentData.shipment_checklist.correct_item}
                      onChange={() => handleChecklistChange('correct_item')}
                      data-testid="correct-item-checkbox"
                    />
                    <span>Correct item included</span>
                  </label>
                  <label className="checklist-item">
                    <input
                      type="checkbox"
                      checked={shipmentData.shipment_checklist.working}
                      onChange={() => handleChecklistChange('working')}
                      data-testid="working-checkbox"
                    />
                    <span>Item is in working condition</span>
                  </label>
                </div>
              </div>

              <div className="info-note">
                <Upload size={20} />
                <span>Courier slip will be automatically uploaded (mocked)</span>
              </div>

              <div className="modal-actions">
                <button type="button" className="btn-secondary" onClick={() => setShowUpdateModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-primary" data-testid="submit-shipment-btn">
                  Update Shipment
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Receive Shipment Modal */}
      {showReceiveModal && (
        <div className="modal-overlay" onClick={() => setShowReceiveModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Mark Shipment as Received</h2>
            <form onSubmit={handleReceiveShipment} className="receive-form">
              <div className="info-note">
                <Upload size={20} />
                <span>Unboxing video will be automatically uploaded (mocked)</span>
              </div>

              <div className="form-group">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={receiveData.items_damaged}
                    onChange={(e) => setReceiveData({ ...receiveData, items_damaged: e.target.checked })}
                    data-testid="damaged-checkbox"
                  />
                  Report damaged or wrong items
                </label>
              </div>

              {receiveData.items_damaged && (
                <div className="form-group">
                  <label htmlFor="dispute">Describe the issue</label>
                  <textarea
                    id="dispute"
                    value={receiveData.dispute_reason}
                    onChange={(e) => setReceiveData({ ...receiveData, dispute_reason: e.target.value })}
                    className="textarea-field"
                    placeholder="Describe what's wrong with the shipment..."
                    required
                    data-testid="dispute-input"
                  />
                </div>
              )}

              <div className="modal-actions">
                <button type="button" className="btn-secondary" onClick={() => setShowReceiveModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-primary" data-testid="submit-receive-btn">
                  Confirm Receipt
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <style jsx>{`
        .shipment-page {
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

        .shipment-container {
          max-width: 1000px;
          margin: 0 auto;
          background: white;
          padding: 48px;
          border-radius: 24px;
          box-shadow: 0 10px 40px rgba(0, 0, 0, 0.08);
        }

        .shipment-header {
          text-align: center;
          margin-bottom: 48px;
        }

        .header-icon {
          color: #667eea;
          margin: 0 auto 16px;
        }

        .shipment-header h1 {
          font-size: 2rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 8px;
        }

        .shipment-header p {
          color: #718096;
          font-size: 1.05rem;
        }

        .no-shipment {
          text-align: center;
          padding: 80px 20px;
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 20px;
          color: #718096;
        }

        .shipment-details {
          display: flex;
          flex-direction: column;
          gap: 32px;
        }

        .status-card {
          display: flex;
          align-items: center;
          gap: 20px;
          padding: 24px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          border-radius: 16px;
          color: white;
        }

        .status-icon {
          width: 64px;
          height: 64px;
          background: rgba(255, 255, 255, 0.2);
          border-radius: 16px;
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .status-label {
          font-size: 0.875rem;
          opacity: 0.9;
          margin-bottom: 4px;
        }

        .status-value {
          font-size: 1.75rem;
          font-weight: 700;
        }

        .details-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
          gap: 24px;
        }

        .detail-card {
          padding: 24px;
          background: #f8f9ff;
          border-radius: 16px;
          border: 2px solid #e2e8f0;
        }

        .detail-card h3 {
          font-size: 1.25rem;
          font-weight: 600;
          color: #2d3748;
          margin-bottom: 20px;
        }

        .detail-item {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 12px;
          padding-bottom: 12px;
          border-bottom: 1px solid #e2e8f0;
        }

        .detail-item:last-child {
          margin-bottom: 0;
          padding-bottom: 0;
          border-bottom: none;
        }

        .detail-item .label {
          color: #718096;
          font-weight: 500;
        }

        .detail-item .value {
          color: #1a202c;
          font-weight: 600;
        }

        .link {
          color: #667eea;
          font-weight: 600;
          text-decoration: none;
        }

        .link:hover {
          text-decoration: underline;
        }

        .checklist {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }

        .checklist-item {
          display: flex;
          align-items: center;
          gap: 12px;
          color: #4a5568;
          cursor: pointer;
        }

        .checklist-item input[type="checkbox"] {
          width: 20px;
          height: 20px;
          cursor: pointer;
        }

        .video-link {
          display: inline-block;
          padding: 12px 24px;
          background: #667eea;
          color: white;
          border-radius: 12px;
          text-decoration: none;
          font-weight: 600;
          transition: all 0.3s ease;
        }

        .video-link:hover {
          background: #5568d3;
        }

        .dispute-alert {
          display: flex;
          align-items: start;
          gap: 16px;
          padding: 24px;
          background: #fef2f2;
          border-radius: 16px;
          border: 2px solid #ef4444;
          color: #991b1b;
        }

        .dispute-alert strong {
          display: block;
          margin-bottom: 8px;
          font-size: 1.1rem;
        }

        .action-buttons {
          display: flex;
          gap: 16px;
          padding-top: 24px;
          border-top: 2px solid #e2e8f0;
        }

        .action-buttons button {
          flex: 1;
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
          max-height: 90vh;
          overflow-y: auto;
        }

        .modal-content h2 {
          font-size: 1.75rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 32px;
        }

        .shipment-form,
        .receive-form {
          display: flex;
          flex-direction: column;
          gap: 20px;
        }

        .info-note {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 16px;
          background: #e0e7ff;
          border-radius: 12px;
          color: #3730a3;
          font-size: 0.95rem;
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

        .modal-actions {
          display: flex;
          gap: 12px;
          margin-top: 8px;
        }

        .modal-actions button {
          flex: 1;
        }

        @media (max-width: 768px) {
          .shipment-container {
            padding: 32px 24px;
          }

          .details-grid {
            grid-template-columns: 1fr;
          }

          .action-buttons {
            flex-direction: column;
          }
        }
      `}</style>
    </div>
  );
}