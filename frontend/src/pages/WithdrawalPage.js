import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import { ArrowLeft, DollarSign, Calendar, AlertCircle } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export default function WithdrawalPage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [withdrawals, setWithdrawals] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showRequestModal, setShowRequestModal] = useState(false);
  const [amount, setAmount] = useState('');
  const [paymentMethod, setPaymentMethod] = useState('upi');
  const [accountDetails, setAccountDetails] = useState({ upi: '', account_number: '', ifsc: '' });

  useEffect(() => {
    fetchWithdrawals();
  }, []);

  const fetchWithdrawals = async () => {
    try {
      const response = await axios.get(`${API}/withdrawal/history`);
      setWithdrawals(response.data);
    } catch (error) {
      toast.error('Failed to load withdrawal history');
    } finally {
      setLoading(false);
    }
  };

  const handleRequestWithdrawal = async (e) => {
    e.preventDefault();

    if (parseFloat(amount) > (user?.balance || 0)) {
      toast.error('Insufficient balance');
      return;
    }

    if (parseFloat(amount) < 10) {
      toast.error('Minimum withdrawal amount is $10');
      return;
    }

    try {
      await axios.post(`${API}/withdrawal/request`, {
        amount: parseFloat(amount),
        payment_method: paymentMethod,
        account_details: accountDetails
      });
      toast.success('Withdrawal request submitted!');
      setShowRequestModal(false);
      setAmount('');
      fetchWithdrawals();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to request withdrawal');
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'pending': return 'badge-pending';
      case 'processing': return 'badge-active';
      case 'completed': return 'badge-approved';
      case 'rejected': return 'badge-rejected';
      default: return 'badge-pending';
    }
  };

  return (
    <div className="withdrawal-page">
      <div className="page-header">
        <button className="back-btn" onClick={() => navigate(-1)} data-testid="back-btn">
          <ArrowLeft size={20} /> Back to Dashboard
        </button>
      </div>

      <div className="withdrawal-container fade-in">
        <div className="balance-card">
          <div className="balance-header">
            <div>
              <h2>Available Balance</h2>
              <p className="balance-amount">${user?.balance?.toFixed(2) || '0.00'}</p>
            </div>
            <button
              className="btn-primary"
              onClick={() => setShowRequestModal(true)}
              disabled={!user?.balance || user.balance < 10}
              data-testid="request-withdrawal-btn"
            >
              <DollarSign size={20} /> Request Withdrawal
            </button>
          </div>
          {(!user?.balance || user.balance < 10) && (
            <div className="warning-message">
              <AlertCircle size={20} />
              <span>Minimum withdrawal amount is $10</span>
            </div>
          )}
        </div>

        <div className="withdrawals-section">
          <h2>Withdrawal History</h2>
          {loading ? (
            <div className="loading">Loading...</div>
          ) : withdrawals.length === 0 ? (
            <div className="empty-state">
              <DollarSign size={64} />
              <p>No withdrawal requests yet</p>
            </div>
          ) : (
            <div className="withdrawals-list">
              {withdrawals.map((withdrawal, idx) => (
                <div key={withdrawal.id} className="withdrawal-card" data-testid={`withdrawal-${idx}`}>
                  <div className="withdrawal-header">
                    <div>
                      <p className="withdrawal-amount">${withdrawal.amount.toFixed(2)}</p>
                      <p className="withdrawal-method">{withdrawal.payment_method.toUpperCase()}</p>
                    </div>
                    <span className={`badge ${getStatusColor(withdrawal.status)}`}>
                      {withdrawal.status}
                    </span>
                  </div>
                  <div className="withdrawal-details">
                    <div className="detail-item">
                      <Calendar size={16} />
                      <span>Requested: {new Date(withdrawal.requested_at).toLocaleDateString()}</span>
                    </div>
                    <div className="detail-item">
                      <AlertCircle size={16} />
                      <span>Processing time: {withdrawal.processing_days} business days</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Withdrawal Request Modal */}
      {showRequestModal && (
        <div className="modal-overlay" onClick={() => setShowRequestModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Request Withdrawal</h2>
            <form onSubmit={handleRequestWithdrawal} className="withdrawal-form">
              <div className="form-group">
                <label htmlFor="amount">Withdrawal Amount ($)</label>
                <input
                  id="amount"
                  type="number"
                  value={amount}
                  onChange={(e) => setAmount(e.target.value)}
                  className="input-field"
                  placeholder="Enter amount"
                  min="10"
                  max={user?.balance || 0}
                  step="0.01"
                  required
                  data-testid="amount-input"
                />
                <span className="hint">Available: ${user?.balance?.toFixed(2) || '0.00'}</span>
              </div>

              <div className="form-group">
                <label htmlFor="paymentMethod">Payment Method</label>
                <select
                  id="paymentMethod"
                  value={paymentMethod}
                  onChange={(e) => setPaymentMethod(e.target.value)}
                  className="input-field"
                  data-testid="payment-method-select"
                >
                  <option value="upi">UPI</option>
                  <option value="bank">Bank Transfer</option>
                  <option value="paypal">PayPal</option>
                </select>
              </div>

              {paymentMethod === 'upi' && (
                <div className="form-group">
                  <label htmlFor="upi">UPI ID</label>
                  <input
                    id="upi"
                    type="text"
                    value={accountDetails.upi}
                    onChange={(e) => setAccountDetails({ ...accountDetails, upi: e.target.value })}
                    className="input-field"
                    placeholder="yourname@upi"
                    required
                    data-testid="upi-input"
                  />
                </div>
              )}

              {paymentMethod === 'bank' && (
                <>
                  <div className="form-group">
                    <label htmlFor="account">Account Number</label>
                    <input
                      id="account"
                      type="text"
                      value={accountDetails.account_number}
                      onChange={(e) => setAccountDetails({ ...accountDetails, account_number: e.target.value })}
                      className="input-field"
                      placeholder="1234567890"
                      required
                      data-testid="account-input"
                    />
                  </div>
                  <div className="form-group">
                    <label htmlFor="ifsc">IFSC Code</label>
                    <input
                      id="ifsc"
                      type="text"
                      value={accountDetails.ifsc}
                      onChange={(e) => setAccountDetails({ ...accountDetails, ifsc: e.target.value })}
                      className="input-field"
                      placeholder="ABCD0123456"
                      required
                      data-testid="ifsc-input"
                    />
                  </div>
                </>
              )}

              <div className="info-box">
                <AlertCircle size={20} />
                <p>Withdrawals typically take 7 business days to process</p>
              </div>

              <div className="modal-actions">
                <button type="button" className="btn-secondary" onClick={() => setShowRequestModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-primary" data-testid="submit-withdrawal-btn">
                  Submit Request
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <style jsx>{`
        .withdrawal-page {
          min-height: 100vh;
          background: linear-gradient(135deg, #f8f9ff 0%, #e8ecff 100%);
          padding: 40px 8%;
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

        .withdrawal-container {
          max-width: 1000px;
          margin: 0 auto;
          display: flex;
          flex-direction: column;
          gap: 32px;
        }

        .balance-card {
          background: white;
          padding: 32px;
          border-radius: 24px;
          box-shadow: 0 10px 40px rgba(0, 0, 0, 0.08);
        }

        .balance-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 16px;
        }

        .balance-header h2 {
          font-size: 1.25rem;
          font-weight: 600;
          color: #4a5568;
          margin-bottom: 8px;
        }

        .balance-amount {
          font-size: 3rem;
          font-weight: 700;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
        }

        .balance-header button {
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .warning-message {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 16px;
          background: #fff3cd;
          border-radius: 12px;
          color: #856404;
          font-weight: 500;
        }

        .withdrawals-section {
          background: white;
          padding: 32px;
          border-radius: 24px;
          box-shadow: 0 10px 40px rgba(0, 0, 0, 0.08);
        }

        .withdrawals-section h2 {
          font-size: 1.75rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 24px;
        }

        .loading,
        .empty-state {
          text-align: center;
          padding: 60px 20px;
          color: #718096;
        }

        .empty-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 16px;
        }

        .withdrawals-list {
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .withdrawal-card {
          padding: 24px;
          background: #f8f9ff;
          border-radius: 16px;
          border: 2px solid #e2e8f0;
        }

        .withdrawal-header {
          display: flex;
          justify-content: space-between;
          align-items: start;
          margin-bottom: 16px;
        }

        .withdrawal-amount {
          font-size: 1.75rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 4px;
        }

        .withdrawal-method {
          color: #718096;
          font-weight: 600;
        }

        .withdrawal-details {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .detail-item {
          display: flex;
          align-items: center;
          gap: 8px;
          color: #4a5568;
          font-size: 0.95rem;
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

        .withdrawal-form {
          display: flex;
          flex-direction: column;
          gap: 20px;
        }

        .hint {
          font-size: 0.875rem;
          color: #a0aec0;
          font-style: italic;
        }

        .info-box {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 16px;
          background: #e0e7ff;
          border-radius: 12px;
          color: #3730a3;
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
          .balance-header {
            flex-direction: column;
            align-items: flex-start;
            gap: 20px;
          }

          .balance-header button {
            width: 100%;
            justify-content: center;
          }
        }
      `}</style>
    </div>
  );
}