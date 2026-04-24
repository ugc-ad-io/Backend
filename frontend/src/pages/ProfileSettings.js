import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import { ArrowLeft, User, Lock, Shield, Camera, Save } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export default function ProfileSettings() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('profile');
  const [loading, setLoading] = useState(false);
  
  // Profile states
  const [bio, setBio] = useState('');
  const [description, setDescription] = useState('');
  const [profilePhoto, setProfilePhoto] = useState(null);
  const [uploadingPhoto, setUploadingPhoto] = useState(false);
  
  // Password states
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  
  // 2FA states
  const [twoFAEnabled, setTwoFAEnabled] = useState(false);
  const [qrCode, setQrCode] = useState('');
  const [secret, setSecret] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [disablePassword, setDisablePassword] = useState('');
  const [showQR, setShowQR] = useState(false);

  useEffect(() => {
    fetchUserData();
    check2FAStatus();
  }, []);

  const fetchUserData = async () => {
    try {
      const response = await axios.get(`${API}/auth/me`);
      setBio(response.data.bio || '');
      setDescription(response.data.description || '');
      setProfilePhoto(response.data.profile_photo || null);
    } catch (error) {
      toast.error('Failed to load profile data');
    }
  };

  const check2FAStatus = async () => {
    try {
      const response = await axios.get(`${API}/profile/2fa/status`);
      setTwoFAEnabled(response.data.enabled);
    } catch (error) {
      console.error('Failed to check 2FA status');
    }
  };

  const handlePhotoUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Validate file size (max 2MB)
    if (file.size > 2 * 1024 * 1024) {
      toast.error('Image too large. Maximum 2MB allowed.');
      return;
    }

    setUploadingPhoto(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await axios.post(`${API}/profile/upload-photo`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setProfilePhoto(response.data.photo_url);
      toast.success('Profile photo updated!');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to upload photo');
    } finally {
      setUploadingPhoto(false);
    }
  };

  const handleUpdateProfile = async () => {
    setLoading(true);
    try {
      await axios.put(`${API}/profile/update-info?bio=${encodeURIComponent(bio)}&description=${encodeURIComponent(description)}`);
      toast.success('Profile updated successfully!');
    } catch (error) {
      toast.error('Failed to update profile');
    } finally {
      setLoading(false);
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    
    if (newPassword !== confirmPassword) {
      toast.error('New passwords do not match');
      return;
    }

    if (newPassword.length < 8) {
      toast.error('Password must be at least 8 characters');
      return;
    }

    setLoading(true);
    try {
      await axios.post(`${API}/profile/change-password?old_password=${encodeURIComponent(oldPassword)}&new_password=${encodeURIComponent(newPassword)}`);
      toast.success('Password changed successfully!');
      setOldPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to change password');
    } finally {
      setLoading(false);
    }
  };

  const handleSetup2FA = async () => {
    setLoading(true);
    try {
      const response = await axios.post(`${API}/profile/2fa/setup`);
      setQrCode(response.data.qr_code);
      setSecret(response.data.secret);
      setShowQR(true);
      toast.success('Scan the QR code with Google Authenticator');
    } catch (error) {
      toast.error('Failed to setup 2FA');
    } finally {
      setLoading(false);
    }
  };

  const handleVerify2FA = async () => {
    if (!verificationCode || verificationCode.length !== 6) {
      toast.error('Please enter a valid 6-digit code');
      return;
    }

    setLoading(true);
    try {
      await axios.post(`${API}/profile/2fa/verify?token=${verificationCode}`);
      toast.success('2FA enabled successfully!');
      setTwoFAEnabled(true);
      setShowQR(false);
      setVerificationCode('');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Invalid verification code');
    } finally {
      setLoading(false);
    }
  };

  const handleDisable2FA = async () => {
    if (!disablePassword) {
      toast.error('Please enter your password');
      return;
    }

    setLoading(true);
    try {
      await axios.post(`${API}/profile/2fa/disable?password=${encodeURIComponent(disablePassword)}`);
      toast.success('2FA disabled successfully');
      setTwoFAEnabled(false);
      setDisablePassword('');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to disable 2FA');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="profile-settings-page">
      <div className="page-header">
        <button className="back-btn" onClick={() => navigate(-1)}>
          <ArrowLeft size={20} /> Back
        </button>
        <h1>Profile Settings</h1>
      </div>

      <div className="settings-container">
        <div className="settings-sidebar">
          <button
            className={`tab-btn ${activeTab === 'profile' ? 'active' : ''}`}
            onClick={() => setActiveTab('profile')}
          >
            <User size={20} /> Profile
          </button>
          <button
            className={`tab-btn ${activeTab === 'password' ? 'active' : ''}`}
            onClick={() => setActiveTab('password')}
          >
            <Lock size={20} /> Password
          </button>
          <button
            className={`tab-btn ${activeTab === '2fa' ? 'active' : ''}`}
            onClick={() => setActiveTab('2fa')}
          >
            <Shield size={20} /> Two-Factor Auth
          </button>
        </div>

        <div className="settings-content">
          {activeTab === 'profile' && (
            <div className="settings-section">
              <h2>Profile Information</h2>
              
              {/* Profile Photo */}
              <div className="form-group">
                <label>Profile Photo</label>
                <div className="photo-upload-section">
                  <div className="photo-preview">
                    {profilePhoto ? (
                      <img src={`${BACKEND_URL}${profilePhoto}`} alt="Profile" />
                    ) : (
                      <div className="photo-placeholder">
                        <Camera size={48} />
                      </div>
                    )}
                  </div>
                  <div className="photo-actions">
                    <input
                      type="file"
                      accept="image/*"
                      onChange={handlePhotoUpload}
                      style={{ display: 'none' }}
                      id="photo-upload"
                    />
                    <label htmlFor="photo-upload" className="btn-upload">
                      {uploadingPhoto ? 'Uploading...' : 'Change Photo'}
                    </label>
                    <p className="hint">JPG, PNG or WebP. Max 2MB.</p>
                  </div>
                </div>
              </div>

              {/* Bio */}
              <div className="form-group">
                <label>Bio</label>
                <textarea
                  value={bio}
                  onChange={(e) => setBio(e.target.value)}
                  placeholder="Tell us about yourself..."
                  rows={4}
                  maxLength={500}
                />
                <span className="char-count">{bio.length}/500</span>
              </div>

              {/* Description */}
              <div className="form-group">
                <label>Description</label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Add a detailed description..."
                  rows={6}
                  maxLength={1000}
                />
                <span className="char-count">{description.length}/1000</span>
              </div>

              <button
                className="btn-primary"
                onClick={handleUpdateProfile}
                disabled={loading}
              >
                <Save size={20} /> {loading ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          )}

          {activeTab === 'password' && (
            <div className="settings-section">
              <h2>Change Password</h2>
              <form onSubmit={handleChangePassword}>
                <div className="form-group">
                  <label>Current Password</label>
                  <input
                    type="password"
                    value={oldPassword}
                    onChange={(e) => setOldPassword(e.target.value)}
                    placeholder="Enter current password"
                    required
                  />
                </div>

                <div className="form-group">
                  <label>New Password</label>
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="Enter new password (min 8 characters)"
                    required
                  />
                </div>

                <div className="form-group">
                  <label>Confirm New Password</label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Confirm new password"
                    required
                  />
                </div>

                <button type="submit" className="btn-primary" disabled={loading}>
                  <Lock size={20} /> {loading ? 'Changing...' : 'Change Password'}
                </button>
              </form>
            </div>
          )}

          {activeTab === '2fa' && (
            <div className="settings-section">
              <h2>Two-Factor Authentication</h2>
              <p className="section-description">
                Add an extra layer of security to your account with 2FA using Google Authenticator.
              </p>

              {!twoFAEnabled ? (
                <>
                  {!showQR ? (
                    <div className="2fa-setup">
                      <div className="info-box">
                        <Shield size={48} />
                        <h3>Enable Two-Factor Authentication</h3>
                        <p>Protect your account with an additional security layer</p>
                      </div>
                      <button
                        className="btn-primary"
                        onClick={handleSetup2FA}
                        disabled={loading}
                      >
                        <Shield size={20} /> {loading ? 'Setting up...' : 'Setup 2FA'}
                      </button>
                    </div>
                  ) : (
                    <div className="2fa-verification">
                      <h3>Scan QR Code</h3>
                      <p>Open Google Authenticator and scan this QR code:</p>
                      <div className="qr-code">
                        <img src={qrCode} alt="QR Code" />
                      </div>
                      <div className="secret-key">
                        <p><strong>Manual Entry Key:</strong></p>
                        <code>{secret}</code>
                      </div>
                      <div className="form-group">
                        <label>Enter 6-digit code from Google Authenticator</label>
                        <input
                          type="text"
                          value={verificationCode}
                          onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                          placeholder="000000"
                          maxLength={6}
                        />
                      </div>
                      <button
                        className="btn-primary"
                        onClick={handleVerify2FA}
                        disabled={loading}
                      >
                        {loading ? 'Verifying...' : 'Verify & Enable'}
                      </button>
                    </div>
                  )}
                </>
              ) : (
                <div className="2fa-enabled">
                  <div className="success-box">
                    <Shield size={48} />
                    <h3>2FA is Enabled</h3>
                    <p>Your account is protected with two-factor authentication</p>
                  </div>
                  <div className="form-group">
                    <label>Enter your password to disable 2FA</label>
                    <input
                      type="password"
                      value={disablePassword}
                      onChange={(e) => setDisablePassword(e.target.value)}
                      placeholder="Enter your password"
                    />
                  </div>
                  <button
                    className="btn-danger"
                    onClick={handleDisable2FA}
                    disabled={loading}
                  >
                    {loading ? 'Disabling...' : 'Disable 2FA'}
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      <style jsx>{`
        .profile-settings-page {
          min-height: 100vh;
          background: linear-gradient(135deg, #f8f9ff 0%, #e8ecff 100%);
          padding: 40px 8%;
        }

        .page-header {
          display: flex;
          align-items: center;
          gap: 20px;
          margin-bottom: 32px;
        }

        .page-header h1 {
          font-size: 2rem;
          font-weight: 700;
          color: #1a202c;
        }

        .back-btn {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 10px 20px;
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
        }

        .settings-container {
          display: grid;
          grid-template-columns: 250px 1fr;
          gap: 32px;
          max-width: 1200px;
        }

        .settings-sidebar {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .tab-btn {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 14px 20px;
          background: white;
          border: 2px solid transparent;
          border-radius: 12px;
          color: #4a5568;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
          text-align: left;
        }

        .tab-btn:hover {
          background: #f8f9ff;
          border-color: #e2e8f0;
        }

        .tab-btn.active {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
        }

        .settings-content {
          background: white;
          border-radius: 20px;
          padding: 32px;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
        }

        .settings-section h2 {
          font-size: 1.75rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 8px;
        }

        .section-description {
          color: #718096;
          margin-bottom: 32px;
        }

        .form-group {
          margin-bottom: 24px;
        }

        .form-group label {
          display: block;
          font-weight: 600;
          color: #2d3748;
          margin-bottom: 8px;
        }

        .form-group input[type="text"],
        .form-group input[type="password"],
        .form-group textarea {
          width: 100%;
          padding: 12px 16px;
          border: 2px solid #e2e8f0;
          border-radius: 12px;
          font-size: 1rem;
          transition: all 0.3s ease;
        }

        .form-group input:focus,
        .form-group textarea:focus {
          outline: none;
          border-color: #667eea;
          box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .char-count {
          display: block;
          text-align: right;
          font-size: 0.875rem;
          color: #718096;
          margin-top: 4px;
        }

        .photo-upload-section {
          display: flex;
          align-items: center;
          gap: 24px;
        }

        .photo-preview {
          width: 120px;
          height: 120px;
          border-radius: 50%;
          overflow: hidden;
          background: #f8f9ff;
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .photo-preview img {
          width: 100%;
          height: 100%;
          object-fit: cover;
        }

        .photo-placeholder {
          color: #cbd5e0;
        }

        .photo-actions {
          flex: 1;
        }

        .btn-upload {
          display: inline-block;
          padding: 10px 20px;
          background: #667eea;
          color: white;
          border-radius: 12px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
        }

        .btn-upload:hover {
          background: #5568d3;
          transform: translateY(-2px);
        }

        .hint {
          color: #718096;
          font-size: 0.875rem;
          margin-top: 8px;
        }

        .btn-primary {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 12px 32px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          border: none;
          border-radius: 12px;
          font-weight: 600;
          font-size: 1rem;
          cursor: pointer;
          transition: all 0.3s ease;
        }

        .btn-primary:hover:not(:disabled) {
          transform: translateY(-2px);
          box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4);
        }

        .btn-primary:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        .btn-danger {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 12px 32px;
          background: #e53e3e;
          color: white;
          border: none;
          border-radius: 12px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
        }

        .btn-danger:hover:not(:disabled) {
          background: #c53030;
        }

        .2fa-setup,
        .2fa-enabled {
          text-align: center;
        }

        .info-box,
        .success-box {
          background: #f8f9ff;
          padding: 48px 32px;
          border-radius: 16px;
          margin-bottom: 24px;
        }

        .info-box svg,
        .success-box svg {
          color: #667eea;
          margin-bottom: 16px;
        }

        .info-box h3,
        .success-box h3 {
          font-size: 1.5rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 8px;
        }

        .info-box p,
        .success-box p {
          color: #718096;
        }

        .2fa-verification {
          text-align: center;
        }

        .2fa-verification h3 {
          font-size: 1.5rem;
          font-weight: 700;
          margin-bottom: 8px;
        }

        .qr-code {
          display: flex;
          justify-content: center;
          margin: 24px 0;
        }

        .qr-code img {
          max-width: 300px;
          border: 4px solid #e2e8f0;
          border-radius: 16px;
          padding: 16px;
          background: white;
        }

        .secret-key {
          background: #f8f9ff;
          padding: 16px;
          border-radius: 12px;
          margin: 24px 0;
        }

        .secret-key code {
          font-family: 'Courier New', monospace;
          font-size: 1.1rem;
          color: #667eea;
          letter-spacing: 2px;
        }

        @media (max-width: 768px) {
          .settings-container {
            grid-template-columns: 1fr;
          }

          .settings-sidebar {
            flex-direction: row;
            overflow-x: auto;
          }

          .photo-upload-section {
            flex-direction: column;
            text-align: center;
          }
        }
      `}</style>
    </div>
  );
}
