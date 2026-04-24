import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import { User, Building2, Lock, Mail } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export default function Auth() {
  const [isLogin, setIsLogin] = useState(true);
  const [role, setRole] = useState('creator');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { login, setUser } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const endpoint = isLogin ? '/auth/login' : '/auth/signup';
      const payload = isLogin ? { email, password } : { email, password, role };
      
      const response = await axios.post(`${API}${endpoint}`, payload);
      const { token, ...userData } = response.data;
      
      login(token, userData);
      toast.success(isLogin ? 'Welcome back!' : 'Account created successfully!');
      
      // Navigate based on profile completion and role
      if (!isLogin) {
        if (role === 'creator') {
          navigate('/profile-setup/creator');
        } else if (role === 'business') {
          navigate('/profile-setup/business');
        }
      } else {
        if (!userData.profile_completed) {
          if (userData.role === 'creator') {
            navigate('/profile-setup/creator');
          } else if (userData.role === 'business') {
            navigate('/profile-setup/business');
          }
        } else {
          if (userData.role === 'creator') {
            navigate('/dashboard/creator');
          } else if (userData.role === 'business') {
            navigate('/dashboard/business');
          } else if (userData.role === 'admin') {
            navigate('/dashboard/admin');
          }
        }
      }
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-container fade-in">
        <div className="auth-card">
          <div className="auth-header">
            <img src="/ugcad-logo.png" alt="UGCad.io" className="auth-logo" />
            <h1>{isLogin ? 'Welcome Back to UGCad.io' : 'Join UGCad.io'}</h1>
            <p>{isLogin ? 'Sign in to continue your journey' : 'Connect with brands and creators worldwide'}</p>
          </div>

          <form onSubmit={handleSubmit} className="auth-form">
            {!isLogin && (
              <div className="role-selector" data-testid="role-selector">
                <label>I am a:</label>
                <div className="role-options">
                  <button
                    type="button"
                    className={`role-btn ${role === 'creator' ? 'active' : ''}`}
                    onClick={() => setRole('creator')}
                    data-testid="role-creator-btn"
                  >
                    <User size={24} />
                    <span>Creator</span>
                  </button>
                  <button
                    type="button"
                    className={`role-btn ${role === 'business' ? 'active' : ''}`}
                    onClick={() => setRole('business')}
                    data-testid="role-business-btn"
                  >
                    <Building2 size={24} />
                    <span>Business</span>
                  </button>
                </div>
              </div>
            )}

            <div className="form-group">
              <label htmlFor="email">
                <Mail size={18} /> Email
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="input-field"
                placeholder="your@email.com"
                required
                data-testid="email-input"
              />
            </div>

            <div className="form-group">
              <label htmlFor="password">
                <Lock size={18} /> Password
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="input-field"
                placeholder="••••••••"
                required
                data-testid="password-input"
              />
            </div>

            <button
              type="submit"
              className="btn-primary"
              disabled={loading}
              data-testid="submit-btn"
            >
              {loading ? 'Processing...' : isLogin ? 'Sign In' : 'Create Account'}
            </button>
          </form>

          <div className="auth-footer">
            <p>
              {isLogin ? "Don't have an account?" : 'Already have an account?'}
              <button
                type="button"
                onClick={() => setIsLogin(!isLogin)}
                className="toggle-btn"
                data-testid="toggle-auth-btn"
              >
                {isLogin ? 'Sign Up' : 'Sign In'}
              </button>
            </p>
          </div>
        </div>
      </div>

      <style jsx>{`
        .auth-page {
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 40px 20px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }

        .auth-container {
          width: 100%;
          max-width: 480px;
        }

        .auth-card {
          background: white;
          border-radius: 24px;
          padding: 48px 40px;
          box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }

        .auth-header {
          text-align: center;
          margin-bottom: 40px;
        }

        .auth-logo {
          width: 180px;
          height: auto;
          margin: 0 auto 20px;
          display: block;
        }

        .auth-header h1 {
          font-size: 2rem;
          font-weight: 700;
          color: #1a202c;
          margin-bottom: 8px;
        }

        .auth-header p {
          color: #718096;
          font-size: 0.95rem;
        }

        .auth-form {
          display: flex;
          flex-direction: column;
          gap: 24px;
        }

        .role-selector {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }

        .role-selector label {
          font-weight: 600;
          color: #2d3748;
          font-size: 0.95rem;
        }

        .role-options {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 12px;
        }

        .role-btn {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 8px;
          padding: 20px;
          border: 2px solid #e2e8f0;
          border-radius: 12px;
          background: white;
          cursor: pointer;
          transition: all 0.3s ease;
          font-weight: 600;
          color: #4a5568;
        }

        .role-btn:hover {
          border-color: #667eea;
          background: #f7fafc;
        }

        .role-btn.active {
          border-color: #667eea;
          background: #667eea;
          color: white;
        }

        .form-group {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .form-group label {
          display: flex;
          align-items: center;
          gap: 8px;
          font-weight: 600;
          color: #2d3748;
          font-size: 0.95rem;
        }

        .auth-form .btn-primary {
          margin-top: 8px;
          width: 100%;
        }

        .auth-footer {
          margin-top: 24px;
          text-align: center;
          color: #718096;
          font-size: 0.95rem;
        }

        .toggle-btn {
          background: none;
          border: none;
          color: #667eea;
          font-weight: 600;
          cursor: pointer;
          margin-left: 6px;
          transition: color 0.3s ease;
        }

        .toggle-btn:hover {
          color: #764ba2;
          text-decoration: underline;
        }

        @media (max-width: 640px) {
          .auth-card {
            padding: 32px 24px;
          }

          .auth-header h1 {
            font-size: 1.75rem;
          }
        }
      `}</style>
    </div>
  );
}