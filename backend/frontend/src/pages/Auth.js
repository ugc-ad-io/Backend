import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import { User, Building2, Lock, Mail, ArrowLeft } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

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
            navigate('/brand-home');
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
    <div className="ap-root">
      {/* Background orbs */}
      <div className="ap-orb ap-orb--1" aria-hidden="true" />
      <div className="ap-orb ap-orb--2" aria-hidden="true" />
      <div className="ap-orb ap-orb--3" aria-hidden="true" />
      <div className="ap-grid" aria-hidden="true" />

      {/* Back button */}
      <button className="ap-back" onClick={() => navigate('/')}>
        <ArrowLeft size={16} />
        Back to home
      </button>

      <motion.div
        className="ap-card"
        initial={{ opacity: 0, y: 32, scale: 0.97 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.5, ease: [0.25, 0.46, 0.45, 0.94] }}
      >
        {/* Logo */}
        <motion.div
          className="ap-logo-wrap"
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15, duration: 0.4 }}
        >
          <img src="/ugcad-logo.png" alt="UGCad.io" className="ap-logo" />
        </motion.div>

        {/* Header */}
        <AnimatePresence mode="wait">
          <motion.div
            key={isLogin ? 'login-header' : 'signup-header'}
            className="ap-header"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.3 }}
          >
            <h1 className="ap-title">
              {isLogin ? 'Welcome back' : 'Create account'}
            </h1>
            <p className="ap-subtitle">
              {isLogin
                ? 'Sign in to continue your journey on UGCad.io'
                : 'Join thousands of creators and brands on UGCad.io'}
            </p>
          </motion.div>
        </AnimatePresence>

        <form onSubmit={handleSubmit} className="ap-form">
          {/* Role selector — only on signup */}
          <AnimatePresence>
            {!isLogin && (
              <motion.div
                className="ap-role-wrap"
                data-testid="role-selector"
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.3 }}
              >
                <label className="ap-label">I am a:</label>
                <div className="ap-role-options">
                  <button
                    type="button"
                    className={`ap-role-btn${role === 'creator' ? ' active' : ''}`}
                    onClick={() => setRole('creator')}
                    data-testid="role-creator-btn"
                  >
                    <div className="ap-role-icon">
                      <User size={20} />
                    </div>
                    <span>Creator</span>
                  </button>
                  <button
                    type="button"
                    className={`ap-role-btn${role === 'business' ? ' active' : ''}`}
                    onClick={() => setRole('business')}
                    data-testid="role-business-btn"
                  >
                    <div className="ap-role-icon">
                      <Building2 size={20} />
                    </div>
                    <span>Business</span>
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Email */}
          <motion.div
            className="ap-field"
            initial={{ opacity: 0, x: -16 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.25, duration: 0.4 }}
          >
            <label className="ap-label" htmlFor="email">
              <Mail size={15} /> Email
            </label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="ap-input input-field"
              placeholder="your@email.com"
              required
              data-testid="email-input"
            />
          </motion.div>

          {/* Password */}
          <motion.div
            className="ap-field"
            initial={{ opacity: 0, x: -16 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.35, duration: 0.4 }}
          >
            <label className="ap-label" htmlFor="password">
              <Lock size={15} /> Password
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="ap-input input-field"
              placeholder="••••••••"
              required
              data-testid="password-input"
            />
          </motion.div>

          {/* Submit */}
          <motion.button
            type="submit"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.42, duration: 0.4 }}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            className="ap-submit btn-primary"
            disabled={loading}
            data-testid="submit-btn"
          >
            {loading ? (
              <span className="ap-spinner" />
            ) : (
              isLogin ? 'Sign In' : 'Create Account'
            )}
          </motion.button>
        </form>

        {/* Footer toggle */}
        <motion.div
          className="ap-footer"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.52, duration: 0.4 }}
        >
          {isLogin ? "Don't have an account?" : 'Already have an account?'}{' '}
          <button
            type="button"
            className="ap-toggle"
            onClick={() => setIsLogin(!isLogin)}
            data-testid="toggle-auth-btn"
          >
            {isLogin ? 'Sign Up' : 'Sign In'}
          </button>
        </motion.div>
      </motion.div>

      <style>{`
        /* ── Root ────────────────────────────────────────────────── */
        .ap-root {
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 40px 20px;
          background: linear-gradient(160deg, #050510 0%, #0D0B26 100%);
          position: relative;
          overflow: hidden;
          font-family: 'Inter', sans-serif;
        }

        /* ── Orbs ────────────────────────────────────────────────── */
        .ap-orb {
          position: absolute;
          border-radius: 50%;
          animation: orbDrift 8s ease-in-out infinite;
          pointer-events: none;
        }
        .ap-orb--1 {
          width: 500px; height: 500px;
          background: rgba(99, 102, 241, 0.18);
          filter: blur(90px);
          top: -150px; left: -100px;
        }
        .ap-orb--2 {
          width: 400px; height: 400px;
          background: rgba(139, 92, 246, 0.14);
          filter: blur(80px);
          bottom: -100px; right: -80px;
          animation-delay: -4s;
        }
        .ap-orb--3 {
          width: 280px; height: 280px;
          background: rgba(34, 211, 238, 0.08);
          filter: blur(70px);
          top: 50%; left: 50%;
          transform: translate(-50%, -50%);
          animation-delay: -2s;
        }

        /* Dot-grid */
        .ap-grid {
          position: absolute;
          inset: 0;
          pointer-events: none;
          background-image:
            linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px);
          background-size: 60px 60px;
        }

        /* ── Back button ─────────────────────────────────────────── */
        .ap-back {
          position: fixed;
          top: 24px;
          left: 28px;
          display: flex;
          align-items: center;
          gap: 7px;
          background: rgba(255,255,255,0.06);
          border: 1px solid rgba(255,255,255,0.1);
          color: #94A3B8;
          font-size: 0.85rem;
          font-weight: 500;
          padding: 8px 16px;
          border-radius: 100px;
          cursor: pointer;
          transition: all 0.25s ease;
          z-index: 10;
          font-family: 'Inter', sans-serif;
          backdrop-filter: blur(8px);
        }
        .ap-back:hover {
          background: rgba(255,255,255,0.1);
          color: #F1F5F9;
          border-color: rgba(255,255,255,0.2);
        }

        /* ── Card ────────────────────────────────────────────────── */
        .ap-card {
          position: relative;
          z-index: 2;
          width: 100%;
          max-width: 440px;
          background: #ffffff;
          border-radius: 24px;
          padding: 44px 40px;
          box-shadow: 0 32px 80px rgba(0, 0, 0, 0.4);
        }


        /* ── Logo ────────────────────────────────────────────────── */
        .ap-logo-wrap {
          display: flex;
          justify-content: center;
          margin-bottom: 24px;
        }
        .ap-logo {
          height: 52px;
          width: auto;
        }

        /* ── Header ──────────────────────────────────────────────── */
        .ap-header {
          text-align: center;
          margin-bottom: 32px;
        }
        .ap-title {
          font-family: 'Space Grotesk', sans-serif;
          font-size: 1.75rem;
          font-weight: 700;
          color: #0F172A;
          margin-bottom: 8px;
        }
        .ap-subtitle {
          color: #6366F1;
          font-size: 0.9rem;
          line-height: 1.55;
        }

        /* ── Form ────────────────────────────────────────────────── */
        .ap-form {
          display: flex;
          flex-direction: column;
          gap: 20px;
        }

        /* Role selector */
        .ap-role-wrap {
          display: flex;
          flex-direction: column;
          gap: 10px;
        }
        .ap-role-options {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 10px;
        }
        .ap-role-btn {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 14px 18px;
          border-radius: 12px;
          border: 1.5px solid #E2E8F0;
          background: #F8FAFC;
          color: #64748B;
          font-family: 'Inter', sans-serif;
          font-size: 0.9rem;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.25s ease;
        }
        .ap-role-btn:hover {
          border-color: #6366F1;
          color: #6366F1;
          background: rgba(99, 102, 241, 0.04);
        }
        .ap-role-btn.active {
          border-color: #6366F1;
          background: rgba(99, 102, 241, 0.08);
          color: #6366F1;
          box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.12);
        }
        .ap-role-icon {
          width: 36px;
          height: 36px;
          border-radius: 10px;
          display: flex;
          align-items: center;
          justify-content: center;
          background: #EEF2FF;
          transition: background 0.25s ease;
          flex-shrink: 0;
        }
        .ap-role-btn.active .ap-role-icon {
          background: rgba(99, 102, 241, 0.15);
        }

        /* Label */
        .ap-label {
          display: flex;
          align-items: center;
          gap: 7px;
          font-size: 0.82rem;
          font-weight: 600;
          color: #475569;
          letter-spacing: 0.02em;
          text-transform: uppercase;
          margin-bottom: 2px;
        }

        /* Field wrapper */
        .ap-field {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        /* Input override for white card */
        .ap-input.input-field {
          background: #F8FAFC !important;
          border: 1.5px solid #E2E8F0 !important;
          border-radius: 12px !important;
          color: #0F172A !important;
          font-family: 'Inter', sans-serif;
          font-size: 0.95rem;
          padding: 13px 16px;
          transition: border-color 0.25s ease, box-shadow 0.25s ease, background 0.25s ease;
        }
        .ap-input.input-field::placeholder {
          color: #94A3B8;
        }
        .ap-input.input-field:focus {
          outline: none;
          border-color: #6366F1 !important;
          background: #ffffff !important;
          box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.12) !important;
        }

        /* Submit button override */
        .ap-submit.btn-primary {
          width: 100%;
          padding: 14px;
          border-radius: 12px !important;
          font-size: 0.97rem;
          font-weight: 600;
          margin-top: 4px;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          background: #0F172A !important;
          box-shadow: 0 8px 24px rgba(15, 23, 42, 0.25) !important;
          transition: box-shadow 0.25s ease !important;
          border: none !important;
        }
        .ap-submit.btn-primary:hover:not(:disabled) {
          box-shadow: 0 12px 32px rgba(15, 23, 42, 0.35) !important;
        }
        .ap-submit.btn-primary:disabled {
          opacity: 0.65;
        }

        /* Spinner */
        .ap-spinner {
          width: 18px;
          height: 18px;
          border: 2px solid rgba(255,255,255,0.3);
          border-top-color: white;
          border-radius: 50%;
          animation: spin 0.7s linear infinite;
          display: inline-block;
        }
        @keyframes spin {
          to { transform: rotate(360deg); }
        }

        /* ── Footer ──────────────────────────────────────────────── */
        .ap-footer {
          margin-top: 24px;
          text-align: center;
          color: #334155;
          font-size: 0.88rem;
        }
        .ap-toggle {
          background: none;
          border: none;
          color: #0F172A;
          font-weight: 700;
          cursor: pointer;
          margin-left: 4px;
          font-size: 0.88rem;
          font-family: 'Inter', sans-serif;
          transition: color 0.2s ease;
          text-decoration: underline;
          text-underline-offset: 3px;
        }
        .ap-toggle:hover {
          color: #6366F1;
        }

        /* ── Responsive ──────────────────────────────────────────── */
        @media (max-width: 480px) {
          .ap-card {
            padding: 36px 24px;
          }
          .ap-title {
            font-size: 1.5rem;
          }
          .ap-back {
            top: 16px;
            left: 16px;
          }
        }
      `}</style>
    </div>
  );
}
