import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import { ArrowRight, Users, Briefcase, Shield, Zap } from 'lucide-react';

export default function Landing() {
  const navigate = useNavigate();
  const { user } = useAuth();

  const handleGetStarted = () => {
    if (user) {
      if (user.role === 'creator') {
        navigate('/dashboard/creator');
      } else if (user.role === 'business') {
        navigate('/dashboard/business');
      } else if (user.role === 'admin') {
        navigate('/dashboard/admin');
      }
    } else {
      navigate('/auth');
    }
  };

  return (
    <div className="landing-page">
      {/* Header with Logo */}
      <header className="landing-header">
        <div className="header-content">
          <img src="/ugcad-logo.png" alt="UGCad.io" className="landing-logo" />
          <button className="btn-header" onClick={() => navigate('/auth')}>
            Sign In
          </button>
        </div>
      </header>

      {/* Hero Section */}
      <section className="hero-section">
        <div className="hero-content">
          <div className="hero-text fade-in">
            <h1 className="hero-title">
              Connect Creators with
              <span className="gradient-text"> Brands Seamlessly</span>
            </h1>
            <p className="hero-subtitle">
              The ultimate platform for user-generated content. Brands find talented creators,
              creators discover exciting projects, all in one secure marketplace.
            </p>
            <div className="hero-buttons">
              <button className="btn-primary" onClick={handleGetStarted} data-testid="get-started-btn">
                Get Started <ArrowRight size={20} />
              </button>
              <button className="btn-secondary" onClick={() => navigate('/auth')} data-testid="learn-more-btn">
                Learn More
              </button>
            </div>
          </div>
          <div className="hero-image slide-in-right">
            <img
              src="https://images.unsplash.com/photo-1624717369095-ebacc7d68a40?crop=entropy&cs=srgb&fm=jpg&q=85"
              alt="Content creator filming"
              className="hero-img"
            />
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="features-section">
        <h2 className="section-title">Why Choose UGCad.io?</h2>
        <div className="features-grid">
          <div className="feature-card fade-in">
            <div className="feature-icon">
              <Users size={40} />
            </div>
            <h3>Verified Creators</h3>
            <p>All creators are manually verified to ensure quality and authenticity</p>
          </div>
          <div className="feature-card fade-in">
            <div className="feature-icon">
              <Briefcase size={40} />
            </div>
            <h3>Campaign Management</h3>
            <p>Full-featured campaign tools with tracking, chat, and collaboration features</p>
          </div>
          <div className="feature-card fade-in">
            <div className="feature-icon">
              <Shield size={40} />
            </div>
            <h3>Escrow Protection</h3>
            <p>Secure payment system that protects both creators and brands</p>
          </div>
          <div className="feature-card fade-in">
            <div className="feature-icon">
              <Zap size={40} />
            </div>
            <h3>Fast & Easy</h3>
            <p>Simple onboarding process with dedicated support throughout</p>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="cta-section">
        <div className="cta-content">
          <h2>Ready to Start Your Journey?</h2>
          <p>Join thousands of creators and brands already using our platform</p>
          <button className="btn-primary" onClick={handleGetStarted} data-testid="join-now-btn">
            Join Now <ArrowRight size={20} />
          </button>
        </div>
      </section>

      <style jsx>{`
        .landing-page {
          min-height: 100vh;
        }

        .landing-header {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          background: rgba(255, 255, 255, 0.95);
          backdrop-filter: blur(10px);
          box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
          z-index: 1000;
          padding: 16px 8%;
        }

        .header-content {
          display: flex;
          justify-content: space-between;
          align-items: center;
          max-width: 1400px;
          margin: 0 auto;
        }

        .landing-logo {
          height: 45px;
          width: auto;
          cursor: pointer;
          transition: transform 0.3s ease;
        }

        .landing-logo:hover {
          transform: scale(1.05);
        }

        .btn-header {
          padding: 10px 24px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          border: none;
          border-radius: 8px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
          font-size: 0.95rem;
        }

        .btn-header:hover {
          transform: translateY(-2px);
          box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }

        .hero-section {
          min-height: 90vh;
          display: flex;
          align-items: center;
          padding: 120px 8% 60px;
          background: linear-gradient(135deg, #f8f9ff 0%, #e8ecff 100%);
        }

        .hero-content {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 60px;
          align-items: center;
          max-width: 1400px;
          margin: 0 auto;
          width: 100%;
        }

        .hero-text {
          display: flex;
          flex-direction: column;
          gap: 24px;
        }

        .hero-title {
          font-size: clamp(2.5rem, 5vw, 4rem);
          font-weight: 700;
          line-height: 1.2;
          color: #1a202c;
        }

        .gradient-text {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
        }

        .hero-subtitle {
          font-size: 1.125rem;
          line-height: 1.7;
          color: #4a5568;
        }

        .hero-buttons {
          display: flex;
          gap: 16px;
          margin-top: 16px;
        }

        .hero-buttons button {
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .hero-image {
          position: relative;
          height: 500px;
        }

        .hero-img {
          width: 100%;
          height: 100%;
          object-fit: cover;
          border-radius: 24px;
          box-shadow: 0 20px 60px rgba(102, 126, 234, 0.3);
        }

        .features-section {
          padding: 100px 8%;
          background: white;
        }

        .section-title {
          text-align: center;
          font-size: 2.5rem;
          font-weight: 700;
          margin-bottom: 60px;
          color: #1a202c;
        }

        .features-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
          gap: 32px;
          max-width: 1200px;
          margin: 0 auto;
        }

        .feature-card {
          background: white;
          padding: 40px 32px;
          border-radius: 20px;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.06);
          transition: all 0.4s ease;
          border: 2px solid transparent;
        }

        .feature-card:hover {
          transform: translateY(-8px);
          box-shadow: 0 12px 40px rgba(102, 126, 234, 0.2);
          border-color: #667eea;
        }

        .feature-icon {
          width: 80px;
          height: 80px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          border-radius: 20px;
          display: flex;
          align-items: center;
          justify-content: center;
          color: white;
          margin-bottom: 24px;
        }

        .feature-card h3 {
          font-size: 1.5rem;
          font-weight: 600;
          margin-bottom: 12px;
          color: #1a202c;
        }

        .feature-card p {
          color: #718096;
          line-height: 1.6;
        }

        .cta-section {
          padding: 100px 8%;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
        }

        .cta-content {
          text-align: center;
          max-width: 800px;
          margin: 0 auto;
        }

        .cta-content h2 {
          font-size: 3rem;
          font-weight: 700;
          margin-bottom: 20px;
        }

        .cta-content p {
          font-size: 1.25rem;
          margin-bottom: 32px;
          opacity: 0.95;
        }

        .cta-content .btn-primary {
          background: white;
          color: #667eea;
          box-shadow: 0 8px 30px rgba(0, 0, 0, 0.2);
        }

        .cta-content .btn-primary:hover {
          transform: translateY(-4px);
          box-shadow: 0 12px 40px rgba(0, 0, 0, 0.3);
        }

        @media (max-width: 968px) {
          .hero-content {
            grid-template-columns: 1fr;
            gap: 40px;
          }

          .hero-image {
            height: 400px;
          }

          .hero-buttons {
            flex-direction: column;
          }

          .hero-buttons button {
            width: 100%;
            justify-content: center;
          }
        }

        @media (max-width: 640px) {
          .hero-section {
            padding: 40px 5%;
          }

          .features-section,
          .cta-section {
            padding: 60px 5%;
          }

          .cta-content h2 {
            font-size: 2rem;
          }
        }
      `}</style>
    </div>
  );
}