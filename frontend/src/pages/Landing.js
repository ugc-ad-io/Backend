import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import { ArrowRight, Users, Briefcase, Shield, Zap, ChevronRight } from 'lucide-react';
import {
  motion,
  useInView,
} from 'framer-motion';

// ─── Static data ────────────────────────────────────────────────────────────

const featureData = [
  {
    Icon: Users,
    title: 'Verified Creators',
    desc: 'All creators are manually verified to ensure quality and authenticity on every campaign.',
    gradient: 'linear-gradient(135deg, #6366F1 0%, #818CF8 100%)',
    glow: 'rgba(99, 102, 241, 0.35)',
    accent: '#818CF8',
    num: '01',
  },
  {
    Icon: Briefcase,
    title: 'Campaign Management',
    desc: 'Full-featured campaign tools with tracking, real-time chat, and collaboration features.',
    gradient: 'linear-gradient(135deg, #8B5CF6 0%, #A78BFA 100%)',
    glow: 'rgba(139, 92, 246, 0.35)',
    accent: '#A78BFA',
    num: '02',
  },
  {
    Icon: Shield,
    title: 'Escrow Protection',
    desc: 'Secure payment system that holds funds safely and releases them only when work is approved.',
    gradient: 'linear-gradient(135deg, #06B6D4 0%, #22D3EE 100%)',
    glow: 'rgba(6, 182, 212, 0.35)',
    accent: '#22D3EE',
    num: '03',
  },
  {
    Icon: Zap,
    title: 'Fast & Easy',
    desc: 'Simple onboarding with a dedicated support team guiding you every step of the way.',
    gradient: 'linear-gradient(135deg, #F59E0B 0%, #FBBF24 100%)',
    glow: 'rgba(245, 158, 11, 0.35)',
    accent: '#FBBF24',
    num: '04',
  },
];

const stats = [
  { value: '10K+', label: 'Creators' },
  { value: '500+', label: 'Brands' },
  { value: '$2M+', label: 'Paid Out' },
];

// ─── Framer Motion variants ──────────────────────────────────────────────────

const heroItemVariants = {
  hidden: { opacity: 0, y: 28 },
  visible: (i) => ({
    opacity: 1,
    y: 0,
    transition: {
      delay: i * 0.12,
      duration: 0.7,
      ease: [0.25, 0.46, 0.45, 0.94],
    },
  }),
};

const containerVariants = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.1 } },
};

const cardVariants = {
  hidden: { opacity: 0, y: 36 },
  visible: (i) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.1, duration: 0.55, ease: 'easeOut' },
  }),
};

const fadeUpVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.55, ease: 'easeOut' } },
};

const statVariants = {
  hidden: { opacity: 0, scale: 0.85 },
  visible: { opacity: 1, scale: 1, transition: { duration: 0.5, ease: 'easeOut' } },
};

// ─── Component ───────────────────────────────────────────────────────────────

export default function Landing() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [scrolled, setScrolled] = useState(false);

  const featuresRef = useRef(null);
  const ctaRef = useRef(null);
  const featuresInView = useInView(featuresRef, { once: true, margin: '-80px' });
  const ctaInView = useInView(ctaRef, { once: true, margin: '-80px' });

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 40);
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

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
    <div className="lp-root">

      {/* ── Navbar ─────────────────────────────────────────────────────────── */}
      <motion.header
        className={`lp-navbar${scrolled ? ' lp-navbar--scrolled' : ''}`}
        initial={{ opacity: 0, y: -16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: 'easeOut' }}
      >
        <div className="lp-navbar__inner">
          <img
            src="/ugcad-logo.png"
            alt="UGCad.io"
            className="lp-navbar__logo"
            onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
          />
          <button className="lp-btn-signin" onClick={() => navigate('/auth')}>
            Sign In
          </button>
        </div>
      </motion.header>

      {/* ── Hero ───────────────────────────────────────────────────────────── */}
      <section className="lp-hero">
        {/* Decorative orbs */}
        <div className="lp-orb lp-orb--1" aria-hidden="true" />
        <div className="lp-orb lp-orb--2" aria-hidden="true" />
        <div className="lp-orb lp-orb--3" aria-hidden="true" />
        {/* Dot-grid overlay */}
        <div className="lp-grid-overlay" aria-hidden="true" />

        <div className="lp-hero__inner">
          {/* Left: text */}
          <div className="lp-hero__text">
            {/* Badge */}
            <motion.div
              className="lp-badge"
              custom={0}
              variants={heroItemVariants}
              initial="hidden"
              animate="visible"
            >
              <span className="lp-badge__dot" aria-hidden="true" />
              Now in Beta &nbsp;·&nbsp; 10,000+ Creators
            </motion.div>

            {/* Title line 1 */}
            <motion.h1
              className="lp-hero__title"
              custom={1}
              variants={heroItemVariants}
              initial="hidden"
              animate="visible"
            >
              Connect Creators with
            </motion.h1>

            {/* Title line 2 — gradient */}
            <motion.h1
              className="lp-hero__title lp-hero__title--gradient"
              custom={2}
              variants={heroItemVariants}
              initial="hidden"
              animate="visible"
            >
              Brands Seamlessly
            </motion.h1>

            {/* Subtitle */}
            <motion.p
              className="lp-hero__subtitle"
              custom={3}
              variants={heroItemVariants}
              initial="hidden"
              animate="visible"
            >
              The ultimate platform for user-generated content. Brands find talented
              creators, creators discover exciting projects — all in one secure marketplace.
            </motion.p>

            {/* CTA buttons */}
            <motion.div
              className="lp-hero__ctas"
              custom={4}
              variants={heroItemVariants}
              initial="hidden"
              animate="visible"
            >
              <button
                className="lp-btn-primary"
                onClick={handleGetStarted}
                data-testid="get-started-btn"
              >
                Get Started <ArrowRight size={18} />
              </button>
              <button
                className="lp-btn-ghost"
                onClick={() => navigate('/auth')}
                data-testid="learn-more-btn"
              >
                See How It Works <ChevronRight size={18} />
              </button>
            </motion.div>
          </div>

          {/* Right: video with image overlay */}
          <motion.div
            className="lp-hero__image-wrap"
            initial={{ opacity: 0, x: 40 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.9, delay: 0.3, ease: [0.25, 0.46, 0.45, 0.94] }}
          >
            <video
              src="/9384669-uhd_2160_3840_24fps.mp4"
              alt="Content creator filming"
              className="lp-hero__video"
              autoPlay
              muted
              loop
              playsInline
            />
            <img
              src="/Instagram.jpg"
              alt="Instagram content"
              className="lp-hero__overlay-img"
            />
            <div className="lp-hero__img-glow" aria-hidden="true" />
          </motion.div>
        </div>
      </section>

      {/* ── Brands Scroll ───────────────────────────────────────────────────── */}
      <section className="lp-brands">
        <div className="lp-brands__scroll">
          <div className="lp-brands__track">
            <div className="lp-brand-item">Amazon</div>
            <div className="lp-brand-item">Apple</div>
            <div className="lp-brand-item">Google</div>
            <div className="lp-brand-item">Netflix</div>
            <div className="lp-brand-item">Spotify</div>
            <div className="lp-brand-item">Tesla</div>
            <div className="lp-brand-item">Meta</div>
            <div className="lp-brand-item">Microsoft</div>
            {/* Duplicate for continuous scroll */}
            <div className="lp-brand-item">Amazon</div>
            <div className="lp-brand-item">Apple</div>
            <div className="lp-brand-item">Google</div>
            <div className="lp-brand-item">Netflix</div>
            <div className="lp-brand-item">Spotify</div>
            <div className="lp-brand-item">Tesla</div>
            <div className="lp-brand-item">Meta</div>
            <div className="lp-brand-item">Microsoft</div>
          </div>
        </div>
      </section>

      {/* ── Features ───────────────────────────────────────────────────────── */}
      <section className="lp-features" ref={featuresRef}>
        <div className="lp-features__inner">
          <motion.span
            className="lp-eyebrow"
            variants={fadeUpVariants}
            initial="hidden"
            animate={featuresInView ? 'visible' : 'hidden'}
          >
            FEATURES
          </motion.span>

          <motion.h2
            className="lp-section-heading"
            variants={fadeUpVariants}
            initial="hidden"
            animate={featuresInView ? 'visible' : 'hidden'}
            transition={{ delay: 0.1 }}
          >
            Why Choose UGCad.io?
          </motion.h2>

          <motion.div
            className="lp-features__grid"
            variants={containerVariants}
            initial="hidden"
            animate={featuresInView ? 'visible' : 'hidden'}
          >
            {featureData.map((feat, i) => (
              <motion.div
                key={feat.title}
                className="lp-card"
                custom={i}
                variants={cardVariants}
                whileHover={{ y: -6, transition: { duration: 0.22 } }}
                style={{ '--card-accent': feat.accent, '--card-glow': feat.glow }}
              >
                {/* Card number */}
                <span className="lp-card__num">{feat.num}</span>

                {/* Icon with per-card gradient */}
                <div
                  className="lp-card__icon"
                  style={{
                    background: feat.gradient,
                    boxShadow: `0 8px 24px ${feat.glow}`,
                  }}
                >
                  <feat.Icon size={24} />
                </div>

                <h3 className="lp-card__title">{feat.title}</h3>
                <p className="lp-card__body">{feat.desc}</p>

                {/* Bottom accent bar */}
                <div
                  className="lp-card__bar"
                  style={{ background: feat.gradient }}
                />
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── CTA ────────────────────────────────────────────────────────────── */}
      <section className="lp-cta" ref={ctaRef}>
        <div className="lp-cta__mesh" aria-hidden="true" />

        <motion.div
          className="lp-cta__inner"
          variants={containerVariants}
          initial="hidden"
          animate={ctaInView ? 'visible' : 'hidden'}
        >
          <motion.h2 className="lp-cta__heading" variants={statVariants}>
            Ready to Start Your Journey?
          </motion.h2>

          <motion.p className="lp-cta__subtext" variants={statVariants}>
            Join thousands of creators and brands already building on our platform.
          </motion.p>

          {/* Stats row */}
          <motion.div className="lp-cta__stats" variants={containerVariants}>
            {stats.map((s) => (
              <motion.div key={s.label} className="lp-stat" variants={statVariants}>
                <span className="lp-stat__value">{s.value}</span>
                <span className="lp-stat__label">{s.label}</span>
              </motion.div>
            ))}
          </motion.div>

          {/* Button + pulse ring */}
          <motion.div className="lp-cta__btn-wrap" variants={statVariants}>
            <div className="lp-pulse-ring" aria-hidden="true" />
            <button
              className="lp-btn-join"
              onClick={handleGetStarted}
              data-testid="join-now-btn"
            >
              Join Now <ArrowRight size={18} />
            </button>
          </motion.div>

          <motion.p className="lp-cta__proof" variants={statVariants}>
            No credit card required &nbsp;·&nbsp; Free to get started
          </motion.p>
        </motion.div>
      </section>

      {/* ── Styles ─────────────────────────────────────────────────────────── */}
      <style>{`

        /* ── Root ─────────────────────────────────────────────────────────── */
        .lp-root {
          min-height: 100vh;
          font-family: 'Inter', sans-serif;
        }

        /* ── Navbar ───────────────────────────────────────────────────────── */
        .lp-navbar {
          position: fixed;
          top: 0; left: 0; right: 0;
          z-index: 1000;
          padding: 18px 8%;
          transition: background 0.35s ease, backdrop-filter 0.35s ease,
                      border-color 0.35s ease, box-shadow 0.35s ease;
          border-bottom: 1px solid transparent;
        }

        .lp-navbar--scrolled {
          background: rgba(5, 5, 16, 0.82);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          border-bottom-color: rgba(255, 255, 255, 0.07);
          box-shadow: 0 4px 24px rgba(0, 0, 0, 0.35);
        }

        .lp-navbar__inner {
          display: flex;
          justify-content: space-between;
          align-items: center;
          max-width: 1300px;
          margin: 0 auto;
        }

        .lp-navbar__logo {
          height: 42px;
          width: auto;
          cursor: pointer;
          transition: opacity 0.2s;
          filter: brightness(0) invert(1);
        }
        .lp-navbar__logo:hover { opacity: 0.85; }

        .lp-btn-signin {
          padding: 9px 22px;
          border-radius: 100px;
          border: 1px solid rgba(255, 255, 255, 0.18);
          background: rgba(255, 255, 255, 0.06);
          color: #F8FAFC;
          font-family: 'Inter', sans-serif;
          font-weight: 500;
          font-size: 0.9rem;
          cursor: pointer;
          transition: all 0.25s ease;
          backdrop-filter: blur(8px);
        }
        .lp-btn-signin:hover {
          background: rgba(255, 255, 255, 0.13);
          border-color: rgba(255, 255, 255, 0.32);
        }

        /* ── Hero ─────────────────────────────────────────────────────────── */
        .lp-hero {
          position: relative;
          min-height: 100vh;
          display: flex;
          align-items: center;
          padding: 140px 8% 80px;
          background: linear-gradient(160deg, #050510 0%, #0D0B26 100%);
          overflow: hidden;
        }

        /* Orbs */
        .lp-orb {
          position: absolute;
          border-radius: 50%;
          animation: orbDrift 8s ease-in-out infinite;
          pointer-events: none;
        }
        .lp-orb--1 {
          width: 520px; height: 520px;
          background: rgba(99, 102, 241, 0.22);
          filter: blur(90px);
          top: -120px; left: -120px;
          animation-delay: 0s;
        }
        .lp-orb--2 {
          width: 420px; height: 420px;
          background: rgba(139, 92, 246, 0.18);
          filter: blur(80px);
          top: 180px; right: -80px;
          animation-delay: -3s;
        }
        .lp-orb--3 {
          width: 300px; height: 300px;
          background: rgba(34, 211, 238, 0.1);
          filter: blur(70px);
          bottom: 0; left: 38%;
          animation-delay: -5.5s;
        }

        /* Dot-grid overlay */
        .lp-grid-overlay {
          position: absolute;
          inset: 0;
          z-index: 1;
          pointer-events: none;
          background-image:
            linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px);
          background-size: 60px 60px;
        }

        .lp-hero__inner {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 64px;
          align-items: center;
          max-width: 1300px;
          margin: 0 auto;
          width: 100%;
          position: relative;
          z-index: 2;
        }

        .lp-hero__text {
          display: flex;
          flex-direction: column;
          gap: 0;
        }

        /* Badge */
        .lp-badge {
          display: inline-flex;
          align-items: center;
          gap: 9px;
          padding: 7px 16px;
          border-radius: 100px;
          background: rgba(99, 102, 241, 0.12);
          border: 1px solid rgba(99, 102, 241, 0.28);
          color: #A5B4FC;
          font-size: 0.82rem;
          font-weight: 500;
          margin-bottom: 28px;
          width: fit-content;
          letter-spacing: 0.01em;
        }

        .lp-badge__dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: #22D3EE;
          box-shadow: 0 0 6px #22D3EE;
          flex-shrink: 0;
          animation: pulseRing 1.8s ease-out infinite;
        }

        /* Titles */
        .lp-hero__title {
          font-family: 'Space Grotesk', sans-serif;
          font-size: clamp(2.8rem, 5vw, 4rem);
          font-weight: 700;
          line-height: 1.15;
          color: #F8FAFC;
          margin: 0;
        }

        .lp-hero__title--gradient {
          background: linear-gradient(135deg, #6366F1 0%, #8B5CF6 55%, #22D3EE 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
          margin-bottom: 24px;
        }

        .lp-hero__subtitle {
          color: #94A3B8;
          font-size: 1.08rem;
          line-height: 1.78;
          max-width: 500px;
          margin: 0 0 32px;
        }

        /* CTA buttons */
        .lp-hero__ctas {
          display: flex;
          gap: 14px;
          align-items: center;
          flex-wrap: wrap;
        }

        .lp-btn-primary {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 14px 28px;
          border-radius: 100px;
          background: linear-gradient(135deg, #6366F1 0%, #8B5CF6 100%);
          color: white;
          font-family: 'Inter', sans-serif;
          font-weight: 600;
          font-size: 0.95rem;
          border: none;
          cursor: pointer;
          transition: transform 0.25s ease, box-shadow 0.25s ease;
          box-shadow: 0 0 30px rgba(99, 102, 241, 0.38);
        }
        .lp-btn-primary:hover {
          transform: translateY(-2px);
          box-shadow: 0 8px 40px rgba(99, 102, 241, 0.55);
        }

        .lp-btn-ghost {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 13px 22px;
          border-radius: 100px;
          background: transparent;
          color: #94A3B8;
          font-family: 'Inter', sans-serif;
          font-weight: 500;
          font-size: 0.95rem;
          border: 1px solid rgba(255, 255, 255, 0.13);
          cursor: pointer;
          transition: all 0.25s ease;
        }
        .lp-btn-ghost:hover {
          color: #F8FAFC;
          border-color: rgba(255, 255, 255, 0.32);
          background: rgba(255, 255, 255, 0.04);
        }

        /* Image */
        .lp-hero__image-wrap {
          position: relative;
          display: inline-block;
          width: 100%;
          max-width: 500px;
        }

        .lp-hero__video {
          width: 49%;
          height: auto;
          border-radius: 16px;
          box-shadow: 0 16px 48px rgba(0, 0, 0, 0.4);
          object-fit: cover;
          display: block;
          float: left;
        }

        .lp-hero__overlay-img {
          width: 49%;
          height: auto;
          max-height: 350px;
          border-radius: 24px;
          box-shadow: 0 24px 64px rgba(0, 0, 0, 0.5);
          object-fit: cover;
          display: block;
          float: right;
          margin: 0;
        }

        .lp-hero__img-glow {
          position: absolute;
          bottom: -24px;
          left: 50%;
          transform: translateX(-50%);
          width: 65%;
          height: 60px;
          background: rgba(99, 102, 241, 0.42);
          filter: blur(40px);
          border-radius: 50%;
          z-index: -1;
          pointer-events: none;
        }

        /* ── Brands Scroll ────────────────────────────────────────────────── */
        .lp-brands {
          background: #0a0a0a;
          padding: 60px 0;
          overflow: hidden;
        }

        .lp-brands__scroll {
          width: 100%;
          overflow: hidden;
        }

        .lp-brands__track {
          display: flex;
          gap: 60px;
          animation: scrollBrands 30s linear infinite;
          width: max-content;
          padding: 0 8%;
        }

        .lp-brand-item {
          font-size: 1.5rem;
          font-weight: 700;
          color: #F8FAFC;
          white-space: nowrap;
          letter-spacing: 0.02em;
          opacity: 0.6;
          transition: opacity 0.3s ease;
        }

        .lp-brand-item:hover {
          opacity: 1;
        }

        @keyframes scrollBrands {
          0% {
            transform: translateX(0);
          }
          100% {
            transform: translateX(-50%);
          }
        }

        /* ── Features ─────────────────────────────────────────────────────── */
        .lp-features {
          position: relative;
          padding: 120px 8%;
          background: #ffffff;
          overflow: hidden;
        }

        .lp-features__inner {
          max-width: 1200px;
          margin: 0 auto;
          text-align: center;
          position: relative;
          z-index: 1;
        }

        .lp-eyebrow {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          font-size: 0.7rem;
          font-weight: 700;
          letter-spacing: 0.18em;
          color: #6366F1;
          text-transform: uppercase;
          margin-bottom: 18px;
          padding: 5px 14px;
          border-radius: 100px;
          background: rgba(99, 102, 241, 0.08);
          border: 1px solid rgba(99, 102, 241, 0.18);
        }

        .lp-section-heading {
          font-family: 'Space Grotesk', sans-serif;
          font-size: clamp(2rem, 3.5vw, 2.8rem);
          font-weight: 700;
          color: #0F172A;
          margin-bottom: 12px;
        }

        .lp-section-subheading {
          color: #64748B;
          font-size: 1rem;
          line-height: 1.65;
          margin-bottom: 60px;
          max-width: 480px;
          margin-left: auto;
          margin-right: auto;
        }

        .lp-features__grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
          gap: 20px;
          text-align: left;
        }

        /* Feature card — clean white, premium */
        .lp-card {
          background: #ffffff;
          padding: 32px 26px 26px;
          border-radius: 20px;
          border: 1.5px solid #F1F5F9;
          box-shadow: 0 2px 12px rgba(0, 0, 0, 0.05);
          cursor: default;
          transition: border-color 0.3s ease, box-shadow 0.3s ease, transform 0.3s ease;
          position: relative;
          overflow: hidden;
        }

        /* Colored top accent line on hover */
        .lp-card::after {
          content: '';
          position: absolute;
          top: 0; left: 0; right: 0;
          height: 3px;
          background: var(--card-accent, #6366F1);
          opacity: 0;
          transition: opacity 0.3s ease;
          border-radius: 20px 20px 0 0;
        }

        .lp-card:hover {
          border-color: rgba(99, 102, 241, 0.15);
          box-shadow: 0 16px 48px var(--card-glow, rgba(99,102,241,0.12));
        }
        .lp-card:hover::after {
          opacity: 1;
        }

        /* Card number */
        .lp-card__num {
          position: absolute;
          top: 20px;
          right: 22px;
          font-family: 'Space Grotesk', sans-serif;
          font-size: 0.7rem;
          font-weight: 700;
          letter-spacing: 0.06em;
          color: #E2E8F0;
        }

        .lp-card__icon {
          width: 54px;
          height: 54px;
          border-radius: 14px;
          display: flex;
          align-items: center;
          justify-content: center;
          color: white;
          margin-bottom: 22px;
          transition: transform 0.3s ease;
          flex-shrink: 0;
        }
        .lp-card:hover .lp-card__icon {
          transform: scale(1.1) rotate(-3deg);
        }

        .lp-card__title {
          font-family: 'Space Grotesk', sans-serif;
          font-size: 1.1rem;
          font-weight: 600;
          color: #0F172A;
          margin-bottom: 10px;
        }

        .lp-card__body {
          color: #64748B;
          font-size: 0.91rem;
          line-height: 1.72;
          margin-bottom: 20px;
        }

        /* Bottom gradient accent bar — animates wider on hover */
        .lp-card__bar {
          height: 2px;
          border-radius: 2px;
          opacity: 0.4;
          transition: opacity 0.3s ease, width 0.35s ease;
          width: 36px;
        }
        .lp-card:hover .lp-card__bar {
          opacity: 0.85;
          width: 100%;
        }

        /* ── CTA ──────────────────────────────────────────────────────────── */
        .lp-cta {
          position: relative;
          padding: 120px 8%;
          background: #0D0B26;
          overflow: hidden;
          text-align: center;
        }

        .lp-cta__mesh {
          position: absolute;
          inset: 0;
          z-index: 0;
          background: linear-gradient(135deg, #050510 0%, #1e1b4b 40%, #0D0B26 60%, #08081a 100%);
          background-size: 300% 300%;
          animation: gradientShift 8s ease infinite;
          pointer-events: none;
        }

        .lp-cta__inner {
          position: relative;
          z-index: 1;
          max-width: 680px;
          margin: 0 auto;
          display: flex;
          flex-direction: column;
          align-items: center;
        }

        .lp-cta__heading {
          font-family: 'Space Grotesk', sans-serif;
          font-size: clamp(2.2rem, 4vw, 3rem);
          font-weight: 700;
          color: #F8FAFC;
          margin-bottom: 18px;
          line-height: 1.2;
        }

        .lp-cta__subtext {
          color: #94A3B8;
          font-size: 1.08rem;
          line-height: 1.7;
          margin-bottom: 52px;
        }

        /* Stats */
        .lp-cta__stats {
          display: flex;
          justify-content: center;
          gap: 52px;
          margin-bottom: 52px;
          flex-wrap: wrap;
        }

        .lp-stat {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 5px;
        }

        .lp-stat__value {
          font-family: 'Space Grotesk', sans-serif;
          font-size: 2.1rem;
          font-weight: 700;
          background: linear-gradient(135deg, #6366F1, #22D3EE);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
          line-height: 1;
        }

        .lp-stat__label {
          color: #64748B;
          font-size: 0.8rem;
          font-weight: 600;
          letter-spacing: 0.1em;
          text-transform: uppercase;
        }

        /* Button + pulse ring */
        .lp-cta__btn-wrap {
          position: relative;
          display: inline-flex;
          margin-bottom: 28px;
        }

        .lp-pulse-ring {
          position: absolute;
          inset: -5px;
          border-radius: 100px;
          border: 2px solid rgba(99, 102, 241, 0.55);
          animation: pulseRing 1.8s ease-out infinite;
          pointer-events: none;
        }

        .lp-btn-join {
          display: inline-flex;
          align-items: center;
          gap: 9px;
          padding: 16px 42px;
          border-radius: 100px;
          background: linear-gradient(135deg, #6366F1 0%, #8B5CF6 100%);
          color: white;
          font-family: 'Inter', sans-serif;
          font-weight: 700;
          font-size: 1.05rem;
          border: none;
          cursor: pointer;
          transition: transform 0.25s ease, box-shadow 0.25s ease;
          box-shadow: 0 0 40px rgba(99, 102, 241, 0.42);
          position: relative;
          z-index: 1;
        }
        .lp-btn-join:hover {
          transform: translateY(-3px);
          box-shadow: 0 12px 50px rgba(99, 102, 241, 0.62);
        }

        .lp-cta__proof {
          color: #475569;
          font-size: 0.83rem;
          letter-spacing: 0.01em;
        }

        /* ── Responsive ───────────────────────────────────────────────────── */
        @media (max-width: 1024px) {
          .lp-hero__inner {
            grid-template-columns: 1fr;
            text-align: center;
          }
          .lp-hero__text {
            align-items: center;
          }
          .lp-hero__subtitle {
            max-width: 100%;
          }
          .lp-hero__ctas {
            justify-content: center;
          }
          .lp-hero__image-wrap {
            order: -1;
            max-width: 460px;
            margin: 0 auto;
          }
          .lp-features__grid {
            text-align: left;
          }
        }

        @media (max-width: 640px) {
          .lp-hero {
            padding: 120px 5% 60px;
          }
          .lp-features {
            padding: 80px 5%;
          }
          .lp-cta {
            padding: 80px 5%;
          }
          .lp-hero__ctas {
            flex-direction: column;
            align-items: stretch;
          }
          .lp-btn-primary,
          .lp-btn-ghost {
            justify-content: center;
          }
          .lp-cta__stats {
            gap: 32px;
          }
          .lp-orb--1 { opacity: 0.7; }
          .lp-orb--2 { opacity: 0.6; }
          .lp-orb--3 { opacity: 0.5; }
          .lp-navbar { padding: 16px 5%; }
        }
      `}</style>
    </div>
  );
}
