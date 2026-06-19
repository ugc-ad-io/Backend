import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'sonner';
import { ArrowLeft, User, Send, X, RefreshCw, Sparkles } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// PRD 5.4 — Shortlist Presentation (Path B). Brand reviews the ops-curated
// candidates, then invites one (or requests a fresh shortlist).
export default function BrandShortlist() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [dismissed, setDismissed] = useState([]);
  const [profile, setProfile] = useState(null);

  const viewProfile = async (creatorId) => {
    try {
      const res = await axios.get(`${API}/profile/${creatorId}`);
      setProfile(res.data);
    } catch (err) {
      toast.error('Could not load profile');
    }
  };

  const fetchShortlist = async () => {
    try {
      const res = await axios.get(`${API}/campaigns/${id}/shortlist`);
      setData(res.data);
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to load shortlist');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchShortlist(); }, [id]);

  const invite = async (creatorId) => {
    if (busy) return;
    setBusy(true);
    try {
      await axios.post(`${API}/campaigns/${id}/shortlist/${creatorId}/invite`, {});
      toast.success('Private invitation sent');
      navigate('/messages');
    } catch (err) {
      const detail = err.response?.data?.detail;
      toast.error((typeof detail === 'string' ? detail : detail?.message) || 'Failed to invite');
    } finally {
      setBusy(false);
    }
  };

  const requestNew = async () => {
    if (busy) return;
    if (!window.confirm('Request a new set of matches? This is counted toward our team\'s workload and replaces the current shortlist.')) return;
    setBusy(true);
    try {
      await axios.post(`${API}/campaigns/${id}/shortlist/request-new`);
      toast.success('New matches requested — our team will respond within 48 hours');
      navigate('/dashboard/business');
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to request new matches');
    } finally {
      setBusy(false);
    }
  };

  if (loading) return <div className="bsl-page"><p className="bsl-muted">Loading shortlist…</p></div>;

  const candidates = (data?.candidates || []).filter((c) => !dismissed.includes(c.creator_id));
  const fulfilled = data?.match_status === 'fulfilled';

  return (
    <div className="bsl-page">
      <button className="bsl-back" onClick={() => navigate('/dashboard/business')}><ArrowLeft size={18} /> Back to dashboard</button>

      <div className="bsl-head">
        <h1><Sparkles size={22} /> Your matches for {data?.campaign_name || 'this brief'}</h1>
        <p>Our team reviewed your brief and recommends these creators.</p>
      </div>

      {fulfilled && <div className="bsl-banner">You've already invited a creator from this shortlist.</div>}

      {candidates.length === 0 ? (
        <div className="bsl-empty">
          <p>No candidates to show yet. Our team is still curating your shortlist (within 48 hours of publishing).</p>
        </div>
      ) : (
        <div className="bsl-grid">
          {candidates.map((c) => {
            const cr = c.creator || {};
            const handle = cr.public_creator_id || c.creator_id;
            return (
              <div key={c.creator_id} className={`bsl-card ${c.status === 'invited' ? 'is-invited' : ''}`}>
                <div className="bsl-card-top">
                  <div className="bsl-avatar">
                    {cr.profile_photo ? <img src={cr.profile_photo} alt={handle} /> : <span>{(handle[0] || '?').toUpperCase()}</span>}
                  </div>
                  <div>
                    <strong>@{handle}</strong>
                    <small>{cr.primary_category || 'Creator'}</small>
                  </div>
                  {c.status === 'invited' && <span className="bsl-pill">Invited</span>}
                </div>

                <div className="bsl-stats">
                  {cr.city_tier ? <span>{cr.city_tier}</span> : null}
                  {(cr.languages || []).length ? <span>{(cr.languages || []).join(', ')}</span> : null}
                  <span>{cr.deliverables_completed || 0} delivered</span>
                </div>

                <div className="bsl-note">
                  <span>Why we chose them</span>
                  <p>{c.ops_note}</p>
                </div>

                <div className="bsl-actions">
                  <button className="bsl-btn ghost" onClick={() => viewProfile(c.creator_id)}><User size={15} /> View Profile</button>
                  <button className="bsl-btn primary" disabled={busy || fulfilled} onClick={() => invite(c.creator_id)}><Send size={15} /> Invite to This Brief</button>
                  <button className="bsl-btn ghost" disabled={busy} onClick={() => setDismissed((d) => [...d, c.creator_id])}><X size={15} /> Decline</button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <div className="bsl-footer">
        <button className="bsl-btn ghost" disabled={busy} onClick={requestNew}><RefreshCw size={15} /> Not satisfied? Request new matches</button>
      </div>

      {profile && (
        <div className="bsl-modal-backdrop" onClick={() => setProfile(null)}>
          <div className="bsl-modal" onClick={(e) => e.stopPropagation()}>
            <button className="bsl-modal-close" onClick={() => setProfile(null)}><X size={18} /></button>
            <h2>@{profile.public_creator_id || profile.nickname || 'Creator'}</h2>
            <p className="bsl-muted">{profile.primary_category || profile.category || 'Creator'}</p>
            {profile.bio || profile.about ? <p className="bsl-modal-bio">{profile.bio || profile.about}</p> : null}
            <div className="bsl-stats">
              {(profile.languages || profile.content_languages || []).length ? <span>{(profile.languages || profile.content_languages).join(', ')}</span> : null}
              {profile.city_tier || profile.location_region ? <span>{profile.city_tier || profile.location_region}</span> : null}
              {profile.deliverables_completed != null ? <span>{profile.deliverables_completed} delivered</span> : null}
            </div>
            {Array.isArray(profile.portfolio) && profile.portfolio.length ? (
              <div className="bsl-portfolio">
                {profile.portfolio.slice(0, 5).map((p, i) => (
                  <div key={i} className="bsl-portfolio-item">{(p && (p.title || p.caption)) || `Sample ${i + 1}`}</div>
                ))}
              </div>
            ) : null}
          </div>
        </div>
      )}

      <style jsx>{`
        .bsl-page { max-width: 1100px; margin: 0 auto; padding: 28px 20px 60px; color: #111827; }
        .bsl-muted { color: #6b7280; }
        .bsl-back { display: inline-flex; align-items: center; gap: 6px; background: none; border: none; color: #4f46e5; cursor: pointer; font-size: 14px; margin-bottom: 14px; }
        .bsl-head h1 { display: flex; align-items: center; gap: 8px; font-size: 24px; margin: 0 0 6px; }
        .bsl-head p { color: #6b7280; margin: 0 0 20px; }
        .bsl-banner { background: #ecfdf5; border: 1px solid #a7f3d0; color: #065f46; padding: 10px 14px; border-radius: 10px; margin-bottom: 18px; font-size: 14px; }
        .bsl-empty { background: #f9fafb; border: 1px dashed #e5e7eb; border-radius: 12px; padding: 32px; text-align: center; color: #6b7280; }
        .bsl-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
        @media (max-width: 900px) { .bsl-grid { grid-template-columns: 1fr; } }
        .bsl-card { border: 1px solid #eef0f3; border-radius: 14px; padding: 16px; background: #fff; display: flex; flex-direction: column; gap: 12px; box-shadow: 0 1px 2px rgba(0,0,0,.04); }
        .bsl-card.is-invited { border-color: #a7f3d0; background: #f6fffb; }
        .bsl-card-top { display: flex; align-items: center; gap: 10px; }
        .bsl-avatar { width: 44px; height: 44px; border-radius: 50%; background: #eef2ff; color: #4f46e5; display: flex; align-items: center; justify-content: center; font-weight: 700; overflow: hidden; flex-shrink: 0; }
        .bsl-avatar img { width: 100%; height: 100%; object-fit: cover; }
        .bsl-card-top strong { display: block; font-size: 15px; }
        .bsl-card-top small { color: #6b7280; font-size: 12px; }
        .bsl-pill { margin-left: auto; background: #d1fae5; color: #065f46; font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 999px; }
        .bsl-stats { display: flex; flex-wrap: wrap; gap: 6px; }
        .bsl-stats span { background: #f3f4f6; color: #374151; font-size: 12px; padding: 3px 8px; border-radius: 6px; }
        .bsl-note { background: #fafafa; border: 1px solid #f0f0f0; border-radius: 10px; padding: 10px 12px; }
        .bsl-note span { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; color: #6b7280; }
        .bsl-note p { margin: 4px 0 0; font-size: 13px; line-height: 1.5; color: #111827; }
        .bsl-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: auto; }
        .bsl-btn { display: inline-flex; align-items: center; gap: 6px; border-radius: 9px; padding: 8px 12px; font-size: 13px; font-weight: 600; cursor: pointer; border: 1px solid transparent; }
        .bsl-btn.primary { background: #4f46e5; color: #fff; }
        .bsl-btn.primary:disabled { opacity: .5; cursor: not-allowed; }
        .bsl-btn.ghost { background: #fff; border-color: #e5e7eb; color: #374151; }
        .bsl-footer { margin-top: 24px; display: flex; justify-content: center; }
        .bsl-modal-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,.45); display: flex; align-items: center; justify-content: center; z-index: 50; padding: 20px; }
        .bsl-modal { background: #fff; border-radius: 16px; padding: 24px; max-width: 480px; width: 100%; position: relative; }
        .bsl-modal-close { position: absolute; top: 14px; right: 14px; background: none; border: none; cursor: pointer; color: #6b7280; }
        .bsl-modal h2 { margin: 0 0 2px; }
        .bsl-modal-bio { margin: 12px 0; font-size: 14px; line-height: 1.6; color: #374151; }
        .bsl-portfolio { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
        .bsl-portfolio-item { background: #f3f4f6; border-radius: 8px; padding: 8px 12px; font-size: 12px; color: #374151; }
      `}</style>
    </div>
  );
}
