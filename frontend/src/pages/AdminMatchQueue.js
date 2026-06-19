import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'sonner';
import { ArrowLeft, Plus, Trash2, Users, BarChart3 } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const MIN = 3;
const MAX = 5;
const emptyRow = () => ({ creator_id: '', ops_note: '' });

// PRD 5.2 Path B / 5.4 — Ops match queue + shortlist builder.
export default function AdminMatchQueue() {
  const navigate = useNavigate();
  const [queue, setQueue] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeId, setActiveId] = useState(null);
  const [rows, setRows] = useState([emptyRow(), emptyRow(), emptyRow()]);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    try {
      const [q, m] = await Promise.all([
        axios.get(`${API}/admin/match-queue`),
        axios.get(`${API}/admin/match-metrics`).catch(() => ({ data: null })),
      ]);
      setQueue(q.data || []);
      setMetrics(m.data);
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to load match queue');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const openBuilder = (campaignId) => {
    setActiveId(campaignId);
    setRows([emptyRow(), emptyRow(), emptyRow()]);
  };

  const updateRow = (i, key, value) => setRows((r) => r.map((row, idx) => (idx === i ? { ...row, [key]: value } : row)));
  const addRow = () => setRows((r) => (r.length >= MAX ? r : [...r, emptyRow()]));
  const removeRow = (i) => setRows((r) => (r.length <= 1 ? r : r.filter((_, idx) => idx !== i)));

  const submitShortlist = async () => {
    const candidates = rows
      .map((r) => ({ creator_id: r.creator_id.trim(), ops_note: r.ops_note.trim() }))
      .filter((r) => r.creator_id && r.ops_note);
    if (candidates.length < MIN || candidates.length > MAX) {
      toast.error(`A shortlist needs ${MIN}-${MAX} creators, each with a note.`);
      return;
    }
    setBusy(true);
    try {
      await axios.post(`${API}/admin/campaigns/${activeId}/shortlist`, { candidates });
      toast.success('Shortlist sent to the brand');
      setActiveId(null);
      load();
    } catch (err) {
      const detail = err.response?.data?.detail;
      toast.error((typeof detail === 'string' ? detail : detail?.message) || 'Failed to submit shortlist');
    } finally {
      setBusy(false);
    }
  };

  if (loading) return <div className="amq-page"><p className="amq-muted">Loading match queue…</p></div>;

  return (
    <div className="amq-page">
      <button className="amq-back" onClick={() => navigate('/dashboard/admin')}><ArrowLeft size={18} /> Back to admin</button>
      <h1><Users size={22} /> Match Queue</h1>
      <p className="amq-muted">Briefs that requested ops-curated matches. Build a {MIN}-{MAX} creator shortlist for each.</p>

      {metrics && (
        <div className="amq-metrics">
          <div className="amq-metrics-head"><BarChart3 size={16} /> Match metrics</div>
          <div className="amq-metric-grid">
            <div><strong>{metrics.invitations_sent}</strong><span>Invites sent</span></div>
            <div><strong>{metrics.acceptance_rate_pct}%</strong><span>Acceptance rate</span></div>
            <div><strong>{metrics.avg_response_hours}h</strong><span>Avg response</span></div>
            <div><strong>{metrics.counter_success_rate_pct}%</strong><span>Counter success</span></div>
            <div><strong>{metrics.briefs_in_queue}</strong><span>In queue</span></div>
            <div><strong>{metrics.shortlists_delivered}</strong><span>Shortlists sent</span></div>
          </div>
        </div>
      )}

      {queue.length === 0 ? (
        <div className="amq-empty">No briefs are waiting for matches right now.</div>
      ) : (
        <div className="amq-list">
          {queue.map((c) => (
            <div key={c.id} className="amq-item">
              <div className="amq-item-main">
                <div>
                  <strong>{c.title || 'Untitled brief'}</strong>
                  <small>{c.brand_name || c.business_nickname} · {c.product_category || '—'} · ₹{c.per_video_budget || c.budget_max || 0}</small>
                </div>
                <span className={`amq-status ${c.match_status}`}>{c.match_status}</span>
              </div>
              <p className="amq-brief">{(c.brief_text || '').slice(0, 180)}{(c.brief_text || '').length > 180 ? '…' : ''}</p>
              <div className="amq-item-actions">
                <button className="amq-btn ghost" onClick={() => navigate(`/campaign/${c.id}`)}>View brief</button>
                <button className="amq-btn primary" onClick={() => openBuilder(c.id)}>Build shortlist</button>
              </div>

              {activeId === c.id && (
                <div className="amq-builder">
                  {rows.map((row, i) => (
                    <div key={i} className="amq-row">
                      <input placeholder="Creator ID" value={row.creator_id} onChange={(e) => updateRow(i, 'creator_id', e.target.value)} />
                      <input placeholder="Why we chose them…" value={row.ops_note} onChange={(e) => updateRow(i, 'ops_note', e.target.value)} />
                      <button className="amq-row-del" onClick={() => removeRow(i)} disabled={rows.length <= 1}><Trash2 size={14} /></button>
                    </div>
                  ))}
                  <div className="amq-builder-actions">
                    <button className="amq-btn ghost" onClick={addRow} disabled={rows.length >= MAX}><Plus size={14} /> Add ({rows.length}/{MAX})</button>
                    <div>
                      <button className="amq-btn ghost" onClick={() => setActiveId(null)}>Cancel</button>
                      <button className="amq-btn primary" onClick={submitShortlist} disabled={busy}>Send to brand</button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      <style jsx>{`
        .amq-page { max-width: 1000px; margin: 0 auto; padding: 28px 20px 60px; color: #111827; }
        .amq-muted { color: #6b7280; }
        .amq-back { display: inline-flex; align-items: center; gap: 6px; background: none; border: none; color: #4f46e5; cursor: pointer; font-size: 14px; margin-bottom: 12px; }
        .amq-page h1 { display: flex; align-items: center; gap: 8px; font-size: 24px; margin: 0 0 4px; }
        .amq-metrics { margin: 18px 0 24px; border: 1px solid #eef0f3; border-radius: 12px; padding: 14px 16px; background: #fafafe; }
        .amq-metrics-head { display: flex; align-items: center; gap: 6px; font-weight: 700; font-size: 13px; color: #4f46e5; margin-bottom: 10px; }
        .amq-metric-grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 10px; }
        @media (max-width: 800px) { .amq-metric-grid { grid-template-columns: repeat(3, 1fr); } }
        .amq-metric-grid div { text-align: center; }
        .amq-metric-grid strong { display: block; font-size: 18px; }
        .amq-metric-grid span { font-size: 11px; color: #6b7280; }
        .amq-empty { background: #f9fafb; border: 1px dashed #e5e7eb; border-radius: 12px; padding: 32px; text-align: center; color: #6b7280; }
        .amq-list { display: flex; flex-direction: column; gap: 14px; }
        .amq-item { border: 1px solid #eef0f3; border-radius: 14px; padding: 16px; background: #fff; }
        .amq-item-main { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
        .amq-item-main strong { display: block; font-size: 16px; }
        .amq-item-main small { color: #6b7280; font-size: 12px; }
        .amq-status { font-size: 11px; font-weight: 700; padding: 3px 9px; border-radius: 999px; background: #fef3c7; color: #92400e; text-transform: capitalize; }
        .amq-status.shortlisted { background: #dbeafe; color: #1e40af; }
        .amq-brief { color: #4b5563; font-size: 13px; margin: 10px 0; }
        .amq-item-actions { display: flex; gap: 8px; }
        .amq-btn { border-radius: 9px; padding: 8px 14px; font-size: 13px; font-weight: 600; cursor: pointer; border: 1px solid transparent; }
        .amq-btn.primary { background: #4f46e5; color: #fff; }
        .amq-btn.primary:disabled { opacity: .5; cursor: not-allowed; }
        .amq-btn.ghost { background: #fff; border: 1px solid #e5e7eb; color: #374151; }
        .amq-builder { margin-top: 14px; border-top: 1px solid #f0f0f0; padding-top: 14px; }
        .amq-row { display: flex; gap: 8px; margin-bottom: 8px; }
        .amq-row input { flex: 1; border: 1px solid #e5e7eb; border-radius: 8px; padding: 8px 10px; font-size: 13px; }
        .amq-row input:first-child { flex: 0 0 200px; }
        .amq-row-del { border: 1px solid #fecaca; background: #fff; color: #ef4444; border-radius: 8px; padding: 0 10px; cursor: pointer; }
        .amq-builder-actions { display: flex; justify-content: space-between; align-items: center; margin-top: 6px; }
        .amq-builder-actions > div { display: flex; gap: 8px; }
      `}</style>
    </div>
  );
}
