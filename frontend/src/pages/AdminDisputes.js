import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'sonner';
import { ArrowLeft, ShieldAlert, Clock, FileText, MessageSquare, Package, Gavel, RefreshCw } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const RULINGS = [
  { value: 'favor_creator', label: 'Rule for creator' },
  { value: 'favor_brand', label: 'Rule for brand' },
  { value: 'split', label: 'Split ruling' },
  { value: 'no_fault', label: 'No-fault (platform absorbs)' },
];

const SEVERITY_COLOR = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#65a30d' };

// PRD Section 9 — admin dispute dashboard + evidence panel + ruling.
export default function AdminDisputes() {
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState(null);
  const [ruling, setRuling] = useState({ ruling: '', refund_amount: 0, creator_amount: 0, reasoning: '', extension_days: 0 });
  const [busy, setBusy] = useState(false);

  const load = async () => {
    try {
      const res = await axios.get(`${API}/admin/disputes`);
      setData(res.data);
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to load disputes');
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { load(); }, []);

  const openDetail = async (id) => {
    try {
      const res = await axios.get(`${API}/admin/disputes/${id}`);
      setDetail(res.data);
      setRuling({ ruling: '', refund_amount: 0, creator_amount: 0, reasoning: '', extension_days: 0 });
    } catch (err) {
      toast.error('Failed to load dispute detail');
    }
  };

  const submitRuling = async () => {
    if (!ruling.ruling) return toast.error('Pick a ruling');
    if ((ruling.reasoning || '').trim().length < 10) return toast.error('Add reasoning (the parties see this)');
    setBusy(true);
    try {
      await axios.post(`${API}/admin/disputes/${detail.dispute.id}/rule`, {
        ruling: ruling.ruling,
        refund_amount: Number(ruling.refund_amount) || 0,
        creator_amount: Number(ruling.creator_amount) || 0,
        reasoning: ruling.reasoning,
        extension_days: Number(ruling.extension_days) || 0,
      });
      toast.success('Dispute resolved');
      setDetail(null);
      load();
    } catch (err) {
      const d = err.response?.data?.detail;
      toast.error((typeof d === 'string' ? d : d?.message) || 'Failed to rule');
    } finally {
      setBusy(false);
    }
  };

  const requestInfo = async (party) => {
    const message = window.prompt(`What info do you need from the ${party}?`);
    if (!message) return;
    try {
      await axios.post(`${API}/admin/disputes/${detail.dispute.id}/request-info`, { party, message });
      toast.success('Info requested (72h window)');
      openDetail(detail.dispute.id);
    } catch (err) {
      toast.error('Failed to request info');
    }
  };

  if (loading) return <div className="adsp-page"><p className="adsp-muted">Loading disputes…</p></div>;

  const disputes = data?.disputes || [];

  return (
    <div className="adsp-page">
      <button className="adsp-back" onClick={() => navigate('/dashboard/admin')}><ArrowLeft size={18} /> Back to admin</button>
      <h1><ShieldAlert size={22} /> Disputes <span className="adsp-count">{data?.open_count || 0} open</span></h1>

      {disputes.length === 0 ? (
        <div className="adsp-empty">No disputes. 🎉</div>
      ) : (
        <div className="adsp-list">
          {disputes.map((d) => (
            <div key={d.id} className={`adsp-item ${d.sla_breached ? 'breached' : ''}`}>
              <div className="adsp-item-main" onClick={() => openDetail(d.id)}>
                <div>
                  <span className="adsp-sev" style={{ background: SEVERITY_COLOR[d.severity] || '#999' }}>{d.severity}</span>
                  <strong>{d.dispute_type.replace(/_/g, ' ')}</strong>
                  <small>{d.deal_id} · wants {d.desired_outcome.replace(/_/g, ' ')} · raised by {d.raised_by_role}</small>
                </div>
                <div className="adsp-sla">
                  <Clock size={14} />
                  <span className={d.sla_breached ? 'breached' : ''}>
                    {d.status === 'resolved' ? 'Resolved' : d.sla_hours_remaining != null ? `${d.sla_hours_remaining}h left` : '—'}
                  </span>
                  <em>{d.status}</em>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {detail && (
        <div className="adsp-modal-backdrop" onClick={() => setDetail(null)}>
          <div className="adsp-modal" onClick={(e) => e.stopPropagation()}>
            <div className="adsp-modal-head">
              <h2>{detail.dispute.dispute_type.replace(/_/g, ' ')} <span className="adsp-sev" style={{ background: SEVERITY_COLOR[detail.dispute.severity] }}>{detail.dispute.severity}</span></h2>
              <button onClick={() => setDetail(null)}>✕</button>
            </div>

            <div className="adsp-grid">
              <section>
                <h4>Dispute</h4>
                <p className="adsp-desc">{detail.dispute.description}</p>
                <p className="adsp-muted">Desired outcome: <strong>{detail.dispute.desired_outcome.replace(/_/g, ' ')}</strong></p>
                <div className="adsp-evi">
                  {(detail.dispute.evidence_urls || []).map((u, i) => <a key={i} href={u} target="_blank" rel="noreferrer">Evidence {i + 1}</a>)}
                </div>
              </section>

              <section>
                <h4><FileText size={14} /> Brief</h4>
                <p className="adsp-muted">{(detail.brief?.brief_text || '').slice(0, 240) || '—'}</p>
                <h4><Package size={14} /> Shipment</h4>
                <p className="adsp-muted">{detail.shipment?.status || 'No shipment'}{detail.shipment?.late_fee_applied ? ` · late fee ₹${detail.shipment.late_fee_applied}` : ''}</p>
              </section>

              <section>
                <h4><MessageSquare size={14} /> Timeline ({detail.timeline?.length || 0})</h4>
                <div className="adsp-scroll">
                  {(detail.timeline || []).slice(-12).map((t, i) => <p key={i} className="adsp-tl">{(t.message || t.event_type)}</p>)}
                </div>
              </section>

              <section>
                <h4>Content versions ({detail.content_versions?.length || 0})</h4>
                {(detail.content_versions || []).map((c, i) => <p key={i} className="adsp-muted">v{c.version} · {c.status} · {(c.submitted_at || '').slice(0, 10)}</p>)}
                <h4>Prior disputes</h4>
                <p className="adsp-muted">{detail.prior_disputes?.length || 0} previous for these parties</p>
              </section>
            </div>

            {detail.dispute.status === 'resolved' ? (
              <div className="adsp-resolved">Resolved: <strong>{detail.dispute.ruling?.replace(/_/g, ' ')}</strong> — {detail.dispute.reasoning}</div>
            ) : (
              <div className="adsp-ruling">
                <h4><Gavel size={15} /> Ruling</h4>
                <div className="adsp-ruling-row">
                  <select value={ruling.ruling} onChange={(e) => setRuling({ ...ruling, ruling: e.target.value })}>
                    <option value="">Select ruling…</option>
                    {RULINGS.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
                  </select>
                  <label>Refund→brand ₹<input type="number" value={ruling.refund_amount} onChange={(e) => setRuling({ ...ruling, refund_amount: e.target.value })} /></label>
                  <label>Pay→creator ₹<input type="number" value={ruling.creator_amount} onChange={(e) => setRuling({ ...ruling, creator_amount: e.target.value })} /></label>
                  <label>Extension d<input type="number" value={ruling.extension_days} onChange={(e) => setRuling({ ...ruling, extension_days: e.target.value })} /></label>
                </div>
                <textarea placeholder="Reasoning (shown to both parties)…" value={ruling.reasoning} onChange={(e) => setRuling({ ...ruling, reasoning: e.target.value })} />
                <div className="adsp-ruling-actions">
                  <button className="ghost" onClick={() => requestInfo('brand')}>Request info: brand</button>
                  <button className="ghost" onClick={() => requestInfo('creator')}>Request info: creator</button>
                  <button className="primary" onClick={submitRuling} disabled={busy}>Execute ruling</button>
                </div>
                <p className="adsp-hint">Leaving amounts at 0 applies the default split for the chosen ruling. Funds move immediately.</p>
              </div>
            )}
          </div>
        </div>
      )}

      <style jsx>{`
        .adsp-page { max-width: 1000px; margin: 0 auto; padding: 28px 20px 60px; color: #111827; }
        .adsp-muted { color: #6b7280; }
        .adsp-back { display: inline-flex; align-items: center; gap: 6px; background: none; border: none; color: #4f46e5; cursor: pointer; font-size: 14px; margin-bottom: 12px; }
        .adsp-page h1 { display: flex; align-items: center; gap: 8px; font-size: 24px; }
        .adsp-count { font-size: 12px; background: #fee2e2; color: #b91c1c; padding: 3px 10px; border-radius: 999px; }
        .adsp-empty { background: #f9fafb; border: 1px dashed #e5e7eb; border-radius: 12px; padding: 40px; text-align: center; color: #6b7280; }
        .adsp-list { display: flex; flex-direction: column; gap: 10px; margin-top: 16px; }
        .adsp-item { border: 1px solid #eef0f3; border-radius: 12px; background: #fff; }
        .adsp-item.breached { border-color: #fecaca; background: #fff7f7; }
        .adsp-item-main { display: flex; justify-content: space-between; align-items: center; padding: 14px 16px; cursor: pointer; gap: 12px; }
        .adsp-item-main strong { display: inline-block; margin: 0 8px; text-transform: capitalize; }
        .adsp-item-main small { display: block; color: #6b7280; font-size: 12px; margin-top: 4px; }
        .adsp-sev { color: #fff; font-size: 10px; font-weight: 700; padding: 2px 7px; border-radius: 999px; text-transform: uppercase; }
        .adsp-sla { text-align: right; font-size: 13px; display: flex; align-items: center; gap: 4px; }
        .adsp-sla .breached { color: #dc2626; font-weight: 700; }
        .adsp-sla em { display: block; width: 100%; color: #9ca3af; font-size: 11px; }
        .adsp-modal-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,.5); display: flex; align-items: center; justify-content: center; padding: 20px; z-index: 60; }
        .adsp-modal { background: #fff; border-radius: 16px; padding: 22px; max-width: 920px; width: 100%; max-height: 88vh; overflow: auto; }
        .adsp-modal-head { display: flex; justify-content: space-between; align-items: center; }
        .adsp-modal-head h2 { text-transform: capitalize; display: flex; gap: 8px; align-items: center; }
        .adsp-modal-head button { background: none; border: none; font-size: 18px; cursor: pointer; }
        .adsp-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 14px 0; }
        @media (max-width: 760px) { .adsp-grid { grid-template-columns: 1fr; } }
        .adsp-grid section { border: 1px solid #f0f0f0; border-radius: 10px; padding: 12px; }
        .adsp-grid h4 { display: flex; align-items: center; gap: 5px; font-size: 13px; margin: 0 0 6px; }
        .adsp-desc { font-size: 14px; line-height: 1.5; }
        .adsp-evi { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
        .adsp-evi a { font-size: 12px; background: #eef2ff; color: #4f46e5; padding: 4px 8px; border-radius: 6px; text-decoration: none; }
        .adsp-scroll { max-height: 140px; overflow: auto; }
        .adsp-tl { font-size: 12px; color: #4b5563; margin: 3px 0; }
        .adsp-resolved { background: #ecfdf5; border: 1px solid #a7f3d0; border-radius: 10px; padding: 12px; color: #065f46; }
        .adsp-ruling { border-top: 1px solid #eee; padding-top: 14px; }
        .adsp-ruling-row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 10px; }
        .adsp-ruling-row select, .adsp-ruling-row input { border: 1px solid #e5e7eb; border-radius: 8px; padding: 7px 9px; font-size: 13px; }
        .adsp-ruling-row input { width: 90px; }
        .adsp-ruling label { font-size: 12px; color: #6b7280; display: flex; align-items: center; gap: 4px; }
        .adsp-ruling textarea { width: 100%; min-height: 70px; border: 1px solid #e5e7eb; border-radius: 8px; padding: 9px; font-size: 13px; }
        .adsp-ruling-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 10px; }
        .adsp-ruling-actions button { border-radius: 8px; padding: 8px 14px; font-size: 13px; font-weight: 600; cursor: pointer; border: 1px solid transparent; }
        .adsp-ruling-actions .ghost { background: #fff; border: 1px solid #e5e7eb; color: #374151; }
        .adsp-ruling-actions .primary { background: #4f46e5; color: #fff; }
        .adsp-hint { font-size: 11px; color: #9ca3af; margin-top: 8px; }
      `}</style>
    </div>
  );
}
