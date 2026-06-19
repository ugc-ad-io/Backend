import { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import { toast } from 'sonner';
import { AlertTriangle, CheckCheck, Clock, ShieldAlert, Package } from 'lucide-react';
import AdminLayout from '../components/AdminLayout';
import './AdminDealRoom.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const EXCEPTION = ['Disputed', 'Damaged/Wrong Product Reported'];
const OUTCOMES = [
  { value: 'release_payment', label: 'Release payment to creator' },
  { value: 'refund', label: 'Refund the brand (close deal)' },
  { value: 'new_deadline', label: 'Resume with a new deadline' },
  { value: 'resume', label: 'Resolve & resume as-is' }
];

const fmt = (v) => (v ? new Date(v).toLocaleString('en-IN', { day: 'numeric', month: 'short', hour: 'numeric', minute: '2-digit', hour12: true }) : '—');
const money = (n) => `₹${Number(n || 0).toLocaleString('en-IN')}`;

export default function AdminDealRoom() {
  const [deals, setDeals] = useState([]);
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [outcome, setOutcome] = useState('release_payment');
  const [resolution, setResolution] = useState('');
  const [newDeadline, setNewDeadline] = useState('');
  const [busy, setBusy] = useState(false);

  const load = async () => {
    try {
      const res = await axios.get(`${API}/deals`);
      const list = res.data || [];
      setDeals(list);
      setSelected((cur) => list.find((d) => d.deal_id === cur?.deal_id) || list[0] || null);
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to load deals');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = useMemo(() => {
    if (filter === 'exceptions') return deals.filter((d) => EXCEPTION.includes(d.current_state));
    if (filter === 'active') return deals.filter((d) => !EXCEPTION.includes(d.current_state) && d.current_state !== 'Paid - Complete');
    return deals;
  }, [deals, filter]);

  const exceptionCount = deals.filter((d) => EXCEPTION.includes(d.current_state)).length;
  const isException = selected && EXCEPTION.includes(selected.current_state);
  const processing = selected?.content_submission?.watermark_removal_processing;

  const resolve = async () => {
    if (!selected) return;
    setBusy(true);
    try {
      await axios.post(`${API}/deals/${selected.deal_id}/resolve`, {
        outcome,
        resolution: resolution.trim() || undefined,
        new_deadline_at: outcome === 'new_deadline' ? newDeadline || undefined : undefined
      });
      toast.success('Resolution applied');
      setResolution('');
      setNewDeadline('');
      await load();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Resolution failed');
    } finally {
      setBusy(false);
    }
  };

  const retryRelease = async () => {
    if (!selected) return;
    setBusy(true);
    try {
      await axios.post(`${API}/deals/${selected.deal_id}/release`);
      toast.success('Watermark removed and payment released');
      await load();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Release failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <AdminLayout>
      <div className="adr">
        <div className="adr-toolbar">
          <h2>Deal Room — Admin Oversight</h2>
          <div className="adr-filters">
            {[['all', `All (${deals.length})`], ['exceptions', `Needs Action (${exceptionCount})`], ['active', 'Active']].map(([k, label]) => (
              <button key={k} type="button" className={filter === k ? 'is-active' : ''} onClick={() => setFilter(k)}>{label}</button>
            ))}
          </div>
        </div>

        {loading ? (
          <p className="adr-empty">Loading deals…</p>
        ) : !filtered.length ? (
          <p className="adr-empty">No deals in this view.</p>
        ) : (
          <div className="adr-grid">
            <aside className="adr-list">
              {filtered.map((d) => (
                <button key={d.deal_id} type="button" className={`adr-list-item ${selected?.deal_id === d.deal_id ? 'is-active' : ''} ${EXCEPTION.includes(d.current_state) ? 'is-flagged' : ''}`} onClick={() => setSelected(d)}>
                  <strong>{d.campaign?.title || 'Untitled'}</strong>
                  <small>{d.deal_id}</small>
                  <span>{d.current_state}</span>
                  <em>{d.brand?.handle} ↔ {d.creator?.handle}</em>
                </button>
              ))}
            </aside>

            {selected && (
              <main className="adr-detail">
                <header className="adr-detail-head">
                  <div>
                    <h3>{selected.campaign?.title}</h3>
                    <p>{selected.deal_id} · Brand @{selected.brand?.handle} · Creator @{selected.creator?.handle}</p>
                  </div>
                  <span className={`adr-state-tag ${isException ? 'warn' : ''}`}>{selected.current_state}</span>
                </header>

                <div className="adr-stat-row">
                  <div><small>Active Party</small><strong>{selected.active_party}</strong></div>
                  <div><small>Escrow Held</small><strong>{money(selected.escrow?.held_amount)}</strong></div>
                  <div><small>Net Payable</small><strong>{money(selected.escrow?.net_payable)}</strong></div>
                  <div><small>Escrow Status</small><strong>{selected.escrow?.status}</strong></div>
                  <div><small>Next Deadline</small><strong>{fmt(selected.deadline)}</strong></div>
                </div>

                {(isException || selected.dispute?.reason || selected.receipt?.items_damaged) && (
                  <section className="adr-flag-card">
                    <div className="adr-flag-head"><ShieldAlert size={18} /> <strong>Issue under review</strong></div>
                    <p><small>Raised by</small> {selected.dispute?.raised_by || 'creator'}</p>
                    <p><small>Reason</small> {selected.dispute?.reason || selected.receipt?.damage_report || 'Damaged / wrong product reported'}</p>
                    <p><small>Evidence</small> {(selected.action_cards || []).flatMap((c) => c.attachment_urls || []).length || 0} file(s)</p>
                    <div className="adr-evidence">
                      {(selected.action_cards || []).flatMap((c) => c.attachment_urls || []).map((u, i) => (
                        <a key={i} href={u.startsWith('http') ? u : `${BACKEND_URL}${u}`} target="_blank" rel="noreferrer">Evidence {i + 1}</a>
                      ))}
                    </div>
                  </section>
                )}

                {processing && (
                  <section className="adr-flag-card processing">
                    <div className="adr-flag-head"><Package size={18} /> <strong>Watermark removal processing</strong></div>
                    <p>Post-approval watermark removal needs completion before the deal closes.</p>
                    <button type="button" className="adr-btn primary" disabled={busy} onClick={retryRelease}>Complete removal & release payment</button>
                  </section>
                )}

                <div className="adr-columns">
                  <section className="adr-panel">
                    <h4><Clock size={16} /> Activity</h4>
                    <ul className="adr-activity">
                      {(selected.activity_feed || []).map((e) => (
                        <li key={e.id}><CheckCheck size={14} /><div><strong>{e.actor_name}</strong><span>{e.message}</span><em>{fmt(e.timestamp)}</em></div></li>
                      ))}
                    </ul>
                  </section>

                  <section className="adr-panel">
                    <h4>Content versions</h4>
                    {(selected.content_submission?.versions || []).length ? (
                      <ul className="adr-versions">
                        {selected.content_submission.versions.map((v) => (
                          <li key={v.version}>
                            <strong>v{v.version}</strong>
                            <span>{v.status}</span>
                            {v.video_url && <a href={v.video_url.startsWith('http') ? v.video_url : `${BACKEND_URL}${v.video_url}`} target="_blank" rel="noreferrer">View</a>}
                          </li>
                        ))}
                      </ul>
                    ) : <p className="adr-muted">No content submitted yet.</p>}
                  </section>
                </div>

                {isException ? (
                  <section className="adr-resolve">
                    <h4><AlertTriangle size={16} /> Resolve</h4>
                    <label>Outcome</label>
                    <select value={outcome} onChange={(e) => setOutcome(e.target.value)}>
                      {OUTCOMES.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                    {outcome === 'new_deadline' && (
                      <>
                        <label>New deadline</label>
                        <input type="datetime-local" value={newDeadline} onChange={(e) => setNewDeadline(e.target.value)} />
                      </>
                    )}
                    <label>Resolution note (visible to both parties)</label>
                    <textarea value={resolution} onChange={(e) => setResolution(e.target.value)} rows={3} placeholder="Summarise the decision and reasoning…" />
                    <button type="button" className="adr-btn primary" disabled={busy} onClick={resolve}>{busy ? 'Applying…' : 'Apply resolution'}</button>
                  </section>
                ) : (
                  <p className="adr-muted adr-observe">Observing — no admin action required in this state. You can still intervene by resolving any dispute the parties raise.</p>
                )}
              </main>
            )}
          </div>
        )}
      </div>
    </AdminLayout>
  );
}
