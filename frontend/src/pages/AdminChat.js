import { useEffect, useState } from 'react';
import axios from 'axios';
import { toast } from 'sonner';
import { Shield, ShieldAlert, LogIn, Pause, FileDown, ListFilter, Send, RotateCcw } from 'lucide-react';
import AdminLayout from '../components/AdminLayout';
import './AdminChat.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;
const fmt = (v) => (v ? new Date(v).toLocaleString('en-IN', { day: 'numeric', month: 'short', hour: 'numeric', minute: '2-digit', hour12: true }) : '—');

export default function AdminChat() {
  const [tab, setTab] = useState('threads');
  const [threads, setThreads] = useState([]);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [adminMsg, setAdminMsg] = useState('');
  const [filterLog, setFilterLog] = useState([]);
  const [audit, setAudit] = useState([]);
  const [transcript, setTranscript] = useState(null);
  const [busy, setBusy] = useState(false);

  const loadThreads = async () => {
    try { setThreads((await axios.get(`${API}/chat/admin/threads`)).data || []); }
    catch (e) { toast.error(e.response?.data?.detail || 'Failed to load threads'); }
  };
  const openThread = async (id) => {
    setSelected(id); setTranscript(null);
    try { setDetail((await axios.get(`${API}/chat/admin/threads/${id}`)).data); }
    catch (e) { toast.error('Failed to load thread'); }
  };
  const loadFilterLog = async () => {
    try { setFilterLog((await axios.get(`${API}/chat/admin/filter-log`)).data || []); }
    catch (e) { toast.error('Failed to load filter log'); }
  };
  const loadAudit = async () => {
    try { setAudit((await axios.get(`${API}/chat/admin/audit`)).data || []); }
    catch (e) { toast.error('Failed to load audit log'); }
  };

  useEffect(() => { loadThreads(); }, []);
  useEffect(() => {
    if (tab === 'filter') loadFilterLog();
    if (tab === 'audit') loadAudit();
  }, [tab]);

  const run = async (fn, msg) => {
    setBusy(true);
    try { await fn(); if (msg) toast.success(msg); }
    catch (e) { toast.error(e.response?.data?.detail || 'Action failed'); }
    finally { setBusy(false); }
  };

  const join = () => run(async () => { await axios.post(`${API}/chat/admin/threads/${selected}/join`); await openThread(selected); }, 'Joined — both parties notified');
  const post = () => run(async () => {
    if (!adminMsg.trim()) return;
    await axios.post(`${API}/chat/admin/threads/${selected}/message`, { message: adminMsg.trim() });
    setAdminMsg(''); await openThread(selected);
  }, 'Posted as admin');
  const pause = (uid) => run(async () => { await axios.post(`${API}/chat/admin/users/${uid}/pause`, { hours: 1 }); }, 'User chat paused 1h');
  const downgrade = (uid) => run(async () => { await axios.post(`${API}/chat/admin/users/${uid}/downgrade`, { days: 14 }); }, 'User downgraded to Action-Cards-Only 14d');
  const restore = (uid) => run(async () => { await axios.post(`${API}/chat/admin/users/${uid}/restore`); }, 'User chat restored');
  const exportT = () => run(async () => { setTranscript((await axios.get(`${API}/chat/admin/threads/${selected}/export`)).data); }, 'Transcript exported');

  return (
    <AdminLayout>
      <div className="ach">
        <div className="ach-tabs">
          {[['threads', 'Threads', Shield], ['filter', 'Filter Log', ListFilter], ['audit', 'Audit Trail', FileDown]].map(([k, label, Icon]) => (
            <button key={k} className={tab === k ? 'is-active' : ''} onClick={() => setTab(k)}><Icon size={15} /> {label}</button>
          ))}
        </div>

        {tab === 'threads' && (
          <div className="ach-grid">
            <aside className="ach-list">
              {threads.length ? threads.map((t) => (
                <button key={t.thread_id} className={`ach-list-item ${selected === t.thread_id ? 'is-active' : ''}`} onClick={() => openThread(t.thread_id)}>
                  <strong>{t.participants.map((p) => p.nickname).join(' ↔ ')}</strong>
                  <small>{t.participants.map((p) => p.role).join(' / ')}</small>
                  <em>{t.last_message?.message?.slice(0, 40) || 'No messages'}</em>
                  {t.admin_joined ? <span className="ach-joined">admin in thread</span> : null}
                </button>
              )) : <p className="ach-muted">No threads yet.</p>}
            </aside>

            <main className="ach-detail">
              {!detail ? <p className="ach-muted">Select a thread to audit.</p> : (
                <>
                  <header className="ach-detail-head">
                    <div>
                      <h3>{detail.participants.map((p) => p.nickname).join(' ↔ ')}</h3>
                      <p>{detail.participants.map((p) => `${p.nickname} (${p.role})`).join(' · ')}</p>
                    </div>
                    <div className="ach-head-actions">
                      <button disabled={busy || detail.admin_joined} onClick={join}><LogIn size={14} /> {detail.admin_joined ? 'Joined' : 'Join'}</button>
                      <button disabled={busy} onClick={exportT}><FileDown size={14} /> Export</button>
                    </div>
                  </header>

                  <div className="ach-mod-row">
                    {detail.participants.map((p) => (
                      <div key={p.id} className="ach-mod-user">
                        <span>{p.nickname}</span>
                        <button disabled={busy} onClick={() => pause(p.id)} title="Pause 1h"><Pause size={13} /></button>
                        <button disabled={busy} onClick={() => downgrade(p.id)} title="Action-Cards-Only 14d"><ShieldAlert size={13} /></button>
                        <button disabled={busy} onClick={() => restore(p.id)} title="Restore"><RotateCcw size={13} /></button>
                      </div>
                    ))}
                  </div>

                  <div className="ach-messages">
                    {detail.messages.map((m) => (
                      <div key={m.id} className={`ach-msg ${m.sender_type}`}>
                        <span className="ach-msg-who">{m.sender_type === 'admin' ? 'ADMIN' : m.item_type === 'system' ? 'SYSTEM' : detail.participants.find((p) => p.id === m.sender_id)?.nickname || 'User'}</span>
                        {m.item_type === 'action_card'
                          ? <span className="ach-msg-card">[{m.type}] {Object.entries(m.fields || {}).slice(0, 4).map(([k, v]) => `${k}: ${v}`).join(', ')} · {m.card_status}</span>
                          : <span>{m.message}{m.attachment_urls?.length ? ` (${m.attachment_urls.length} file)` : ''}</span>}
                        <em>{fmt(m.created_at)}</em>
                      </div>
                    ))}
                  </div>

                  {detail.admin_joined && (
                    <div className="ach-post">
                      <input value={adminMsg} onChange={(e) => setAdminMsg(e.target.value)} placeholder="Post as UGCAD.IO Admin…" onKeyDown={(e) => e.key === 'Enter' && post()} />
                      <button disabled={busy} onClick={post}><Send size={15} /></button>
                    </div>
                  )}

                  {transcript && (
                    <div className="ach-transcript">
                      <h4>Transcript ({transcript.count} items)</h4>
                      <textarea readOnly value={transcript.transcript} rows={8} />
                    </div>
                  )}
                </>
              )}
            </main>
          </div>
        )}

        {tab === 'filter' && (
          <div className="ach-table-wrap">
            <table className="ach-table">
              <thead><tr><th>When</th><th>User</th><th>Role</th><th>Category</th><th>Matched</th><th>Snippet</th><th>FP</th></tr></thead>
              <tbody>
                {filterLog.length ? filterLog.map((s, i) => (
                  <tr key={i}>
                    <td>{fmt(s.at)}</td><td>{s.nickname}</td><td>{s.role}</td><td>{s.category}</td>
                    <td>{(s.matched || []).join(', ')}</td><td className="ach-snip">{s.snippet}</td>
                    <td>{s.false_positive ? '✓' : ''}</td>
                  </tr>
                )) : <tr><td colSpan={7} className="ach-muted">No filter strikes logged.</td></tr>}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'audit' && (
          <div className="ach-table-wrap">
            <table className="ach-table">
              <thead><tr><th>When</th><th>Admin</th><th>Action</th><th>Detail</th></tr></thead>
              <tbody>
                {audit.length ? audit.map((a) => (
                  <tr key={a._id}>
                    <td>{fmt(a.createdAt)}</td><td>{a.admin_id?.nickname || a.admin_id?.email || 'system'}</td>
                    <td>{a.action}</td><td className="ach-snip">{a.detail}</td>
                  </tr>
                )) : <tr><td colSpan={4} className="ach-muted">No admin actions logged.</td></tr>}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </AdminLayout>
  );
}
