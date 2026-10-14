import { useCallback, useEffect, useState } from 'react';
import axios from 'axios';
import { toast } from 'sonner';

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

// {amount} -> sample value; unknown placeholders stay as typed (same rule as the backend).
const fill = (text, samples) => (text || '').replace(/\{(\w+)\}/g, (m, k) => (k in samples ? samples[k] : m));
const same = (a, b) => (a || '').trim() === (b || '').trim();

const S = {
  card: { background: '#fff', border: '1px solid #e2e8f0', borderRadius: 14, marginBottom: 12, overflow: 'hidden' },
  head: { display: 'flex', alignItems: 'center', gap: 10, padding: '14px 18px', cursor: 'pointer', flexWrap: 'wrap' },
  chip: { fontSize: 12, fontWeight: 600, padding: '3px 10px', borderRadius: 20, background: '#eef1ff', color: '#4452c4' },
  body: { padding: '4px 18px 18px', borderTop: '1px solid #f1f5f9' },
  label: { display: 'block', fontSize: 13, fontWeight: 600, margin: '14px 0 6px', color: '#334155' },
  hint: { fontSize: 12, color: '#64748b', marginTop: 4 },
  preview: { background: '#f8fafc', border: '1px dashed #cbd5e1', borderRadius: 10, padding: 12, fontSize: 14, whiteSpace: 'pre-wrap' },
  ph: { fontFamily: 'monospace', fontSize: 12, padding: '2px 8px', borderRadius: 6, border: '1px solid #cbd5e1', background: '#fff', cursor: 'pointer' },
  btn: { padding: '9px 20px', fontSize: 14, borderRadius: 10 },
};

function TemplateCard({ ev, samples, onChanged }) {
  const o = ev.override || {};
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [focus, setFocus] = useState('message');
  // Email fields start as "same as the notification" until the admin writes separate text.
  const [f, setF] = useState({
    title: o.title || ev.title,
    message: o.message || ev.message,
    emailEnabled: o.email_enabled ?? ev.email,
    emailSubject: o.email_subject || o.title || ev.title,
    emailBody: o.email_body || o.message || ev.message,
  });
  const set = (k) => (e) => setF((p) => ({ ...p, [k]: e.target.value }));
  const edited = !!ev.override;

  const save = async () => {
    setBusy(true);
    try {
      await axios.put(`${API}/admin/notification-templates/${ev.key}`, {
        title: same(f.title, ev.title) ? '' : f.title,
        message: same(f.message, ev.message) ? '' : f.message,
        email_enabled: f.emailEnabled,
        email_subject: same(f.emailSubject, f.title) ? '' : f.emailSubject,
        email_body: same(f.emailBody, f.message) ? '' : f.emailBody,
      });
      toast.success('Saved - new notifications use this wording');
      onChanged();
    } catch (e) {
      toast.error(e.response?.data?.detail || 'Could not save');
    } finally {
      setBusy(false);
    }
  };

  const reset = async () => {
    setBusy(true);
    try {
      await axios.delete(`${API}/admin/notification-templates/${ev.key}`);
      toast.success('Back to the default wording');
      onChanged();
    } catch (e) {
      toast.error(e.response?.data?.detail || 'Could not reset');
    } finally {
      setBusy(false);
    }
  };

  const field = (k, rows) => {
    const common = { value: f[k], onChange: set(k), onFocus: () => setFocus(k) };
    return rows
      ? <textarea className="textarea-field" style={{ minHeight: 0 }} rows={rows} {...common} />
      : <input className="input-field" {...common} />;
  };

  return (
    <div style={S.card} data-testid={`template-${ev.key}`}>
      <div style={S.head} onClick={() => setOpen(!open)}>
        <strong style={{ flex: 1, minWidth: 180 }}>{ev.label}</strong>
        <span style={S.chip}>To: {ev.to}</span>
        <span style={{ ...S.chip, background: f.emailEnabled ? '#e8f8ee' : '#f1f5f9', color: f.emailEnabled ? '#15803d' : '#64748b' }}>
          Email {f.emailEnabled ? 'on' : 'off'}
        </span>
        {edited && <span style={{ ...S.chip, background: '#fff4e0', color: '#b45309' }}>Edited</span>}
        <span style={{ color: '#94a3b8' }}>{open ? '▲' : '▼'}</span>
      </div>

      {open && (
        <div style={S.body}>
          <label style={S.label}>Notification title (bell)</label>
          {field('title')}
          <label style={S.label}>Notification message (bell)</label>
          {field('message', 3)}

          <div style={{ marginTop: 10, display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={S.hint}>Auto-filled values - click to insert:</span>
            {ev.vars.length === 0 && <span style={S.hint}>none for this one</span>}
            {ev.vars.map((v) => (
              <button type="button" key={v} style={S.ph} title={`e.g. ${samples[v] ?? v}`}
                onClick={() => setF((p) => ({ ...p, [focus]: `${p[focus]}{${v}}` }))}>{`{${v}}`}</button>
            ))}
          </div>

          <label style={{ ...S.label, display: 'flex', alignItems: 'center', gap: 8 }}>
            <input type="checkbox" checked={f.emailEnabled}
              onChange={(e) => setF((p) => ({ ...p, emailEnabled: e.target.checked }))} />
            Also send this as an email
          </label>
          {f.emailEnabled && (
            <>
              <label style={S.label}>Email subject</label>
              {field('emailSubject')}
              <label style={S.label}>Email body</label>
              {field('emailBody', 4)}
              <div style={S.hint}>Starts as a copy of the notification. Change it only if the email should read differently.</div>
            </>
          )}

          <label style={S.label}>Preview (sample values)</label>
          <div style={S.preview}>
            <strong>{fill(f.title, samples)}</strong>{'\n'}{fill(f.message, samples)}
          </div>
          {f.emailEnabled && (
            <div style={{ ...S.preview, marginTop: 8 }}>
              <span style={S.hint}>Email - subject:</span> <strong>{fill(f.emailSubject, samples)}</strong>{'\n'}{fill(f.emailBody, samples)}
            </div>
          )}

          <div style={{ display: 'flex', gap: 10, marginTop: 16 }}>
            <button type="button" className="btn-primary" style={S.btn} disabled={busy} onClick={save}>Save changes</button>
            {edited && (
              <button type="button" style={{ ...S.btn, border: '1px solid #cbd5e1', background: '#fff', cursor: 'pointer' }}
                disabled={busy} onClick={reset}>Reset to default</button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function AdminNotificationTemplates() {
  const [data, setData] = useState(null);
  const [audience, setAudience] = useState('All');
  const [q, setQ] = useState('');

  const load = useCallback(async () => {
    try {
      const { data: d } = await axios.get(`${API}/admin/notification-templates`);
      setData(d);
    } catch (e) {
      toast.error(e.response?.data?.detail || 'Could not load notification templates');
    }
  }, []);
  useEffect(() => { load(); }, [load]);

  if (!data) return <p>Loading notifications...</p>;
  const shown = data.events.filter((ev) =>
    (audience === 'All' || ev.to === audience) &&
    (!q || `${ev.label} ${ev.title} ${ev.message}`.toLowerCase().includes(q.toLowerCase())));

  return (
    <div className="fade-in">
      <h2>Notification &amp; Email Templates</h2>
      <p style={{ color: '#64748b', maxWidth: 760 }}>
        Every automatic message the platform sends is listed here with its default wording already filled in.
        Edit any of it: the bell notification and the email. Words in {'{curly brackets}'} are filled in
        automatically (names, amounts, campaign titles). &quot;Reset to default&quot; goes back to the original text.
      </p>
      <div style={{ display: 'flex', gap: 10, margin: '16px 0', flexWrap: 'wrap' }}>
        <select className="input-field" style={{ width: 180 }} value={audience} onChange={(e) => setAudience(e.target.value)}>
          {['All', 'Creator', 'Brand', 'Either party', 'Any user'].map((a) => <option key={a}>{a}</option>)}
        </select>
        <input className="input-field" style={{ flex: 1, minWidth: 220 }} placeholder="Search notifications..."
          value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      {shown.map((ev) => (
        <TemplateCard key={ev.key + (ev.override?.updated_at || '')} ev={ev} samples={data.samples} onChanged={load} />
      ))}
      {shown.length === 0 && <p>No notifications match.</p>}
    </div>
  );
}
