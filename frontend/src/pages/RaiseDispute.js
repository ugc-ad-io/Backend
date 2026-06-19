import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'sonner';
import { ArrowLeft, ShieldAlert, Upload } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const TYPES = [
  ['non_delivery', 'Non-delivery'],
  ['quality_below_brief', 'Quality below brief'],
  ['damaged_wrong', 'Damaged / wrong product'],
  ['scope_creep', 'Scope creep'],
  ['revision_abuse', 'Revision abuse'],
  ['communication_issue', 'Communication issue'],
  ['off_platform_attempt', 'Off-platform attempt'],
  ['payment_issue', 'Payment issue'],
  ['other', 'Other'],
];
const OUTCOMES = [
  ['full_refund', 'Full refund'],
  ['partial_refund', 'Partial refund'],
  ['extension', 'Deadline extension'],
  ['redo', 'Content re-do'],
  ['reassignment', 'Creator reassignment'],
  ['other', 'Other'],
];

// PRD 9.3 — structured dispute intake.
export default function RaiseDispute() {
  const { dealId } = useParams();
  const navigate = useNavigate();
  const [form, setForm] = useState({ dispute_type: '', description: '', desired_outcome: '', evidence_urls: [] });
  const [busy, setBusy] = useState(false);
  const [uploading, setUploading] = useState(false);

  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));

  const uploadEvidence = async (files) => {
    const list = Array.from(files || []);
    if (!list.length) return;
    setUploading(true);
    try {
      const urls = await Promise.all(list.map(async (file) => {
        const fd = new FormData();
        fd.append('file', file);
        const res = await axios.post(`${API}/uploads`, fd, { headers: { 'Content-Type': 'multipart/form-data' } });
        return res.data?.file_url;
      }));
      set('evidence_urls', [...form.evidence_urls, ...urls.filter(Boolean)]);
      toast.success('Evidence uploaded');
    } catch {
      toast.error('Upload failed');
    } finally {
      setUploading(false);
    }
  };

  const submit = async () => {
    if (!form.dispute_type) return toast.error('Select a dispute type');
    if (!form.desired_outcome) return toast.error('Select a desired outcome');
    if (form.description.trim().length < 100) return toast.error('Description must be at least 100 characters');
    if (form.evidence_urls.length < 1) return toast.error('Attach at least one piece of evidence');
    setBusy(true);
    try {
      await axios.post(`${API}/deals/${dealId}/raise-dispute`, form);
      toast.success('Dispute raised. Deal activity is paused while our team reviews.');
      navigate(-1);
    } catch (err) {
      const d = err.response?.data?.detail;
      toast.error((typeof d === 'string' ? d : d?.message) || 'Failed to raise dispute');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rd-page">
      <button className="rd-back" onClick={() => navigate(-1)}><ArrowLeft size={18} /> Back</button>
      <h1><ShieldAlert size={22} /> Raise a dispute</h1>
      <p className="rd-muted">Be specific and factual. A clear, evidence-backed dispute resolves faster.</p>

      <label className="rd-label">Dispute type *</label>
      <select className="rd-input" value={form.dispute_type} onChange={(e) => set('dispute_type', e.target.value)}>
        <option value="">Select…</option>
        {TYPES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
      </select>

      <label className="rd-label">Description * (100–1000 characters)</label>
      <textarea className="rd-input rd-area" value={form.description} maxLength={1000} onChange={(e) => set('description', e.target.value)} placeholder="What happened, when, and why it breaches the brief…" />
      <small className="rd-muted">{form.description.length}/1000</small>

      <label className="rd-label">Desired outcome *</label>
      <select className="rd-input" value={form.desired_outcome} onChange={(e) => set('desired_outcome', e.target.value)}>
        <option value="">Select…</option>
        {OUTCOMES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
      </select>

      <label className="rd-label">Evidence * (at least 1)</label>
      <label className="rd-upload"><Upload size={16} /> {uploading ? 'Uploading…' : 'Upload screenshots / photos / video'}
        <input type="file" multiple hidden onChange={(e) => uploadEvidence(e.target.files)} />
      </label>
      {form.evidence_urls.length > 0 && <p className="rd-muted">{form.evidence_urls.length} file(s) attached</p>}

      <button className="rd-submit" onClick={submit} disabled={busy}>{busy ? 'Submitting…' : 'Submit dispute'}</button>

      <style jsx>{`
        .rd-page { max-width: 640px; margin: 0 auto; padding: 28px 20px 60px; color: #111827; }
        .rd-muted { color: #6b7280; font-size: 13px; }
        .rd-back { display: inline-flex; align-items: center; gap: 6px; background: none; border: none; color: #4f46e5; cursor: pointer; font-size: 14px; margin-bottom: 10px; }
        .rd-page h1 { display: flex; align-items: center; gap: 8px; font-size: 24px; margin: 0 0 4px; }
        .rd-label { display: block; font-weight: 600; font-size: 13px; margin: 18px 0 6px; }
        .rd-input { width: 100%; border: 1px solid #e5e7eb; border-radius: 9px; padding: 10px 12px; font-size: 14px; }
        .rd-area { min-height: 130px; resize: vertical; }
        .rd-upload { display: inline-flex; align-items: center; gap: 8px; border: 1px dashed #c7d2fe; color: #4f46e5; border-radius: 9px; padding: 12px 16px; cursor: pointer; font-size: 14px; }
        .rd-submit { display: block; width: 100%; margin-top: 24px; background: #dc2626; color: #fff; border: none; border-radius: 10px; padding: 12px; font-size: 15px; font-weight: 600; cursor: pointer; }
        .rd-submit:disabled { opacity: .5; cursor: not-allowed; }
      `}</style>
    </div>
  );
}
