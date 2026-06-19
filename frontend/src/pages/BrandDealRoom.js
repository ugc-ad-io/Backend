import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import {
  AlertTriangle,
  Archive,
  CheckCheck,
  CheckCircle,
  ChevronDown,
  ClipboardList,
  Clock,
  FileCheck,
  FileText,
  Flag,
  Headphones,
  LayoutGrid,
  MessageSquare,
  MoreHorizontal,
  Package,
  Paperclip,
  Play,
  RotateCcw,
  Send,
  Settings,
  ShieldAlert,
  SquarePen,
  Truck,
  UserRoundSearch,
  Wallet
} from 'lucide-react';
import { EmptyPanel, formatMoney, getInitial } from '../components/CreatorComponents';
import DashboardLayout from '../components/DashboardLayout';
import './MyDealsPage.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const DEAL_STATES = [
  'Accepted - Awaiting Shipment',
  'Shipped - In Transit',
  'Delivered - Awaiting Receipt Confirmation',
  'Received - Content in Progress',
  'Content Submitted - Awaiting Review',
  'Revision Requested',
  'Approved - Payment Processing',
  'Paid - Complete'
];
const EXCEPTION_STATES = ['Disputed', 'Damaged/Wrong Product Reported'];

function normalizeDash(value) {
  return String(value || '').replace(/\s*(?:—|–|-)\s*/g, ' - ');
}
function stateKey(value) {
  return normalizeDash(value).toLowerCase();
}
function getState(deal) {
  return normalizeDash(deal?.current_state || 'Status unavailable');
}
function isState(deal, state) {
  return stateKey(getState(deal)) === stateKey(state);
}
function isDamageState(deal) {
  return stateKey(getState(deal)) === stateKey('Damaged/Wrong Product Reported');
}
function isDisputed(deal) {
  return stateKey(getState(deal)) === stateKey('Disputed');
}
function getCreatorHandle(deal) {
  return deal?.creator?.handle || deal?.creator_handle || 'Creator';
}
function getDealTitle(deal) {
  return deal?.campaign?.title || 'Untitled campaign';
}
function getDealId(deal) {
  return deal?.deal_id || deal?.campaign?.id || 'Deal ID unavailable';
}
function getCountdownLabel(deal) {
  if (isDamageState(deal) || isDisputed(deal)) return 'On hold (admin review)';
  const hours = deal?.deadline_countdown_hours;
  if (typeof hours === 'number') return `${Math.max(0, hours)} hrs left`;
  return 'Deadline pending';
}
function formatDateTime(value) {
  if (!value) return 'Not scheduled';
  return new Date(value).toLocaleString('en-IN', { day: 'numeric', month: 'short', year: 'numeric', hour: 'numeric', minute: '2-digit', hour12: true });
}
function formatDate(value) {
  if (!value) return 'Not available';
  return new Date(value).toLocaleDateString('en-IN');
}
function getAssetUrl(url) {
  if (!url) return '';
  return url.startsWith('http') ? url : `${BACKEND_URL}${url}`;
}

function getPrimaryAction(deal) {
  if (!deal) return { label: 'No deal selected', type: 'none', disabled: true };
  if (isState(deal, 'Accepted - Awaiting Shipment')) return { label: 'Upload Tracking ID', type: 'tracking', disabled: false };
  if (isState(deal, 'Shipped - In Transit')) return { label: 'Mark Delivered', type: 'delivered', disabled: false };
  if (isState(deal, 'Content Submitted - Awaiting Review')) return { label: 'Review Content', type: 'review', disabled: false };
  if (isState(deal, 'Paid - Complete')) return { label: 'Archive Deal', type: 'archive', disabled: false };
  return { label: deal.primary_next_action || 'Waiting on the other party', type: 'passive', disabled: true };
}

export default function BrandDealRoom() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [deals, setDeals] = useState([]);
  const [selectedDeal, setSelectedDeal] = useState(null);
  const [loading, setLoading] = useState(true);
  const [briefOpen, setBriefOpen] = useState(false);
  const [message, setMessage] = useState('');
  const [mobileSection, setMobileSection] = useState('workspace');
  const [showAllActivity, setShowAllActivity] = useState(false);

  // tracking form
  const [trackingId, setTrackingId] = useState('');
  const [courier, setCourier] = useState('');
  const [trackingUrl, setTrackingUrl] = useState('');
  const [expectedDelivery, setExpectedDelivery] = useState('');

  // modals
  const [confirmApprove, setConfirmApprove] = useState(false);
  const [revisionOpen, setRevisionOpen] = useState(false);
  const [revisionFeedback, setRevisionFeedback] = useState('');
  const [busy, setBusy] = useState(false);

  const navItems = [
    { name: 'Brand Dashboard', icon: LayoutGrid, action: () => navigate('/dashboard/business') },
    { name: 'Post a Brief', icon: SquarePen, action: () => navigate('/dashboard/business/post-brief') },
    { name: 'Creator Bids', icon: UserRoundSearch, action: () => navigate('/dashboard/business/pending-bids') },
    { name: 'All Campaigns', icon: ClipboardList, action: () => navigate('/dashboard/business/all-campaigns') },
    { name: 'Deal Room', icon: FileCheck, action: () => navigate('/dashboard/business/deal-room'), active: true },
    { name: 'Messages', icon: MessageSquare, action: () => navigate('/messages') },
    { name: 'Manage Shipment', icon: Package, action: () => navigate('/dashboard/business/shipments') },
    { name: 'Wallet', icon: Wallet, action: () => navigate('/dashboard/business/wallet') },
    { name: 'Settings', icon: Settings, action: () => navigate('/settings') }
  ];

  useEffect(() => {
    if (user?.id) fetchDeals();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id]);

  const fetchDeals = async () => {
    try {
      const res = await axios.get(`${API}/deals/business`);
      const list = res.data || [];
      setDeals(list);
      setSelectedDeal((current) => list.find((d) => getDealId(d) === getDealId(current)) || list[0] || null);
    } catch (err) {
      toast.error('Failed to load deals');
    } finally {
      setLoading(false);
    }
  };

  const act = async (fn) => {
    if (busy) return;
    setBusy(true);
    try {
      await fn();
      await fetchDeals();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Action failed');
    } finally {
      setBusy(false);
    }
  };

  const handleUploadTracking = () =>
    act(async () => {
      if (!trackingId.trim()) return toast.error('Tracking ID is required');
      await axios.post(`${API}/deals/${selectedDeal.deal_id}/tracking`, {
        tracking_id: trackingId.trim(),
        courier: courier.trim() || undefined,
        courier_tracking_url: trackingUrl.trim() || undefined,
        expected_delivery_at: expectedDelivery || undefined
      });
      setTrackingId('');
      setCourier('');
      setTrackingUrl('');
      setExpectedDelivery('');
      toast.success('Tracking uploaded — product marked shipped');
    });

  const handleMarkDelivered = () =>
    act(async () => {
      await axios.post(`${API}/deals/${selectedDeal.deal_id}/delivered`);
      toast.success('Marked delivered');
    });

  const handleApprove = () =>
    act(async () => {
      await axios.post(`${API}/deals/${selectedDeal.deal_id}/approve`);
      setConfirmApprove(false);
      toast.success('Content approved — payment released');
    });

  const handleRequestRevision = () =>
    act(async () => {
      if (!revisionFeedback.trim()) return toast.error('Please add revision feedback');
      await axios.post(`${API}/deals/${selectedDeal.deal_id}/request-revision`, {
        feedback: revisionFeedback.trim(),
        requested_changes: revisionFeedback.split('\n').map((s) => s.trim()).filter(Boolean)
      });
      setRevisionOpen(false);
      setRevisionFeedback('');
      toast.success('Revision requested');
    });

  const handleSendMessage = () =>
    act(async () => {
      if (!message.trim()) return;
      await axios.post(`${API}/deals/${selectedDeal.deal_id}/chat`, { message: message.trim() });
      setMessage('');
    });

  const handleActionCard = (label) =>
    act(async () => {
      if (label === 'Raise Dispute') {
        await axios.post(`${API}/deals/${selectedDeal.deal_id}/dispute`, { message: 'Brand raised a dispute from the Deal Room' });
      } else if (label === 'Escalate to Admin' || label === 'Get Help') {
        await axios.post(`${API}/deals/${selectedDeal.deal_id}/escalate`, { message: 'Brand requested admin assistance' });
      } else {
        await axios.post(`${API}/deals/${selectedDeal.deal_id}/action-card`, { type: 'milestone_update', message: label });
      }
      toast.success(`${label} sent`);
    });

  const handleArchive = () =>
    act(async () => {
      await axios.post(`${API}/deals/${selectedDeal.deal_id}/archive`);
      toast.success('Deal archived');
    });

  const primary = getPrimaryAction(selectedDeal);
  const handlePrimary = () => {
    if (primary.disabled) return;
    if (primary.type === 'delivered') return handleMarkDelivered();
    if (primary.type === 'review') {
      setMobileSection('workspace');
      document.getElementById('brand-review-card')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      return;
    }
    if (primary.type === 'archive') return handleArchive();
    if (primary.type === 'tracking') {
      document.getElementById('brand-tracking-card')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  const activeDeals = deals.filter((d) => !['paid - complete', 'disputed', 'damaged/wrong product reported'].includes(stateKey(d.current_state)));
  const awaitingMe = deals.filter((d) => d.active_party === 'brand' && !isDamageState(d) && !isDisputed(d));
  const pastDeals = deals.filter((d) => stateKey(d.current_state) === 'paid - complete');
  const exceptionDeals = deals.filter((d) => EXCEPTION_STATES.some((s) => stateKey(s) === stateKey(d.current_state)));

  const activity = useMemo(() => selectedDeal?.activity_feed || [], [selectedDeal]);
  const visibleActivity = showAllActivity ? activity : activity.slice(0, 5);
  const escrow = selectedDeal?.escrow || {};
  const revision = selectedDeal?.revision_tracker || {};
  const versions = selectedDeal?.content_submission?.versions || [];
  const watermarked = selectedDeal?.content_submission?.watermark_required_until_approval;
  const messages = selectedDeal?.chat_summary?.messages || [];
  const brandIsActive = selectedDeal?.active_party === 'brand' && !isDamageState(selectedDeal) && !isDisputed(selectedDeal);

  if (loading) {
    return (
      <DashboardLayout navItems={navItems} sidebarVariant="business-match" title="Deal Room" description="Brand-side delivery workspace">
        <div className="deal-page"><EmptyPanel text="Loading..." /></div>
      </DashboardLayout>
    );
  }
  if (!deals.length) {
    return (
      <DashboardLayout navItems={navItems} sidebarVariant="business-match" title="Deal Room" description="Brand-side delivery workspace">
        <div className="deal-page"><EmptyPanel text="No active deals yet. Accept a creator bid to open a Deal Room." /></div>
      </DashboardLayout>
    );
  }

  const groups = [
    ['Active Deals', activeDeals],
    ['Awaiting My Action', awaitingMe],
    ['Past Deals', pastDeals],
    ['Disputed Deals', exceptionDeals]
  ];

  return (
    <DashboardLayout navItems={navItems} sidebarVariant="business-match" title="Deal Room" description="Brand-side delivery workspace">
      <div className="deal-page">
        {/* Status header */}
        <section className="deal-status-header">
          <div className="deal-brand-logo">{getInitial(getCreatorHandle(selectedDeal))}</div>
          <div className="deal-status-copy">
            <p>@{getCreatorHandle(selectedDeal)}</p>
            <h2>{getDealTitle(selectedDeal)}</h2>
            <span>{getDealId(selectedDeal)}</span>
          </div>
          <div className="deal-header-metrics">
            <div className="deal-header-pill is-state"><small>Current State</small><strong>{getState(selectedDeal)}</strong></div>
            <div className="deal-header-pill"><small>Active Party</small><strong>{selectedDeal?.active_party || 'Not assigned'}</strong></div>
            <div className="deal-header-pill"><small>Brand Status</small><strong>{brandIsActive ? 'Action needed' : 'Waiting'}</strong></div>
            <div className={`deal-header-pill ${brandIsActive ? 'is-urgent' : ''}`}><small>Deadline</small><strong>{getCountdownLabel(selectedDeal)}</strong></div>
            <div className="deal-header-pill"><small>Escrow</small><strong>{formatMoney(escrow.held_amount || 0)} held</strong></div>
          </div>
          <div className="deal-header-pill is-next-step">
            <div className="deal-next-step-copy">
              <small>Due</small>
              <strong>{formatDateTime(selectedDeal?.deadline)}</strong>
            </div>
            <div className="deal-header-actions">
              <button type="button" className="deal-primary-action" disabled={primary.disabled} onClick={handlePrimary}>
                {primary.label}
              </button>
              <div className="deal-more">
                <button type="button" aria-label="More deal actions"><MoreHorizontal size={18} /></button>
                <div>
                  <button type="button" onClick={() => handleActionCard('Raise Dispute')}>Raise Dispute</button>
                  <button type="button" onClick={() => handleActionCard('Get Help')}>Get Help</button>
                  <button type="button" onClick={handleArchive}><Archive size={14} /> Archive if completed</button>
                </div>
              </div>
            </div>
          </div>
        </section>

        <div className="deal-mobile-tabs" role="tablist">
          {['deals', 'workspace', 'chat'].map((s) => (
            <button key={s} type="button" className={mobileSection === s ? 'is-active' : ''} onClick={() => setMobileSection(s)}>{s}</button>
          ))}
        </div>

        <div className={`deal-room-grid show-${mobileSection}`}>
          {/* Left nav */}
          <aside className="deal-nav-panel">
            {groups.map(([label, list]) => (
              <section key={label}>
                <div className="deal-nav-heading"><span>{label}</span><em>{list.length}</em></div>
                {list.length ? list.map((deal) => (
                  <button
                    key={`${label}-${getDealId(deal)}`}
                    type="button"
                    className={getDealId(selectedDeal) === getDealId(deal) ? 'is-active' : ''}
                    onClick={() => setSelectedDeal(deal)}
                  >
                    <strong>{getDealTitle(deal)}</strong>
                    <small>@{getCreatorHandle(deal)} - {getState(deal)}</small>
                    <em>{deal.primary_next_action || 'No action pending'} - {getCountdownLabel(deal)}</em>
                  </button>
                )) : <p>No deals</p>}
              </section>
            ))}
          </aside>

          {/* Workspace */}
          <main className="deal-workspace">
            <section className="deal-card deal-brief-card">
              <button type="button" className="deal-brief-toggle" onClick={() => setBriefOpen((v) => !v)}>
                <span><FileText size={18} /></span>
                <strong>Full Campaign Brief</strong>
                <em>Usage rights highlighted</em>
                <ChevronDown size={18} className={briefOpen ? 'is-open' : ''} />
              </button>
              {briefOpen && (
                <div className="deal-brief-body">
                  {(selectedDeal?.brief_sections || []).map((s) => (
                    <article key={s.title} className={s.title === 'Usage Rights' ? 'is-rights' : ''}>
                      <h3>{s.title}</h3>
                      <p>{s.content || 'Not specified'}</p>
                    </article>
                  ))}
                </div>
              )}
            </section>

            <section className="deal-card deal-activity">
              <div className="deal-section-title"><span><Clock size={18} /></span><div><h2>Activity Feed</h2><p>Chronological deal state transitions</p></div></div>
              <div className="deal-timeline">
                {activity.length ? visibleActivity.map((e) => (
                  <div key={e.id} className="deal-timeline-item">
                    <span className="blue"><CheckCheck size={16} /></span>
                    <article><header><strong>{e.actor_name || e.actor_type}</strong><small>{formatDateTime(e.timestamp)}</small></header><p>{e.message}</p></article>
                  </div>
                )) : <EmptyPanel text="No activity yet." />}
              </div>
              {activity.length > 5 && (
                <button type="button" className="deal-expand-timeline" onClick={() => setShowAllActivity((v) => !v)}>
                  {showAllActivity ? 'Show fewer activities' : `Show ${activity.length - 5} more`}
                </button>
              )}
            </section>

            {/* Shipping block — brand uploads tracking in state 1 */}
            <section className="deal-card deal-shipping-card" id="brand-tracking-card">
              <div className="deal-section-title"><span><Truck size={18} /></span><div><h2>Shipping</h2><p>Coordinate product delivery to the creator</p></div></div>
              {selectedDeal?.shipment?.tracking_id ? (
                <div className="deal-receipt-grid">
                  <p><small>Tracking ID</small>{selectedDeal.shipment.courier_tracking_url ? <a href={selectedDeal.shipment.courier_tracking_url} target="_blank" rel="noreferrer">{selectedDeal.shipment.tracking_id}</a> : <strong>{selectedDeal.shipment.tracking_id}</strong>}</p>
                  <p><small>Courier Status</small><strong>{selectedDeal.shipment.courier_status || 'Not available'}</strong></p>
                  <p><small>Expected Delivery</small><strong>{formatDate(selectedDeal.shipment.expected_delivery_at)}</strong></p>
                  <p><small>Date Received</small><strong>{formatDate(selectedDeal.receipt?.received_at)}</strong></p>
                </div>
              ) : isState(selectedDeal, 'Accepted - Awaiting Shipment') ? (
                <div className="deal-tracking-form">
                  <label>Tracking ID *</label>
                  <input value={trackingId} onChange={(e) => setTrackingId(e.target.value)} placeholder="e.g. DELHIVERY-12345678" />
                  <label>Courier</label>
                  <input value={courier} onChange={(e) => setCourier(e.target.value)} placeholder="Delhivery / BlueDart" />
                  <label>Tracking URL</label>
                  <input value={trackingUrl} onChange={(e) => setTrackingUrl(e.target.value)} placeholder="https://..." />
                  <label>Expected Delivery</label>
                  <input type="date" value={expectedDelivery} onChange={(e) => setExpectedDelivery(e.target.value)} />
                  <button type="button" className="deal-submit" disabled={busy || !trackingId.trim()} onClick={handleUploadTracking}>
                    <Truck size={16} /> {busy ? 'Saving...' : 'Upload Tracking & Mark Shipped'}
                  </button>
                </div>
              ) : (
                <div className="deal-pause-note">Waiting for shipment details or already delivered.</div>
              )}
              {isState(selectedDeal, 'Shipped - In Transit') && (
                <button type="button" className="deal-secondary-action" disabled={busy} onClick={handleMarkDelivered}>Mark Delivered (simulate courier)</button>
              )}
            </section>

            {/* Content review */}
            <section className="deal-card deal-delivery-card" id="brand-review-card">
              <div className="deal-section-title"><span><FileCheck size={18} /></span><div><h2>Content Review</h2><p>{watermarked ? 'Watermarked preview until you approve' : 'Approved — full-resolution unlocked'}</p></div></div>
              {watermarked && versions.length ? <div className="deal-watermark">Watermarked preview until brand approval</div> : null}
              {selectedDeal?.content_submission?.watermark_removal_processing && (
                <div className="deal-pause-note">Processing: removing watermark and finalising delivery…</div>
              )}
              <div className="deal-version-row">
                {versions.length ? versions.map((v) => (
                  <article key={v.version}>
                    <div className="deal-preview-tile">
                      {v.thumbnail_url ? <img src={getAssetUrl(v.thumbnail_url)} alt={`v${v.version}`} /> : v.video_url ? <video src={getAssetUrl(v.video_url)} /> : <Play size={24} />}
                      {watermarked && v.status !== 'approved' && <b>UGCAD.IO Preview</b>}
                      {v.video_url && <a href={getAssetUrl(v.video_url)} target="_blank" rel="noreferrer" aria-label={`Open v${v.version}`}><Play size={16} /></a>}
                    </div>
                    <strong>v{v.version}</strong>
                    <small>{formatDateTime(v.submitted_at)}</small>
                    <span>{v.status}</span>
                  </article>
                )) : <article><strong>No content yet</strong><small>Creator has not submitted</small><span>Awaiting submission</span></article>}
              </div>
              {isState(selectedDeal, 'Content Submitted - Awaiting Review') && (
                <div className="deal-revision-actions">
                  <button type="button" className="deal-submit" disabled={busy} onClick={() => setConfirmApprove(true)}>
                    <CheckCircle size={16} /> Approve & Release Payment
                  </button>
                  <button
                    type="button"
                    disabled={busy || selectedDeal.revisions_remaining === 0}
                    onClick={() => setRevisionOpen(true)}
                  >
                    <RotateCcw size={16} /> Request Revision ({selectedDeal.revisions_remaining ?? 0} left)
                  </button>
                </div>
              )}
            </section>

            <section className="deal-card deal-revisions">
              <div className="deal-section-title"><span className="warn"><RotateCcw size={18} /></span><div><h2>Revision Tracker</h2><p>Revision {revision.revision_count_used || 0} of {revision.revision_limit || 0} used</p></div></div>
              <div className="deal-revision-box">
                <p><small>Latest Feedback</small><strong>{revision.latest_feedback || 'No revision requested yet.'}</strong></p>
                <p><small>Requested Changes</small><strong>{revision.requested_changes?.length ? revision.requested_changes.join(', ') : 'None'}</strong></p>
                <p><small>New Deadline</small><strong>{formatDateTime(revision.new_deadline_at)}</strong></p>
              </div>
            </section>
          </main>

          {/* Right panel — chat + escrow */}
          <aside className="deal-right-column">
            <div className="deal-right-panel">
              <div className="deal-chat">
                <div className="deal-pinned"><AlertTriangle size={16} /><strong>{getState(selectedDeal)}</strong><span>{selectedDeal?.primary_next_action} - {getCountdownLabel(selectedDeal)}</span></div>
                <div className="deal-message-list">
                  {messages.length ? messages.map((m) => (
                    <p key={m.id} className={m.sender_type === 'brand' ? 'brand' : m.sender_type === 'system' ? 'system' : 'creator'}>
                      {m.sender_name}: {m.message}
                    </p>
                  )) : <p className="system">No messages yet.</p>}
                </div>
                <div className="deal-support-actions">
                  <div className="deal-action-section-title"><h3>Support Actions</h3></div>
                  <div className="deal-action-menu">
                    {['Milestone Update', 'Escalate to Admin', 'Raise Dispute'].map((l) => (
                      <button key={l} type="button" onClick={() => handleActionCard(l)}>{l}</button>
                    ))}
                  </div>
                </div>
                <div className="deal-chat-input">
                  <button type="button" aria-label="Attach"><Paperclip size={17} /></button>
                  <input value={message} onChange={(e) => setMessage(e.target.value)} placeholder="Message this deal thread" onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()} />
                  <button type="button" onClick={handleSendMessage}><Send size={17} /></button>
                </div>
              </div>
            </div>

            <div className="deal-payout-section">
              <div className="deal-action-section-title"><h3>Escrow Summary</h3></div>
              <div className="deal-payout-tab">
                <p><span>Escrow Held</span><strong>{formatMoney(escrow.held_amount || 0)}</strong></p>
                <p><span>Net Payable</span><strong>{formatMoney(escrow.net_payable || 0)}</strong></p>
                <p><span>Status</span><strong>{escrow.status || 'held'}</strong></p>
                <p><span>Estimated Payout</span><strong>{formatDateTime(escrow.estimated_payout_at)}</strong></p>
                <em>Funds release to the creator on approval or after the 5-day auto-approval window.</em>
              </div>
            </div>

            <div className="deal-help-list">
              {[[Headphones, 'Escalate to Admin'], [Flag, 'Raise Dispute']].map(([Icon, label]) => (
                <button key={label} type="button" onClick={() => handleActionCard(label)}>
                  <span><Icon size={18} /></span>
                  <div><strong>{label}</strong><small>Deal support action</small></div>
                </button>
              ))}
            </div>
          </aside>
        </div>

        <button type="button" className="deal-mobile-fab" disabled={primary.disabled} onClick={handlePrimary}>{primary.label}</button>
      </div>

      {/* 6.10 — Approval confirmation modal (approval is final) */}
      {confirmApprove && (
        <div className="deal-modal-overlay" onClick={() => setConfirmApprove(false)}>
          <div className="deal-modal" onClick={(e) => e.stopPropagation()}>
            <div className="deal-modal-icon warn"><ShieldAlert size={22} /></div>
            <h2>Approve content?</h2>
            <p>Once approved, this content is final and payment will be released per the creator's schedule. Continue?</p>
            <div className="deal-modal-actions">
              <button type="button" className="ghost" onClick={() => setConfirmApprove(false)}>Cancel</button>
              <button type="button" className="primary" disabled={busy} onClick={handleApprove}>{busy ? 'Approving...' : 'Yes, approve & release'}</button>
            </div>
          </div>
        </div>
      )}

      {/* Request revision modal with limit enforcement */}
      {revisionOpen && (
        <div className="deal-modal-overlay" onClick={() => setRevisionOpen(false)}>
          <div className="deal-modal" onClick={(e) => e.stopPropagation()}>
            <h2>Request Revision</h2>
            <p>{selectedDeal?.revisions_remaining ?? 0} revision(s) remaining. One change request per line.</p>
            <textarea value={revisionFeedback} onChange={(e) => setRevisionFeedback(e.target.value)} placeholder={'Tighten the intro hook\nAdd the discount code on screen'} rows={5} />
            <div className="deal-modal-actions">
              <button type="button" className="ghost" onClick={() => setRevisionOpen(false)}>Cancel</button>
              <button type="button" className="primary" disabled={busy || !revisionFeedback.trim()} onClick={handleRequestRevision}>{busy ? 'Sending...' : 'Send revision request'}</button>
            </div>
          </div>
        </div>
      )}
    </DashboardLayout>
  );
}
