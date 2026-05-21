import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import {
  AlertTriangle,
  Archive,
  Bookmark,
  Briefcase,
  CheckCheck,
  ChevronDown,
  Clock,
  FileCheck,
  FileText,
  Flag,
  Headphones,
  Image,
  IndianRupee,
  LayoutDashboard,
  MessageSquare,
  MoreHorizontal,
  Package,
  Paperclip,
  Play,
  RotateCcw,
  Send,
  Settings,
  ShieldAlert,
  Smile,
  Star,
  Upload,
  User,
  Zap
} from 'lucide-react';
import { EmptyPanel, formatMoney, getInitial } from '../components/CreatorComponents';
import DashboardLayout from '../components/DashboardLayout';
import './CreatorDashboard.css';
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

const ACTION_CARD_TYPES = {
  'Milestone Update': 'milestone_update',
  'Add Evidence': 'damage_report',
  'Damage Report': 'damage_report',
  'Escalate to Admin': 'escalate_to_admin',
  'Raise Dispute': 'raise_dispute',
  'Message Support': 'escalate_to_admin'
};

function DealCard({ children, className = '' }) {
  return <section className={`deal-card ${className}`}>{children}</section>;
}

function UploadZone({ icon: Icon, label, accept, uploaded, onClick, disabled }) {
  return (
    <button type="button" className={`deal-upload ${uploaded ? 'is-uploaded' : ''}`} onClick={onClick} disabled={disabled}>
      <span><Icon size={22} strokeWidth={1.6} /></span>
      <strong>{uploaded ? 'File uploaded successfully' : label}</strong>
      <small>{uploaded ? 'Ready for submission' : accept}</small>
    </button>
  );
}

function normalizeDash(value) {
  return String(value || '').replace(/\s*(?:\u2014|\u2013|-)\s*/g, ' - ');
}

function stateKey(value) {
  return normalizeDash(value).toLowerCase();
}

function getState(deal) {
  return normalizeDash(deal?.current_state || deal?.campaign_status || deal?.campaign?.status || 'Status unavailable');
}

function isDamageState(dealOrState) {
  const value = typeof dealOrState === 'string' ? dealOrState : getState(dealOrState);
  return stateKey(value) === stateKey('Damaged/Wrong Product Reported');
}

function getBrandHandle(deal) {
  return deal?.brand?.handle || deal?.campaign?.brand_handle || deal?.campaign?.business_nickname || 'Brand';
}

function getDealTitle(deal) {
  return deal?.campaign?.title || 'Untitled campaign';
}

function getDealDeadline(deal) {
  return deal?.deadline || deal?.next_deadline_at || deal?.state_started_at || null;
}

function getCountdownLabel(deal) {
  if (isDamageState(deal)) return 'Creator timeline paused';
  const hours = deal?.deadline_countdown_hours;
  if (typeof hours === 'number') return `${Math.max(0, Math.round(hours))} hrs left`;
  return 'Deadline pending';
}

function formatDateTime(dateValue) {
  if (!dateValue) return 'Not scheduled';
  return new Date(dateValue).toLocaleString('en-IN', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true
  });
}

function formatDate(dateValue) {
  if (!dateValue) return 'Not available';
  return new Date(dateValue).toLocaleDateString('en-IN');
}

function getEscrowAmount(deal) {
  return Number(deal?.escrow?.held_amount ?? deal?.escrow?.amount ?? deal?.my_bid?.amount ?? 0);
}

function getDealId(deal) {
  return deal?.deal_id || deal?.campaign?.deal_id || deal?.campaign?.id || 'Deal ID unavailable';
}

function getRequiredAssets(deal) {
  return deal?.content_submission?.required_assets || {};
}

function getDamageReport(deal) {
  const receipt = deal?.receipt || {};
  const damageCards = (deal?.action_cards || []).filter((card) => card.type === 'damage_report');
  const damageCard = damageCards[damageCards.length - 1];
  const damageEvent = (deal?.activity_feed || []).find((event) => event.event_type === 'dispute_raised' || event.event_type === 'damage_report');
  const evidence = [
    ...damageCards.flatMap((card) => card.attachment_urls || []),
    receipt.unboxing_video_url
  ].filter(Boolean);

  return {
    submittedOn: damageCard?.created_at || damageEvent?.timestamp || receipt.received_at,
    reason: damageCard?.title || 'Damaged / Wrong Product Reported',
    description: damageCard?.message || receipt.damage_report || 'Damage report submitted by creator.',
    evidenceUrls: evidence,
    evidenceCount: evidence.length,
    hasUnboxing: Boolean(receipt.unboxing_video_url),
    status: damageCard?.status === 'resolved' ? 'Resolved' : 'Under Admin Review'
  };
}

function isState(dealOrState, state) {
  const value = typeof dealOrState === 'string' ? dealOrState : getState(dealOrState);
  return stateKey(value) === stateKey(state);
}

function getAssetUrl(url) {
  if (!url) return '';
  return url.startsWith('http') ? url : `${BACKEND_URL}${url}`;
}

function canSubmitUploadedAssets(deal, uploads) {
  const required = getRequiredAssets(deal);
  if (!uploads.finalVideoUrl) return false;
  if (required.caption_script && !uploads.captionUrl) return false;
  if (required.thumbnail && !uploads.thumbnailUrl) return false;
  if (required.raw_footage && !uploads.rawFootageUrl) return false;
  return Boolean(deal?.can_submit_content);
}

function getPrimaryActionConfig(deal, uploads, submitting) {
  if (!deal) return { label: 'No deal selected', disabled: true, type: 'none' };
  if (isDamageState(deal)) return { label: 'Add Evidence', disabled: false, type: 'add_evidence' };
  if (isState(deal, 'Paid - Complete')) return { label: 'Archive Deal', disabled: false, type: 'archive' };
  if (isState(deal, 'Delivered - Awaiting Receipt Confirmation')) {
    return {
      label: 'Mark Received',
      disabled: !deal.can_mark_received || !uploads.unboxingVideoUrl,
      type: 'receipt'
    };
  }
  if (isState(deal, 'Received - Content in Progress') || isState(deal, 'Revision Requested')) {
    return {
      label: submitting ? 'Submitting...' : isState(deal, 'Revision Requested') ? 'Submit Revision' : 'Submit Content',
      disabled: submitting || !canSubmitUploadedAssets(deal, uploads),
      type: 'content'
    };
  }
  return {
    label: deal.primary_next_action || 'Waiting',
    disabled: true,
    type: 'passive'
  };
}

export default function MyDealsPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [deals, setDeals] = useState([]);
  const [selectedDeal, setSelectedDeal] = useState(null);
  const [loading, setLoading] = useState(true);
  const [briefOpen, setBriefOpen] = useState(false);
  const [rightTab, setRightTab] = useState('chat');
  const [message, setMessage] = useState('');
  const [messageAttachments, setMessageAttachments] = useState([]);
  const [finalVideoUrl, setFinalVideoUrl] = useState(null);
  const [captionUrl, setCaptionUrl] = useState(null);
  const [thumbnailUrl, setThumbnailUrl] = useState(null);
  const [rawFootageUrl, setRawFootageUrl] = useState(null);
  const [unboxingVideoUrl, setUnboxingVideoUrl] = useState(null);
  const [uploadingFile, setUploadingFile] = useState(null);
  const [uploadingEvidence, setUploadingEvidence] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [mobileSection, setMobileSection] = useState('workspace');
  const [showAllActivity, setShowAllActivity] = useState(false);
  const evidenceInputRef = useRef(null);

  const navItems = [
    { name: 'Dashboard', icon: LayoutDashboard, action: () => navigate('/dashboard/creator') },
    { name: 'My Active Work', icon: Zap, action: () => navigate('/my-active-work') },
    { name: 'My Bids', icon: Bookmark, action: () => navigate('/my-bids') },
    { name: 'Reviews', icon: Star, action: () => navigate('/reviews') },
    { name: 'Portfolio', icon: User, action: () => navigate('/portfolio') },
    { name: 'Browse Briefs', icon: Briefcase, action: () => navigate('/browse-briefs') },
    { name: 'My Deals', icon: FileCheck, action: () => navigate('/my-deals'), active: true },
    { name: 'Messages', icon: MessageSquare, action: () => navigate('/messages') },
    { name: 'Payout', icon: IndianRupee, action: () => navigate('/withdrawal') },
    { name: 'Settings', icon: Settings, action: () => navigate('/settings') }
  ];

  useEffect(() => {
    if (user?.id) fetchDeals();
  }, [user?.id]);

  const fetchDeals = async () => {
    try {
      const res = await axios.get(`${API}/deals/my`);
      const list = res.data || [];
      setDeals(list);
      setSelectedDeal((current) => {
        if (!list.length) return null;
        return list.find((item) => getDealId(item) === getDealId(current)) || list[0];
      });
    } catch (error) {
      toast.error('Failed to load deals');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (file, setUrlFn, fileType) => {
    if (!file) return;
    setUploadingFile(fileType);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const res = await axios.post(`${API}/upload/file`, formData, { headers: { 'Content-Type': 'multipart/form-data' } });
      setUrlFn(res.data.file_url);
      toast.success('File uploaded');
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Upload failed');
    } finally {
      setUploadingFile(null);
    }
  };

  const handleSubmitReceipt = async () => {
    if (!selectedDeal?.deal_id) return;
    if (!unboxingVideoUrl && !selectedDeal?.receipt?.unboxing_video_url) {
      toast.error('Upload an unboxing video before marking received');
      return;
    }
    try {
      await axios.post(`${API}/deals/${selectedDeal.deal_id}/receipt`, {
        received_at: new Date().toISOString(),
        unboxing_video_url: unboxingVideoUrl || selectedDeal?.receipt?.unboxing_video_url,
        items_damaged: false,
        damage_report: null
      });
      toast.success('Receipt submitted');
      setUnboxingVideoUrl(null);
      fetchDeals();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Receipt submission failed');
    }
  };

  const handleSubmitContent = async () => {
    if (!selectedDeal?.deal_id) return;
    const required = getRequiredAssets(selectedDeal);
    const missing = [];
    if (!finalVideoUrl) missing.push('final video');
    if (required.caption_script && !captionUrl) missing.push('caption/script');
    if (required.thumbnail && !thumbnailUrl) missing.push('thumbnail');
    if (required.raw_footage && !rawFootageUrl) missing.push('raw footage');
    if (missing.length) {
      toast.error(`Missing required asset: ${missing.join(', ')}`);
      return;
    }

    setSubmitting(true);
    try {
      await axios.post(`${API}/deals/${selectedDeal.deal_id}/content`, {
        video_url: finalVideoUrl,
        caption_url: captionUrl,
        thumbnail_url: thumbnailUrl,
        raw_footage_url: rawFootageUrl,
        creator_note: 'Submitted from creator deal room'
      });
      toast.success('Content submitted for brand review');
      setFinalVideoUrl(null);
      setCaptionUrl(null);
      setThumbnailUrl(null);
      setRawFootageUrl(null);
      fetchDeals();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Submission failed');
    } finally {
      setSubmitting(false);
    }
  };

  const handleSendMessage = async () => {
    if (!selectedDeal?.deal_id || (!message.trim() && !messageAttachments.length)) return;
    try {
      await axios.post(`${API}/deals/${selectedDeal.deal_id}/chat`, {
        message: message.trim() || 'Attachment sent',
        attachment_urls: messageAttachments
      });
      setMessage('');
      setMessageAttachments([]);
      fetchDeals();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Message failed');
    }
  };

  const handleCreateActionCard = async (label, attachmentUrls = []) => {
    if (!selectedDeal?.deal_id) return;
    try {
      const type = ACTION_CARD_TYPES[label];
      const attachments = attachmentUrls.length
        ? attachmentUrls
        : [unboxingVideoUrl || selectedDeal?.receipt?.unboxing_video_url].filter(Boolean);
      if (type === 'raise_dispute') {
        await axios.post(`${API}/deals/${selectedDeal.deal_id}/dispute`, {
          message: label,
          attachment_urls: attachments
        });
      } else if (type === 'escalate_to_admin') {
        await axios.post(`${API}/deals/${selectedDeal.deal_id}/escalate`, {
          message: label,
          attachment_urls: attachments
        });
      } else if (label === 'Damage Report') {
        await axios.post(`${API}/deals/${selectedDeal.deal_id}/damage-report`, {
          message: 'Damaged or wrong product reported by creator',
          attachment_urls: attachments
        });
      } else {
        await axios.post(`${API}/deals/${selectedDeal.deal_id}/action-card`, {
          type,
          message: label,
          attachment_urls: attachments
        });
      }
      toast.success(`${label} created`);
      fetchDeals();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Action failed');
    }
  };

  const handleAddEvidenceClick = () => {
    if (uploadingEvidence) return;
    evidenceInputRef.current?.click();
  };

  const handleEvidenceUpload = async (event) => {
    const files = Array.from(event.target.files || []);
    if (!files.length || !selectedDeal?.deal_id) return;

    setUploadingEvidence(true);
    try {
      const uploadedUrls = await Promise.all(files.map(async (file) => {
        const formData = new FormData();
        formData.append('file', file);
        const res = await axios.post(`${API}/upload/file`, formData, { headers: { 'Content-Type': 'multipart/form-data' } });
        return res.data.file_url;
      }));
      await handleCreateActionCard('Add Evidence', uploadedUrls);
      toast.success(`${uploadedUrls.length} evidence file${uploadedUrls.length > 1 ? 's' : ''} uploaded`);
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Evidence upload failed');
    } finally {
      setUploadingEvidence(false);
      event.target.value = '';
    }
  };

  const handleActionCardRequest = (label) => {
    if (label === 'Add Evidence') return handleAddEvidenceClick();
    return handleCreateActionCard(label);
  };

  const handleRevisionResponse = async (response) => {
    if (!selectedDeal?.deal_id) return;
    try {
      await axios.post(`${API}/deals/${selectedDeal.deal_id}/revision-response`, {
        response,
        note: response === 'accepted' ? 'Creator accepted the revision request.' : 'Creator flagged the revision request from Deal Room.'
      });
      toast.success('Revision response submitted');
      fetchDeals();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Revision response failed');
    }
  };

  const handleArchiveDeal = () => {
    if (!selectedDeal) return;
    if (!isState(selectedDeal, 'Paid - Complete')) {
      toast.error('Only completed deals can be archived');
      return;
    }
    const nextDeals = deals.filter((deal) => getDealId(deal) !== getDealId(selectedDeal));
    setDeals(nextDeals);
    setSelectedDeal(nextDeals[0] || null);
    toast.success('Deal archived from this view');
  };

  const primaryAction = getPrimaryActionConfig(
    selectedDeal,
    { finalVideoUrl, captionUrl, thumbnailUrl, rawFootageUrl, unboxingVideoUrl: unboxingVideoUrl || selectedDeal?.receipt?.unboxing_video_url },
    submitting
  );

  const handlePrimaryAction = () => {
    if (primaryAction.disabled) return;
    if (primaryAction.type === 'receipt') return handleSubmitReceipt();
    if (primaryAction.type === 'content') return handleSubmitContent();
    if (primaryAction.type === 'add_evidence') return handleAddEvidenceClick();
    if (primaryAction.type === 'archive') return handleArchiveDeal();
    return null;
  };

  const selectedState = getState(selectedDeal);
  const activeDeals = deals.filter((item) => (
    !['paid - complete', 'disputed', 'damaged/wrong product reported'].includes(stateKey(item.current_state))
  ));
  const awaitingAction = deals.filter((item) => item.active_party === 'creator' && !isDamageState(item));
  const pastDeals = deals.filter((item) => stateKey(item.current_state) === 'paid - complete');
  const disputedDeals = deals.filter((item) => EXCEPTION_STATES.some((state) => stateKey(state) === stateKey(item.current_state)));
  const escrowAmount = getEscrowAmount(selectedDeal);
  const activity = useMemo(() => selectedDeal?.activity_feed || [], [selectedDeal]);
  const visibleActivity = showAllActivity ? activity : activity.slice(0, 5);
  const hiddenActivityCount = Math.max(0, activity.length - visibleActivity.length);

  if (loading) {
    return (
      <DashboardLayout navItems={navItems} title="Deal Room" description="Creator-side delivery workspace" topbarExtra={null} sidebarExtra={null}>
        <div className="deal-page"><EmptyPanel text="Loading..." /></div>
      </DashboardLayout>
    );
  }

  if (!deals.length) {
    return (
      <DashboardLayout navItems={navItems} title="Deal Room" description="Creator-side delivery workspace" topbarExtra={null} sidebarExtra={null}>
        <div className="deal-page"><EmptyPanel text="No active deals yet. Browse briefs and submit bids to get started." /></div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout navItems={navItems} title="Deal Room" description="Creator-side delivery workspace" topbarExtra={null} sidebarExtra={null}>
      <div className="deal-page">
        <input
          ref={evidenceInputRef}
          type="file"
          hidden
          multiple
          accept="image/*,video/*,.pdf"
          onChange={handleEvidenceUpload}
        />
        <StatusHeader
          deal={selectedDeal}
          currentState={selectedState}
          escrowAmount={escrowAmount}
          primaryAction={uploadingEvidence && primaryAction.type === 'add_evidence' ? { ...primaryAction, label: 'Uploading...', disabled: true } : primaryAction}
          onPrimaryAction={handlePrimaryAction}
          onActionCard={handleActionCardRequest}
          onArchive={handleArchiveDeal}
        />

        <div className="deal-mobile-tabs" role="tablist" aria-label="Deal room sections">
          {['deals', 'workspace', 'chat'].map((section) => (
            <button key={section} type="button" className={mobileSection === section ? 'is-active' : ''} onClick={() => setMobileSection(section)}>
              {section}
            </button>
          ))}
        </div>

        <div className={`deal-room-grid show-${mobileSection}`}>
          <DealNavigation
            groups={[
              ['Active Deals', activeDeals],
              ['Awaiting My Action', awaitingAction],
              ['Past Deals', pastDeals],
              ['Disputed Deals', disputedDeals]
            ]}
            selectedDeal={selectedDeal}
            onSelect={setSelectedDeal}
          />

          <main className="deal-workspace">
            <DealCard className="deal-brief-card">
              <button type="button" className="deal-brief-toggle" onClick={() => setBriefOpen((value) => !value)}>
                <span><FileText size={18} /></span>
                <strong>Full Campaign Brief</strong>
                <em>Usage rights highlighted</em>
                <ChevronDown size={18} className={briefOpen ? 'is-open' : ''} />
              </button>
              {briefOpen && (
                <div className="deal-brief-body">
                  {(selectedDeal?.brief_sections || []).map((section) => (
                    <article key={section.title} className={section.title === 'Usage Rights' ? 'is-rights' : ''}>
                      <h3>{section.title}</h3>
                      <p>{section.content || 'Not specified'}</p>
                    </article>
                  ))}
                  <button type="button" className="deal-link-btn" onClick={() => navigate(`/campaign/${selectedDeal?.campaign?.id}`)}>View full brief in new tab</button>
                </div>
              )}
            </DealCard>

            <DealCard className="deal-activity">
              <div className="deal-section-title">
                <span><Clock size={18} /></span>
                <div><h2>Activity Feed</h2><p>Chronological deal state transitions</p></div>
              </div>
              <div className="deal-timeline">
                {activity.length ? visibleActivity.map((event) => (
                  <div key={event.id} className="deal-timeline-item">
                    <span className="blue"><CheckCheck size={16} /></span>
                    <article>
                      <header><strong>{event.actor_name || event.actor_type}</strong><small>{formatDateTime(event.timestamp)}</small></header>
                      <p>{event.message}</p>
                    </article>
                  </div>
                )) : <EmptyPanel text="No activity yet." />}
              </div>
              {activity.length > 5 && (
                <button type="button" className="deal-expand-timeline" onClick={() => setShowAllActivity((value) => !value)}>
                  {showAllActivity ? 'Show fewer activities' : `Show ${hiddenActivityCount} more activit${hiddenActivityCount > 1 ? 'ies' : 'y'}`}
                </button>
              )}
            </DealCard>

            <ShippingBlock
              deal={selectedDeal}
              unboxingVideoUrl={unboxingVideoUrl}
              onUpload={(file) => handleFileUpload(file, setUnboxingVideoUrl, 'unboxing')}
              onSubmitReceipt={handleSubmitReceipt}
              uploading={uploadingFile === 'unboxing'}
              onActionCard={handleActionCardRequest}
            />

            {isDamageState(selectedDeal) && <DamageReportCard deal={selectedDeal} onActionCard={handleActionCardRequest} />}

            {isDamageState(selectedDeal) ? (
              <DealCard className="deal-paused-card">
                <div className="deal-section-title">
                  <span><AlertTriangle size={18} /></span>
                  <div><h2>Creator Timeline Paused</h2><p>Damage report under review</p></div>
                </div>
                <p>Work is paused until resolution. No late penalty will apply while this issue is under review.</p>
              </DealCard>
            ) : (
              <ContentSubmission
                deal={selectedDeal}
                finalVideoUrl={finalVideoUrl}
                captionUrl={captionUrl}
                thumbnailUrl={thumbnailUrl}
                rawFootageUrl={rawFootageUrl}
                onUpload={handleFileUpload}
                setFinalVideoUrl={setFinalVideoUrl}
                setCaptionUrl={setCaptionUrl}
                setThumbnailUrl={setThumbnailUrl}
                setRawFootageUrl={setRawFootageUrl}
                uploadingFile={uploadingFile}
                onSubmit={handleSubmitContent}
                submitting={submitting}
              />
            )}

            <RevisionTracker deal={selectedDeal} onRevisionResponse={handleRevisionResponse} />
          </main>

          <RightPanel
            tab={rightTab}
            setTab={setRightTab}
            deal={selectedDeal}
            currentState={selectedState}
            message={message}
            setMessage={setMessage}
            messageAttachments={messageAttachments}
            setMessageAttachments={setMessageAttachments}
            onSendMessage={handleSendMessage}
            onActionCard={handleActionCardRequest}
          />
        </div>
        <button type="button" className="deal-mobile-fab" disabled={primaryAction.disabled} onClick={handlePrimaryAction}>
          {primaryAction.label}
        </button>
      </div>
    </DashboardLayout>
  );
}

function StatusHeader({ deal, currentState, escrowAmount, primaryAction, onPrimaryAction, onActionCard, onArchive }) {
  const deadline = getDealDeadline(deal);
  const damaged = isDamageState(currentState);
  const reviewTimer = isState(currentState, 'Content Submitted - Awaiting Review') ? `Auto-approval ${getCountdownLabel(deal)}` : null;
  const creatorIsActive = deal?.active_party === 'creator' && !damaged;
  return (
    <section className={`deal-status-header ${damaged ? 'is-passive' : ''}`}>
      <div className="deal-brand-logo">
        {deal?.brand?.logo_url ? <img src={getAssetUrl(deal.brand.logo_url)} alt={deal.brand.name || 'Brand'} /> : getInitial(deal?.brand?.name || 'B')}
      </div>
      <div className="deal-status-copy">
        <p>{getBrandHandle(deal)}</p>
        <h2>{getDealTitle(deal)}</h2>
        <span>{getDealId(deal)}</span>
      </div>
      <div className="deal-header-metrics">
        <div className="deal-header-pill is-state"><small>Current State</small><strong>{currentState}</strong></div>
        <div className="deal-header-pill"><small>{damaged ? 'Waiting on' : 'Active Party'}</small><strong>{damaged ? 'Admin + Brand' : deal?.active_party || 'Not assigned'}</strong></div>
        <div className="deal-header-pill"><small>Creator Status</small><strong>{damaged ? 'Work paused' : creatorIsActive ? 'Action needed' : 'Waiting'}</strong></div>
        <div className={`deal-header-pill ${damaged ? 'is-paused' : creatorIsActive ? 'is-urgent' : ''}`}><small>{damaged ? 'Timeline' : 'Deadline'}</small><strong>{damaged ? 'Creator timeline paused' : getCountdownLabel(deal)}</strong></div>
        <div className="deal-header-pill"><small>Escrow</small><strong>{formatMoney(escrowAmount)} held</strong></div>
      </div>
      <div className="deal-header-pill is-next-step">
        <div className="deal-next-step-copy">
          <small>{damaged ? 'Next Step' : 'Due'}</small>
          <strong>{damaged ? 'Admin and brand will review your uploaded evidence. You may add more evidence or contact support if needed.' : reviewTimer || formatDateTime(deadline)}</strong>
        </div>
        <div className="deal-header-actions">
          <button type="button" className="deal-primary-action" disabled={primaryAction.disabled} onClick={onPrimaryAction}>
            <Upload size={17} /> {primaryAction.label}
          </button>
          <div className="deal-more">
            <button type="button" aria-label="More deal actions"><MoreHorizontal size={18} /></button>
            <div>
              <button type="button" onClick={() => onActionCard('Raise Dispute')}>Raise Dispute</button>
              <button type="button" onClick={() => onActionCard('Message Support')}>Get Help</button>
              <button type="button" onClick={onArchive}><Archive size={14} /> Archive if completed</button>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function DealNavigation({ groups, selectedDeal, onSelect }) {
  const [openGroups, setOpenGroups] = useState(() => ({
    'Active Deals': true,
    'Awaiting My Action': false,
    'Past Deals': false,
    'Disputed Deals': false
  }));

  const toggleGroup = (label) => {
    setOpenGroups((current) => ({ ...current, [label]: !current[label] }));
  };

  return (
    <aside className="deal-nav-panel">
      {groups.map(([label, groupDeals]) => (
        <section key={label}>
          <button type="button" className="deal-nav-heading" onClick={() => toggleGroup(label)} aria-expanded={Boolean(openGroups[label])}>
            <span>{label}</span>
            <em>{groupDeals.length}</em>
            <ChevronDown size={16} className={openGroups[label] ? 'is-open' : ''} />
          </button>
          {openGroups[label] && (groupDeals.length ? groupDeals.map((deal) => (
            <button
              key={`${label}-${getDealId(deal)}`}
              type="button"
              className={getDealId(selectedDeal) === getDealId(deal) ? 'is-active' : ''}
              onClick={() => onSelect(deal)}
            >
              <strong>{getDealTitle(deal)}</strong>
              <small>{getBrandHandle(deal)} - {getState(deal)}</small>
              <em>{isDamageState(deal) ? 'Work paused - resolution pending' : `${deal.primary_next_action || 'No action pending'} - ${getCountdownLabel(deal)}`}</em>
            </button>
          )) : <p>No deals</p>)}
        </section>
      ))}
    </aside>
  );
}

function ShippingBlock({ deal, unboxingVideoUrl, onUpload, onSubmitReceipt, uploading, onActionCard }) {
  const shipment = deal?.shipment || {};
  const receipt = deal?.receipt || {};
  const damaged = isDamageState(deal);
  const hasCourierDetails = shipment.tracking_id || shipment.courier_status || shipment.expected_delivery_at || receipt.received_at;
  const canSubmitReceipt = Boolean(deal?.can_mark_received && (unboxingVideoUrl || receipt.unboxing_video_url));
  return (
    <DealCard className="deal-shipping-card">
      <div className="deal-section-title">
        <span><Package size={18} /></span>
        <div><h2>Shipping / Receipt</h2><p>{damaged ? 'Product issue has been reported' : 'Confirm package condition before producing content'}</p></div>
      </div>
      {hasCourierDetails ? (
        <div className="deal-receipt-grid">
          <p><small>Tracking ID</small>{shipment.courier_tracking_url ? <a href={shipment.courier_tracking_url} target="_blank" rel="noreferrer">{shipment.tracking_id || 'Tracking link'}</a> : <strong>{shipment.tracking_id || 'Not available'}</strong>}</p>
          <p><small>Courier Status</small><strong>{shipment.courier_status || 'Not available'}</strong></p>
          <p><small>Expected Delivery</small><strong>{formatDate(shipment.expected_delivery_at)}</strong></p>
          <p><small>Date Received</small><strong>{formatDate(receipt.received_at)}</strong></p>
        </div>
      ) : (
        <div className="deal-pause-note">{damaged ? 'Product issue has been reported. Shipping/content workflow is paused until admin resolution.' : 'Waiting for brand shipment details.'}</div>
      )}
      {damaged ? (
        <div className="deal-revision-actions">
          <button type="button" onClick={() => onActionCard('Add Evidence')}>Add Evidence</button>
          <button type="button" onClick={() => onActionCard('Message Support')}>Message Support</button>
        </div>
      ) : (
        <>
          <button type="button" className="deal-secondary-action" disabled={!canSubmitReceipt} onClick={onSubmitReceipt}>Mark Received</button>
          <label>Upload Unboxing Video</label>
          <p className="deal-helper-text">Upload a short unboxing video showing package condition, opening, and product received.</p>
          <input type="file" id="unboxing-upload" accept="video/mp4,video/quicktime" onChange={(event) => onUpload(event.target.files?.[0])} />
          <UploadZone icon={Paperclip} label="Upload Unboxing Video" accept="MP4/MOV - Max 150MB - Max 2 minutes" uploaded={Boolean(unboxingVideoUrl || receipt.unboxing_video_url)} onClick={() => document.getElementById('unboxing-upload').click()} disabled={uploading} />
        </>
      )}
    </DealCard>
  );
}

function ContentSubmission({
  deal,
  finalVideoUrl,
  captionUrl,
  thumbnailUrl,
  rawFootageUrl,
  onUpload,
  setFinalVideoUrl,
  setCaptionUrl,
  setThumbnailUrl,
  setRawFootageUrl,
  uploadingFile,
  onSubmit,
  submitting
}) {
  const content = deal?.content_submission || {};
  const required = getRequiredAssets(deal);
  const versions = content.versions || [];
  const needsCaption = Boolean(required.caption_script);
  const needsThumbnail = Boolean(required.thumbnail);
  const needsRaw = Boolean(required.raw_footage);
  const canSubmit = canSubmitUploadedAssets(deal, { finalVideoUrl, captionUrl, thumbnailUrl, rawFootageUrl });

  return (
    <DealCard className="deal-delivery-card">
      <div className="deal-section-title">
        <span><Upload size={18} /></span>
        <div><h2>Content Submission</h2><p>{content.watermark_required_until_approval ? 'Watermarked preview until brand approval' : 'Brand approval rules loaded'}</p></div>
      </div>
      {content.watermark_required_until_approval && <div className="deal-watermark">Watermarked preview until brand approval</div>}
      <UploadZone icon={Play} label="Final Video Upload" accept="MP4 - MOV" uploaded={Boolean(finalVideoUrl)} onClick={() => document.getElementById('video-file-real').click()} disabled={uploadingFile === 'video'} />
      <input type="file" id="video-file-real" accept="video/*" onChange={(event) => onUpload(event.target.files?.[0], setFinalVideoUrl, 'video')} hidden />
      <div className="deal-asset-grid">
        {needsCaption && (
          <div>
            <label>Caption / Script Upload</label>
            <UploadZone icon={FileText} label="Caption / Script" accept=".txt - .docx" uploaded={Boolean(captionUrl)} onClick={() => document.getElementById('caption-file-real').click()} disabled={uploadingFile === 'caption'} />
            <input type="file" id="caption-file-real" onChange={(event) => onUpload(event.target.files?.[0], setCaptionUrl, 'caption')} hidden />
          </div>
        )}
        {needsThumbnail && (
          <div>
            <label>Thumbnail Upload</label>
            <UploadZone icon={Image} label="Thumbnail" accept="JPG - PNG" uploaded={Boolean(thumbnailUrl)} onClick={() => document.getElementById('thumb-file-real').click()} disabled={uploadingFile === 'thumb'} />
            <input type="file" id="thumb-file-real" accept="image/*" onChange={(event) => onUpload(event.target.files?.[0], setThumbnailUrl, 'thumb')} hidden />
          </div>
        )}
        {needsRaw && (
          <div>
            <label>Raw Footage Upload</label>
            <UploadZone icon={Paperclip} label="Raw Footage" accept="MP4 - MOV" uploaded={Boolean(rawFootageUrl)} onClick={() => document.getElementById('raw-file-real').click()} disabled={uploadingFile === 'raw'} />
            <input type="file" id="raw-file-real" accept="video/*" onChange={(event) => onUpload(event.target.files?.[0], setRawFootageUrl, 'raw')} hidden />
          </div>
        )}
      </div>
      <div className="deal-version-row">
        {versions.length ? versions.map((version) => (
          <article key={version.version}>
            <div className="deal-preview-tile">
              {version.thumbnail_url ? (
                <img src={getAssetUrl(version.thumbnail_url)} alt={`v${version.version} thumbnail`} />
              ) : version.video_url ? (
                <video src={getAssetUrl(version.video_url)} />
              ) : (
                <Play size={24} />
              )}
              {content.watermark_required_until_approval && version.status !== 'approved' && <b>UGCAD.IO Preview</b>}
              {version.video_url && (
                <a href={getAssetUrl(version.video_url)} target="_blank" rel="noreferrer" aria-label={`Open v${version.version} preview`}>
                  <Play size={16} />
                </a>
              )}
            </div>
            <strong>v{version.version}</strong>
            <small>{formatDateTime(version.submitted_at)}</small>
            <span>{version.status}</span>
          </article>
        )) : <article><strong>v1</strong><small>No upload yet</small><span>Awaiting submission</span></article>}
      </div>
      <button type="button" className="deal-submit" disabled={!canSubmit || submitting} onClick={onSubmit}>
        <Upload size={17} /> {submitting ? 'Submitting...' : 'Submit Final Delivery'}
      </button>
    </DealCard>
  );
}

function DamageReportCard({ deal, onActionCard }) {
  const report = getDamageReport(deal);
  const evidenceParts = [];
  if (report.evidenceCount) evidenceParts.push(`${report.evidenceCount} uploaded file${report.evidenceCount > 1 ? 's' : ''}`);
  if (report.hasUnboxing) evidenceParts.push('1 unboxing video');

  return (
    <DealCard className="deal-damage-card">
      <div className="deal-section-title">
        <span className="warn"><ShieldAlert size={18} /></span>
        <div><h2>Damage Report Submitted</h2><p>Damage report under review</p></div>
      </div>
      <div className="deal-revision-box">
        <p><small>Report Type</small><strong>Damaged / Wrong Product Reported</strong></p>
        <p><small>Submitted By</small><strong>Creator</strong></p>
        <p><small>Submitted On</small><strong>{formatDateTime(report.submittedOn)}</strong></p>
        <p><small>Reason</small><strong>{report.reason}</strong></p>
        <p className="is-wide"><small>Description</small><strong>{report.description}</strong></p>
        <p className="is-wide"><small>Evidence Uploaded</small><strong>{evidenceParts.length ? evidenceParts.join(' + ') : 'No evidence count available'}</strong></p>
        <p><small>Status</small><strong>{report.status}</strong></p>
        <p><small>Creator Timeline</small><strong>Paused</strong></p>
        <p><small>Escrow Status</small><strong>Held until resolution</strong></p>
      </div>
      <div className="deal-revision-actions">
        <button type="button" disabled={!report.evidenceUrls.length} onClick={() => window.open(getAssetUrl(report.evidenceUrls[0]), '_blank', 'noopener,noreferrer')}>View Uploaded Evidence</button>
      </div>
      {report.evidenceUrls.length ? (
        <div className="deal-evidence-list">
          {report.evidenceUrls.map((url, index) => {
            const assetUrl = getAssetUrl(url);
            const isVideo = /\.(mp4|webm|mov)$/i.test(String(url).split('?')[0]);
            return (
              <a key={`${url}-${index}`} href={assetUrl} target="_blank" rel="noreferrer">
                {isVideo ? <Play size={18} /> : <FileText size={18} />}
                <span>Evidence {index + 1}</span>
              </a>
            );
          })}
        </div>
      ) : null}
    </DealCard>
  );
}

function RevisionTracker({ deal, onRevisionResponse }) {
  const revision = deal?.revision_tracker || {};
  const hasRevision = Boolean(revision.latest_feedback || revision.requested_changes?.length);
  return (
    <DealCard className="deal-revisions">
      <div className="deal-section-title">
        <span className="warn"><RotateCcw size={18} /></span>
        <div><h2>Revision Tracker</h2><p>Revision {revision.revision_count_used || 0} of {revision.revision_limit || 0} used</p></div>
      </div>
      <div className="deal-revision-box">
        <p><small>Brand Feedback</small><strong>{revision.latest_feedback || 'No revision requested yet.'}</strong></p>
        <p><small>Requested Changes</small><strong>{revision.requested_changes?.length ? revision.requested_changes.join(', ') : 'No requested changes.'}</strong></p>
        <p><small>New Deadline</small><strong>{formatDateTime(revision.new_deadline_at)}</strong></p>
      </div>
      <div className="deal-revision-actions">
        <button type="button" disabled={!hasRevision} onClick={() => onRevisionResponse('accepted')}>Accept and revise</button>
        <button type="button" disabled={!hasRevision} onClick={() => onRevisionResponse('scope_creep')}>Flag scope creep</button>
        <button type="button" disabled={!hasRevision} onClick={() => onRevisionResponse('partial_dispute')}>Partially accept and dispute remaining items</button>
      </div>
    </DealCard>
  );
}

function RightPanel({ tab, setTab, deal, currentState, message, setMessage, messageAttachments, setMessageAttachments, onSendMessage, onActionCard }) {
  const [emojiPickerOpen, setEmojiPickerOpen] = useState(false);
  const [uploadingMessageFile, setUploadingMessageFile] = useState(false);
  const messageFileInputRef = useRef(null);
  const chat = deal?.chat_summary || {};
  const messages = chat.messages || [];
  const escrow = deal?.escrow || {};
  const deductions = escrow.deductions || [];
  const damaged = isDamageState(currentState);
  const creatorActions = damaged ? ['Add Evidence', 'Escalate to Admin', 'Raise Dispute', 'Message Support'] : ['Milestone Update', 'Escalate to Admin', 'Raise Dispute', 'Damage Report'];

  const handleMessageFileUpload = async (event) => {
    const files = Array.from(event.target.files || []);
    if (!files.length) return;

    setUploadingMessageFile(true);
    try {
      const uploadedUrls = await Promise.all(files.map(async (file) => {
        const formData = new FormData();
        formData.append('file', file);
        const res = await axios.post(`${API}/upload/file`, formData, { headers: { 'Content-Type': 'multipart/form-data' } });
        return res.data.file_url;
      }));
      setMessageAttachments((current) => [...current, ...uploadedUrls]);
      toast.success(`${uploadedUrls.length} file${uploadedUrls.length > 1 ? 's' : ''} attached`);
    } catch (err) {
      toast.error(err.response?.data?.detail || 'File attachment failed');
    } finally {
      setUploadingMessageFile(false);
      event.target.value = '';
    }
  };

  return (
    <aside className="deal-right-column">
      <div className="deal-right-panel">
        <div className="deal-right-tabs">
          {['chat', 'progress'].map((name) => (
            <button key={name} type="button" className={tab === name ? 'is-active' : ''} onClick={() => setTab(name)}>{name}</button>
          ))}
        </div>
        {tab === 'chat' && (
          <div className="deal-chat">
            <div className="deal-pinned"><AlertTriangle size={16} /><strong>{currentState}</strong><span>{damaged ? 'Creator work paused. Admin and brand are reviewing the evidence.' : `${deal?.primary_next_action || 'No action pending'} - ${getCountdownLabel(deal)}`}</span></div>
            <div className="deal-message-list">
              {messages.length ? messages.map((item) => (
                <p key={item.id} className={item.sender_type === 'creator' ? 'creator' : item.sender_type === 'system' ? 'system' : 'brand'}>
                  {item.sender_name}: {item.message}
                </p>
              )) : <p className="system">No messages yet.</p>}
            </div>
            <div className="deal-support-actions">
              <div className="deal-action-section-title">
                <h3>Support Actions</h3>
              </div>
              <div className="deal-action-menu">
                {creatorActions.map((item) => <button key={item} type="button" onClick={() => onActionCard(item)}>{item}</button>)}
              </div>
            </div>
            <div className="deal-chat-input">
              <input
                ref={messageFileInputRef}
                type="file"
                hidden
                multiple
                accept="image/*,video/*,.pdf,.doc,.docx,.txt"
                onChange={handleMessageFileUpload}
              />
              <div className="deal-emoji-wrap">
                <button type="button" aria-label="Choose emoji" onClick={() => setEmojiPickerOpen((value) => !value)}><Smile size={17} /></button>
                {emojiPickerOpen && (
                  <div className="deal-emoji-picker">
                    {['😊', '👍', '🙏', '🔥', '✨', '✅', '👀', '💬', '📦', '🎥', '⚠️', '❤️'].map((emoji) => (
                      <button
                        key={emoji}
                        type="button"
                        onClick={() => {
                          setMessage(`${message}${emoji}`);
                          setEmojiPickerOpen(false);
                        }}
                      >
                        {emoji}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <button type="button" aria-label="Attach file" disabled={uploadingMessageFile} onClick={() => messageFileInputRef.current?.click()}><Paperclip size={17} /></button>
              <input value={message} onChange={(event) => setMessage(event.target.value)} placeholder="Message this deal thread" />
              <button type="button" onClick={onSendMessage}><Send size={17} /></button>
            </div>
            {messageAttachments.length ? (
              <div className="deal-message-attachments">
                {messageAttachments.map((url, index) => (
                  <span key={`${url}-${index}`}>Attachment {index + 1}</span>
                ))}
              </div>
            ) : null}
          </div>
        )}
        {tab === 'progress' && (
          <div className="deal-progress-tab">
            {[...DEAL_STATES, ...EXCEPTION_STATES].map((state) => {
              const currentIndex = DEAL_STATES.findIndex((item) => stateKey(item) === stateKey(currentState));
              const itemIndex = DEAL_STATES.findIndex((item) => stateKey(item) === stateKey(state));
              const isCurrent = stateKey(state) === stateKey(currentState);
              const isDone = itemIndex !== -1 && currentIndex !== -1 && itemIndex < currentIndex;
              return (
                <div key={state} className={isCurrent ? 'is-current' : isDone ? 'is-done' : ''}>
                  <span>{isCurrent ? <Clock size={15} /> : <CheckCheck size={15} />}</span>
                  <strong>{state}</strong>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {tab === 'chat' && (
        <>
          <div className="deal-payout-section">
            <div className="deal-action-section-title">
              <h3>Payout Summary</h3>
            </div>
            <div className="deal-payout-tab">
              <p><span>Escrow Held</span><strong>{formatMoney(escrow.held_amount || 0)}</strong></p>
              <p><span>Net Payable</span><strong>{formatMoney(escrow.net_payable || 0)}</strong></p>
              <p><span>Deductions</span><strong>{deductions.length ? deductions.map((item) => `${item.label}: ${formatMoney(item.amount)}`).join(', ') : 'No deductions'}</strong></p>
              <p><span>Estimated Payout</span><strong>{formatDateTime(escrow.estimated_payout_at)}</strong></p>
              <em>Disputed deals remain on hold until resolved.</em>
            </div>
          </div>

          <div className="deal-deadline-section">
            <div className="deal-action-section-title">
              <h3>{damaged ? 'Resolution Status' : 'Deadline Alert'}</h3>
            </div>
            <div className="deal-deadline">
              <div><span><AlertTriangle size={21} /></span><div><strong>{damaged ? 'Resolution pending' : getCountdownLabel(deal)}</strong><h2>{damaged ? 'Work paused' : deal?.primary_next_action || 'Next action pending'}</h2><p>{damaged ? 'Work is paused until resolution' : `Due: ${formatDateTime(getDealDeadline(deal))}`}</p><p>{damaged ? 'Waiting on: Admin + Brand' : `Active party: ${deal?.active_party || 'Not assigned'}`}</p><p>{damaged ? 'No late penalty will apply while this issue is under review' : `Required action: ${deal?.primary_next_action || 'No action pending'}`}</p></div></div>
            </div>
          </div>

          <div className="deal-help-list">
            {[
              [Headphones, 'Escalate to Admin'],
              [Flag, 'Raise Dispute'],
              [ShieldAlert, 'Report Damaged / Wrong Product']
            ].map(([Icon, label]) => (
              <button key={label} type="button" onClick={() => onActionCard(label === 'Report Damaged / Wrong Product' ? 'Damage Report' : label)}>
                <span><Icon size={18} /></span>
                <div><strong>{label}</strong><small>Deal support action</small></div>
              </button>
            ))}
          </div>
        </>
      )}
    </aside>
  );
}
