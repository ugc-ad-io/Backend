import { useState, useEffect, useRef } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import { AlertTriangle, BellOff, CheckCheck, ClipboardList, FileText, Flag, MoreHorizontal, Paperclip, Search, Send, ShieldAlert, Smile, SquarePen, User, UserRoundSearch, Wallet, X, Zap, Bookmark, FileCheck, IndianRupee, LayoutDashboard, MessageSquare, Settings, Star, Briefcase, Package } from 'lucide-react';
import { getInitial } from '../components/CreatorComponents';
import DashboardLayout from '../components/DashboardLayout';
import './CreatorDashboard.css';
import './MessagesPage.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;
const ATTACHMENT_MESSAGE_PREFIX = '__UGCAD_ATTACHMENT__:';
const MAX_ATTACHMENTS = 5;
const CHAT_FILTERS = [
  { label: 'All', value: 'all' },
  { label: 'Active Deals', value: 'active_deal' },
  { label: 'New Chat', value: 'no_deal' },
  { label: 'Archived', value: 'archived' }
];
const ACTION_CARD_LABELS = {
  custom_offer: 'Custom Offer',
  private_invitation: 'Private Invitation',
  counter_offer: 'Counter Offer',
  revision_request: 'Revision Request',
  milestone_update: 'Milestone Update',
  damage_report: 'Damage Report',
  escalate_to_admin: 'Escalate to Admin',
  raise_dispute: 'Raise Dispute'
};
const ACTION_CARD_TYPES = Object.keys(ACTION_CARD_LABELS);

// Define which action cards are available for each role
const ACTION_CARDS_BY_ROLE = {
  creator: ['custom_offer', 'counter_offer', 'revision_request', 'milestone_update', 'damage_report', 'escalate_to_admin', 'raise_dispute'],
  business: ['private_invitation', 'custom_offer', 'counter_offer', 'revision_request', 'milestone_update', 'escalate_to_admin', 'raise_dispute']
};

const getAvailableActionCards = (userRole, selectedConversation) => {
  const cards = ACTION_CARDS_BY_ROLE[userRole] || ACTION_CARD_TYPES;

  // For creators, only show Milestone Update if there's an active deal
  if (userRole === 'creator' && selectedConversation?.status !== 'active_deal') {
    return cards.filter(card => card !== 'milestone_update');
  }

  return cards;
};

const ACTION_CARD_FORM_FIELDS = {
  custom_offer: [
    ['deliverable_type', 'Deliverable type', 'text', 'Video'],
    ['quantity', 'Quantity', 'number', '1'],
    ['duration', 'Duration', 'text', '30 seconds'],
    ['price', 'Price', 'number', '5000'],
    ['timeline', 'Timeline', 'text', '7 days'],
    ['usage_rights', 'Usage rights', 'text', 'Organic social']
  ],
  private_invitation: [
    ['campaign_name', 'Campaign name', 'text', 'Private campaign'],
    ['deliverable_summary', 'Deliverable summary', 'text', 'UGC video'],
    ['budget', 'Budget', 'number', '5000'],
    ['timeline', 'Timeline', 'text', '7 days'],
    ['usage_rights', 'Usage rights', 'text', 'Organic social'],
    ['full_brief_link', 'Full brief link', 'url', 'https://ugcads.io']
  ],
  counter_offer: [
    ['modified_price', 'Modified price', 'number', '5000'],
    ['revisions', 'Revisions', 'text', '1'],
    ['timeline', 'Timeline', 'text', '7 days'],
    ['usage_rights', 'Usage rights', 'text', 'Organic social'],
    ['diff_vs_original', 'Diff vs original', 'textarea', 'Updated terms']
  ],
  revision_request: [
    ['revision_text', 'Revision item', 'textarea', 'Please revise the submitted content.']
  ],
  milestone_update: [
    ['status', 'Current status', 'select', 'editing', ['In planning', 'Filming', 'Editing', 'Ready to submit']],
    ['notes', 'Notes', 'textarea', '']
  ],
  damage_report: [
    ['reason', 'Reason', 'text', 'Damaged product'],
    ['description', 'Description', 'textarea', 'Damage reported by creator.'],
    ['severity', 'Severity', 'select', 'medium', ['low', 'medium', 'high']]
  ],
  escalate_to_admin: [
    ['summary', 'Summary', 'textarea', 'Please review this chat thread and help resolve the communication issue between both parties.'],
    ['category', 'Category', 'select', 'communication', ['communication', 'timeline', 'clarity', 'other']]
  ],
  raise_dispute: [
    ['summary', 'Dispute summary', 'textarea', 'I want to raise a dispute for this chat/deal.'],
    ['category', 'Category', 'select', 'communication', ['communication', 'timeline', 'clarity', 'other']]
  ]
};

const avatarColors = ['#7387ff', '#ff7043', '#26a69a', '#ab47bc', '#ef5350', '#42a5f5', '#ffa726', '#29b6f6'];
const avatarColor = (name) => avatarColors[name?.charCodeAt ? (name.charCodeAt(0) % avatarColors.length) : 0];

const timeAgo = (timestamp) => {
  if (!timestamp) return '';
  const diff = Date.now() - new Date(timestamp);
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h`;
  const days = Math.floor(hrs / 24);
  if (days === 1) return 'Yesterday';
  return `${days}d`;
};

export default function MessagesPage() {
  const { user, setUser } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const messagesEndRef = useRef(null);
  const fileInputRef = useRef(null);

  const [conversations, setConversations] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [newMessage, setNewMessage] = useState('');
  const [emojiPickerOpen, setEmojiPickerOpen] = useState(false);
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [uploadingFiles, setUploadingFiles] = useState(false);
  const [warnings, setWarnings] = useState(null);
  const [isOtherTyping, setIsOtherTyping] = useState(false);
  const [creatingCard, setCreatingCard] = useState(false);
  const [actionComposerType, setActionComposerType] = useState(null);
  const [actionForm, setActionForm] = useState({});
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const typingSentAtRef = useRef(0);
  const messageContainerRef = useRef(null);
  const userScrolledUpRef = useRef(false);

  const navItems = user?.role === 'business'
    ? [
      { name: 'Brand Dashboard', icon: LayoutDashboard, action: () => navigate('/dashboard/business') },
      { name: 'Post a Brief', icon: SquarePen, action: () => navigate('/dashboard/business/post-brief') },
      { name: 'Creator Bids', icon: UserRoundSearch, action: () => navigate('/dashboard/business/pending-bids') },
      { name: 'Browse Creator', icon: Search, action: () => navigate('/dashboard/business/browse-creator') },
      { name: 'All Campaigns', icon: ClipboardList, action: () => navigate('/dashboard/business/all-campaigns') },
      { name: 'Work Review', icon: FileCheck, action: () => navigate('/dashboard/business/work-review') },
      { name: 'Messages', icon: MessageSquare, action: () => navigate('/messages'), active: true },
      { name: 'Manage Shipment', icon: Package, action: () => navigate('/dashboard/business/shipments') },
      { name: 'Wallet', icon: Wallet, action: () => navigate('/dashboard/business/wallet') },
      { name: 'Settings', icon: Settings, action: () => navigate('/settings') }
    ]
    : [
      { name: 'Dashboard', icon: LayoutDashboard, action: () => navigate('/dashboard/creator') },
      { name: 'My Active Work', icon: Zap, action: () => navigate('/my-active-work') },
      { name: 'My Bids', icon: Bookmark, action: () => navigate('/my-bids') },
      { name: 'Reviews', icon: Star, action: () => navigate('/reviews') },
      { name: 'Portfolio', icon: User, action: () => navigate('/portfolio') },
      { name: 'Browse Briefs', icon: Briefcase, action: () => navigate('/browse-briefs') },
      { name: 'My Deals', icon: FileCheck, action: () => navigate('/my-deals') },
      { name: 'Messages', icon: MessageSquare, action: () => navigate('/messages'), active: true },
      { name: 'Payout', icon: IndianRupee, action: () => navigate('/withdrawal') },
      { name: 'Settings', icon: Settings, action: () => navigate('/settings') }
    ];

  // Refresh user data on mount
  useEffect(() => {
    const refreshUserData = async () => {
      try {
        const response = await axios.get(`${API}/auth/me`);
        setUser(response.data);
      } catch (error) {
        console.error('Failed to refresh user data');
      }
    };
    refreshUserData();
  }, [setUser]);

  // Fetch conversations on mount and every 5s
  useEffect(() => {
    if (user?.id) {
      fetchConversations();
      fetchWarnings();
      const interval = setInterval(fetchConversations, 5000);
      return () => clearInterval(interval);
    }
  }, [user?.id]);

  // Auto-select conversation from URL param
  useEffect(() => {
    const convId = searchParams.get('conv');
    if (convId) setSelectedId(convId);
  }, [searchParams]);

  // Fetch messages when conversation selected
  useEffect(() => {
    if (!selectedId) return;
    fetchMessages(selectedId);
    fetchTyping(selectedId);
    const interval = setInterval(() => fetchMessages(selectedId), 3000);
    const typingInterval = setInterval(() => fetchTyping(selectedId), 3000);
    return () => {
      clearInterval(interval);
      clearInterval(typingInterval);
    };
  }, [selectedId]);

  // Smart auto-scroll: only scroll if user is at bottom
  useEffect(() => {
    if (!messageContainerRef.current) return;
    const container = messageContainerRef.current;
    const isAtBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 100;

    if (isAtBottom && !userScrolledUpRef.current) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages]);

  const handleMessagesScroll = () => {
    if (!messageContainerRef.current) return;
    const container = messageContainerRef.current;
    const isAtBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 100;
    userScrolledUpRef.current = !isAtBottom;
  };

  const fetchConversations = async () => {
    try {
      const res = await axios.get(`${API}/chat/conversations`);
      setConversations(res.data);
      setLoading(false);
    } catch (err) {
      console.error('Failed to load conversations');
      setLoading(false);
    }
  };

  const fetchMessages = async (otherId) => {
    try {
      const res = await axios.get(`${API}/chat/${otherId}`);
      setMessages(res.data);
    } catch (err) {
      console.error('Failed to load messages');
    }
  };

  const fetchWarnings = async () => {
    try {
      const res = await axios.get(`${API}/chat/warnings`);
      setWarnings(res.data);
    } catch (err) {
      console.error('Failed to load chat warnings');
    }
  };

  const fetchTyping = async (otherId) => {
    try {
      const res = await axios.get(`${API}/chat/${otherId}/typing`);
      setIsOtherTyping(Boolean(res.data.typing));
    } catch (err) {
      setIsOtherTyping(false);
    }
  };

  const sendTypingSignal = async () => {
    if (!selectedId) return;
    const now = Date.now();
    if (now - typingSentAtRef.current < 2500) return;
    typingSentAtRef.current = now;
    try {
      await axios.post(`${API}/chat/${selectedId}/typing`);
    } catch (err) {
      // Typing indicators are best-effort.
    }
  };

  const handleSendMessage = async (e) => {
    e?.preventDefault();
    const attachmentUrls = selectedFiles.map((file) => file.url).filter(Boolean);
    if ((!newMessage.trim() && !attachmentUrls.length) || !selectedId) return;

    if (selectedFiles.length && !attachmentUrls.length) {
      toast.error('File upload did not complete. Please attach the file again.');
      return;
    }

    setSending(true);
    try {
      const res = await axios.post(`${API}/chat/send`, {
        recipient_id: selectedId,
        message: newMessage.trim() || `${ATTACHMENT_MESSAGE_PREFIX}${attachmentUrls.join('|')}`,
        attachment_urls: attachmentUrls
      });

      if (res.data.filtered) {
        toast.warning(`Message filtered for policy violations. Warning ${res.data.warning_count}/3`);
      }

      setNewMessage('');
      setSelectedFiles([]);
      setEmojiPickerOpen(false);
      await fetchMessages(selectedId);
    } catch (err) {
      if (err.response?.status === 400 && err.response?.data?.detail?.includes('contact information')) {
        toast.error(err.response.data.detail);
        fetchWarnings();
        return;
      }
      toast.error(err.response?.data?.detail || 'Failed to send message');
    } finally {
      setSending(false);
    }
  };

  const handleFileSelect = (event) => {
    const files = Array.from(event.target.files || []);
    if (!files.length) {
      event.target.value = '';
      return;
    }

    const validationError = validateSelectedFiles(files);
    if (validationError) {
      toast.error(validationError);
      event.target.value = '';
      return;
    }

    setUploadingFiles(true);
    Promise.all(files.map(async (file) => {
      const formData = new FormData();
      formData.append('file', file);
      const res = await axios.post(`${API}/upload/file`, formData, { headers: { 'Content-Type': 'multipart/form-data' } });
      const fileUrl = res.data.file_url || res.data.url || res.data.path;
      if (!fileUrl) throw new Error(`${file.name} uploaded but no file URL was returned`);
      return { name: file.name, url: fileUrl };
    }))
      .then((uploadedFiles) => {
        setSelectedFiles((current) => [...current, ...uploadedFiles]);
        toast.success(`${uploadedFiles.length} file${uploadedFiles.length > 1 ? 's' : ''} attached`);
      })
      .catch((err) => {
        toast.error(err.response?.data?.detail || 'File attachment failed');
      })
      .finally(() => {
        setUploadingFiles(false);
      });

    event.target.value = '';
  };

  const removeSelectedFile = (url) => {
    setSelectedFiles((current) => current.filter((file) => file.url !== url));
  };

  const validateSelectedFiles = (files) => {
    if (selectedFiles.length + files.length > MAX_ATTACHMENTS) return 'A message can include at most 5 attachments.';
    for (const file of files) {
      const isImage = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif'].includes(file.type);
      const isPdf = file.type === 'application/pdf';
      const isVideo = file.type?.startsWith('video/');
      if (!isImage && !isPdf && !isVideo) return 'Upload jpg, png, gif, pdf, or video files only.';
      if (isImage && file.size > 10 * 1024 * 1024) return 'Images must be 10 MB or smaller.';
      if (isPdf && file.size > 25 * 1024 * 1024) return 'PDFs must be 25 MB or smaller.';
      if (isVideo && file.size > 50 * 1024 * 1024) return 'Videos must be 50 MB or smaller.';
    }
    return '';
  };

  const getAttachmentUrl = (url) => {
    if (!url) return '';
    return url.startsWith('http') ? url : `${BACKEND_URL}${url}`;
  };

  const getAttachmentName = (url, index) => {
    if (!url) return `Attachment ${index + 1}`;
    return decodeURIComponent(String(url).split('/').pop() || `Attachment ${index + 1}`);
  };

  const getMessageAttachments = (msg) => {
    if (msg.attachment_urls?.length) return msg.attachment_urls;
    if (typeof msg.message === 'string' && msg.message.startsWith(ATTACHMENT_MESSAGE_PREFIX)) {
      return msg.message.slice(ATTACHMENT_MESSAGE_PREFIX.length).split('|').filter(Boolean);
    }
    return [];
  };

  const getDisplayMessage = (msg) => {
    if (typeof msg.message === 'string' && msg.message.startsWith(ATTACHMENT_MESSAGE_PREFIX)) return '';
    return msg.message;
  };

  const renderAttachments = (attachmentUrls = []) => {
    if (!attachmentUrls.length) return null;
    return (
      <div className="msg-bubble-attachments">
        {attachmentUrls.map((url, index) => (
          <a key={`${url}-${index}`} href={getAttachmentUrl(url)} target="_blank" rel="noreferrer">
            <FileText size={14} />
            <span>{getAttachmentName(url, index)}</span>
          </a>
        ))}
      </div>
    );
  };

  const getItemTime = (item) => item.created_at || item.timestamp;

  const formatActionValue = (value) => {
    if (Array.isArray(value)) return value.map((item) => typeof item === 'object' ? Object.values(item).filter(Boolean).join(' - ') : item).join(', ');
    if (typeof value === 'object' && value !== null) return Object.values(value).filter(Boolean).join(' - ');
    return String(value ?? '');
  };

  const getReadLabel = (item) => {
    if (item.sender_id !== user.id) return '';
    if (item.status === 'read' || item.read_at || (item.read_by || []).includes(selectedId)) return 'Read';
    return 'Delivered';
  };

  const respondToActionCard = async (cardId, action) => {
    try {
      await axios.post(`${API}/chat/action-cards/${cardId}/respond`, { action });
      toast.success('Action card updated');
      fetchMessages(selectedId);
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Action failed');
    }
  };

  const renderActionCard = (item) => {
    const fields = item.fields || {};
    const isOwn = item.sender_id === user.id;
    return (
      <div key={item.id} className={`msg-action-card ${isOwn ? 'is-own' : ''}`}>
        <div className="msg-action-card-head">
          <span><ShieldAlert size={16} /></span>
          <div>
            <strong>{ACTION_CARD_LABELS[item.type] || item.type}</strong>
            {item.deal_id ? <small>{item.deal_id}</small> : null}
          </div>
          <em>{item.status || 'open'}</em>
        </div>
        <div className="msg-action-card-fields">
          {Object.entries(fields).slice(0, 6).map(([key, value]) => (
            <p key={key}><span>{key.replaceAll('_', ' ')}</span><strong>{formatActionValue(value)}</strong></p>
          ))}
        </div>
        {!isOwn && item.status === 'open' && item.available_actions?.length ? (
          <div className="msg-action-card-actions">
            {item.available_actions.map((action) => (
              <button key={action} type="button" onClick={() => respondToActionCard(item.id, action)}>{action}</button>
            ))}
          </div>
        ) : null}
        <small className="msg-action-card-time">{new Date(getItemTime(item)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</small>
      </div>
    );
  };

  const getDefaultActionForm = (type) => Object.fromEntries(
    (ACTION_CARD_FORM_FIELDS[type] || []).map(([key, , , fallback]) => [key, fallback])
  );

  const openActionComposer = (type) => {
    setActionComposerType(type);
    setActionForm(getDefaultActionForm(type));
  };

  const closeActionComposer = () => {
    setActionComposerType(null);
    setActionForm({});
  };

  const getActionCardPayloadFields = () => {
    const fields = { ...actionForm };
    if (actionComposerType === 'revision_request') {
      return { revision_items: [{ description: fields.revision_text, severity: 'medium' }] };
    }
    ['quantity', 'price', 'budget', 'modified_price'].forEach((key) => {
      if (fields[key] !== undefined) fields[key] = Number(fields[key]);
    });
    return fields;
  };

  const submitActionCard = async (event) => {
    event?.preventDefault();
    if (!selectedId || creatingCard || !actionComposerType) return;
    setCreatingCard(true);
    try {
      await axios.post(`${API}/chat/action-cards`, {
        recipient_id: selectedId,
        type: actionComposerType,
        fields: getActionCardPayloadFields()
      });
      toast.success(`${ACTION_CARD_LABELS[actionComposerType]} sent`);
      closeActionComposer();
      fetchMessages(selectedId);
      fetchConversations();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Action card failed');
    } finally {
      setCreatingCard(false);
    }
  };

  const renderActionComposerField = ([key, label, type, , options]) => {
    const value = actionForm[key] ?? '';
    if (type === 'textarea') {
      return (
        <label key={key}>
          <span>{label}</span>
          <textarea value={value} onChange={(event) => setActionForm((current) => ({ ...current, [key]: event.target.value }))} />
        </label>
      );
    }
    if (type === 'select') {
      return (
        <label key={key}>
          <span>{label}</span>
          <select value={value} onChange={(event) => setActionForm((current) => ({ ...current, [key]: event.target.value }))}>
            {(options || []).map((option) => <option key={option} value={String(option).toLowerCase().replaceAll(' ', '_')}>{option}</option>)}
          </select>
        </label>
      );
    }
    return (
      <label key={key}>
        <span>{label}</span>
        <input type={type} value={value} onChange={(event) => setActionForm((current) => ({ ...current, [key]: event.target.value }))} />
      </label>
    );
  };

  const handleEmojiSelect = (emoji) => {
    setNewMessage((current) => `${current}${emoji}`);
    setEmojiPickerOpen(false);
  };

  // Filter conversations
  const filteredConversations = conversations.filter((conv) => {
    const matchesSearch = conv.nickname.toLowerCase().includes(search.toLowerCase());
    const matchesFilter =
      filter === 'all' ||
      conv.thread_classification === filter;
    return matchesSearch && matchesFilter;
  });

  const selectedConv = conversations.find((c) => c.user_id === selectedId);
  const actionCardsOnly = warnings?.action_cards_only_until && new Date(warnings.action_cards_only_until) > new Date();

  return (
    <DashboardLayout
      navItems={navItems}
      title="Messages"
      description={user?.role === 'business' ? 'Connect with creators and manage campaign conversations' : 'Connect with brands and manage conversations'}
      topbarExtra={null}
      sidebarExtra={null}
      sidebarVariant={user?.role === 'business' ? 'business-match' : undefined}
      sidebarLabel={user?.role === 'business' ? 'Business' : 'Menu'}
    >
      <div className="msg-layout">
        {/* Left Panel: Conversations List */}
        <div className="msg-list-panel">
          <div className="msg-list-header">
            <h2>Messages</h2>
            <p>Manage your campaign conversations</p>
          </div>

          <div className="msg-search">
            <Search size={16} />
            <input
              type="text"
              placeholder="Search messages..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          <div className="msg-filters">
            {CHAT_FILTERS.map((f) => (
              <button
                key={f.value}
                className={filter === f.value ? 'is-active' : ''}
                onClick={() => setFilter(f.value)}
              >
                {f.label}
              </button>
            ))}
          </div>

          <div className="msg-conv-list">
            {loading ? (
              <div style={{ padding: '20px', textAlign: 'center', color: '#999' }}>Loading...</div>
            ) : filteredConversations.length === 0 ? (
              <div style={{ padding: '20px', textAlign: 'center', color: '#999' }}>No conversations</div>
            ) : (
              filteredConversations.map((conv) => (
                <div
                  key={conv.user_id}
                  className={`msg-conv-item ${selectedId === conv.user_id ? 'is-active' : ''}`}
                  onClick={() => setSelectedId(conv.user_id)}
                >
                  <div className="msg-avatar-wrap">
                    <div className="msg-avatar" style={{ background: avatarColor(conv.nickname) }}>
                      {getInitial(conv.nickname)}
                    </div>
                    <span className="msg-online-dot" />
                  </div>
                  <div className="msg-conv-body">
                    <div className="msg-conv-top">
                      <strong>{conv.nickname}</strong>
                      <span className="msg-time-ago">{timeAgo(conv.timestamp || conv.last_message?.timestamp)}</span>
                    </div>
                    <p className="msg-preview">
                      {getDisplayMessage(conv.last_message || {})
                        ? `${getDisplayMessage(conv.last_message).slice(0, 50)}...`
                        : getMessageAttachments(conv.last_message || {}).length
                          ? 'File attachment'
                          : ''}
                    </p>
                    {conv.associated_deal_status ? <small className="msg-deal-status">{conv.associated_deal_status}</small> : null}
                  </div>
                  {conv.unread_count > 0 && <span className="msg-badge">{conv.unread_count}</span>}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Center Panel: Chat Area */}
        {selectedId ? (
          <div className="msg-chat-panel">
            {/* Header */}
            <div className="msg-chat-header">
              <div className="msg-avatar-wrap" style={{ width: '48px', height: '48px' }}>
                <div className="msg-avatar" style={{ background: avatarColor(selectedConv?.nickname) }}>
                  {getInitial(selectedConv?.nickname)}
                </div>
                <span className="msg-online-dot"></span>
              </div>
              <div className="msg-header-info">
                <div>
                  <strong>{selectedConv?.nickname}</strong>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ width: '8px', height: '8px', background: '#48bb78', borderRadius: '50%', display: 'inline-block' }}></span>
                  <small className="msg-online">Online</small>
                </div>
              </div>
              <div className="msg-chat-actions">
                <button type="button" title="View profile" onClick={() => navigate(`/profile/${selectedId}`)}><User size={18} /></button>
                <button type="button" title="Report user" onClick={() => toast.info('Report flow coming soon')}><Flag size={18} /></button>
                <button type="button" title="Mute notifications" onClick={() => toast.success('Notifications muted for this thread')}><BellOff size={18} /></button>
                <button type="button" title="More actions"><MoreHorizontal size={18} /></button>
              </div>
            </div>

            {/* Messages */}
            <div className="msg-messages" ref={messageContainerRef} onScroll={handleMessagesScroll}>
              {messages.length === 0 ? (
                <div style={{ textAlign: 'center', color: '#999', marginTop: '40px' }}>No messages yet</div>
              ) : (
                messages.map((msg, idx) => {
                  if (msg.item_type === 'action_card') return renderActionCard(msg);
                  const isOwn = msg.sender_id === user.id;
                  const isSystem = msg.system_message || msg.sender_id === 'system';

                  if (isSystem) {
                    return (
                      <div key={msg.id || idx} className="msg-system-pill">
                        {msg.message}
                      </div>
                    );
                  }

                  return (
                    <div key={msg.id || idx} className={`msg-bubble-row ${isOwn ? 'is-own' : ''}`}>
                      {!isOwn && (
                        <div className="msg-avatar sm" style={{ background: avatarColor(selectedConv?.nickname) }}>
                          {getInitial(selectedConv?.nickname)}
                        </div>
                      )}
                      <div className="msg-bubble">
                        {getDisplayMessage(msg) ? <p>{getDisplayMessage(msg)}</p> : null}
                        {renderAttachments(getMessageAttachments(msg))}
                        <span className="msg-time">
                          {new Date(getItemTime(msg)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          {getReadLabel(msg) ? <em><CheckCheck size={13} /> {getReadLabel(msg)}</em> : null}
                        </span>
                      </div>
                    </div>
                  );
                })
              )}
              {isOtherTyping ? <div className="msg-typing">{selectedConv?.nickname || 'User'} is typing...</div> : null}
              <div ref={messagesEndRef} />
            </div>

            {/* Quick Actions */}
            <div className="msg-quick-chips">
              {getAvailableActionCards(user?.role, selectedConv).map((action) => (
                <button
                  key={action}
                  disabled={creatingCard}
                  onClick={() => openActionComposer(action)}
                >
                  {ACTION_CARD_LABELS[action]}
                </button>
              ))}
            </div>

            {actionCardsOnly ? (
              <div className="msg-policy-banner">
                <AlertTriangle size={16} />
                <span>Free-form chat is temporarily disabled. Action Cards are still available.</span>
              </div>
            ) : null}

            {actionComposerType ? (
              <form className="msg-action-composer" onSubmit={submitActionCard}>
                <div className="msg-action-composer-head">
                  <div>
                    <strong>{ACTION_CARD_LABELS[actionComposerType]}</strong>
                    <small>Fill the details and send a structured action card.</small>
                  </div>
                  <div className="msg-action-composer-head-actions">
                    <button type="submit" className="msg-action-send-top" disabled={creatingCard}>
                      {creatingCard ? 'Sending...' : 'Send Card'}
                    </button>
                    <button type="button" className="msg-action-close" aria-label="Close action card form" onClick={closeActionComposer}><X size={16} /></button>
                  </div>
                </div>
                <div className="msg-action-composer-grid">
                  {(ACTION_CARD_FORM_FIELDS[actionComposerType] || []).map(renderActionComposerField)}
                </div>
                <div className="msg-action-composer-actions">
                  <button type="button" onClick={closeActionComposer}>Cancel</button>
                  <button type="submit" disabled={creatingCard}>{creatingCard ? 'Sending...' : 'Send Card'}</button>
                </div>
              </form>
            ) : null}

            {/* Input */}
            {selectedFiles.length > 0 && (
              <div className="msg-attachment-preview">
                {selectedFiles.map((file) => (
                  <span key={file.url}>
                    {file.name}
                    <button type="button" aria-label={`Remove ${file.name}`} onClick={() => removeSelectedFile(file.url)}>x</button>
                  </span>
                ))}
              </div>
            )}
            <form className="msg-input-row" onSubmit={handleSendMessage}>
              <input
                ref={fileInputRef}
                type="file"
                hidden
                multiple
                accept="image/jpeg,image/png,image/gif,application/pdf,video/*"
                onChange={handleFileSelect}
              />
              <div className="msg-emoji-wrap">
                <button
                  type="button"
                  className="msg-input-icon"
                  aria-label="Choose emoji"
                  onClick={() => setEmojiPickerOpen((open) => !open)}
                >
                  <Smile size={18} />
                </button>
                {emojiPickerOpen && (
                  <div className="msg-emoji-picker">
                    {['😊', '👍', '🙏', '🔥', '✨', '✅', '👀', '💬', '📦', '🎥', '⚠️', '❤️'].map((emoji) => (
                      <button key={emoji} type="button" onClick={() => handleEmojiSelect(emoji)}>
                        {emoji}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <button
                type="button"
                className="msg-input-icon"
                aria-label="Attach file"
                disabled={uploadingFiles || sending}
                onClick={() => fileInputRef.current?.click()}
              >
                <Paperclip size={18} />
              </button>
              <input
                type="text"
                value={newMessage}
                onChange={(e) => {
                  setNewMessage(e.target.value);
                  sendTypingSignal();
                }}
                placeholder={actionCardsOnly ? 'Use an Action Card to continue this thread' : 'Type a message...'}
                className="msg-input"
                disabled={actionCardsOnly}
              />
              <button type="submit" className="msg-send" disabled={actionCardsOnly || sending || uploadingFiles || (!newMessage.trim() && !selectedFiles.length)}>
                <Send size={18} />
              </button>
            </form>
          </div>
        ) : (
          <div className="msg-chat-panel msg-empty">
            <div style={{ textAlign: 'center', color: '#999' }}>
              <MessageSquare size={48} style={{ margin: '0 auto 16px', opacity: 0.5 }} />
              <p>Select a conversation to start messaging</p>
            </div>
          </div>
        )}

      </div>
    </DashboardLayout>
  );
}
