import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'sonner';
import { AlertTriangle, Check, ChevronLeft, ChevronRight, FileText, Info, Plus, Save, Send, Trash2, Upload } from 'lucide-react';
import { useAuth } from '../App';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;
const DRAFT_KEY = 'ugcad-brand-brief-draft-v2';
const COMMISSION_RATE = 0.25;
const LISTING_FEE = 500;

const STEPS = [
  'Campaign Basics',
  'Deliverables',
  'Must-Include',
  'Must-Avoid',
  'Style Guidance',
  'Usage Rights',
  'Timeline & Budget',
  'Review & Publish'
];

const CATEGORIES = ['Beauty', 'Tech', 'Fitness', 'Fashion', 'Travel', 'Food', 'Gaming', 'Lifestyle', 'Home Decor', 'Wellness'];
const OBJECTIVES = ['Awareness', 'Product launch', 'Seasonal push', 'Testimonial', 'Tutorial', 'Unboxing', 'Comparison', 'Sale promotion', 'Customer education', 'Other'];
const DELIVERABLE_TYPES = ['Reel (9:16, under 30s)', 'Short-form (30-60s)', 'YouTube Short (9:16, 60s max)', 'Long-form video (2+ minutes)', 'Static post', 'Carousel post', 'Story set (3-5 frames)'];
const ASPECTS = ['9:16', '1:1', '16:9', '4:5'];
const CTAS = ['Visit website', 'Use code', 'Swipe up', 'Follow brand', 'None'];
const TONES = ['Casual', 'Energetic', 'Informative', 'Humorous', 'Aspirational', 'Authentic', 'Educational', 'Trustworthy'];
const CREATOR_LEVELS = ['New', 'Verified', 'L1', 'L2', 'Elite'];
const QUALITY_TIERS = ['A', 'A+', 'A++'];
const GENDER_OPTIONS = ['No Preference', 'Female', 'Male', 'Non-binary'];
const CITIES = ['Any City', 'Mumbai', 'Delhi NCR', 'Bengaluru', 'Hyderabad', 'Chennai', 'Pune', 'Kolkata', 'Ahmedabad', 'Jaipur'];
const NICHE_TAGS = ['Beauty', 'Skincare', 'Fashion', 'Fitness', 'Food', 'Lifestyle', 'Tech', 'Travel', 'Home Decor', 'Wellness', 'Parenting', 'Gaming'];
const VIDEO_DELIVERABLES = ['Reel', 'Short-form', 'YouTube Short', 'Long-form video'];
const PLATFORMS = [
  "Brand's own Instagram",
  "Brand's own TikTok / Reels",
  "Brand's own YouTube",
  "Brand's own website",
  "Brand's email marketing",
  'Paid ads on Meta platforms',
  'Paid ads on Google / YouTube',
  'Paid ads on other platforms',
  'Out-of-home (billboards, print)',
  'B2B sales materials (pitch decks, demos)',
  'Third-party aggregators / marketplaces'
];

const createDeliverable = () => ({
  id: crypto.randomUUID?.() || String(Date.now()),
  type: '',
  quantity: 1,
  duration: '',
  aspectRatios: ['9:16'],
  rawRequired: false
});

const initialForm = {
  campaignName: '',
  brandName: '',
  category: '',
  productName: '',
  productDescription: '',
  campaignHook: '',
  keyMessage: '',
  objectives: [],
  targetAudience: '',
  budgetVisible: true,
  deliverables: [createDeliverable()],
  productVisible: true,
  visibilitySeconds: '',
  verbalMention: true,
  productNames: '',
  requiredPhrases: [''],
  requiredShots: [''],
  callToAction: 'Visit website',
  promoCode: '',
  hashtags: '',
  brandHandleTag: true,
  noCompetitors: true,
  competitors: '',
  noOtherProducts: true,
  noProfanity: true,
  noPolitical: true,
  avoidFilters: false,
  filterTypes: '',
  avoidText: '',
  tones: [],
  pacing: 'No preference',
  moodImages: [],
  referenceVideos: [''],
  musicPreference: 'No preference',
  platforms: [],
  rightsDuration: '',
  exclusivity: 'None',
  whitelisting: false,
  modificationRights: '',
  productShippingBy: '',
  draftDeliveryBy: '',
  revisions: 2,
  finalDeliveryBy: '',
  budgetMode: 'fixed',
  fixedBudget: '',
  budgetMin: '',
  budgetMax: '',
  creatorLevel: '',
  qualityTier: '',
  genderPreference: 'No Preference',
  cityFilter: 'Any City',
  nicheTags: []
};

const ToggleChip = ({ active, children, onClick }) => (
  <button type="button" className={`brief-chip ${active ? 'active' : ''}`} onClick={onClick}>
    {children}
  </button>
);

const isVideoDeliverable = (type = '') => VIDEO_DELIVERABLES.some(label => type.startsWith(label));

const parseDurationSeconds = (value = '') => {
  const match = String(value).match(/\d+/);
  return match ? Number(match[0]) : 30;
};

const addDays = (dateString, days) => {
  if (!dateString) return '';
  const date = new Date(dateString);
  if (Number.isNaN(date.getTime())) return '';
  date.setDate(date.getDate() + days);
  return date.toISOString().slice(0, 10);
};

export default function PostABrief() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [step, setStep] = useState(1);
  const [form, setForm] = useState(initialForm);
  const [submitting, setSubmitting] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [publishMode, setPublishMode] = useState('matches');
  const [draftSavedAt, setDraftSavedAt] = useState('');

  useEffect(() => {
    const saved = localStorage.getItem(DRAFT_KEY);
    if (saved) {
      try {
        setForm({ ...initialForm, ...JSON.parse(saved) });
      } catch {
        localStorage.removeItem(DRAFT_KEY);
      }
    }

    axios.get(`${API}/business/settings/profile`)
      .then(res => {
        const profile = res.data || {};
        setForm(current => ({
          ...current,
          brandName: current.brandName || profile.brand_name || user?.nickname || user?.full_name || '',
          category: current.category || profile.primary_category || profile.business_category || ''
        }));
      })
      .catch(() => {
        setForm(current => ({ ...current, brandName: current.brandName || user?.nickname || user?.full_name || '' }));
      });
  }, [user?.id]);

  useEffect(() => {
    localStorage.setItem(DRAFT_KEY, JSON.stringify(form));
    setDraftSavedAt(new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
  }, [form]);

  const set = (field, value) => setForm(current => ({ ...current, [field]: value }));
  const toggleArray = (field, value) => {
    setForm(current => {
      const values = current[field] || [];
      return { ...current, [field]: values.includes(value) ? values.filter(item => item !== value) : [...values, value] };
    });
  };

  const budget = Number(form.budgetMode === 'fixed' ? form.fixedBudget : form.budgetMax) || 0;
  const commission = Math.round(budget * COMMISSION_RATE);
  const totalDebit = budget + commission + LISTING_FEE;
  const paidAdsSelected = form.platforms.some(platform => platform.toLowerCase().includes('paid ads'));
  const draftDeliverySuggestion = useMemo(() => addDays(form.productShippingBy, 7), [form.productShippingBy]);
  const pricingLifts = [
    form.rightsDuration === 'Perpetual' ? 'Perpetual rights: +40% suggested' : '',
    form.whitelisting ? 'Whitelisting enabled: +30% suggested' : '',
    form.exclusivity === '90 days' ? '90-day exclusivity: +25% suggested' : '',
    paidAdsSelected ? 'Paid ads allowed: +20% suggested' : ''
  ].filter(Boolean);

  const finalDeliverySuggestion = useMemo(() => {
    return addDays(form.draftDeliveryBy, Math.max(1, Number(form.revisions || 0) * 2));
  }, [form.draftDeliveryBy, form.revisions]);

  useEffect(() => {
    if (!form.draftDeliveryBy && draftDeliverySuggestion) {
      set('draftDeliveryBy', draftDeliverySuggestion);
    }
  }, [draftDeliverySuggestion]);

  useEffect(() => {
    if (!form.finalDeliveryBy && finalDeliverySuggestion) {
      set('finalDeliveryBy', finalDeliverySuggestion);
    }
  }, [finalDeliverySuggestion]);

  const updateDeliverable = (id, patch) => {
    set('deliverables', form.deliverables.map(item => item.id === id ? { ...item, ...patch } : item));
  };

  const addDeliverable = () => {
    if (form.deliverables.length >= 5) {
      toast.error('You can add up to 5 deliverables');
      return;
    }
    set('deliverables', [...form.deliverables, createDeliverable()]);
  };

  const removeDeliverable = (id) => {
    if (form.deliverables.length === 1) return;
    if (window.confirm('Remove this deliverable from the brief?')) {
      set('deliverables', form.deliverables.filter(item => item.id !== id));
    }
  };

  const addTextItem = (field, max) => {
    if ((form[field] || []).length >= max) return;
    set(field, [...(form[field] || []), '']);
  };

  const updateTextItem = (field, index, value) => {
    set(field, form[field].map((item, idx) => idx === index ? value : item));
  };

  const isStepValid = (target = step) => {
    if (target === 1) return form.campaignName.trim().length >= 3 && form.campaignName.trim().length <= 80 && form.productName.trim().length >= 2 && form.productDescription.trim().length >= 20 && form.campaignHook.trim().length >= 10 && form.keyMessage.trim().length >= 10 && form.category && form.objectives.length > 0 && form.targetAudience.trim().length >= 50 && form.targetAudience.trim().length <= 200;
    if (target === 2) return form.deliverables.length > 0 && form.deliverables.every(item => item.type && item.quantity >= 1 && item.quantity <= 5 && item.aspectRatios.length > 0 && (!isVideoDeliverable(item.type) || item.duration));
    if (target === 3) return (!form.productVisible || form.visibilitySeconds) && (!form.verbalMention || form.productNames) && form.callToAction && (form.callToAction !== 'Use code' || form.promoCode);
    if (target === 4) return form.avoidText.length <= 200;
    if (target === 5) return form.tones.length > 0 && form.pacing;
    if (target === 6) return form.platforms.length > 0 && form.rightsDuration && form.exclusivity && form.modificationRights;
    if (target === 7) return form.productShippingBy && form.draftDeliveryBy && form.finalDeliveryBy && budget > 0 && form.creatorLevel && form.qualityTier;
    return true;
  };

  const goNext = () => {
    if (!isStepValid()) {
      toast.error('Please complete the required fields for this section');
      return;
    }
    setStep(Math.min(8, step + 1));
  };

  const saveDraft = () => {
    localStorage.setItem(DRAFT_KEY, JSON.stringify(form));
    toast.success('Draft saved');
  };

  const handleHashtagsChange = (value) => {
    const tags = value.split(/\s+/).filter(Boolean).slice(0, 10);
    set('hashtags', tags.join(' '));
  };

  const briefText = () => {
    return [
      `Campaign: ${form.campaignName}`,
      `Brand: ${form.brandName}`,
      `Category: ${form.category}`,
      `Product: ${form.productName}`,
      `Product description: ${form.productDescription}`,
      `Hook: ${form.campaignHook}`,
      `Key message: ${form.keyMessage}`,
      `Objectives: ${form.objectives.join(', ')}`,
      `Target audience: ${form.targetAudience}`,
      `Budget visibility: ${form.budgetVisible ? 'Visible to creators' : 'Hidden from creators - admin flag'}`,
      '',
      'Deliverables:',
      ...form.deliverables.map((item, index) => `${index + 1}. ${item.quantity} x ${item.type}; duration ${item.duration || 'n/a'}; ratios ${item.aspectRatios.join(', ')}; raw files ${item.rawRequired ? 'required' : 'not required'}`),
      '',
      `Must include: product visible ${form.productVisible ? `${form.visibilitySeconds}s minimum` : 'no'}; verbal mention ${form.verbalMention ? form.productNames : 'no'}; CTA ${form.callToAction}; promo ${form.promoCode || 'n/a'}; hashtags ${form.hashtags || 'n/a'}; brand tag ${form.brandHandleTag ? 'yes' : 'no'}`,
      `Required phrases: ${form.requiredPhrases.filter(Boolean).join(', ') || 'none'}`,
      `Required shots: ${form.requiredShots.filter(Boolean).join(', ') || 'none'}`,
      `Must avoid: competitors ${form.noCompetitors ? form.competitors || 'listed competitors' : 'not specified'}; other products ${form.noOtherProducts ? 'no' : 'allowed'}; profanity ${form.noProfanity ? 'no' : 'allowed'}; political/religious ${form.noPolitical ? 'no' : 'allowed'}; filters ${form.avoidFilters ? form.filterTypes || 'avoid' : 'allowed'}; specific avoid ${form.avoidText || 'none'}`,
      `Style guidance: tones ${form.tones.join(', ')}; pacing ${form.pacing}; music ${form.musicPreference}; references ${form.referenceVideos.filter(Boolean).join(', ') || 'none'}`,
      `Usage rights: platforms ${form.platforms.join(', ')}; duration ${form.rightsDuration}; exclusivity ${form.exclusivity}; whitelisting ${form.whitelisting ? 'yes' : 'no'}; modification ${form.modificationRights}`,
      `Creator targeting: level ${form.creatorLevel}; quality ${form.qualityTier}; gender ${form.genderPreference}; city ${form.cityFilter}; niches ${form.nicheTags.join(', ') || 'none'}`,
      `Timeline: ship by ${form.productShippingBy}; draft by ${form.draftDeliveryBy}; revisions ${form.revisions}; final by ${form.finalDeliveryBy}`,
      `Budget: ${form.budgetMode === 'fixed' ? `fixed Rs. ${form.fixedBudget}` : `range Rs. ${form.budgetMin} - Rs. ${form.budgetMax}`}`,
      `Commission: platform 25%, total wallet debit Rs. ${totalDebit}, creator receives Rs. ${budget} pre-tax`
    ].join('\n');
  };

  const publish = async () => {
    try {
      setSubmitting(true);
      const primaryDeliverable = form.deliverables[0] || {};
      const payload = {
        status: 'pending_approval',
        title: form.campaignName,
        brief_text: briefText(),
        budget_min: form.budgetMode === 'fixed' ? budget : Number(form.budgetMin || 0),
        budget_max: budget,
        objectives: form.objectives,
        requires_shipment: true,
        shipment_required: true,
        shipment_option: 'yes',
        due_date: form.finalDeliveryBy,
        deadline: form.finalDeliveryBy,
        revision_limit: Number(form.revisions || 0),
        product_name: form.productName,
        product_category: form.category,
        product_description: form.productDescription,
        brief_type: primaryDeliverable.type,
        campaign_hook: form.campaignHook,
        key_message: form.keyMessage,
        what_not_to_do: avoidRules,
        tone_reference: form.pacing,
        tone_tags: form.tones,
        video_format: primaryDeliverable.type,
        aspect_ratio: primaryDeliverable.aspectRatios[0],
        duration_seconds: parseDurationSeconds(primaryDeliverable.duration),
        additional_deliverables: form.deliverables.slice(1).map(item => `${item.quantity} x ${item.type}`),
        free_revisions: Number(form.revisions || 0),
        creator_level: form.creatorLevel,
        content_quality_tier: form.qualityTier,
        gender_preference: form.genderPreference,
        city_filter: form.cityFilter,
        creator_niche_tags: form.nicheTags,
        per_video_budget: budget,
        total_budget: budget,
        currency: 'INR'
      };
      const response = await axios.post(`${API}/campaigns`, payload);
      localStorage.removeItem(DRAFT_KEY);
      const submitted = response.data?.status === 'pending_approval';
      toast.success(submitted ? 'Brief submitted for admin approval' : 'Brief saved as draft');
      navigate(publishMode === 'invite' ? '/dashboard/business/pending-bids' : '/dashboard/business');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to publish brief');
    } finally {
      setSubmitting(false);
      setShowConfirm(false);
    }
  };

  const renderTextList = (field, max, placeholder) => (
    <div className="brief-list-inputs">
      {form[field].map((item, index) => (
        <input key={index} value={item} onChange={(event) => updateTextItem(field, index, event.target.value)} placeholder={placeholder} />
      ))}
      {form[field].length < max && <button type="button" onClick={() => addTextItem(field, max)}><Plus size={15} /> Add item</button>}
    </div>
  );

  const requiredPhrases = form.requiredPhrases.filter(Boolean).join(', ') || 'None';
  const requiredShots = form.requiredShots.filter(Boolean).join(', ') || 'None';
  const referenceVideos = form.referenceVideos.filter(Boolean).join(', ') || 'None';
  const avoidRules = [
    form.noCompetitors ? `No competitor brands visible${form.competitors ? `: ${form.competitors}` : ''}` : '',
    form.noOtherProducts ? 'No other products in frame' : '',
    form.noProfanity ? 'No profanity or adult language' : '',
    form.noPolitical ? 'No political or religious content' : '',
    form.avoidFilters ? `Avoid filters / effects${form.filterTypes ? `: ${form.filterTypes}` : ''}` : '',
    form.avoidText ? `Specific avoid: ${form.avoidText}` : ''
  ].filter(Boolean).join('; ') || 'None';

  return (
    <div className="pab-page brief-builder-page">
      <div className="pab-stepper brief-stepper">
        <div className="stepper-track">
          {STEPS.map((label, index) => {
            const number = index + 1;
            const active = step === number;
            const done = step > number;
            return (
              <button key={label} type="button" className={`brief-step ${active ? 'active' : ''} ${done ? 'done' : ''}`} onClick={() => done && setStep(number)}>
                <span>{done ? <Check size={15} /> : number}</span>
                <small>{label}</small>
              </button>
            );
          })}
        </div>
      </div>

      <div className="pab-body brief-body">
        <div className="pab-form-panel brief-panel">
          <div className="step-content">
            <div className="step-badge">Section {String.fromCharCode(64 + step)} of H</div>
            <div className="step-header">
              <h2>{STEPS[step - 1]}</h2>
              <p>{draftSavedAt ? `Draft autosaved at ${draftSavedAt}` : 'Partial briefs are saved as drafts automatically.'}</p>
            </div>

            {step === 1 && (
              <>
                <div className="form-group"><label>Campaign name *</label><input className="input-field" value={form.campaignName} onChange={e => set('campaignName', e.target.value.slice(0, 80))} placeholder="Summer Launch - Unboxing 2" /><small>{form.campaignName.length}/80 characters</small></div>
                <div className="form-row">
                  <div className="form-group"><label>Brand name</label><input className="input-field" value={form.brandName} disabled /></div>
                  <div className="form-group"><label>Category *</label><select className="input-field" value={form.category} onChange={e => set('category', e.target.value)}><option value="">Select category</option>{CATEGORIES.map(item => <option key={item}>{item}</option>)}</select></div>
                </div>
                <div className="form-row">
                  <div className="form-group"><label>Product name *</label><input className="input-field" value={form.productName} onChange={e => set('productName', e.target.value)} placeholder="Glow Serum 30ml" /></div>
                  <div className="form-group"><label>Campaign hook *</label><input className="input-field" value={form.campaignHook} onChange={e => set('campaignHook', e.target.value)} placeholder="Start with a morning routine problem-solution moment" /></div>
                </div>
                <div className="form-group"><label>Product description * (20+ characters)</label><textarea className="textarea-field" value={form.productDescription} onChange={e => set('productDescription', e.target.value)} placeholder="Describe the product, who it helps, and what creators should understand before filming." rows={3} /></div>
                <div className="form-group"><label>Key message *</label><input className="input-field" value={form.keyMessage} onChange={e => set('keyMessage', e.target.value)} placeholder="The one message every video should communicate" /></div>
                <div className="form-group"><label>Campaign objective *</label><div className="brief-chip-grid">{OBJECTIVES.map(item => <ToggleChip key={item} active={form.objectives.includes(item)} onClick={() => set('objectives', [item])}>{item}</ToggleChip>)}</div></div>
                <div className="form-group"><label>Target audience * (50-200 characters)</label><textarea className="textarea-field" value={form.targetAudience} onChange={e => set('targetAudience', e.target.value.slice(0, 200))} placeholder="Urban women 25-35 interested in clean skincare." rows={3} /><small>{form.targetAudience.length}/200 characters</small></div>
                <div className="brief-switch-row"><div><strong>Budget visibility</strong><p>Show or hide budget from creators. Hidden budgets are flagged to admin.</p></div><button type="button" className={form.budgetVisible ? 'is-on' : ''} onClick={() => set('budgetVisible', !form.budgetVisible)}>{form.budgetVisible ? 'Show' : 'Hide'}</button></div>
              </>
            )}

            {step === 2 && (
              <>
                {form.deliverables.map((item, index) => (
                  <div className="deliverable-card" key={item.id}>
                    <div className="deliverable-head"><strong>Deliverable {index + 1}</strong>{form.deliverables.length > 1 && <button type="button" onClick={() => removeDeliverable(item.id)}><Trash2 size={16} /> Remove</button>}</div>
                    <div className="form-row">
                      <div className="form-group"><label>Deliverable type *</label><select className="input-field" value={item.type} onChange={e => updateDeliverable(item.id, { type: e.target.value })}><option value="">Select type</option>{DELIVERABLE_TYPES.map(type => <option key={type}>{type}</option>)}</select></div>
                      <div className="form-group"><label>Quantity *</label><input className="input-field" type="number" min="1" max="5" value={item.quantity} onChange={e => updateDeliverable(item.id, { quantity: Number(e.target.value) })} /></div>
                    </div>
                    <div className="form-row">
                      <div className="form-group"><label>Duration {isVideoDeliverable(item.type) ? '*' : ''}</label><input className="input-field" value={item.duration} onChange={e => updateDeliverable(item.id, { duration: e.target.value })} placeholder="15-20 seconds" /></div>
                      <div className="form-group"><label>Raw file delivery required *</label><div className="brief-segment"><button type="button" className={item.rawRequired ? 'active' : ''} onClick={() => updateDeliverable(item.id, { rawRequired: true })}>Yes</button><button type="button" className={!item.rawRequired ? 'active' : ''} onClick={() => updateDeliverable(item.id, { rawRequired: false })}>No</button></div></div>
                    </div>
                    <div className="form-group"><label>Aspect ratio *</label><div className="brief-chip-grid compact">{ASPECTS.map(ratio => <ToggleChip key={ratio} active={item.aspectRatios.includes(ratio)} onClick={() => updateDeliverable(item.id, { aspectRatios: item.aspectRatios.includes(ratio) ? item.aspectRatios.filter(r => r !== ratio) : [...item.aspectRatios, ratio] })}>{ratio}</ToggleChip>)}</div></div>
                  </div>
                ))}
                <button type="button" className="brief-add-btn" onClick={addDeliverable}><Plus size={17} /> Add deliverable ({form.deliverables.length}/5)</button>
              </>
            )}

            {step === 3 && (
              <>
                <div className="brief-switch-row"><div><strong>Product visible on camera *</strong><p>If yes, specify minimum visibility duration.</p></div><button type="button" className={form.productVisible ? 'is-on' : ''} onClick={() => set('productVisible', !form.productVisible)}>{form.productVisible ? 'Yes' : 'No'}</button></div>
                {form.productVisible && <div className="form-group"><label>Minimum visibility duration (seconds)</label><input className="input-field" value={form.visibilitySeconds} onChange={e => set('visibilitySeconds', e.target.value)} placeholder="5" /></div>}
                <div className="brief-switch-row"><div><strong>Verbal product mention *</strong><p>List exact product names to be spoken.</p></div><button type="button" className={form.verbalMention ? 'is-on' : ''} onClick={() => set('verbalMention', !form.verbalMention)}>{form.verbalMention ? 'Yes' : 'No'}</button></div>
                {form.verbalMention && <div className="form-group"><label>Exact product name(s)</label><input className="input-field" value={form.productNames} onChange={e => set('productNames', e.target.value)} /></div>}
                <div className="form-row"><div className="form-group"><label>Required phrases (up to 5)</label>{renderTextList('requiredPhrases', 5, 'Perfect for oily skin')}</div><div className="form-group"><label>Required visual shots (up to 5)</label>{renderTextList('requiredShots', 5, 'Close-up of label')}</div></div>
                <div className="form-row"><div className="form-group"><label>Call to action *</label><select className="input-field" value={form.callToAction} onChange={e => set('callToAction', e.target.value)}>{CTAS.map(item => <option key={item}>{item}</option>)}</select></div>{form.callToAction === 'Use code' && <div className="form-group"><label>Promo code *</label><input className="input-field" value={form.promoCode} onChange={e => set('promoCode', e.target.value)} /></div>}</div>
                <div className="form-row"><div className="form-group"><label>Required hashtags</label><input className="input-field" value={form.hashtags} onChange={e => handleHashtagsChange(e.target.value)} placeholder="#brand #launch" /><small>Up to 10 hashtags.</small></div><div className="form-group"><label>Brand handle tag *</label><div className="brief-segment"><button className={form.brandHandleTag ? 'active' : ''} type="button" onClick={() => set('brandHandleTag', true)}>Yes</button><button className={!form.brandHandleTag ? 'active' : ''} type="button" onClick={() => set('brandHandleTag', false)}>No</button></div></div></div>
              </>
            )}

            {step === 4 && (
              <>
                {[
                  ['noCompetitors', 'No competitor brands visible'],
                  ['noOtherProducts', 'No other products in frame'],
                  ['noProfanity', 'No profanity or adult language'],
                  ['noPolitical', 'No political or religious content'],
                  ['avoidFilters', 'Avoid filters / effects']
                ].map(([field, label]) => <label key={field} className="brief-check"><input type="checkbox" checked={form[field]} onChange={e => set(field, e.target.checked)} /> {label}</label>)}
                {form.noCompetitors && <div className="form-group"><label>Competitor list</label><input className="input-field" value={form.competitors} onChange={e => set('competitors', e.target.value)} /></div>}
                {form.avoidFilters && <div className="form-group"><label>Which filters/effects?</label><input className="input-field" value={form.filterTypes} onChange={e => set('filterTypes', e.target.value)} /></div>}
                <div className="form-group"><label>Specific things to avoid (200 max)</label><textarea className="textarea-field" rows={3} value={form.avoidText} onChange={e => set('avoidText', e.target.value.slice(0, 200))} /><small>{form.avoidText.length}/200</small></div>
              </>
            )}

            {step === 5 && (
              <>
                <div className="brief-note"><Info size={18} /> This section is guidance, not grounds for dispute. Creators are expected to interpret style flexibly.</div>
                <div className="form-group"><label>Tone *</label><div className="brief-chip-grid">{TONES.map(item => <ToggleChip key={item} active={form.tones.includes(item)} onClick={() => toggleArray('tones', item)}>{item}</ToggleChip>)}</div></div>
                <div className="form-row"><div className="form-group"><label>Pacing preference *</label><select className="input-field" value={form.pacing} onChange={e => set('pacing', e.target.value)}>{['Fast-cut', 'Medium', 'Slow & reflective', 'No preference'].map(item => <option key={item}>{item}</option>)}</select></div><div className="form-group"><label>Music preference</label><select className="input-field" value={form.musicPreference} onChange={e => set('musicPreference', e.target.value)}>{['Original creator audio', 'Trending sound', 'Brand-provided audio file', 'No preference'].map(item => <option key={item}>{item}</option>)}</select></div></div>
                <div className="form-group"><label>Mood board images (up to 5)</label><label className="mini-upload"><Upload size={18} /> Upload references<input type="file" multiple accept="image/*" onChange={e => set('moodImages', Array.from(e.target.files || []).slice(0, 5).map(file => file.name))} /></label>{form.moodImages.length > 0 && <small>{form.moodImages.join(', ')}</small>}</div>
                <div className="form-group"><label>Reference videos (up to 3)</label>{renderTextList('referenceVideos', 3, 'Paste reference video link')}</div>
              </>
            )}

            {step === 6 && (
              <>
                <div className="form-group"><label>Platforms where content can be posted *</label><div className="brief-chip-grid">{PLATFORMS.map(item => <ToggleChip key={item} active={form.platforms.includes(item)} onClick={() => toggleArray('platforms', item)}>{item}</ToggleChip>)}</div></div>
                <div className="form-row"><div className="form-group"><label>Duration of rights *</label><select className="input-field" value={form.rightsDuration} onChange={e => set('rightsDuration', e.target.value)}><option value="">Select duration</option>{['3 months', '6 months', '1 year', '2 years', 'Perpetual'].map(item => <option key={item}>{item}</option>)}</select></div><div className="form-group"><label>Exclusivity period *</label><select className="input-field" value={form.exclusivity} onChange={e => set('exclusivity', e.target.value)}>{['None', '15 days', '30 days', '60 days', '90 days'].map(item => <option key={item}>{item}</option>)}</select></div></div>
                <div className="form-row"><div className="form-group"><label>Whitelisting / allowlisting *</label><div className="brief-segment"><button className={form.whitelisting ? 'active' : ''} type="button" onClick={() => set('whitelisting', true)}>Yes (+30%)</button><button className={!form.whitelisting ? 'active' : ''} type="button" onClick={() => set('whitelisting', false)}>No</button></div></div><div className="form-group"><label>Modification rights *</label><select className="input-field" value={form.modificationRights} onChange={e => set('modificationRights', e.target.value)}><option value="">Select rights</option>{['Yes (full rights)', 'Limited (minor edits only)', 'No (use as-is)'].map(item => <option key={item}>{item}</option>)}</select></div></div>
                {pricingLifts.length > 0 && <div className="brief-note warning"><AlertTriangle size={18} /> Suggested pricing lifts: {pricingLifts.join('; ')}</div>}
              </>
            )}

            {step === 7 && (
              <>
                <div className="deliverable-card">
                  <div className="deliverable-head"><strong>Creator targeting</strong></div>
                  <div className="form-row">
                    <div className="form-group"><label>Minimum creator level *</label><select className="input-field" value={form.creatorLevel} onChange={e => set('creatorLevel', e.target.value)}><option value="">Select level</option>{CREATOR_LEVELS.map(item => <option key={item}>{item}</option>)}</select></div>
                    <div className="form-group"><label>Content quality tier *</label><select className="input-field" value={form.qualityTier} onChange={e => set('qualityTier', e.target.value)}><option value="">Select tier</option>{QUALITY_TIERS.map(item => <option key={item}>{item}</option>)}</select></div>
                  </div>
                  <div className="form-row">
                    <div className="form-group"><label>Gender preference</label><select className="input-field" value={form.genderPreference} onChange={e => set('genderPreference', e.target.value)}>{GENDER_OPTIONS.map(item => <option key={item}>{item}</option>)}</select></div>
                    <div className="form-group"><label>City filter</label><select className="input-field" value={form.cityFilter} onChange={e => set('cityFilter', e.target.value)}>{CITIES.map(item => <option key={item}>{item}</option>)}</select></div>
                  </div>
                  <div className="form-group"><label>Creator niche tags</label><div className="brief-chip-grid">{NICHE_TAGS.map(item => <ToggleChip key={item} active={form.nicheTags.includes(item)} onClick={() => toggleArray('nicheTags', item)}>{item}</ToggleChip>)}</div></div>
                </div>
                <div className="form-row"><div className="form-group"><label>Product shipping by *</label><input className="input-field" type="date" value={form.productShippingBy} onChange={e => set('productShippingBy', e.target.value)} /></div><div className="form-group"><label>Content draft delivery by *</label><input className="input-field" type="date" value={form.draftDeliveryBy} onChange={e => set('draftDeliveryBy', e.target.value)} /><small>{draftDeliverySuggestion ? `Suggested from shipping date: ${draftDeliverySuggestion}` : 'Suggested as product shipping + 7 days.'}</small></div></div>
                <div className="form-row"><div className="form-group"><label>Revisions included *</label><input className="input-field" type="number" min="0" value={form.revisions} onChange={e => set('revisions', Number(e.target.value))} /><small>Extra revisions: Rs. 500 each (Rs. 300 creator, Rs. 200 platform)</small></div><div className="form-group"><label>Final content delivery by</label><input className="input-field" type="date" value={form.finalDeliveryBy} onChange={e => set('finalDeliveryBy', e.target.value)} /></div></div>
                <div className="form-group"><label>Budget *</label><div className="brief-segment"><button className={form.budgetMode === 'fixed' ? 'active' : ''} type="button" onClick={() => set('budgetMode', 'fixed')}>Fixed amount</button><button className={form.budgetMode === 'range' ? 'active' : ''} type="button" onClick={() => set('budgetMode', 'range')}>Range</button></div></div>
                {form.budgetMode === 'fixed' ? <div className="form-group"><label>Fixed budget (Rs.)</label><input className="input-field" type="number" value={form.fixedBudget} onChange={e => set('fixedBudget', e.target.value)} /></div> : <div className="form-row"><div className="form-group"><label>Min budget (Rs.)</label><input className="input-field" type="number" value={form.budgetMin} onChange={e => set('budgetMin', e.target.value)} /></div><div className="form-group"><label>Max budget (Rs.)</label><input className="input-field" type="number" value={form.budgetMax} onChange={e => set('budgetMax', e.target.value)} /></div></div>}
                <div className="brief-note"><Info size={18} /> Rush delivery is not available in V0.5.</div>
                <div className="commission-card"><p>Your budget <strong>Rs. {budget.toLocaleString('en-IN')}</strong></p><p>Platform commission (25%) <strong>Rs. {commission.toLocaleString('en-IN')}</strong></p><p>Total wallet debit <strong>Rs. {totalDebit.toLocaleString('en-IN')}</strong></p><p>Creator receives on approval <strong>Rs. {budget.toLocaleString('en-IN')}</strong></p><small>Creator amount is pre-tax. TDS may apply.</small></div>
              </>
            )}

            {step === 8 && (
              <div className="review-summary">
                <Summary title="Campaign Basics" rows={[['Campaign', form.campaignName], ['Brand', form.brandName], ['Category', form.category], ['Product', form.productName], ['Product description', form.productDescription], ['Hook', form.campaignHook], ['Key message', form.keyMessage], ['Objectives', form.objectives.join(', ')], ['Audience', form.targetAudience], ['Budget visibility', form.budgetVisible ? 'Visible to creators' : 'Hidden from creators; flagged to admin']]} />
                <Summary title="Deliverables" rows={form.deliverables.map((item, index) => [`Deliverable ${index + 1}`, `${item.quantity} x ${item.type}; ${item.duration || 'no duration'}; ${item.aspectRatios.join(', ')}; raw files ${item.rawRequired ? 'required' : 'not required'}`])} />
                <Summary title="Must-Include Checklist" rows={[['Product visible', form.productVisible ? `${form.visibilitySeconds}s minimum` : 'No'], ['Verbal mention', form.verbalMention ? form.productNames : 'No'], ['Required phrases', requiredPhrases], ['Required shots', requiredShots], ['CTA', form.callToAction], ['Promo code', form.promoCode || 'None'], ['Required hashtags', form.hashtags || 'None'], ['Brand tag', form.brandHandleTag ? 'Yes' : 'No']]} />
                <Summary title="Must-Avoid Checklist" rows={[['Restrictions', avoidRules]]} />
                <Summary title="Style Guidance" rows={[['Tone', form.tones.join(', ')], ['Pacing', form.pacing], ['Mood board images', form.moodImages.join(', ') || 'None'], ['Reference videos', referenceVideos], ['Music preference', form.musicPreference], ['Note', 'Guidance only; not grounds for dispute.']]} />
                <Summary title="Usage Rights" rows={[['Platforms', form.platforms.join(', ')], ['Rights duration', form.rightsDuration], ['Exclusivity', form.exclusivity], ['Whitelisting', form.whitelisting ? 'Yes' : 'No'], ['Modification', form.modificationRights]]} />
                <Summary title="Creator Targeting" rows={[['Minimum level', form.creatorLevel], ['Quality tier', form.qualityTier], ['Gender preference', form.genderPreference], ['City filter', form.cityFilter], ['Niche tags', form.nicheTags.join(', ') || 'None']]} />
                <Summary title="Timeline & Budget" rows={[['Ship by', form.productShippingBy], ['Draft by', form.draftDeliveryBy], ['Revisions included', form.revisions], ['Final by', form.finalDeliveryBy], ['Budget', form.budgetMode === 'fixed' ? `Rs. ${budget.toLocaleString('en-IN')}` : `Rs. ${Number(form.budgetMin || 0).toLocaleString('en-IN')} - Rs. ${budget.toLocaleString('en-IN')}`], ['Platform commission', `Rs. ${commission.toLocaleString('en-IN')}`], ['Listing fee', `Rs. ${LISTING_FEE.toLocaleString('en-IN')}`], ['Total wallet debit', `Rs. ${totalDebit.toLocaleString('en-IN')}`]]} />
              </div>
            )}
          </div>

          <div className="pab-footer">
            <button type="button" className="btn-secondary" onClick={saveDraft}><Save size={16} /> Save as Draft</button>
            <div className="pab-footer-actions">
              {step > 1 && <button type="button" className="btn-secondary" onClick={() => setStep(step - 1)}><ChevronLeft size={18} /> Back</button>}
              {step < 8 ? (
                <button type="button" className="btn-primary" onClick={goNext}>Next Section <ChevronRight size={18} /></button>
              ) : (
                <>
                  <button type="button" className="btn-secondary" onClick={() => { setPublishMode('invite'); setShowConfirm(true); }} disabled={submitting}><Send size={16} /> Publish & Invite Creator</button>
                  <button type="button" className="btn-primary" onClick={() => { setPublishMode('matches'); setShowConfirm(true); }} disabled={submitting}>Publish & Request Matches</button>
                </>
              )}
            </div>
          </div>
        </div>

        <aside className="pab-right-rail brief-rail">
          <div className="rail-card preview-card">
            <h3><FileText size={16} /> Brief Status</h3>
            <div className="brief-progress-ring"><strong>{step}/8</strong><span>{STEPS[step - 1]}</span></div>
            <p className="preview-type">{isStepValid() ? 'Section complete' : 'Required fields pending'}</p>
          </div>
          <div className="rail-card tip-card">
            <div className="tip-head"><span><Info size={16} /></span><h3>Why this matters</h3></div>
            <p>Must-include and usage-right fields become clear approval criteria, reducing disputes after delivery.</p>
          </div>
          <div className="rail-card">
            <h3>Cost Preview</h3>
            <div className="summary-items">
              <div className="summary-item"><span>Budget</span><strong>Rs. {budget.toLocaleString('en-IN')}</strong></div>
              <div className="summary-item"><span>Commission</span><strong>Rs. {commission.toLocaleString('en-IN')}</strong></div>
              <div className="summary-item"><span>Listing fee</span><strong>Rs. {LISTING_FEE.toLocaleString('en-IN')}</strong></div>
              <div className="summary-item"><span>Total debit</span><strong>Rs. {totalDebit.toLocaleString('en-IN')}</strong></div>
            </div>
          </div>
        </aside>
      </div>

      {showConfirm && (
        <div className="brief-modal-backdrop">
          <div className="brief-modal">
            <h3>Confirm publishing</h3>
            <p>This will debit Rs. {totalDebit.toLocaleString('en-IN')} from your wallet: Rs. {budget.toLocaleString('en-IN')} budget + Rs. {commission.toLocaleString('en-IN')} platform commission + Rs. {LISTING_FEE.toLocaleString('en-IN')} listing fee. It cannot be modified after a creator accepts. Continue?</p>
            <div>
              <button type="button" className="btn-secondary" onClick={() => setShowConfirm(false)}>Cancel</button>
              <button type="button" className="btn-primary" onClick={publish} disabled={submitting}>{submitting ? 'Publishing...' : 'Continue'}</button>
            </div>
          </div>
        </div>
      )}

      <style jsx>{`
        .brief-builder-page {
          color: #07074E;
        }

        .brief-stepper {
          padding: 0 0 24px;
        }

        .brief-stepper .stepper-track {
          width: 100%;
          display: grid;
          grid-template-columns: repeat(8, minmax(94px, 1fr));
          gap: 8px;
          padding: 14px;
          background: white;
          border: 1px solid #E9EBFF;
          border-radius: 22px;
          box-shadow: 0 18px 40px rgba(7, 7, 78, 0.05);
          overflow-x: auto;
        }

        .brief-step {
          min-height: 78px;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          gap: 8px;
          border: 0;
          border-radius: 16px;
          background: transparent;
          color: #9F9FD1;
          font-weight: 800;
          cursor: pointer;
        }

        .brief-step span {
          display: grid;
          place-items: center;
          width: 34px;
          height: 34px;
          border-radius: 50%;
          border: 2px dashed #D8D8E8;
        }

        .brief-step small {
          font-size: 11px;
          line-height: 1.25;
          text-align: center;
        }

        .brief-step.active {
          background: #EEF0FF;
          color: #7387FF;
        }

        .brief-step.active span,
        .brief-step.done span {
          border-color: #7387FF;
          background: #7387FF;
          color: white;
        }

        .brief-body {
          display: grid;
          grid-template-columns: minmax(0, 1fr) 360px;
          gap: 26px;
          padding: 0;
        }

        .brief-panel {
          background: white;
          border: 1px solid #E9EBFF;
          border-radius: 22px;
          padding: 34px 36px;
          box-shadow: 0 18px 40px rgba(7, 7, 78, 0.05);
        }

        .step-content {
          display: flex;
          flex-direction: column;
          gap: 22px;
        }

        .step-badge {
          width: fit-content;
          padding: 8px 14px;
          border-radius: 999px;
          background: #F3F3FF;
          color: #7387FF;
          font-size: 12px;
          font-weight: 800;
          text-transform: uppercase;
        }

        .step-header h2 {
          margin: 0 0 8px;
          color: #07074E;
          font-size: 30px;
        }

        .step-header p {
          margin: 0;
          color: #9F9FD1;
          font-weight: 700;
        }

        .form-row {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 20px;
        }

        .form-group {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .form-group label {
          color: #07074E;
          font-size: 13px;
          font-weight: 900;
          text-transform: uppercase;
        }

        .form-group small {
          color: #9F9FD1;
          font-weight: 700;
        }

        .input-field,
        .textarea-field,
        .brief-list-inputs input {
          width: 100%;
          border: 1px solid #E2E4F0;
          border-radius: 13px;
          background: #FAFAFE;
          color: #07074E;
          font: inherit;
          font-size: 15px;
          font-weight: 700;
          padding: 14px 16px;
          outline: 0;
        }

        .textarea-field {
          resize: vertical;
        }

        .brief-chip-grid {
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
        }

        .brief-chip {
          min-height: 38px;
          padding: 0 14px;
          border: 1px solid #E2E4F0;
          border-radius: 999px;
          background: white;
          color: #7777B7;
          font-weight: 800;
          cursor: pointer;
        }

        .brief-chip.active {
          border-color: #7387FF;
          background: #7387FF;
          color: white;
        }

        .brief-chip-grid.compact .brief-chip {
          min-width: 72px;
        }

        .brief-switch-row,
        .brief-note,
        .commission-card,
        .deliverable-card {
          padding: 18px;
          border: 1px solid #E9EBFF;
          border-radius: 18px;
          background: #F9F9FF;
        }

        .brief-switch-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 18px;
        }

        .brief-switch-row p {
          margin: 5px 0 0;
          color: #9F9FD1;
          font-weight: 700;
        }

        .brief-switch-row > button {
          min-width: 82px;
          height: 38px;
          border: 0;
          border-radius: 999px;
          background: #DCDDFA;
          color: #07074E;
          font-weight: 900;
          cursor: pointer;
        }

        .brief-switch-row > button.is-on {
          background: #7387FF;
          color: white;
        }

        .brief-segment {
          display: flex;
          padding: 5px;
          border-radius: 13px;
          background: #EEF0FF;
        }

        .brief-segment button {
          flex: 1;
          min-height: 38px;
          border: 0;
          border-radius: 10px;
          background: transparent;
          color: #7777B7;
          font-weight: 900;
          cursor: pointer;
        }

        .brief-segment button.active {
          background: white;
          color: #07074E;
          box-shadow: 0 6px 14px rgba(7, 7, 78, 0.06);
        }

        .deliverable-card {
          display: flex;
          flex-direction: column;
          gap: 18px;
          background: white;
        }

        .deliverable-head {
          display: flex;
          align-items: center;
          justify-content: space-between;
        }

        .deliverable-head button,
        .brief-list-inputs button,
        .brief-add-btn,
        .mini-upload {
          width: fit-content;
          display: inline-flex;
          align-items: center;
          gap: 8px;
          border: 0;
          border-radius: 11px;
          background: #EEF0FF;
          color: #7387FF;
          font-weight: 900;
          padding: 10px 13px;
          cursor: pointer;
        }

        .mini-upload input {
          display: none;
        }

        .brief-list-inputs {
          display: flex;
          flex-direction: column;
          gap: 9px;
        }

        .brief-check {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 16px;
          border: 1px solid #E9EBFF;
          border-radius: 14px;
          background: white;
          color: #07074E;
          font-weight: 800;
        }

        .brief-check input {
          width: 18px;
          height: 18px;
        }

        .brief-note {
          display: flex;
          align-items: flex-start;
          gap: 10px;
          color: #7387FF;
          font-weight: 800;
        }

        .brief-note.warning {
          background: #FFF8E8;
          color: #C47A00;
        }

        .commission-card {
          display: grid;
          gap: 12px;
        }

        .commission-card p {
          display: flex;
          justify-content: space-between;
          margin: 0;
          color: #7777B7;
          font-weight: 800;
        }

        .commission-card strong {
          color: #07074E;
        }

        .review-summary {
          display: grid;
          gap: 16px;
        }

        .summary-box {
          border: 1px solid #E9EBFF;
          border-radius: 16px;
          overflow: hidden;
        }

        .summary-box h3 {
          margin: 0;
          padding: 14px 16px;
          background: #F8F9FF;
          color: #07074E;
        }

        .summary-box div {
          display: grid;
          grid-template-columns: 190px 1fr;
          gap: 16px;
          padding: 12px 16px;
          border-top: 1px solid #EEF0FF;
        }

        .summary-box span {
          color: #9F9FD1;
          font-weight: 800;
        }

        .summary-box strong {
          color: #07074E;
          font-weight: 800;
        }

        .pab-footer {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 16px;
          margin: 30px -36px -34px;
          padding: 22px 36px;
          border-top: 1px solid #EEF0FF;
          background: white;
          border-radius: 0 0 22px 22px;
        }

        .pab-footer-actions {
          display: flex;
          align-items: center;
          gap: 12px;
          flex-wrap: wrap;
        }

        .btn-primary,
        .btn-secondary {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          min-height: 44px;
          padding: 0 22px;
          border: 0;
          border-radius: 11px;
          font-weight: 900;
          cursor: pointer;
        }

        .btn-primary {
          background: #7387FF;
          color: white;
          box-shadow: 0 12px 22px rgba(115, 135, 255, 0.24);
        }

        .btn-secondary {
          border: 1px solid #E2E4F0;
          background: white;
          color: #7777B7;
        }

        .brief-rail {
          display: flex;
          flex-direction: column;
          gap: 18px;
        }

        .rail-card {
          background: white;
          border: 1px solid #E9EBFF;
          border-radius: 22px;
          padding: 24px;
          box-shadow: 0 18px 40px rgba(7, 7, 78, 0.05);
        }

        .rail-card h3 {
          display: flex;
          align-items: center;
          gap: 8px;
          margin: 0 0 16px;
          color: #7387FF;
          font-size: 13px;
          text-transform: uppercase;
        }

        .brief-progress-ring {
          display: grid;
          place-items: center;
          gap: 4px;
          min-height: 130px;
          border-radius: 20px;
          background: #F3F3FF;
          text-align: center;
        }

        .brief-progress-ring strong {
          font-size: 30px;
          color: #07074E;
        }

        .brief-progress-ring span,
        .preview-type {
          color: #9F9FD1;
          font-weight: 800;
        }

        .tip-card {
          background: linear-gradient(135deg, rgba(115, 135, 255, 0.12), rgba(159, 159, 209, 0.11));
        }

        .tip-head {
          display: flex;
          gap: 12px;
        }

        .tip-head span {
          display: grid;
          place-items: center;
          width: 36px;
          height: 36px;
          border-radius: 10px;
          background: rgba(115, 135, 255, 0.16);
          color: #7387FF;
        }

        .tip-head h3 {
          color: #07074E;
          text-transform: none;
          margin: 4px 0 0;
        }

        .tip-card p {
          color: #7777B7;
          font-weight: 800;
          line-height: 1.55;
        }

        .summary-items {
          display: grid;
          gap: 12px;
        }

        .summary-item {
          display: flex;
          justify-content: space-between;
          gap: 12px;
          color: #9F9FD1;
          font-weight: 800;
        }

        .summary-item strong {
          color: #07074E;
        }

        .brief-modal-backdrop {
          position: fixed;
          inset: 0;
          z-index: 1000;
          display: grid;
          place-items: center;
          padding: 20px;
          background: rgba(7, 7, 78, 0.45);
        }

        .brief-modal {
          max-width: 520px;
          width: 100%;
          padding: 28px;
          border-radius: 22px;
          background: white;
          box-shadow: 0 22px 70px rgba(0, 0, 0, 0.18);
        }

        .brief-modal h3 {
          margin: 0 0 10px;
          color: #07074E;
          font-size: 24px;
        }

        .brief-modal p {
          color: #7777B7;
          font-weight: 700;
          line-height: 1.55;
        }

        .brief-modal div {
          display: flex;
          justify-content: flex-end;
          gap: 12px;
          margin-top: 22px;
        }

        @media (max-width: 1100px) {
          .brief-body,
          .form-row {
            grid-template-columns: 1fr;
          }
        }
      `}</style>
    </div>
  );
}

function Summary({ title, rows }) {
  return (
    <section className="summary-box">
      <h3>{title}</h3>
      {rows.map(([label, value]) => (
        <div key={`${title}-${label}`}>
          <span>{label}</span>
          <strong>{value || '-'}</strong>
        </div>
      ))}
    </section>
  );
}
