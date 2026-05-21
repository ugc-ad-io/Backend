import { useState } from "react";
import {
  Check,
  Upload,
  ChevronRight,
  ImagePlus,
  Sparkles,
  Video,
  Clock,
  Film,
  Star,
  MapPin,
  Tag,
  Users,
  DollarSign,
  Info,
  Minus,
  Plus,
  ArrowLeft,
  ArrowRight,
  Save,
  Send,
  Lightbulb,
  Target,
  TrendingUp,
  Zap,
  CheckCircle2,
} from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────
interface FormData {
  // Step 1
  productName: string;
  variant: string;
  retailPrice: string;
  category: string;
  briefType: string;
  productImage: string | null;
  // Step 2
  hook: string;
  keyMessage: string;
  doNot: string;
  toneReference: string;
  tones: string[];
  // Step 3
  videoFormat: string;
  aspectRatio: string;
  duration: string;
  bRoll: boolean;
  photos: boolean;
  rawFootage: boolean;
  revisions: number;
  // Step 4
  creatorLevel: string;
  qualityTier: string;
  genderPref: string;
  city: string;
  nicheTags: string[];
  // Step 5
  perVideoBudget: string;
}

const STEPS = [
  { id: 1, label: "Product Info",           icon: ImagePlus    },
  { id: 2, label: "Content Requirements",   icon: Lightbulb    },
  { id: 3, label: "Deliverables",           icon: Video        },
  { id: 4, label: "Creator Requirements",   icon: Users        },
  { id: 5, label: "Budget & Review",        icon: DollarSign   },
];

const CATEGORIES = ["Beauty", "Fitness", "Tech", "Fashion", "Home Decor", "Food & Beverage", "Travel", "Lifestyle", "Gaming", "Health"];
const BRIEF_TYPES = ["UGC Reel", "Unboxing", "Testimonial", "Tutorial"];
const TONE_CHIPS = ["Fun", "Luxury", "Minimal", "Bold", "Emotional", "Trustworthy", "Playful", "Premium"];
const VIDEO_FORMATS = [
  { id: "reel",  label: "Reel",      icon: "🎬", desc: "Instagram / TikTok vertical" },
  { id: "story", label: "Story",     icon: "📱", desc: "24-hr story format" },
  { id: "feed",  label: "Feed Post", icon: "🖼️", desc: "Square or portrait" },
  { id: "short", label: "Shorts",    icon: "⚡", desc: "YouTube vertical short" },
];
const ASPECT_RATIOS = ["9:16", "1:1", "16:9"];
const DURATIONS = ["15 sec", "30 sec", "60 sec"];
const CREATOR_LEVELS = [
  { id: "New",      label: "New",      desc: "Entry-level creators",    min: "₹1,500",  color: "#9F9FD1" },
  { id: "Verified", label: "Verified", desc: "Identity-verified",       min: "₹2,500",  color: "#7387FF" },
  { id: "L1",       label: "L1 Rising",desc: "5+ deals completed",      min: "₹4,000",  color: "#27AE60" },
  { id: "L2",       label: "L2 Pro",   desc: "High-volume creators",    min: "₹7,500",  color: "#F39C12" },
  { id: "Elite",    label: "Elite",    desc: "Top 5% of all creators",  min: "₹15,000", color: "#E74C3C" },
];
const QUALITY_TIERS = [
  { id: "A",   label: "A",   desc: "Standard quality",  mult: "×1.0",  color: "#9F9FD1" },
  { id: "A+",  label: "A+",  desc: "Premium quality",   mult: "×1.25", color: "#7387FF" },
  { id: "A++", label: "A++", desc: "Top-tier quality",  mult: "×1.6",  color: "#F39C12" },
];
const GENDER_OPTIONS = ["No Preference", "Female", "Male", "Non-binary"];
const CITIES = ["All India", "Mumbai", "Delhi", "Bengaluru", "Hyderabad", "Chennai", "Pune", "Kolkata", "Ahmedabad", "Jaipur"];
const NICHE_TAGS = ["Beauty", "Tech", "Fitness", "Fashion", "Travel", "Lifestyle", "Food", "Gaming", "Parenting", "Finance", "Education", "Wellness"];

// Commission rate based on plan (Brand Pro = 20%)
const COMMISSION_RATE = 0.20;
const LISTING_FEE = 500;

export function PostBrief() {
  const [step, setStep] = useState(1);
  const [form, setForm] = useState<FormData>({
    productName: "",
    variant: "",
    retailPrice: "",
    category: "",
    briefType: "",
    productImage: null,
    hook: "",
    keyMessage: "",
    doNot: "",
    toneReference: "",
    tones: [],
    videoFormat: "",
    aspectRatio: "",
    duration: "",
    bRoll: false,
    photos: false,
    rawFootage: false,
    revisions: 2,
    creatorLevel: "",
    qualityTier: "",
    genderPref: "No Preference",
    city: "All India",
    nicheTags: [],
    perVideoBudget: "",
  });

  const set = (field: keyof FormData, value: unknown) =>
    setForm((f) => ({ ...f, [field]: value }));

  const toggleArray = (field: "tones" | "nicheTags", val: string) => {
    setForm((f) => {
      const arr = f[field] as string[];
      return { ...f, [field]: arr.includes(val) ? arr.filter((x) => x !== val) : [...arr, val] };
    });
  };

  // Budget calculations
  const brandPays     = parseFloat(form.perVideoBudget) || 0;
  const commission    = Math.round(brandPays * COMMISSION_RATE);
  const creatorGets   = brandPays - commission;

  return (
    <div className="flex flex-col gap-0 min-h-full" style={{ fontFamily: "'Inter', 'Just Sans', sans-serif" }}>

      {/* ── Step Progress Bar ─────────────────────────────────────────────── */}
      <div className="sticky top-0 z-20 bg-[#F3F3FF] pb-6 pt-1">
        <div className="bg-white rounded-[18px] shadow-[0_2px_16px_rgba(7,7,78,0.07)] border border-[#E9EBFF]/60 px-8 py-5">
          <div className="flex items-center justify-between">
            {STEPS.map((s, idx) => {
              const done    = step > s.id;
              const active  = step === s.id;
              const future  = step < s.id;
              return (
                <div key={s.id} className="flex items-center flex-1">
                  {/* Step node */}
                  <button
                    onClick={() => done && setStep(s.id)}
                    className="flex flex-col items-center gap-2 group"
                  >
                    <div
                      className={`w-10 h-10 rounded-full flex items-center justify-center transition-all duration-300 ${
                        done
                          ? "bg-[#27AE60] shadow-[0_4px_12px_rgba(39,174,96,0.3)]"
                          : active
                          ? "bg-[#7387FF] shadow-[0_4px_16px_rgba(115,135,255,0.4)]"
                          : "bg-white border-2 border-dashed border-[#D8D8E8]"
                      }`}
                    >
                      {done ? (
                        <Check strokeWidth={2.5} className="w-4 h-4 text-white" />
                      ) : active ? (
                        <span className="text-white font-semibold text-[14px]">{s.id}</span>
                      ) : (
                        <span className="text-[#C0C0D8] font-semibold text-[14px]">{s.id}</span>
                      )}
                    </div>
                    <div className="text-center">
                      <div
                        className={`text-[12px] font-semibold whitespace-nowrap ${
                          active ? "text-[#7387FF]" : done ? "text-[#27AE60]" : "text-[#B0B0CC]"
                        }`}
                      >
                        {s.label}
                      </div>
                    </div>
                  </button>

                  {/* Connector */}
                  {idx < STEPS.length - 1 && (
                    <div className="flex-1 mx-3 mb-5">
                      <div className="h-[2px] relative overflow-hidden rounded-full bg-[#E8E8F0]">
                        <div
                          className="absolute inset-y-0 left-0 bg-[#27AE60] rounded-full transition-all duration-500"
                          style={{ width: step > s.id ? "100%" : "0%" }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* ── Form Body ─────────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-6">

        {/* STEP 1 ── Product Info ──────────────────────────────────────────── */}
        {step === 1 && (
          <div className="grid grid-cols-[1fr_340px] gap-6 items-start">
            {/* Left: Form */}
            <div className="bg-white rounded-[18px] shadow-[0_2px_16px_rgba(7,7,78,0.07)] border border-[#E9EBFF]/60 p-8">
              <div className="mb-7">
                <div className="inline-flex items-center gap-2 bg-[#F3F3FF] rounded-full px-3 py-1.5 mb-3">
                  <ImagePlus className="w-3.5 h-3.5 text-[#7387FF]" />
                  <span className="text-[11px] font-semibold text-[#7387FF] uppercase tracking-wide">Step 1 of 5</span>
                </div>
                <h2 className="text-[22px] font-semibold text-[#07074E]" style={{ fontFamily: "'Readex Pro', sans-serif" }}>
                  Tell us about your product
                </h2>
                <p className="text-[14px] text-[#9F9FD1] mt-1 font-medium">Creators will use this to understand what they're promoting.</p>
              </div>

              <div className="grid grid-cols-2 gap-5">
                {/* Product Name */}
                <div className="col-span-2">
                  <label className="block text-[12px] font-semibold text-[#07074E] mb-2 uppercase tracking-wide">Product Name *</label>
                  <input
                    value={form.productName}
                    onChange={(e) => set("productName", e.target.value)}
                    placeholder="e.g. Glow Serum Ultra"
                    className="w-full h-12 px-4 rounded-[12px] border border-[#E2E4F0] bg-[#FAFAFE] text-[14px] text-[#07074E] placeholder:text-[#C0C0D8] focus:outline-none focus:border-[#7387FF] focus:ring-2 focus:ring-[#7387FF]/10 transition-all font-medium"
                  />
                </div>

                {/* Variant */}
                <div>
                  <label className="block text-[12px] font-semibold text-[#07074E] mb-2 uppercase tracking-wide">Variant</label>
                  <input
                    value={form.variant}
                    onChange={(e) => set("variant", e.target.value)}
                    placeholder="e.g. 30ml, Rosehip"
                    className="w-full h-12 px-4 rounded-[12px] border border-[#E2E4F0] bg-[#FAFAFE] text-[14px] text-[#07074E] placeholder:text-[#C0C0D8] focus:outline-none focus:border-[#7387FF] focus:ring-2 focus:ring-[#7387FF]/10 transition-all font-medium"
                  />
                </div>

                {/* Retail Price */}
                <div>
                  <label className="block text-[12px] font-semibold text-[#07074E] mb-2 uppercase tracking-wide">Retail Price</label>
                  <div className="relative">
                    <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[14px] font-semibold text-[#9F9FD1]">₹</span>
                    <input
                      value={form.retailPrice}
                      onChange={(e) => set("retailPrice", e.target.value)}
                      placeholder="1,499"
                      className="w-full h-12 pl-8 pr-4 rounded-[12px] border border-[#E2E4F0] bg-[#FAFAFE] text-[14px] text-[#07074E] placeholder:text-[#C0C0D8] focus:outline-none focus:border-[#7387FF] focus:ring-2 focus:ring-[#7387FF]/10 transition-all font-medium"
                    />
                  </div>
                </div>

                {/* Category */}
                <div>
                  <label className="block text-[12px] font-semibold text-[#07074E] mb-2 uppercase tracking-wide">Product Category *</label>
                  <select
                    value={form.category}
                    onChange={(e) => set("category", e.target.value)}
                    className="w-full h-12 px-4 rounded-[12px] border border-[#E2E4F0] bg-[#FAFAFE] text-[14px] text-[#07074E] focus:outline-none focus:border-[#7387FF] focus:ring-2 focus:ring-[#7387FF]/10 transition-all font-medium appearance-none cursor-pointer"
                  >
                    <option value="">Select category</option>
                    {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
                  </select>
                </div>

                {/* Brief Type */}
                <div>
                  <label className="block text-[12px] font-semibold text-[#07074E] mb-2 uppercase tracking-wide">Brief Type *</label>
                  <select
                    value={form.briefType}
                    onChange={(e) => set("briefType", e.target.value)}
                    className="w-full h-12 px-4 rounded-[12px] border border-[#E2E4F0] bg-[#FAFAFE] text-[14px] text-[#07074E] focus:outline-none focus:border-[#7387FF] focus:ring-2 focus:ring-[#7387FF]/10 transition-all font-medium appearance-none cursor-pointer"
                  >
                    <option value="">Select type</option>
                    {BRIEF_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
                  </select>
                </div>
              </div>

              {/* Image Upload */}
              <div className="mt-6">
                <label className="block text-[12px] font-semibold text-[#07074E] mb-2 uppercase tracking-wide">Product Image</label>
                <div
                  className="border-2 border-dashed border-[#D8D8F0] rounded-[14px] bg-[#F9F9FF] flex flex-col items-center justify-center py-10 gap-3 cursor-pointer hover:border-[#7387FF] hover:bg-[#F3F3FF] transition-all group"
                  onClick={() => {
                    // Demo: set a placeholder image
                    set("productImage", "https://images.unsplash.com/photo-1598440947619-2c35fc9aa908?w=300&h=300&fit=crop");
                  }}
                >
                  {form.productImage ? (
                    <div className="flex flex-col items-center gap-3">
                      <div className="w-20 h-20 rounded-[12px] overflow-hidden shadow-md">
                        <img src={form.productImage} alt="product" className="w-full h-full object-cover" />
                      </div>
                      <span className="text-[13px] font-semibold text-[#27AE60]">Image uploaded ✓</span>
                    </div>
                  ) : (
                    <>
                      <div className="w-14 h-14 rounded-[12px] bg-[#EEF0FF] flex items-center justify-center group-hover:bg-[#7387FF]/10 transition-colors">
                        <Upload className="w-6 h-6 text-[#7387FF]" />
                      </div>
                      <div className="text-center">
                        <div className="text-[14px] font-semibold text-[#07074E]">Drop your product image here</div>
                        <div className="text-[12px] text-[#9F9FD1] mt-1">PNG, JPG up to 10MB · Recommended 1:1 ratio</div>
                      </div>
                      <button className="px-5 py-2.5 bg-[#7387FF] text-white rounded-[10px] text-[13px] font-semibold shadow-[0_4px_12px_rgba(115,135,255,0.3)] hover:bg-[#5a6de0] transition-all">
                        Browse Files
                      </button>
                    </>
                  )}
                </div>
              </div>
            </div>

            {/* Right: Live Preview */}
            <div className="flex flex-col gap-4">
              {/* Campaign Card Preview */}
              <div className="bg-white rounded-[18px] shadow-[0_2px_16px_rgba(7,7,78,0.07)] border border-[#E9EBFF]/60 p-6">
                <div className="flex items-center gap-2 mb-4">
                  <Sparkles className="w-4 h-4 text-[#7387FF]" />
                  <span className="text-[12px] font-semibold text-[#7387FF] uppercase tracking-wide">Live Preview</span>
                </div>
                {/* Mini card */}
                <div className="rounded-[14px] border border-[#E9EBFF] overflow-hidden">
                  <div className="h-32 bg-gradient-to-br from-[#EEF0FF] to-[#F3F3FF] flex items-center justify-center relative">
                    {form.productImage ? (
                      <img src={form.productImage} alt="product" className="h-full w-full object-cover" />
                    ) : (
                      <div className="flex flex-col items-center gap-2 text-[#C0C0D8]">
                        <ImagePlus className="w-8 h-8" />
                        <span className="text-[11px] font-medium">Product image</span>
                      </div>
                    )}
                    {form.category && (
                      <div className="absolute top-3 left-3 bg-white rounded-full px-2.5 py-1 text-[11px] font-semibold text-[#07074E] shadow-sm">
                        {form.category}
                      </div>
                    )}
                  </div>
                  <div className="p-4">
                    <div className="text-[15px] font-semibold text-[#07074E] mb-1 min-h-[22px]">
                      {form.productName || <span className="text-[#C0C0D8]">Product name</span>}
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[12px] text-[#9F9FD1] font-medium">
                        {form.briefType || "Brief type"}
                      </span>
                      <span className="text-[13px] font-semibold text-[#27AE60]">
                        {form.retailPrice ? `₹${form.retailPrice}` : "—"}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Tip card */}
              <div className="bg-gradient-to-br from-[#7387FF]/8 to-[#9F9FD1]/10 rounded-[18px] border border-[#7387FF]/15 p-5">
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-[8px] bg-[#7387FF]/15 flex items-center justify-center shrink-0">
                    <Info className="w-4 h-4 text-[#7387FF]" />
                  </div>
                  <div>
                    <div className="text-[13px] font-semibold text-[#07074E] mb-1.5">Why this matters</div>
                    <div className="text-[12px] text-[#9F9FD1] leading-relaxed font-medium">
                      Clear product info helps creators understand exactly what they'll be promoting. Briefs with images get <span className="text-[#7387FF] font-semibold">2.3× more applications</span> on average.
                    </div>
                  </div>
                </div>
              </div>

              {/* Completeness indicator */}
              <div className="bg-white rounded-[18px] shadow-[0_2px_16px_rgba(7,7,78,0.07)] border border-[#E9EBFF]/60 p-5">
                <div className="text-[12px] font-semibold text-[#07074E] mb-3 uppercase tracking-wide">Step completeness</div>
                {[
                  { label: "Product Name", done: !!form.productName },
                  { label: "Category",     done: !!form.category    },
                  { label: "Brief Type",   done: !!form.briefType   },
                  { label: "Product Image",done: !!form.productImage },
                ].map((item) => (
                  <div key={item.label} className="flex items-center justify-between py-1.5">
                    <span className="text-[12px] text-[#9F9FD1] font-medium">{item.label}</span>
                    <div className={`w-5 h-5 rounded-full flex items-center justify-center ${item.done ? "bg-[#27AE60]/10" : "bg-[#E8E8F0]"}`}>
                      {item.done
                        ? <Check className="w-3 h-3 text-[#27AE60]" strokeWidth={2.5} />
                        : <div className="w-1.5 h-1.5 rounded-full bg-[#C0C0D8]" />
                      }
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* STEP 2 ── Content Requirements ─────────────────────────────────── */}
        {step === 2 && (
          <div className="grid grid-cols-[1fr_340px] gap-6 items-start">
            <div className="bg-white rounded-[18px] shadow-[0_2px_16px_rgba(7,7,78,0.07)] border border-[#E9EBFF]/60 p-8">
              <div className="mb-7">
                <div className="inline-flex items-center gap-2 bg-[#F3F3FF] rounded-full px-3 py-1.5 mb-3">
                  <Lightbulb className="w-3.5 h-3.5 text-[#7387FF]" />
                  <span className="text-[11px] font-semibold text-[#7387FF] uppercase tracking-wide">Step 2 of 5</span>
                </div>
                <h2 className="text-[22px] font-semibold text-[#07074E]" style={{ fontFamily: "'Readex Pro', sans-serif" }}>
                  Content direction & tone
                </h2>
                <p className="text-[14px] text-[#9F9FD1] mt-1 font-medium">Guide the creator on how you want the content to feel.</p>
              </div>

              <div className="flex flex-col gap-5">
                {/* Campaign Hook */}
                <div>
                  <label className="block text-[12px] font-semibold text-[#07074E] mb-2 uppercase tracking-wide">Campaign Hook / Opening Line *</label>
                  <textarea
                    value={form.hook}
                    onChange={(e) => set("hook", e.target.value)}
                    placeholder="e.g. 'This serum completely changed my skincare routine — here's why I can't stop talking about it...'"
                    rows={3}
                    className="w-full px-4 py-3.5 rounded-[12px] border border-[#E2E4F0] bg-[#FAFAFE] text-[14px] text-[#07074E] placeholder:text-[#C0C0D8] focus:outline-none focus:border-[#7387FF] focus:ring-2 focus:ring-[#7387FF]/10 transition-all font-medium resize-none leading-relaxed"
                  />
                </div>

                {/* Key Message */}
                <div>
                  <label className="block text-[12px] font-semibold text-[#07074E] mb-2 uppercase tracking-wide">
                    Key Message
                    <span className="ml-2 text-[#9F9FD1] normal-case font-medium">({form.keyMessage.length}/120)</span>
                  </label>
                  <input
                    value={form.keyMessage}
                    onChange={(e) => set("keyMessage", e.target.value.slice(0, 120))}
                    placeholder="One core thing you want the audience to remember"
                    className="w-full h-12 px-4 rounded-[12px] border border-[#E2E4F0] bg-[#FAFAFE] text-[14px] text-[#07074E] placeholder:text-[#C0C0D8] focus:outline-none focus:border-[#7387FF] focus:ring-2 focus:ring-[#7387FF]/10 transition-all font-medium"
                  />
                  <div className="flex justify-end mt-1.5">
                    <div className="h-1 w-32 bg-[#E8E8F0] rounded-full overflow-hidden">
                      <div
                        className="h-full bg-[#7387FF] rounded-full transition-all"
                        style={{ width: `${(form.keyMessage.length / 120) * 100}%` }}
                      />
                    </div>
                  </div>
                </div>

                {/* What NOT to do */}
                <div>
                  <label className="block text-[12px] font-semibold text-[#07074E] mb-2 uppercase tracking-wide">What NOT To Do</label>
                  <textarea
                    value={form.doNot}
                    onChange={(e) => set("doNot", e.target.value)}
                    placeholder="e.g. No filter effects, avoid comparing with competitor products, don't show price in video..."
                    rows={2}
                    className="w-full px-4 py-3.5 rounded-[12px] border border-[#E2E4F0] bg-[#FAFAFE] text-[14px] text-[#07074E] placeholder:text-[#C0C0D8] focus:outline-none focus:border-[#7387FF] focus:ring-2 focus:ring-[#7387FF]/10 transition-all font-medium resize-none leading-relaxed"
                  />
                </div>

                {/* Tone Reference */}
                <div>
                  <label className="block text-[12px] font-semibold text-[#07074E] mb-2 uppercase tracking-wide">Tone Reference</label>
                  <textarea
                    value={form.toneReference}
                    onChange={(e) => set("toneReference", e.target.value)}
                    placeholder="Paste a video link or describe the vibe: e.g. 'Like a trusted friend recommending something, not an ad...'"
                    rows={2}
                    className="w-full px-4 py-3.5 rounded-[12px] border border-[#E2E4F0] bg-[#FAFAFE] text-[14px] text-[#07074E] placeholder:text-[#C0C0D8] focus:outline-none focus:border-[#7387FF] focus:ring-2 focus:ring-[#7387FF]/10 transition-all font-medium resize-none leading-relaxed"
                  />
                </div>

                {/* Tone chips */}
                <div>
                  <label className="block text-[12px] font-semibold text-[#07074E] mb-3 uppercase tracking-wide">Tone Tags</label>
                  <div className="flex flex-wrap gap-2">
                    {TONE_CHIPS.map((tone) => {
                      const active = form.tones.includes(tone);
                      return (
                        <button
                          key={tone}
                          onClick={() => toggleArray("tones", tone)}
                          className={`px-4 py-2 rounded-full text-[13px] font-semibold transition-all duration-200 ${
                            active
                              ? "bg-[#7387FF] text-white shadow-[0_4px_10px_rgba(115,135,255,0.3)]"
                              : "bg-[#F3F3FF] text-[#9F9FD1] border border-[#E2E4F0] hover:border-[#7387FF] hover:text-[#7387FF]"
                          }`}
                        >
                          {tone}
                        </button>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>

            {/* Right Panel */}
            <div className="flex flex-col gap-4">
              <div className="bg-white rounded-[18px] shadow-[0_2px_16px_rgba(7,7,78,0.07)] border border-[#E9EBFF]/60 p-6">
                <div className="flex items-center gap-2 mb-4">
                  <TrendingUp className="w-4 h-4 text-[#7387FF]" />
                  <span className="text-[12px] font-semibold text-[#7387FF] uppercase tracking-wide">Better briefs = better results</span>
                </div>
                {[
                  { icon: "✍️", tip: "Specific hooks perform 3× better than generic ones" },
                  { icon: "🎯", tip: "A clear 'what NOT to do' reduces revisions by 60%" },
                  { icon: "🎬", tip: "Share 1-2 reference videos for best tone alignment" },
                  { icon: "💡", tip: "Use tone tags so creators can self-filter" },
                ].map((item, i) => (
                  <div key={i} className="flex items-start gap-3 py-3 border-b border-[#F3F3FF] last:border-0">
                    <span className="text-lg">{item.icon}</span>
                    <span className="text-[12px] text-[#9F9FD1] font-medium leading-relaxed">{item.tip}</span>
                  </div>
                ))}
              </div>

              {/* Selected tones preview */}
              {form.tones.length > 0 && (
                <div className="bg-gradient-to-br from-[#7387FF]/8 to-transparent rounded-[18px] border border-[#7387FF]/15 p-5">
                  <div className="text-[12px] font-semibold text-[#07074E] mb-3">Selected Tones</div>
                  <div className="flex flex-wrap gap-2">
                    {form.tones.map((t) => (
                      <span key={t} className="px-3 py-1 bg-[#7387FF] text-white rounded-full text-[11px] font-semibold">{t}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* STEP 3 ── Deliverables ──────────────────────────────────────────── */}
        {step === 3 && (
          <div className="grid grid-cols-[1fr_340px] gap-6 items-start">
            <div className="bg-white rounded-[18px] shadow-[0_2px_16px_rgba(7,7,78,0.07)] border border-[#E9EBFF]/60 p-8">
              <div className="mb-7">
                <div className="inline-flex items-center gap-2 bg-[#F3F3FF] rounded-full px-3 py-1.5 mb-3">
                  <Video className="w-3.5 h-3.5 text-[#7387FF]" />
                  <span className="text-[11px] font-semibold text-[#7387FF] uppercase tracking-wide">Step 3 of 5</span>
                </div>
                <h2 className="text-[22px] font-semibold text-[#07074E]" style={{ fontFamily: "'Readex Pro', sans-serif" }}>
                  What do you need delivered?
                </h2>
                <p className="text-[14px] text-[#9F9FD1] mt-1 font-medium">Specify the exact format and specs for the content.</p>
              </div>

              {/* Video Format */}
              <div className="mb-7">
                <label className="block text-[12px] font-semibold text-[#07074E] mb-3 uppercase tracking-wide">Primary Video Format</label>
                <div className="grid grid-cols-4 gap-3">
                  {VIDEO_FORMATS.map((f) => {
                    const active = form.videoFormat === f.id;
                    return (
                      <button
                        key={f.id}
                        onClick={() => set("videoFormat", f.id)}
                        className={`flex flex-col items-center gap-2 p-4 rounded-[14px] border-2 transition-all duration-200 ${
                          active
                            ? "border-[#7387FF] bg-[#EEF0FF] shadow-[0_4px_12px_rgba(115,135,255,0.15)]"
                            : "border-[#E8E8F0] bg-[#FAFAFE] hover:border-[#C0C4F0] hover:bg-[#F6F6FF]"
                        }`}
                      >
                        <span className="text-2xl">{f.icon}</span>
                        <div className="text-[13px] font-semibold text-[#07074E]">{f.label}</div>
                        <div className="text-[11px] text-[#9F9FD1] text-center">{f.desc}</div>
                        {active && <div className="w-5 h-5 rounded-full bg-[#7387FF] flex items-center justify-center"><Check className="w-3 h-3 text-white" strokeWidth={2.5} /></div>}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Aspect Ratio + Duration */}
              <div className="grid grid-cols-2 gap-6 mb-7">
                <div>
                  <label className="block text-[12px] font-semibold text-[#07074E] mb-3 uppercase tracking-wide">Aspect Ratio</label>
                  <div className="flex gap-2">
                    {ASPECT_RATIOS.map((r) => {
                      const active = form.aspectRatio === r;
                      return (
                        <button
                          key={r}
                          onClick={() => set("aspectRatio", r)}
                          className={`flex-1 h-11 rounded-[10px] border-2 text-[13px] font-semibold transition-all ${
                            active
                              ? "border-[#7387FF] bg-[#EEF0FF] text-[#7387FF]"
                              : "border-[#E8E8F0] bg-[#FAFAFE] text-[#9F9FD1] hover:border-[#C0C4F0]"
                          }`}
                        >
                          {r}
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div>
                  <label className="block text-[12px] font-semibold text-[#07074E] mb-3 uppercase tracking-wide">Duration</label>
                  <div className="flex gap-2">
                    {DURATIONS.map((d) => {
                      const active = form.duration === d;
                      return (
                        <button
                          key={d}
                          onClick={() => set("duration", d)}
                          className={`flex-1 h-11 rounded-[10px] border-2 text-[13px] font-semibold transition-all ${
                            active
                              ? "border-[#7387FF] bg-[#EEF0FF] text-[#7387FF]"
                              : "border-[#E8E8F0] bg-[#FAFAFE] text-[#9F9FD1] hover:border-[#C0C4F0]"
                          }`}
                        >
                          {d}
                        </button>
                      );
                    })}
                  </div>
                </div>
              </div>

              {/* Extras */}
              <div className="mb-7">
                <label className="block text-[12px] font-semibold text-[#07074E] mb-3 uppercase tracking-wide">Additional Deliverables</label>
                <div className="flex gap-3">
                  {[
                    { key: "bRoll",       label: "B-Roll Footage",  icon: "🎥", desc: "Raw b-roll clips" },
                    { key: "photos",      label: "Product Photos",  icon: "📸", desc: "Hi-res stills"    },
                    { key: "rawFootage",  label: "Raw Footage",     icon: "💾", desc: "Unedited clips"   },
                  ].map((item) => {
                    const checked = form[item.key as keyof FormData] as boolean;
                    return (
                      <button
                        key={item.key}
                        onClick={() => set(item.key as keyof FormData, !checked)}
                        className={`flex-1 flex flex-col items-center gap-2 p-4 rounded-[14px] border-2 transition-all ${
                          checked
                            ? "border-[#27AE60] bg-[#E8F8EE] shadow-[0_4px_12px_rgba(39,174,96,0.12)]"
                            : "border-[#E8E8F0] bg-[#FAFAFE] hover:border-[#C0C4F0]"
                        }`}
                      >
                        <span className="text-xl">{item.icon}</span>
                        <div className="text-[12px] font-semibold text-[#07074E]">{item.label}</div>
                        <div className="text-[11px] text-[#9F9FD1]">{item.desc}</div>
                        <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${checked ? "bg-[#27AE60] border-[#27AE60]" : "border-[#D8D8E8]"}`}>
                          {checked && <Check className="w-3 h-3 text-white" strokeWidth={2.5} />}
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Revision Count */}
              <div>
                <label className="block text-[12px] font-semibold text-[#07074E] mb-3 uppercase tracking-wide">
                  Free Revisions Included
                  <span className="ml-2 text-[#9F9FD1] normal-case font-medium">(default: 2)</span>
                </label>
                <div className="flex items-center gap-4">
                  <button
                    onClick={() => set("revisions", Math.max(0, form.revisions - 1))}
                    className="w-10 h-10 rounded-full bg-[#F3F3FF] border border-[#E2E4F0] flex items-center justify-center hover:bg-[#EEF0FF] transition-all"
                  >
                    <Minus className="w-4 h-4 text-[#07074E]" />
                  </button>
                  <div className="w-20 h-12 rounded-[12px] border-2 border-[#7387FF] bg-[#EEF0FF] flex items-center justify-center">
                    <span className="text-[20px] font-semibold text-[#7387FF]" style={{ fontFamily: "'Readex Pro', sans-serif" }}>{form.revisions}</span>
                  </div>
                  <button
                    onClick={() => set("revisions", Math.min(5, form.revisions + 1))}
                    className="w-10 h-10 rounded-full bg-[#F3F3FF] border border-[#E2E4F0] flex items-center justify-center hover:bg-[#EEF0FF] transition-all"
                  >
                    <Plus className="w-4 h-4 text-[#07074E]" />
                  </button>
                  <span className="text-[13px] text-[#9F9FD1] font-medium">
                    {form.revisions === 0 ? "No free revisions" : `${form.revisions} revision${form.revisions > 1 ? "s" : ""} included`}
                  </span>
                </div>
              </div>
            </div>

            {/* Right panel */}
            <div className="flex flex-col gap-4">
              <div className="bg-white rounded-[18px] shadow-[0_2px_16px_rgba(7,7,78,0.07)] border border-[#E9EBFF]/60 p-6">
                <div className="flex items-center gap-2 mb-4">
                  <Film className="w-4 h-4 text-[#7387FF]" />
                  <span className="text-[12px] font-semibold text-[#7387FF] uppercase tracking-wide">Your Deliverable</span>
                </div>
                <div className="flex flex-col gap-3">
                  {[
                    { label: "Format",    value: form.videoFormat ? VIDEO_FORMATS.find(f => f.id === form.videoFormat)?.label : null },
                    { label: "Ratio",     value: form.aspectRatio || null },
                    { label: "Duration",  value: form.duration || null },
                    { label: "Revisions", value: `${form.revisions} free` },
                    { label: "Extras",    value: [form.bRoll && "B-Roll", form.photos && "Photos", form.rawFootage && "Raw"].filter(Boolean).join(", ") || null },
                  ].map((item) => (
                    <div key={item.label} className="flex items-center justify-between py-2 border-b border-[#F3F3FF] last:border-0">
                      <span className="text-[12px] text-[#9F9FD1] font-medium">{item.label}</span>
                      <span className={`text-[12px] font-semibold ${item.value ? "text-[#07074E]" : "text-[#D8D8E8]"}`}>
                        {item.value || "—"}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-gradient-to-br from-[#F39C12]/8 to-transparent rounded-[18px] border border-[#F39C12]/20 p-5">
                <div className="flex items-start gap-3">
                  <Clock className="w-4 h-4 text-[#F39C12] mt-0.5 shrink-0" />
                  <div>
                    <div className="text-[12px] font-semibold text-[#07074E] mb-1">Pro tip on revisions</div>
                    <div className="text-[12px] text-[#9F9FD1] leading-relaxed font-medium">
                      2 free revisions is the platform default. More revisions may increase your creator payout expectations.
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* STEP 4 ── Creator Requirements ─────────────────────────────────── */}
        {step === 4 && (
          <div className="grid grid-cols-[1fr_340px] gap-6 items-start">
            <div className="bg-white rounded-[18px] shadow-[0_2px_16px_rgba(7,7,78,0.07)] border border-[#E9EBFF]/60 p-8">
              <div className="mb-7">
                <div className="inline-flex items-center gap-2 bg-[#F3F3FF] rounded-full px-3 py-1.5 mb-3">
                  <Users className="w-3.5 h-3.5 text-[#7387FF]" />
                  <span className="text-[11px] font-semibold text-[#7387FF] uppercase tracking-wide">Step 4 of 5</span>
                </div>
                <h2 className="text-[22px] font-semibold text-[#07074E]" style={{ fontFamily: "'Readex Pro', sans-serif" }}>
                  Define your ideal creator
                </h2>
                <p className="text-[14px] text-[#9F9FD1] mt-1 font-medium">Filter the creator pool to match exactly who you need.</p>
              </div>

              {/* Creator Level */}
              <div className="mb-7">
                <label className="block text-[12px] font-semibold text-[#07074E] mb-3 uppercase tracking-wide">Minimum Creator Level</label>
                <div className="flex flex-col gap-2">
                  {CREATOR_LEVELS.map((lvl) => {
                    const active = form.creatorLevel === lvl.id;
                    return (
                      <button
                        key={lvl.id}
                        onClick={() => set("creatorLevel", lvl.id)}
                        className={`flex items-center gap-4 p-4 rounded-[12px] border-2 text-left transition-all ${
                          active
                            ? "border-[#7387FF] bg-[#EEF0FF]"
                            : "border-[#E8E8F0] bg-[#FAFAFE] hover:border-[#C0C4F0]"
                        }`}
                      >
                        <div className="w-8 h-8 rounded-full flex items-center justify-center shrink-0" style={{ background: `${lvl.color}20` }}>
                          <Star className="w-3.5 h-3.5" style={{ color: lvl.color }} />
                        </div>
                        <div className="flex-1">
                          <div className="text-[13px] font-semibold text-[#07074E]">{lvl.label}</div>
                          <div className="text-[11px] text-[#9F9FD1] font-medium">{lvl.desc}</div>
                        </div>
                        <div className="text-[12px] font-semibold" style={{ color: lvl.color }}>
                          Min {lvl.min}
                        </div>
                        {active && (
                          <div className="w-5 h-5 rounded-full bg-[#7387FF] flex items-center justify-center">
                            <Check className="w-3 h-3 text-white" strokeWidth={2.5} />
                          </div>
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Quality Tier */}
              <div className="mb-7">
                <label className="block text-[12px] font-semibold text-[#07074E] mb-3 uppercase tracking-wide">Content Quality Tier</label>
                <div className="grid grid-cols-3 gap-3">
                  {QUALITY_TIERS.map((qt) => {
                    const active = form.qualityTier === qt.id;
                    return (
                      <button
                        key={qt.id}
                        onClick={() => set("qualityTier", qt.id)}
                        className={`flex flex-col items-center gap-2 p-4 rounded-[14px] border-2 transition-all ${
                          active
                            ? "border-[#7387FF] bg-[#EEF0FF]"
                            : "border-[#E8E8F0] bg-[#FAFAFE] hover:border-[#C0C4F0]"
                        }`}
                      >
                        <div className="text-[24px] font-semibold" style={{ fontFamily: "'Readex Pro', sans-serif", color: active ? "#7387FF" : qt.color }}>
                          {qt.id}
                        </div>
                        <div className="text-[11px] text-[#9F9FD1] text-center font-medium">{qt.desc}</div>
                        <div className="text-[11px] font-semibold" style={{ color: qt.color }}>{qt.mult}</div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Gender + City */}
              <div className="grid grid-cols-2 gap-5 mb-7">
                <div>
                  <label className="block text-[12px] font-semibold text-[#07074E] mb-2 uppercase tracking-wide">Gender Preference</label>
                  <select
                    value={form.genderPref}
                    onChange={(e) => set("genderPref", e.target.value)}
                    className="w-full h-12 px-4 rounded-[12px] border border-[#E2E4F0] bg-[#FAFAFE] text-[14px] text-[#07074E] focus:outline-none focus:border-[#7387FF] focus:ring-2 focus:ring-[#7387FF]/10 transition-all font-medium appearance-none"
                  >
                    {GENDER_OPTIONS.map((g) => <option key={g}>{g}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-[12px] font-semibold text-[#07074E] mb-2 uppercase tracking-wide">City Filter</label>
                  <select
                    value={form.city}
                    onChange={(e) => set("city", e.target.value)}
                    className="w-full h-12 px-4 rounded-[12px] border border-[#E2E4F0] bg-[#FAFAFE] text-[14px] text-[#07074E] focus:outline-none focus:border-[#7387FF] focus:ring-2 focus:ring-[#7387FF]/10 transition-all font-medium appearance-none"
                  >
                    {CITIES.map((c) => <option key={c}>{c}</option>)}
                  </select>
                </div>
              </div>

              {/* Niche Tags */}
              <div>
                <label className="block text-[12px] font-semibold text-[#07074E] mb-3 uppercase tracking-wide">
                  Creator Niche Tags
                  <span className="ml-2 text-[#9F9FD1] normal-case font-medium">Select all that apply</span>
                </label>
                <div className="flex flex-wrap gap-2">
                  {NICHE_TAGS.map((tag) => {
                    const active = form.nicheTags.includes(tag);
                    return (
                      <button
                        key={tag}
                        onClick={() => toggleArray("nicheTags", tag)}
                        className={`flex items-center gap-1.5 px-3.5 py-2 rounded-full text-[12px] font-semibold border transition-all ${
                          active
                            ? "bg-[#07074E] text-white border-[#07074E] shadow-sm"
                            : "bg-white text-[#9F9FD1] border-[#E2E4F0] hover:border-[#07074E] hover:text-[#07074E]"
                        }`}
                      >
                        <Tag className="w-3 h-3" />
                        {tag}
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Right: Matching Preview */}
            <div className="flex flex-col gap-4">
              <div className="bg-white rounded-[18px] shadow-[0_2px_16px_rgba(7,7,78,0.07)] border border-[#E9EBFF]/60 p-6">
                <div className="flex items-center gap-2 mb-5">
                  <Target className="w-4 h-4 text-[#7387FF]" />
                  <span className="text-[12px] font-semibold text-[#7387FF] uppercase tracking-wide">Matching Preview</span>
                </div>

                {/* Estimated creators */}
                <div className="text-center mb-5 p-5 bg-[#F3F3FF] rounded-[14px]">
                  <div className="text-[40px] font-semibold text-[#07074E] mb-1" style={{ fontFamily: "'Readex Pro', sans-serif" }}>
                    {form.creatorLevel
                      ? form.creatorLevel === "Elite" ? "12"
                        : form.creatorLevel === "L2" ? "48"
                        : form.creatorLevel === "L1" ? "140"
                        : form.creatorLevel === "Verified" ? "320"
                        : "580"
                      : "—"}
                  </div>
                  <div className="text-[13px] text-[#9F9FD1] font-medium">Estimated creators</div>
                  <div className="text-[11px] text-[#9F9FD1] mt-1">match your current filters</div>
                </div>

                <div className="flex flex-col gap-2.5">
                  {[
                    { label: "Creator Level",  val: form.creatorLevel || "Any",  ok: !!form.creatorLevel },
                    { label: "Quality Tier",   val: form.qualityTier  || "Any",  ok: !!form.qualityTier  },
                    { label: "Gender",         val: form.genderPref,             ok: true                },
                    { label: "City",           val: form.city,                   ok: true                },
                    { label: "Niches",         val: form.nicheTags.length > 0 ? `${form.nicheTags.length} selected` : "Any", ok: form.nicheTags.length > 0 },
                  ].map((row) => (
                    <div key={row.label} className="flex items-center justify-between">
                      <span className="text-[12px] text-[#9F9FD1] font-medium">{row.label}</span>
                      <span className={`text-[12px] font-semibold ${row.ok ? "text-[#07074E]" : "text-[#C0C0D8]"}`}>{row.val}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-gradient-to-br from-[#27AE60]/8 to-transparent rounded-[18px] border border-[#27AE60]/20 p-5">
                <div className="flex items-start gap-3">
                  <Zap className="w-4 h-4 text-[#27AE60] mt-0.5 shrink-0" />
                  <div>
                    <div className="text-[12px] font-semibold text-[#07074E] mb-1">Smart matching tip</div>
                    <div className="text-[12px] text-[#9F9FD1] leading-relaxed font-medium">
                      Briefs that match L1+ with A quality tier get filled 40% faster. Elite creators have the lowest revision rates.
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* STEP 5 ── Budget & Review ───────────────────────────────────────── */}
        {step === 5 && (
          <div className="flex flex-col gap-6">
            {/* Budget input + breakdown */}
            <div className="grid grid-cols-[1fr_360px] gap-6">
              {/* Left: Budget input */}
              <div className="bg-white rounded-[18px] shadow-[0_2px_16px_rgba(7,7,78,0.07)] border border-[#E9EBFF]/60 p-8">
                <div className="mb-7">
                  <div className="inline-flex items-center gap-2 bg-[#F3F3FF] rounded-full px-3 py-1.5 mb-3">
                    <DollarSign className="w-3.5 h-3.5 text-[#7387FF]" />
                    <span className="text-[11px] font-semibold text-[#7387FF] uppercase tracking-wide">Step 5 of 5</span>
                  </div>
                  <h2 className="text-[22px] font-semibold text-[#07074E]" style={{ fontFamily: "'Readex Pro', sans-serif" }}>
                    Set your budget
                  </h2>
                  <p className="text-[14px] text-[#9F9FD1] mt-1 font-medium">Enter what you want to pay per video. We handle the rest.</p>
                </div>

                {/* Budget input */}
                <div className="mb-6">
                  <label className="block text-[12px] font-semibold text-[#07074E] mb-3 uppercase tracking-wide">Per Video Budget</label>
                  <div className="relative">
                    <span className="absolute left-5 top-1/2 -translate-y-1/2 text-[24px] font-semibold text-[#9F9FD1]">₹</span>
                    <input
                      value={form.perVideoBudget}
                      onChange={(e) => set("perVideoBudget", e.target.value.replace(/\D/g, ""))}
                      placeholder="18,750"
                      className="w-full h-16 pl-12 pr-5 rounded-[14px] border-2 border-[#E2E4F0] bg-[#FAFAFE] text-[26px] font-semibold text-[#07074E] placeholder:text-[#D8D8E8] focus:outline-none focus:border-[#7387FF] focus:ring-4 focus:ring-[#7387FF]/10 transition-all"
                      style={{ fontFamily: "'Readex Pro', sans-serif" }}
                    />
                  </div>
                </div>

                {/* Breakdown table */}
                {brandPays > 0 && (
                  <div className="rounded-[14px] border border-[#E8E8F0] overflow-hidden">
                    <div className="bg-[#F9F9FF] px-5 py-3 border-b border-[#E8E8F0]">
                      <span className="text-[12px] font-semibold text-[#07074E] uppercase tracking-wide">Payment Breakdown</span>
                    </div>
                    <div className="divide-y divide-[#F3F3FF]">
                      <div className="flex items-center justify-between px-5 py-4">
                        <div className="flex items-center gap-3">
                          <div className="w-2 h-2 rounded-full bg-[#07074E]" />
                          <span className="text-[13px] font-medium text-[#07074E]">Brand pays (per video)</span>
                        </div>
                        <span className="text-[15px] font-semibold text-[#07074E]">₹{brandPays.toLocaleString("en-IN")}</span>
                      </div>
                      <div className="flex items-center justify-between px-5 py-4">
                        <div className="flex items-center gap-3">
                          <div className="w-2 h-2 rounded-full bg-[#9F9FD1]" />
                          <div>
                            <span className="text-[13px] font-medium text-[#9F9FD1]">Platform commission</span>
                            <span className="ml-2 text-[11px] bg-[#F3F3FF] text-[#7387FF] px-2 py-0.5 rounded-full font-semibold">Brand Pro · 20%</span>
                          </div>
                        </div>
                        <span className="text-[15px] font-semibold text-[#9F9FD1]">₹{commission.toLocaleString("en-IN")}</span>
                      </div>
                      <div className="flex items-center justify-between px-5 py-4 bg-[#E8F8EE]/60">
                        <div className="flex items-center gap-3">
                          <div className="w-2 h-2 rounded-full bg-[#27AE60]" />
                          <span className="text-[13px] font-semibold text-[#07074E]">Creator receives</span>
                        </div>
                        <span className="text-[17px] font-semibold text-[#27AE60]">₹{creatorGets.toLocaleString("en-IN")}</span>
                      </div>
                      <div className="flex items-center justify-between px-5 py-4">
                        <div className="flex items-center gap-3">
                          <div className="w-2 h-2 rounded-full bg-[#F39C12]" />
                          <div>
                            <span className="text-[13px] font-medium text-[#9F9FD1]">Listing fee</span>
                            <span className="ml-2 text-[11px] bg-[#FFF8E8] text-[#F39C12] px-2 py-0.5 rounded-full font-semibold">Refunded if hired</span>
                          </div>
                        </div>
                        <span className="text-[15px] font-semibold text-[#F39C12]">₹{LISTING_FEE.toLocaleString("en-IN")}</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Escrow notice */}
                <div className="mt-5 flex items-start gap-3 p-4 bg-[#EEF0FF] rounded-[12px] border border-[#7387FF]/20">
                  <Info className="w-4 h-4 text-[#7387FF] mt-0.5 shrink-0" />
                  <div className="text-[12px] text-[#7387FF] font-medium leading-relaxed">
                    <span className="font-semibold">Escrow-protected.</span> Payment is locked on deal acceptance and only released when you approve the delivered content — or after 5 calendar days automatically.
                  </div>
                </div>
              </div>

              {/* Right: Brief Review Summary */}
              <div className="flex flex-col gap-4">
                <div className="bg-white rounded-[18px] shadow-[0_2px_16px_rgba(7,7,78,0.07)] border border-[#E9EBFF]/60 p-6">
                  <div className="flex items-center gap-2 mb-5">
                    <CheckCircle2 className="w-4 h-4 text-[#27AE60]" />
                    <span className="text-[12px] font-semibold text-[#27AE60] uppercase tracking-wide">Brief Summary</span>
                  </div>
                  <div className="flex flex-col gap-3">
                    {[
                      { label: "Product",        val: form.productName || "—" },
                      { label: "Category",       val: form.category    || "—" },
                      { label: "Brief Type",     val: form.briefType   || "—" },
                      { label: "Video Format",   val: form.videoFormat ? VIDEO_FORMATS.find(f => f.id === form.videoFormat)?.label : "—" },
                      { label: "Duration",       val: form.duration    || "—" },
                      { label: "Creator Level",  val: form.creatorLevel|| "—" },
                      { label: "Quality Tier",   val: form.qualityTier || "—" },
                      { label: "Revisions",      val: `${form.revisions} free` },
                    ].map((row) => (
                      <div key={row.label} className="flex items-center justify-between py-2 border-b border-[#F3F3FF] last:border-0">
                        <span className="text-[11px] text-[#9F9FD1] font-medium uppercase tracking-wide">{row.label}</span>
                        <span className="text-[12px] font-semibold text-[#07074E]">{row.val}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Total cost */}
                {brandPays > 0 && (
                  <div className="bg-[#07074E] rounded-[18px] p-6 text-white">
                    <div className="text-[11px] font-semibold text-[#9F9FD1] uppercase tracking-wide mb-2">Total cost (1 creator)</div>
                    <div className="text-[32px] font-semibold" style={{ fontFamily: "'Readex Pro', sans-serif" }}>
                      ₹{(brandPays + LISTING_FEE).toLocaleString("en-IN")}
                    </div>
                    <div className="text-[12px] text-[#9F9FD1] mt-1 font-medium">
                      Includes ₹{LISTING_FEE} listing fee (refunded if hired)
                    </div>
                    <div className="mt-4 pt-4 border-t border-white/10">
                      <div className="flex items-center gap-2 text-[#27AE60]">
                        <Check className="w-4 h-4" strokeWidth={2.5} />
                        <span className="text-[12px] font-semibold">Escrow-protected payment</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Admin review notice */}
                <div className="flex items-start gap-3 p-4 bg-[#FFF8E8] rounded-[14px] border border-[#F39C12]/25">
                  <Clock className="w-4 h-4 text-[#F39C12] mt-0.5 shrink-0" />
                  <div className="text-[12px] text-[#07074E] font-medium leading-relaxed">
                    Your brief goes to <span className="font-semibold">admin review</span> before creators can apply. Estimated review time: <span className="text-[#F39C12] font-semibold">24 hours</span>.
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── Bottom Action Bar ─────────────────────────────────────────────── */}
        <div className="bg-white rounded-[18px] shadow-[0_2px_16px_rgba(7,7,78,0.07)] border border-[#E9EBFF]/60 px-8 py-5 flex items-center justify-between">
          {/* Save Draft */}
          <button className="flex items-center gap-2 px-5 py-2.5 rounded-[10px] border border-[#E2E4F0] text-[#9F9FD1] hover:border-[#9F9FD1] hover:text-[#07074E] transition-all text-[13px] font-semibold">
            <Save className="w-4 h-4" />
            Save Draft
          </button>

          <div className="flex items-center gap-3">
            {/* Back */}
            {step > 1 && (
              <button
                onClick={() => setStep(step - 1)}
                className="flex items-center gap-2 px-5 py-2.5 rounded-[10px] border border-[#E2E4F0] text-[#9F9FD1] hover:border-[#9F9FD1] hover:text-[#07074E] transition-all text-[13px] font-semibold"
              >
                <ArrowLeft className="w-4 h-4" />
                Back
              </button>
            )}

            {/* Next or Submit */}
            {step < 5 ? (
              <button
                onClick={() => setStep(step + 1)}
                className="flex items-center gap-2 px-6 py-2.5 bg-[#7387FF] text-white rounded-[10px] text-[13px] font-semibold shadow-[0_4px_12px_rgba(115,135,255,0.3)] hover:bg-[#5a6de0] transition-all"
              >
                Next Step
                <ArrowRight className="w-4 h-4" />
              </button>
            ) : (
              <button className="flex items-center gap-2 px-7 py-2.5 bg-[#07074E] text-white rounded-[10px] text-[13px] font-semibold shadow-[0_4px_16px_rgba(7,7,78,0.25)] hover:bg-[#0d0d60] transition-all">
                <Send className="w-4 h-4" />
                Submit Brief
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
