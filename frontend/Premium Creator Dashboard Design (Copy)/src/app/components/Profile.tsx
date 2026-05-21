import { useState } from "react";
import {
  Edit3,
  Eye,
  Share2,
  Star,
  Briefcase,
  MessageCircle,
  RefreshCw,
  MapPin,
  Globe2,
  ChevronDown,
  X,
  Plus,
  ShieldCheck,
  BadgeCheck,
  CreditCard,
  Award,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Sparkles,
  Play,
  Trash2,
  UploadCloud,
  Tag,
  Eye as EyeIcon,
  Zap,
  TrendingUp,
  Lock,
  Save,
  ExternalLink,
  Film,
  Image as ImageIcon,
} from "lucide-react";

// ─── Data ─────────────────────────────────────────────────────────────────────

const NICHES = ["Beauty & Skincare", "Tech & Gadgets", "Fitness & Health", "Travel", "Lifestyle", "Food & Cooking", "Fashion", "Home Decor", "Parenting", "Finance"];
const CITIES  = ["Mumbai", "Delhi", "Bengaluru", "Hyderabad", "Chennai", "Pune", "Kolkata", "Jaipur", "Ahmedabad", "Surat"];
const LANGS   = ["English", "Hindi", "Marathi", "Tamil", "Telugu", "Kannada", "Bengali", "Gujarati"];

const PAST_BRANDS = [
  { name: "Glow & Co",  color: "#7387FF", initial: "G" },
  { name: "TechNova",   color: "#06B6D4", initial: "T" },
  { name: "FitLife",    color: "#22C55E", initial: "F" },
  { name: "Wanderlust", color: "#F59E0B", initial: "W" },
  { name: "EcoHome",    color: "#8B5CF6", initial: "E" },
];

const VISIBILITY_TAGS = [
  { label: "Recommended for Beauty",  icon: Sparkles,   color: "#7387FF" },
  { label: "Recommended for Tech",    icon: Zap,        color: "#06B6D4" },
  { label: "Available in Mumbai",     icon: MapPin,     color: "#F59E0B" },
  { label: "Ships Nationwide",        icon: Globe2,     color: "#22C55E" },
  { label: "Accepts Barter Deals",    icon: RefreshCw,  color: "#8B5CF6" },
  { label: "Fast Turnaround < 5d",    icon: Clock,      color: "#EF4444" },
];

const PORTFOLIO_ITEMS = [
  {
    id: 1,
    title: "Morning Skincare Routine",
    category: "Beauty",
    duration: "0:45",
    views: "12.4K",
    thumbnail: "https://images.unsplash.com/photo-1609357912334-e96886c0212b?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxza2luY2FyZSUyMG1vcm5pbmclMjByb3V0aW5lJTIwYmVhdXR5fGVufDF8fHx8MTc3NzA5NzE3MHww&ixlib=rb-4.1.0&q=80&w=1080",
    catColor: "#7387FF",
  },
  {
    id: 2,
    title: "Smart Home Setup Tour",
    category: "Tech",
    duration: "1:02",
    views: "8.9K",
    thumbnail: "https://images.unsplash.com/photo-1776001781601-8d28e7b52f6c?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxzbWFydCUyMGhvbWUlMjB0ZWNoJTIwc2V0dXAlMjBtb2Rlcm58ZW58MXx8fHwxNzc3MDk3MTczfDA&ixlib=rb-4.1.0&q=80&w=1080",
    catColor: "#06B6D4",
  },
  {
    id: 3,
    title: "Fitness Challenge Day 1",
    category: "Fitness",
    duration: "0:30",
    views: "21.7K",
    thumbnail: "https://images.unsplash.com/photo-1734189605012-f03d97a4d98f?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxmaXRuZXNzJTIwd29ya291dCUyMGd5bSUyMGNoYWxsZW5nZXxlbnwxfHx8fDE3NzcwOTcxNzR8MA&ixlib=rb-4.1.0&q=80&w=1080",
    catColor: "#22C55E",
  },
  {
    id: 4,
    title: "Travel Packing Essentials",
    category: "Travel",
    duration: "0:55",
    views: "5.3K",
    thumbnail: "https://images.unsplash.com/photo-1761653457980-21b9f7fd3a04?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHx0cmF2ZWwlMjBwYWNraW5nJTIwbHVnZ2FnZSUyMGVzc2VudGlhbHN8ZW58MXx8fHwxNzc3MDk3MTc0fDA&ixlib=rb-4.1.0&q=80&w=1080",
    catColor: "#F59E0B",
  },
  {
    id: 5,
    title: "Eco-friendly Lifestyle Haul",
    category: "Lifestyle",
    duration: "0:38",
    views: "9.1K",
    thumbnail: "https://images.unsplash.com/photo-1776950220655-ce737cbfbe75?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxlY28lMjBmcmllbmRseSUyMHN1c3RhaW5hYmxlJTIwbGlmZXN0eWxlJTIwcHJvZHVjdHN8ZW58MXx8fHwxNzc3MDk3MTc0fDA&ixlib=rb-4.1.0&q=80&w=1080",
    catColor: "#8B5CF6",
  },
];

const STRENGTH_SUGGESTIONS = [
  { done: true,  text: "Profile photo uploaded"            },
  { done: true,  text: "Bio completed"                     },
  { done: true,  text: "Primary niche selected"            },
  { done: true,  text: "Payment verified"                  },
  { done: false, text: "Add at least 3 portfolio samples"  },
  { done: false, text: "Complete GST verification"         },
  { done: false, text: "Add a second niche"                },
  { done: false, text: "Add spoken languages"              },
];

const VERIFICATIONS = [
  { icon: BadgeCheck,   label: "Identity Verified",  status: "verified",  note: "PAN matched"           },
  { icon: CreditCard,   label: "Payment Verified",   status: "verified",  note: "Bank account linked"   },
  { icon: ShieldCheck,  label: "GST Verification",   status: "pending",   note: "Upload GST certificate" },
  { icon: Award,        label: "Top Rated Badge",    status: "locked",    note: "Complete 10 deals"      },
];

// ─── Sub Components ───────────────────────────────────────────────────────────

function NicheChip({ label, onRemove, color = "#7387FF" }: { label: string; onRemove?: () => void; color?: string }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 pl-3 pr-2 py-1 rounded-full text-[12px] font-semibold border"
      style={{ backgroundColor: `${color}10`, color, borderColor: `${color}25` }}
    >
      {label}
      {onRemove && (
        <button onClick={onRemove} className="hover:opacity-70 transition-opacity">
          <X className="w-3 h-3" />
        </button>
      )}
    </span>
  );
}

function CircularProgress({ pct }: { pct: number }) {
  const r = 44;
  const circ = 2 * Math.PI * r;
  const dash = circ - (pct / 100) * circ;
  return (
    <div className="relative w-[100px] h-[100px] flex items-center justify-center">
      <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={r} fill="none" stroke="#F3F3FF" strokeWidth="8" />
        <circle
          cx="50" cy="50" r={r} fill="none"
          stroke="#7387FF" strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={dash}
          className="transition-all duration-700"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-[22px] font-semibold text-[#07074E] font-heading leading-none">{pct}%</span>
        <span className="text-[9px] font-semibold text-[#B7B7E6] uppercase tracking-wider mt-0.5">Complete</span>
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export function Profile() {
  const [bio, setBio] = useState(
    "Lifestyle & beauty UGC creator from Mumbai. I craft authentic short-form videos that connect real people with brands they love. 3+ years of content creation experience."
  );
  const [bioWarning, setBioWarning] = useState(false);
  const [primaryNiche, setPrimaryNiche] = useState("Beauty & Skincare");
  const [secondaryNiches, setSecondaryNiches] = useState(["Lifestyle", "Tech & Gadgets"]);
  const [city, setCity] = useState("Mumbai");
  const [languages, setLanguages] = useState(["English", "Hindi"]);
  const [showNicheDD, setShowNicheDD] = useState(false);
  const [showCityDD, setShowCityDD]   = useState(false);
  const [showLangDD, setShowLangDD]   = useState(false);
  const [saved, setSaved]             = useState(false);
  const [activePortfolioHover, setActivePortfolioHover] = useState<number | null>(null);
  const [editingBio, setEditingBio]   = useState(false);

  const privacyRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|(\+91|0)?[6-9]\d{9}/;

  const handleBioChange = (val: string) => {
    if (val.length > 280) return;
    setBioWarning(privacyRegex.test(val));
    setBio(val);
  };

  const handleSave = () => {
    if (bioWarning) return;
    setSaved(true);
    setEditingBio(false);
    setTimeout(() => setSaved(false), 2500);
  };

  const addSecondaryNiche = (n: string) => {
    if (!secondaryNiches.includes(n) && n !== primaryNiche && secondaryNiches.length < 3) {
      setSecondaryNiches([...secondaryNiches, n]);
    }
    setShowNicheDD(false);
  };

  const removeSecondaryNiche = (n: string) => setSecondaryNiches(secondaryNiches.filter((s) => s !== n));

  const toggleLang = (l: string) => {
    setLanguages(prev => prev.includes(l) ? prev.filter(x => x !== l) : [...prev, l]);
  };

  const strengthPct = 82;
  const doneCount   = STRENGTH_SUGGESTIONS.filter(s => s.done).length;

  return (
    <div className="flex flex-col gap-6 pb-12 pt-2 font-sans" onClick={() => { setShowNicheDD(false); setShowCityDD(false); setShowLangDD(false); }}>

      {/* ══════════════════════════════════════
          SECTION 1 — HERO PROFILE CARD
      ══════════════════════════════════════ */}
      <div className="relative">

        {/* ── BANNER ── */}
        <div
          className="relative h-[200px] rounded-[22px] overflow-hidden"
          style={{ background: "linear-gradient(135deg, #07074E 0%, #0f1580 38%, #3a4fd4 65%, #7387FF 82%, #B7B7E6 100%)" }}
        >
          {/* Decorative glow orbs */}
          <div className="absolute -top-12 left-[20%] w-72 h-72 rounded-full bg-[#7387FF]/22 blur-3xl pointer-events-none" />
          <div className="absolute -bottom-10 right-[6%] w-48 h-48 rounded-full bg-[#B7B7E6]/20 blur-2xl pointer-events-none" />
          <div className="absolute top-0 -left-6 w-36 h-36 rounded-full bg-white/5 blur-2xl pointer-events-none" />
          <div className="absolute top-6 right-[35%] w-24 h-24 rounded-full bg-[#7387FF]/15 blur-2xl pointer-events-none" />
        </div>

        {/* ── CONTENT CARD — overlaps banner ── */}
        <div className="relative -mt-[62px] mx-5">
          <div className="bg-white rounded-[20px] shadow-[0_12px_48px_rgba(7,7,78,0.13)] border border-[#E9EBEF]/50 flex items-center px-7 py-6 gap-0">

            {/* ─────────────────────────────────
                ZONE 1: Profile Identity  (45%)
            ───────────────────────────────── */}
            <div className="flex items-center gap-5 min-w-0" style={{ flex: "0 0 45%" }}>
              {/* Avatar */}
              <div className="relative flex-shrink-0">
                <img
                  src="https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=192&h=192"
                  alt="Alex Rivera"
                  className="w-[88px] h-[88px] rounded-full object-cover ring-[3px] ring-white shadow-[0_6px_24px_rgba(7,7,78,0.18)]"
                />
                <button className="absolute bottom-0.5 right-0.5 w-[26px] h-[26px] bg-[#7387FF] rounded-full flex items-center justify-center shadow-md hover:bg-[#5A6EED] transition-all hover:scale-105 border-[2px] border-white">
                  <Edit3 strokeWidth={2.2} className="w-3 h-3 text-white" />
                </button>
              </div>

              {/* Identity text stack */}
              <div className="flex flex-col gap-[10px] min-w-0">
                {/* Name */}
                <h2 className="text-[21px] font-semibold text-[#07074E] font-heading tracking-tight leading-none">
                  Alex Rivera
                </h2>

                {/* Badges */}
                <div className="flex items-center gap-2">
                  <span className="inline-flex items-center gap-1.5 bg-[#7387FF]/10 text-[#7387FF] border border-[#7387FF]/20 px-2.5 py-[5px] rounded-full text-[11px] font-semibold whitespace-nowrap">
                    <Star strokeWidth={2} className="w-3 h-3 fill-[#7387FF]" />
                    L1 Rising Creator
                  </span>
                  <span className="inline-flex items-center gap-1.5 bg-[#22C55E]/10 text-[#22C55E] border border-[#22C55E]/20 px-2.5 py-[5px] rounded-full text-[11px] font-semibold whitespace-nowrap">
                    <BadgeCheck strokeWidth={2} className="w-3 h-3" />
                    Verified
                  </span>
                </div>

                {/* City + handle */}
                <div className="flex items-center gap-1.5 text-[12.5px] font-medium text-[#9F9FD1]">
                  <MapPin strokeWidth={1.5} className="w-3.5 h-3.5 flex-shrink-0" />
                  <span>Mumbai, India</span>
                  <span className="w-1 h-1 rounded-full bg-[#D8D8EE] flex-shrink-0" />
                  <span className="font-semibold text-[#B7B7E6]">@alexrivera.ugc</span>
                </div>

                {/* Bio */}
                <p className="text-[12.5px] font-medium text-[#4A4A7A] leading-[1.55] line-clamp-2 max-w-[340px]">
                  {bio}
                </p>
              </div>
            </div>

            {/* Zone 1 → 2 divider */}
            <div className="w-px self-stretch bg-[#F0F0FA] mx-8 flex-shrink-0" />

            {/* ─────────────────────────────────
                ZONE 2: Quick Stats
            ───────────────────────────────── */}
            <div className="flex gap-3 flex-1 px-2">
              {[
                { icon: Star,          label: "Rating",        value: "4.9",  sub: "/ 5.0"  },
                { icon: Briefcase,     label: "Deals Done",    value: "12",   sub: "total"  },
                { icon: MessageCircle, label: "Response Rate", value: "98%",  sub: "avg"    },
                { icon: RefreshCw,     label: "Repeat Hires",  value: "3",    sub: "brands" },
              ].map((stat, i) => (
                <div
                  key={i}
                  className="flex flex-col items-center justify-center gap-[6px] bg-[#F8F8FF] rounded-[14px] shadow-[0_2px_10px_rgba(7,7,78,0.05)] border border-[#EBEBFA] px-3 py-3.5 flex-1 cursor-default hover:shadow-[0_6px_22px_rgba(115,135,255,0.13)] hover:-translate-y-[2px] transition-all duration-200 group"
                >
                  {/* Icon */}
                  <div className="w-7 h-7 rounded-full bg-white border border-[#7387FF]/18 flex items-center justify-center shadow-[0_1px_4px_rgba(115,135,255,0.10)] group-hover:border-[#7387FF]/35 transition-colors">
                    <stat.icon strokeWidth={1.4} className="w-[12px] h-[12px] text-[#7387FF]" />
                  </div>

                  {/* Value + meta */}
                  <div className="flex flex-col items-center gap-[2px]">
                    <div className="flex items-baseline gap-[2px]">
                      <span className="text-[16px] font-semibold text-[#07074E] font-heading leading-none tracking-tight">{stat.value}</span>
                      <span className="text-[9px] font-medium text-[#C4C4E8] leading-none">{stat.sub}</span>
                    </div>
                    {/* Label */}
                    <p className="text-[8.5px] font-semibold text-[#B7B7E6] uppercase tracking-[0.07em] text-center whitespace-nowrap">{stat.label}</p>
                  </div>
                </div>
              ))}
            </div>

            {/* Zone 2 → 3 divider */}
            <div className="w-px self-stretch bg-[#F0F0FA] mx-8 flex-shrink-0" />

            {/* ─────────────────────────────────
                ZONE 3: Actions  (20%)
            ───────────────────────────────── */}
            <div className="flex flex-col gap-2 flex-shrink-0" style={{ flex: "0 0 auto" }}>
              <button className="flex items-center justify-center bg-[#7387FF] text-white w-10 h-10 rounded-[10px] shadow-[0_4px_14px_rgba(115,135,255,0.32)] hover:bg-[#5A6EED] hover:-translate-y-0.5 transition-all flex-shrink-0">
                <Edit3 strokeWidth={1.8} className="w-4 h-4" />
              </button>
              <button className="flex items-center justify-center bg-white w-10 h-10 rounded-[10px] border border-[#E2E2F0] hover:bg-[#F3F3FF] hover:border-[#B7B7E6] transition-all flex-shrink-0">
                <Eye strokeWidth={1.8} className="w-4 h-4 text-[#9F9FD1]" />
              </button>
              <button className="flex items-center justify-center bg-white w-10 h-10 rounded-[10px] border border-[#E2E2F0] hover:bg-[#F3F3FF] hover:border-[#B7B7E6] transition-all flex-shrink-0">
                <Share2 strokeWidth={1.8} className="w-4 h-4 text-[#9F9FD1]" />
              </button>
            </div>

          </div>
        </div>

        {/* Bottom spacer so the next section has breathing room */}
        <div className="h-5" />
      </div>

      {/* ═════════════════════════════════════
          SECTION 2 — TWO COLUMN LAYOUT
      ══════════════════════════════════════ */}
      <div className="flex gap-5">

        {/* ── LEFT COLUMN (60%) ── */}
        <div className="flex flex-col gap-5 min-w-0" style={{ flex: "0 0 60%" }}>

          {/* A. Public Info Card */}
          <div className="bg-white rounded-[20px] shadow-[0_4px_24px_rgba(7,7,78,0.05)] border border-[#E9EBEF]/50 overflow-visible">
            <div className="px-7 pt-6 pb-5 border-b border-[#F3F3FF] flex items-center justify-between">
              <div>
                <h3 className="text-[16px] font-semibold text-[#07074E] font-heading">Public Info</h3>
                <p className="text-[12px] font-medium text-[#9F9FD1] mt-0.5">Visible to all brands on UGCad</p>
              </div>
              {saved && (
                <div className="flex items-center gap-1.5 bg-[#22C55E]/10 border border-[#22C55E]/20 text-[#22C55E] px-3 py-1.5 rounded-full text-[12px] font-semibold">
                  <CheckCircle2 strokeWidth={2} className="w-3.5 h-3.5" />
                  Auto-saved
                </div>
              )}
            </div>

            <div className="px-7 py-6 flex flex-col gap-5">
              {/* Handle (read only) */}
              <div>
                <label className="block text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-2">
                  Permanent Handle
                </label>
                <div className="flex items-center gap-2.5 bg-[#F3F3FF] rounded-[12px] px-4 py-3 border border-[#E9EBEF]/60">
                  <Lock strokeWidth={1.5} className="w-4 h-4 text-[#B7B7E6] flex-shrink-0" />
                  <span className="text-[13.5px] font-semibold text-[#07074E] font-mono">@alexrivera.ugc</span>
                  <span className="ml-auto text-[11px] font-semibold text-[#B7B7E6] uppercase tracking-wider">Read only</span>
                </div>
              </div>

              {/* Bio */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="block text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider">Bio</label>
                  <span className={`text-[11.5px] font-semibold ${bio.length > 240 ? "text-[#F59E0B]" : "text-[#B7B7E6]"}`}>
                    {bio.length} / 280
                  </span>
                </div>
                <textarea
                  value={bio}
                  onChange={(e) => { handleBioChange(e.target.value); setEditingBio(true); }}
                  rows={3}
                  className="w-full bg-[#F3F3FF] rounded-[12px] px-4 py-3 text-[13.5px] font-medium text-[#07074E] placeholder-[#B7B7E6] outline-none border border-[#E9EBEF]/60 focus:border-[#7387FF]/40 focus:bg-white transition-all resize-none leading-relaxed"
                  placeholder="Describe yourself as a creator…"
                />
                {bioWarning && (
                  <div className="mt-2 flex items-start gap-2 bg-[#F59E0B]/8 border border-[#F59E0B]/20 rounded-[10px] px-3.5 py-2.5">
                    <AlertTriangle strokeWidth={1.8} className="w-4 h-4 text-[#F59E0B] flex-shrink-0 mt-0.5" />
                    <p className="text-[12px] font-semibold text-[#F59E0B]">
                      Privacy warning — your bio appears to contain a phone or email. Remove it before saving.
                    </p>
                  </div>
                )}
              </div>

              {/* Primary Niche */}
              <div className="relative" onClick={(e) => e.stopPropagation()}>
                <label className="block text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-2">Primary Niche</label>
                <button
                  onClick={() => { setShowNicheDD(!showNicheDD); setShowCityDD(false); setShowLangDD(false); }}
                  className="w-full flex items-center justify-between bg-[#F3F3FF] rounded-[12px] px-4 py-3 text-[13.5px] font-semibold text-[#07074E] border border-[#E9EBEF]/60 hover:border-[#7387FF]/30 focus:border-[#7387FF]/40 transition-all"
                >
                  <span>{primaryNiche}</span>
                  <ChevronDown strokeWidth={2} className={`w-4 h-4 text-[#B7B7E6] transition-transform ${showNicheDD ? "rotate-180" : ""}`} />
                </button>
                {showNicheDD && (
                  <div className="absolute top-full mt-1 left-0 right-0 bg-white rounded-[14px] shadow-[0_8px_32px_rgba(7,7,78,0.12)] border border-[#E9EBEF]/60 z-30 overflow-hidden max-h-[220px] overflow-y-auto">
                    {NICHES.map((n) => (
                      <button
                        key={n}
                        onClick={() => { setPrimaryNiche(n); setShowNicheDD(false); }}
                        className={`w-full text-left px-4 py-2.5 text-[13px] font-medium transition-colors flex items-center gap-2.5 ${n === primaryNiche ? "bg-[#7387FF]/8 text-[#7387FF] font-semibold" : "text-[#07074E] hover:bg-[#F3F3FF]"}`}
                      >
                        {n === primaryNiche && <div className="w-1.5 h-1.5 rounded-full bg-[#7387FF]" />}
                        {n}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Secondary Niches */}
              <div className="relative" onClick={(e) => e.stopPropagation()}>
                <label className="block text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-2">
                  Secondary Niches <span className="text-[#B7B7E6] normal-case tracking-normal font-medium">(up to 3)</span>
                </label>
                <div className="flex flex-wrap gap-2 mb-2">
                  {secondaryNiches.map((n) => (
                    <NicheChip key={n} label={n} onRemove={() => removeSecondaryNiche(n)} color="#7387FF" />
                  ))}
                  {secondaryNiches.length < 3 && (
                    <button
                      onClick={(e) => { e.stopPropagation(); setShowNicheDD(false); setShowCityDD(false); setShowLangDD(!showLangDD); }}
                      className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-[12px] font-semibold border border-dashed border-[#B7B7E6] text-[#B7B7E6] hover:border-[#7387FF] hover:text-[#7387FF] transition-colors"
                    >
                      <Plus className="w-3 h-3" /> Add niche
                    </button>
                  )}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {NICHES.filter(n => n !== primaryNiche && !secondaryNiches.includes(n)).map((n) => (
                    <button
                      key={n}
                      onClick={() => addSecondaryNiche(n)}
                      className="px-3 py-1 rounded-full text-[11.5px] font-medium bg-[#F3F3FF] text-[#9F9FD1] hover:bg-[#7387FF]/10 hover:text-[#7387FF] transition-colors border border-[#E9EBEF]/60 hover:border-[#7387FF]/20"
                    >
                      + {n}
                    </button>
                  ))}
                </div>
              </div>

              {/* City + Languages side by side */}
              <div className="grid grid-cols-2 gap-4">
                {/* City */}
                <div className="relative" onClick={(e) => e.stopPropagation()}>
                  <label className="block text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-2">City</label>
                  <button
                    onClick={() => { setShowCityDD(!showCityDD); setShowNicheDD(false); setShowLangDD(false); }}
                    className="w-full flex items-center justify-between bg-[#F3F3FF] rounded-[12px] px-4 py-3 text-[13.5px] font-semibold text-[#07074E] border border-[#E9EBEF]/60 hover:border-[#7387FF]/30 transition-all"
                  >
                    <span className="flex items-center gap-2">
                      <MapPin strokeWidth={1.5} className="w-3.5 h-3.5 text-[#B7B7E6]" />
                      {city}
                    </span>
                    <ChevronDown strokeWidth={2} className={`w-4 h-4 text-[#B7B7E6] transition-transform ${showCityDD ? "rotate-180" : ""}`} />
                  </button>
                  {showCityDD && (
                    <div className="absolute top-full mt-1 left-0 right-0 bg-white rounded-[14px] shadow-[0_8px_32px_rgba(7,7,78,0.12)] border border-[#E9EBEF]/60 z-30 overflow-hidden max-h-[200px] overflow-y-auto">
                      {CITIES.map((c) => (
                        <button
                          key={c}
                          onClick={() => { setCity(c); setShowCityDD(false); }}
                          className={`w-full text-left px-4 py-2.5 text-[13px] font-medium transition-colors ${c === city ? "bg-[#7387FF]/8 text-[#7387FF] font-semibold" : "text-[#07074E] hover:bg-[#F3F3FF]"}`}
                        >
                          {c}
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                {/* Languages */}
                <div className="relative" onClick={(e) => e.stopPropagation()}>
                  <label className="block text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-2">Languages</label>
                  <button
                    onClick={() => { setShowLangDD(!showLangDD); setShowNicheDD(false); setShowCityDD(false); }}
                    className="w-full flex items-center justify-between bg-[#F3F3FF] rounded-[12px] px-4 py-3 text-[13.5px] font-semibold text-[#07074E] border border-[#E9EBEF]/60 hover:border-[#7387FF]/30 transition-all"
                  >
                    <span className="flex items-center gap-1.5">
                      <Globe2 strokeWidth={1.5} className="w-3.5 h-3.5 text-[#B7B7E6]" />
                      <span className="truncate max-w-[100px]">{languages.join(", ") || "Select…"}</span>
                    </span>
                    <ChevronDown strokeWidth={2} className={`w-4 h-4 text-[#B7B7E6] flex-shrink-0 transition-transform ${showLangDD ? "rotate-180" : ""}`} />
                  </button>
                  {showLangDD && (
                    <div className="absolute top-full mt-1 left-0 right-0 bg-white rounded-[14px] shadow-[0_8px_32px_rgba(7,7,78,0.12)] border border-[#E9EBEF]/60 z-30 overflow-hidden max-h-[200px] overflow-y-auto">
                      {LANGS.map((l) => (
                        <button
                          key={l}
                          onClick={() => toggleLang(l)}
                          className={`w-full text-left px-4 py-2.5 text-[13px] font-medium transition-colors flex items-center justify-between ${languages.includes(l) ? "bg-[#7387FF]/8 text-[#7387FF] font-semibold" : "text-[#07074E] hover:bg-[#F3F3FF]"}`}
                        >
                          {l}
                          {languages.includes(l) && <CheckCircle2 strokeWidth={2} className="w-3.5 h-3.5" />}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Save Button */}
              <div className="flex items-center gap-3 pt-1">
                <button
                  onClick={handleSave}
                  disabled={bioWarning}
                  className={`flex items-center gap-2 px-6 py-2.5 rounded-[12px] text-[13px] font-semibold transition-all ${
                    bioWarning
                      ? "bg-[#F3F3FF] text-[#B7B7E6] cursor-not-allowed"
                      : "bg-[#07074E] text-white hover:bg-[#0D0D6B] shadow-[0_4px_16px_rgba(7,7,78,0.18)] hover:-translate-y-0.5"
                  }`}
                >
                  <Save strokeWidth={1.8} className="w-4 h-4" />
                  Save Changes
                </button>
                {editingBio && !saved && (
                  <span className="text-[12px] font-medium text-[#B7B7E6] flex items-center gap-1.5">
                    <Clock strokeWidth={1.5} className="w-3.5 h-3.5" />
                    Unsaved changes
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* B. Verification Card */}
          <div className="bg-white rounded-[20px] shadow-[0_4px_24px_rgba(7,7,78,0.05)] border border-[#E9EBEF]/50">
            <div className="px-7 pt-6 pb-5 border-b border-[#F3F3FF] flex items-center justify-between">
              <div>
                <h3 className="text-[16px] font-semibold text-[#07074E] font-heading">Trust & Verification</h3>
                <p className="text-[12px] font-medium text-[#9F9FD1] mt-0.5">Builds brand confidence in your profile</p>
              </div>
              <div className="flex items-center gap-1.5 bg-[#22C55E]/10 border border-[#22C55E]/20 px-3 py-1.5 rounded-full">
                <ShieldCheck strokeWidth={2} className="w-3.5 h-3.5 text-[#22C55E]" />
                <span className="text-[11.5px] font-semibold text-[#22C55E]">2 of 4 verified</span>
              </div>
            </div>
            <div className="px-7 py-5 flex flex-col gap-3">
              {VERIFICATIONS.map((v, i) => {
                const statusMap = {
                  verified: { bg: "#22C55E10", border: "#22C55E25", text: "#22C55E", label: "Verified",  icon: CheckCircle2 },
                  pending:  { bg: "#F59E0B10", border: "#F59E0B25", text: "#F59E0B", label: "Pending",   icon: Clock        },
                  locked:   { bg: "#9F9FD110", border: "#9F9FD125", text: "#9F9FD1", label: "Locked",    icon: Lock         },
                };
                const s = statusMap[v.status as keyof typeof statusMap];
                const SIcon = s.icon;
                return (
                  <div
                    key={i}
                    className="flex items-center gap-4 p-4 rounded-[14px] border transition-all hover:shadow-sm"
                    style={{ backgroundColor: s.bg, borderColor: s.border }}
                  >
                    <div className="w-10 h-10 rounded-[11px] bg-white flex items-center justify-center shadow-sm flex-shrink-0">
                      <v.icon strokeWidth={1.5} className="w-5 h-5" style={{ color: s.text }} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-[13.5px] font-semibold text-[#07074E]">{v.label}</p>
                      <p className="text-[12px] font-medium text-[#9F9FD1]">{v.note}</p>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span
                        className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-semibold"
                        style={{ backgroundColor: "white", color: s.text, border: `1px solid ${s.border}` }}
                      >
                        <SIcon strokeWidth={2} className="w-3 h-3" />
                        {s.label}
                      </span>
                      {v.status !== "verified" && (
                        <button className="text-[12px] font-semibold text-[#7387FF] hover:underline whitespace-nowrap">
                          {v.status === "pending" ? "Upload now" : "Unlock"}
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* ── RIGHT COLUMN (40%) ── */}
        <div className="flex flex-col gap-5 flex-shrink-0" style={{ flex: "0 0 38%" }}>

          {/* A. Brand Visibility */}
          <div className="bg-white rounded-[20px] shadow-[0_4px_24px_rgba(7,7,78,0.05)] border border-[#E9EBEF]/50 px-6 py-5">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-[15px] font-semibold text-[#07074E] font-heading">Brand Visibility</h3>
                <p className="text-[11.5px] font-medium text-[#9F9FD1] mt-0.5">How brands discover you</p>
              </div>
              <div className="w-8 h-8 rounded-[9px] bg-[#7387FF]/10 flex items-center justify-center">
                <EyeIcon strokeWidth={1.5} className="w-4 h-4 text-[#7387FF]" />
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              {VISIBILITY_TAGS.map((tag, i) => (
                <span
                  key={i}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11.5px] font-semibold border"
                  style={{ backgroundColor: `${tag.color}10`, color: tag.color, borderColor: `${tag.color}25` }}
                >
                  <tag.icon strokeWidth={1.8} className="w-3 h-3" />
                  {tag.label}
                </span>
              ))}
            </div>
            <div className="mt-4 flex items-start gap-2 bg-[#F3F3FF] rounded-[11px] px-3.5 py-2.5">
              <TrendingUp strokeWidth={1.5} className="w-4 h-4 text-[#7387FF] flex-shrink-0 mt-0.5" />
              <p className="text-[12px] font-medium text-[#9F9FD1]">
                Your profile appeared in <span className="text-[#07074E] font-semibold">48 brand searches</span> this month.
              </p>
            </div>
          </div>

          {/* B. Past Collaborations */}
          <div className="bg-white rounded-[20px] shadow-[0_4px_24px_rgba(7,7,78,0.05)] border border-[#E9EBEF]/50 px-6 py-5">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-[15px] font-semibold text-[#07074E] font-heading">Past Collaborations</h3>
                <p className="text-[11.5px] font-medium text-[#9F9FD1] mt-0.5">Earned through completed campaigns</p>
              </div>
              <Award strokeWidth={1.5} className="w-5 h-5 text-[#F59E0B]" />
            </div>
            <div className="flex flex-wrap gap-2.5 mb-4">
              {PAST_BRANDS.map((b, i) => (
                <div
                  key={i}
                  className="flex items-center gap-2 px-3.5 py-2 rounded-full border"
                  style={{ backgroundColor: `${b.color}08`, borderColor: `${b.color}20` }}
                >
                  <div
                    className="w-5 h-5 rounded-full flex items-center justify-center text-white text-[9px] font-bold flex-shrink-0"
                    style={{ backgroundColor: b.color }}
                  >
                    {b.initial}
                  </div>
                  <span className="text-[12px] font-semibold text-[#07074E]">{b.name}</span>
                </div>
              ))}
            </div>
            <p className="text-[11.5px] font-medium text-[#B7B7E6]">
              Brands are auto-added after deal approval. They cannot be edited.
            </p>
          </div>

          {/* C. Profile Strength */}
          <div className="flex-1 bg-white rounded-[20px] shadow-[0_4px_24px_rgba(7,7,78,0.05)] border border-[#E9EBEF]/50 px-6 py-5">
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="text-[15px] font-semibold text-[#07074E] font-heading">Profile Strength</h3>
                <p className="text-[11.5px] font-medium text-[#9F9FD1] mt-0.5">{doneCount} of {STRENGTH_SUGGESTIONS.length} completed</p>
              </div>
              <CircularProgress pct={strengthPct} />
            </div>

            <div className="flex flex-col gap-2">
              {STRENGTH_SUGGESTIONS.map((s, i) => (
                <div
                  key={i}
                  className={`flex items-center gap-2.5 px-3 py-2 rounded-[10px] transition-colors ${
                    s.done ? "opacity-60" : "bg-[#F3F3FF]/60 hover:bg-[#F3F3FF]"
                  }`}
                >
                  <div className={`w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 ${
                    s.done ? "bg-[#22C55E]/15" : "bg-[#F59E0B]/15"
                  }`}>
                    {s.done
                      ? <CheckCircle2 strokeWidth={2} className="w-3.5 h-3.5 text-[#22C55E]" />
                      : <AlertTriangle strokeWidth={2} className="w-3 h-3 text-[#F59E0B]" />
                    }
                  </div>
                  <p className={`text-[12.5px] font-medium ${s.done ? "line-through text-[#B7B7E6]" : "text-[#07074E]"}`}>
                    {s.text}
                  </p>
                  {!s.done && (
                    <ChevronDown strokeWidth={2} className="w-3.5 h-3.5 text-[#B7B7E6] ml-auto -rotate-90 flex-shrink-0" />
                  )}
                </div>
              ))}
            </div>

            <button className="mt-4 w-full flex items-center justify-center gap-2 bg-gradient-to-r from-[#7387FF] to-[#5A6EED] text-white py-2.5 rounded-[12px] text-[13px] font-semibold shadow-[0_4px_16px_rgba(115,135,255,0.25)] hover:-translate-y-0.5 transition-all">
              <Sparkles strokeWidth={1.8} className="w-4 h-4" />
              Boost Profile Strength
            </button>
          </div>
        </div>
      </div>

      {/* ══════════════════════════════════════
          SECTION 3 — PORTFOLIO SHOWCASE
      ══════════════════════════════════════ */}
      <div className="bg-white rounded-[20px] shadow-[0_4px_24px_rgba(7,7,78,0.05)] border border-[#E9EBEF]/50 overflow-hidden">
        <div className="px-7 pt-6 pb-5 border-b border-[#F3F3FF] flex items-center justify-between">
          <div>
            <h3 className="text-[18px] font-semibold text-[#07074E] font-heading">Portfolio Samples</h3>
            <p className="text-[12.5px] font-medium text-[#9F9FD1] mt-0.5">
              Showcase your best work · {PORTFOLIO_ITEMS.length} / 5 uploaded
            </p>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 text-[12px] font-medium text-[#9F9FD1]">
              <Film strokeWidth={1.5} className="w-4 h-4 text-[#B7B7E6]" />
              UGCad watermarks all samples
            </div>
            <button className="flex items-center gap-2 bg-[#07074E] text-white px-4 py-2.5 rounded-[12px] text-[13px] font-semibold hover:bg-[#0D0D6B] shadow-[0_4px_12px_rgba(7,7,78,0.15)] hover:-translate-y-0.5 transition-all">
              <UploadCloud strokeWidth={1.8} className="w-4 h-4" />
              Add New Sample
            </button>
          </div>
        </div>

        <div className="px-7 py-6 grid grid-cols-5 gap-4">
          {PORTFOLIO_ITEMS.map((item) => (
            <div
              key={item.id}
              className="relative rounded-[16px] overflow-hidden group cursor-pointer shadow-sm hover:shadow-[0_8px_24px_rgba(7,7,78,0.12)] transition-all duration-300 hover:-translate-y-1"
              onMouseEnter={() => setActivePortfolioHover(item.id)}
              onMouseLeave={() => setActivePortfolioHover(null)}
            >
              {/* Thumbnail */}
              <div className="aspect-[9/16] relative overflow-hidden">
                <img
                  src={item.thumbnail}
                  alt={item.title}
                  className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
                />

                {/* Gradient overlay */}
                <div className="absolute inset-0 bg-gradient-to-t from-[#07074E]/80 via-[#07074E]/20 to-transparent" />

                {/* Duration pill */}
                <div className="absolute top-2.5 right-2.5 bg-[#07074E]/70 backdrop-blur-sm text-white text-[10px] font-semibold px-2 py-0.5 rounded-full">
                  {item.duration}
                </div>

                {/* Watermark */}
                <div className="absolute top-2.5 left-2.5 bg-white/90 text-[#7387FF] text-[9px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wider">
                  UGCad
                </div>

                {/* Play button */}
                <div className={`absolute inset-0 flex items-center justify-center transition-opacity duration-200 ${activePortfolioHover === item.id ? "opacity-100" : "opacity-0"}`}>
                  <div className="w-12 h-12 rounded-full bg-white/25 backdrop-blur-sm border border-white/40 flex items-center justify-center shadow-lg">
                    <Play strokeWidth={2} className="w-5 h-5 text-white ml-0.5" />
                  </div>
                </div>

                {/* Bottom info */}
                <div className="absolute bottom-0 left-0 right-0 px-3 py-3">
                  <span
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[9.5px] font-semibold mb-1.5"
                    style={{ backgroundColor: `${item.catColor}25`, color: "white" }}
                  >
                    <Tag strokeWidth={2} className="w-2.5 h-2.5" />
                    {item.category}
                  </span>
                  <p className="text-[11px] font-semibold text-white leading-snug">{item.title}</p>
                  <div className="flex items-center gap-1 mt-1">
                    <EyeIcon strokeWidth={1.5} className="w-3 h-3 text-white/60" />
                    <span className="text-[10px] font-medium text-white/60">{item.views} views</span>
                  </div>
                </div>
              </div>

              {/* Hover Actions */}
              <div className={`absolute inset-0 flex flex-col items-center justify-end pb-4 gap-2 transition-all duration-200 ${activePortfolioHover === item.id ? "opacity-100" : "opacity-0 pointer-events-none"}`}>
                <button className="flex items-center gap-1.5 bg-white text-[#07074E] px-4 py-1.5 rounded-full text-[11px] font-semibold shadow-lg hover:bg-[#F3F3FF] transition-colors w-[80%] justify-center">
                  <Edit3 strokeWidth={2} className="w-3 h-3" />
                  Replace
                </button>
                <button className="flex items-center gap-1.5 bg-[#EF4444]/90 text-white px-4 py-1.5 rounded-full text-[11px] font-semibold shadow-lg hover:bg-[#DC2626] transition-colors w-[80%] justify-center">
                  <Trash2 strokeWidth={2} className="w-3 h-3" />
                  Delete
                </button>
              </div>
            </div>
          ))}

          {/* Upload placeholder */}
          <div className="aspect-[9/16] rounded-[16px] border-2 border-dashed border-[#E9EBEF] flex flex-col items-center justify-center gap-3 hover:border-[#7387FF]/40 hover:bg-[#7387FF]/4 transition-all cursor-pointer group">
            <div className="w-12 h-12 rounded-full bg-[#F3F3FF] group-hover:bg-[#7387FF]/10 flex items-center justify-center transition-colors">
              <UploadCloud strokeWidth={1.5} className="w-5 h-5 text-[#B7B7E6] group-hover:text-[#7387FF] transition-colors" />
            </div>
            <div className="text-center px-3">
              <p className="text-[12px] font-semibold text-[#B7B7E6] group-hover:text-[#7387FF] transition-colors">Add Sample</p>
              <p className="text-[10px] font-medium text-[#B7B7E6] mt-0.5">MP4 · Max 50MB</p>
            </div>
          </div>
        </div>

        {/* Portfolio Footer */}
        <div className="px-7 pb-5 flex items-center justify-between">
          <p className="text-[12px] font-medium text-[#B7B7E6] flex items-center gap-1.5">
            <Lock strokeWidth={1.5} className="w-3.5 h-3.5" />
            All samples are watermarked with your UGCad handle before brands view them.
          </p>
          <button className="flex items-center gap-1.5 text-[#7387FF] text-[12.5px] font-semibold hover:underline">
            View as brand <ExternalLink strokeWidth={2} className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}