import { useState, useRef, useEffect } from "react";
import {
  Star,
  MapPin,
  Check,
  Search,
  Bookmark,
  BookmarkCheck,
  SlidersHorizontal,
  ChevronDown,
  X,
  RotateCcw,
  Zap,
  TrendingUp,
  Users,
  CheckCircle2,
  Clock,
  ArrowUpRight,
  Download,
  BadgeCheck,
  Volume2,
  VolumeX,
  Filter,
} from "lucide-react";

// ─── Creator type ─────────────────────────────────────────────────────────────
interface Creator {
  id: number;
  handle: string;
  city: string;
  level: string;
  qualityTier: string;
  category: string;
  categoryEmoji: string;
  rating: number;
  deals: number;
  responseRate: number;
  pastBrands: string[];
  avatarInitials: string;
  avatarColor: string;
  avatarBg: string;
  verified: boolean;
  available: boolean;
  appliedHoursAgo?: number;
  videoUrl: string;
  videoDuration: string;
  posterGradient: [string, string];   // [from, to]
}

// ─── Video sources (publicly accessible, CORS-friendly) ───────────────────────
const V = {
  blaze:    "https://storage.googleapis.com/gtv-videos-bucket/sample/ForBiggerBlazes.mp4",
  escape:   "https://storage.googleapis.com/gtv-videos-bucket/sample/ForBiggerEscapes.mp4",
  joy:      "https://storage.googleapis.com/gtv-videos-bucket/sample/ForBiggerJoyrides.mp4",
  melt:     "https://storage.googleapis.com/gtv-videos-bucket/sample/ForBiggerMeltdowns.mp4",
  fun:      "https://storage.googleapis.com/gtv-videos-bucket/sample/ForBiggerFun.mp4",
  subie:    "https://storage.googleapis.com/gtv-videos-bucket/sample/SubaruOutbackOnStreetAndDirt.mp4",
  bull:     "https://storage.googleapis.com/gtv-videos-bucket/sample/WeAreGoingOnBullrun.mp4",
  vw:       "https://storage.googleapis.com/gtv-videos-bucket/sample/VolkswagenGTIReview.mp4",
  grand:    "https://storage.googleapis.com/gtv-videos-bucket/sample/WhatCarCanYouGetForAGrand.mp4",
};

// ─── Creator data ─────────────────────────────────────────────────────────────
const CREATORS: Creator[] = [
  {
    id: 1,
    handle: "@glowskin.ugc",
    city: "Mumbai",
    level: "Elite",
    qualityTier: "A++",
    category: "Beauty",
    categoryEmoji: "✨",
    rating: 4.9,
    deals: 48,
    responseRate: 99,
    pastBrands: ["Mamaearth", "Minimalist", "Dot & Key"],
    avatarInitials: "GS",
    avatarColor: "#fff",
    avatarBg: "#7387FF",
    verified: true,
    available: true,
    videoUrl: V.blaze,
    videoDuration: "0:32",
    posterGradient: ["#FFAFC5", "#FF758C"],
  },
  {
    id: 2,
    handle: "@fitpulse.ugc",
    city: "Bengaluru",
    level: "L2 Pro",
    qualityTier: "A+",
    category: "Fitness",
    categoryEmoji: "💪",
    rating: 4.8,
    deals: 32,
    responseRate: 96,
    pastBrands: ["HealthKart", "Muscle Blaze", "Fittr"],
    avatarInitials: "FP",
    avatarColor: "#fff",
    avatarBg: "#F39C12",
    verified: true,
    available: true,
    appliedHoursAgo: 3,
    videoUrl: V.joy,
    videoDuration: "0:47",
    posterGradient: ["#FFD166", "#F39C12"],
  },
  {
    id: 3,
    handle: "@techgeek.ugc",
    city: "Delhi",
    level: "L1 Rising",
    qualityTier: "A",
    category: "Tech",
    categoryEmoji: "⚡",
    rating: 4.7,
    deals: 18,
    responseRate: 94,
    pastBrands: ["boAt", "Noise", "Realme"],
    avatarInitials: "TG",
    avatarColor: "#fff",
    avatarBg: "#27AE60",
    verified: true,
    available: false,
    videoUrl: V.vw,
    videoDuration: "1:02",
    posterGradient: ["#56AB2F", "#1DB954"],
  },
  {
    id: 4,
    handle: "@styleframe.ugc",
    city: "Mumbai",
    level: "Verified",
    qualityTier: "A+",
    category: "Fashion",
    categoryEmoji: "👗",
    rating: 4.6,
    deals: 11,
    responseRate: 91,
    pastBrands: ["Myntra", "Nykaa Fashion", "H&M"],
    avatarInitials: "SF",
    avatarColor: "#fff",
    avatarBg: "#9F9FD1",
    verified: true,
    available: true,
    videoUrl: V.escape,
    videoDuration: "0:29",
    posterGradient: ["#A18CD1", "#7387FF"],
  },
  {
    id: 5,
    handle: "@tastecraft.ugc",
    city: "Hyderabad",
    level: "L2 Pro",
    qualityTier: "A++",
    category: "Food",
    categoryEmoji: "🍽️",
    rating: 4.9,
    deals: 41,
    responseRate: 98,
    pastBrands: ["Swiggy", "Zomato", "Licious"],
    avatarInitials: "TC",
    avatarColor: "#fff",
    avatarBg: "#E74C3C",
    verified: true,
    available: true,
    appliedHoursAgo: 8,
    videoUrl: V.subie,
    videoDuration: "0:55",
    posterGradient: ["#FF6B6B", "#F39C12"],
  },
  {
    id: 6,
    handle: "@wandershot.ugc",
    city: "Pune",
    level: "L1 Rising",
    qualityTier: "A",
    category: "Travel",
    categoryEmoji: "✈️",
    rating: 4.5,
    deals: 9,
    responseRate: 88,
    pastBrands: ["MakeMyTrip", "Airbnb", "Skyscanner"],
    avatarInitials: "WS",
    avatarColor: "#fff",
    avatarBg: "#3498DB",
    verified: false,
    available: true,
    videoUrl: V.bull,
    videoDuration: "0:38",
    posterGradient: ["#48C6EF", "#3498DB"],
  },
  {
    id: 7,
    handle: "@nestlife.ugc",
    city: "Chennai",
    level: "Verified",
    qualityTier: "A+",
    category: "Home Decor",
    categoryEmoji: "🏠",
    rating: 4.7,
    deals: 15,
    responseRate: 93,
    pastBrands: ["IKEA", "Pepperfry", "Urban Ladder"],
    avatarInitials: "NL",
    avatarColor: "#fff",
    avatarBg: "#16A085",
    verified: true,
    available: true,
    videoUrl: V.grand,
    videoDuration: "0:42",
    posterGradient: ["#0F9B8E", "#A8E6CF"],
  },
  {
    id: 8,
    handle: "@zenflow.ugc",
    city: "Delhi",
    level: "L1 Rising",
    qualityTier: "A",
    category: "Wellness",
    categoryEmoji: "🧘",
    rating: 4.8,
    deals: 22,
    responseRate: 97,
    pastBrands: ["Cult.fit", "Yoga Bar", "Kapiva"],
    avatarInitials: "ZF",
    avatarColor: "#fff",
    avatarBg: "#8E44AD",
    verified: true,
    available: false,
    videoUrl: V.melt,
    videoDuration: "1:08",
    posterGradient: ["#DA8FFF", "#8E44AD"],
  },
  {
    id: 9,
    handle: "@pixelpress.ugc",
    city: "Bengaluru",
    level: "New",
    qualityTier: "A",
    category: "Gaming",
    categoryEmoji: "🎮",
    rating: 4.3,
    deals: 5,
    responseRate: 85,
    pastBrands: ["Razer", "Steam"],
    avatarInitials: "PP",
    avatarColor: "#fff",
    avatarBg: "#2C3E50",
    verified: false,
    available: true,
    videoUrl: V.fun,
    videoDuration: "0:50",
    posterGradient: ["#373B44", "#4286F4"],
  },
];

// ─── Static config ─────────────────────────────────────────────────────────────
const LEVELS     = ["New", "Verified", "L1 Rising", "L2 Pro", "Elite"];
const Q_TIERS    = ["A", "A+", "A++"];
const CATEGORIES = ["Beauty", "Tech", "Fitness", "Fashion", "Lifestyle", "Food", "Travel", "Home Decor", "Wellness", "Gaming"];
const CITIES     = ["All Cities", "Mumbai", "Delhi", "Bengaluru", "Hyderabad", "Chennai", "Pune"];
const SORT_OPTS  = ["Best Match", "Highest Rated", "Most Deals", "Newest"];

const LEVEL_STYLE: Record<string, { bg: string; text: string }> = {
  "New":       { bg: "rgba(243,243,255,0.92)", text: "#9F9FD1" },
  "Verified":  { bg: "rgba(238,240,255,0.92)", text: "#7387FF" },
  "L1 Rising": { bg: "rgba(232,248,238,0.92)", text: "#27AE60" },
  "L2 Pro":    { bg: "rgba(255,248,232,0.92)", text: "#F39C12" },
  "Elite":     { bg: "rgba(238,240,255,0.92)", text: "#7387FF" },
};

const QT_STYLE: Record<string, { bg: string; text: string }> = {
  "A":   { bg: "#F3F3FF", text: "#9F9FD1" },
  "A+":  { bg: "#EEF0FF", text: "#7387FF" },
  "A++": { bg: "#FFF8E8", text: "#F39C12" },
};

// ─── Donut chart ──────────────────────────────────────────────────────────────
function DonutChart({ value }: { value: number }) {
  const r = 38, cx = 52, cy = 52;
  const circ   = 2 * Math.PI * r;
  const offset = circ * (1 - value / 100);
  return (
    <svg width="104" height="104" viewBox="0 0 104 104">
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#F3F3FF" strokeWidth="10" />
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#7387FF" strokeWidth="10"
        strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
        transform={`rotate(-90 ${cx} ${cy})`} style={{ transition: "stroke-dashoffset .6s ease" }} />
      <text x={cx} y={cy - 7} textAnchor="middle" fill="#07074E" fontSize="17" fontWeight="700" fontFamily="'Readex Pro',sans-serif">{value}%</text>
      <text x={cx} y={cy + 11} textAnchor="middle" fill="#9F9FD1" fontSize="10" fontWeight="500">Match</text>
    </svg>
  );
}

// ─── Video Creator Card ───────────────────────────────────────────────────────
function VideoCreatorCard({
  creator,
  invited,
  shortlisted,
  onInvite,
  onShortlist,
}: {
  creator: Creator;
  invited: boolean;
  shortlisted: boolean;
  onInvite: () => void;
  onShortlist: () => void;
}) {
  const videoRef    = useRef<HTMLVideoElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [loaded, setLoaded] = useState(false);
  const [muted, setMuted]   = useState(true);
  const [hovered, setHovered] = useState(false);

  // Intersection observer — play when in view, pause when not
  useEffect(() => {
    const el  = videoRef.current;
    const con = containerRef.current;
    if (!el || !con) return;
    const obs = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) { el.play().catch(() => {}); }
        else                      { el.pause(); }
      },
      { threshold: 0.25 }
    );
    obs.observe(con);
    return () => obs.disconnect();
  }, []);

  // Sync muted state to video element
  useEffect(() => {
    if (videoRef.current) videoRef.current.muted = muted;
  }, [muted]);

  const applied    = creator.appliedHoursAgo !== undefined;
  const lvlStyle   = LEVEL_STYLE[creator.level]  ?? LEVEL_STYLE["New"];
  const qtStyle    = QT_STYLE[creator.qualityTier] ?? QT_STYLE["A"];
  const [pgFrom, pgTo] = creator.posterGradient;

  return (
    <div
      ref={containerRef}
      className="relative flex flex-col cursor-pointer"
      style={{ isolation: "isolate" }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >

      {/* ── VIDEO SECTION ────────────────────────────────────────────────── */}
      <div
        className="relative rounded-[22px] overflow-hidden"
        style={{
          height: 280,
          boxShadow: hovered
            ? "0 16px 48px rgba(115,135,255,0.22), 0 4px 16px rgba(7,7,78,0.10)"
            : "0 4px 20px rgba(7,7,78,0.10)",
          transition: "box-shadow 0.35s ease, transform 0.35s ease",
          transform: hovered ? "translateY(-6px)" : "translateY(0)",
        }}
      >
        {/* Gradient poster (always visible below video) */}
        <div
          className="absolute inset-0"
          style={{ background: `linear-gradient(135deg, ${pgFrom}, ${pgTo})` }}
        />

        {/* Video element */}
        <video
          ref={videoRef}
          autoPlay
          muted
          loop
          playsInline
          preload="auto"
          onCanPlay={() => setLoaded(true)}
          className="absolute inset-0 w-full h-full"
          style={{
            objectFit: "cover",
            opacity: loaded ? 1 : 0,
            transition: "opacity 0.6s ease, transform 0.5s ease",
            transform: hovered ? "scale(1.06)" : "scale(1)",
          }}
        >
          <source src={creator.videoUrl} type="video/mp4" />
        </video>

        {/* Gradient overlays */}
        <div className="absolute inset-0 bg-gradient-to-t from-black/70 via-black/5 to-black/30 pointer-events-none" />

        {/* ── Top row: category + level ── */}
        <div className="absolute top-3 left-3 right-3 flex items-start justify-between gap-2 pointer-events-none">
          <div
            className="flex items-center gap-1.5 rounded-full px-2.5 py-1"
            style={{ background: "rgba(0,0,0,0.35)", backdropFilter: "blur(8px)" }}
          >
            <span className="text-[13px]">{creator.categoryEmoji}</span>
            <span className="text-white text-[11px] font-semibold">{creator.category}</span>
          </div>
          <div
            className="rounded-full px-2.5 py-1 text-[11px] font-semibold pointer-events-none"
            style={{ background: lvlStyle.bg, color: lvlStyle.text, backdropFilter: "blur(8px)" }}
          >
            {creator.level}
          </div>
        </div>

        {/* ── Bottom row: duration + preview pulse + mute + shortlist ── */}
        <div className="absolute bottom-3 left-3 right-3 flex items-end justify-between">
          {/* Left cluster */}
          <div className="flex items-center gap-2">
            {/* Duration */}
            <div
              className="rounded-full px-2.5 py-1 flex items-center"
              style={{ background: "rgba(0,0,0,0.45)", backdropFilter: "blur(8px)" }}
            >
              <span className="text-white text-[11px] font-semibold">{creator.videoDuration}</span>
            </div>
            {/* Preview indicator */}
            <div
              className="rounded-full px-2.5 py-1 flex items-center gap-1.5"
              style={{ background: "rgba(115,135,255,0.75)", backdropFilter: "blur(8px)" }}
            >
              <span
                className="w-1.5 h-1.5 rounded-full bg-white"
                style={{ animation: "pulse 1.4s ease-in-out infinite" }}
              />
              <span className="text-white text-[10px] font-semibold tracking-wide">PREVIEW</span>
            </div>
          </div>

          {/* Right cluster: mute + shortlist */}
          <div className="flex items-center gap-2">
            <button
              onClick={(e) => { e.stopPropagation(); setMuted((p) => !p); }}
              className="w-8 h-8 rounded-full flex items-center justify-center transition-all"
              style={{
                background: "rgba(0,0,0,0.4)",
                backdropFilter: "blur(8px)",
                opacity: hovered ? 1 : 0,
                transform: hovered ? "scale(1)" : "scale(0.8)",
                transition: "opacity 0.25s ease, transform 0.25s ease",
              }}
            >
              {muted
                ? <VolumeX className="w-3.5 h-3.5 text-white" strokeWidth={2} />
                : <Volume2 className="w-3.5 h-3.5 text-white" strokeWidth={2} />
              }
            </button>
            <button
              onClick={(e) => { e.stopPropagation(); onShortlist(); }}
              className="w-8 h-8 rounded-full flex items-center justify-center transition-all"
              style={{
                background: shortlisted ? "#7387FF" : "rgba(0,0,0,0.40)",
                backdropFilter: "blur(8px)",
              }}
            >
              {shortlisted
                ? <BookmarkCheck className="w-4 h-4 text-white" strokeWidth={2} />
                : <Bookmark className="w-4 h-4 text-white" strokeWidth={2} />
              }
            </button>
          </div>
        </div>
      </div>

      {/* ── FLOATING INFO BOX ────────────────────────────────────────────── */}
      <div
        className="relative z-10 mx-3"
        style={{
          marginTop: -36,
          transform: hovered ? "translateY(-6px)" : "translateY(0)",
          transition: "transform 0.35s ease",
        }}
      >
        <div
          className="rounded-[18px] p-4 border"
          style={{
            background: "rgba(255,255,255,0.97)",
            backdropFilter: "blur(20px)",
            borderColor: hovered ? "rgba(115,135,255,0.25)" : "rgba(234,234,245,0.8)",
            boxShadow: hovered
              ? "0 8px 32px rgba(115,135,255,0.14), 0 2px 12px rgba(7,7,78,0.08)"
              : "0 4px 20px rgba(7,7,78,0.09), 0 1px 4px rgba(7,7,78,0.05)",
            transition: "box-shadow 0.35s ease, border-color 0.35s ease",
          }}
        >
          {/* Row 1: Avatar + Handle + Verified + Available */}
          <div className="flex items-center gap-3 mb-3">
            <div
              className="w-10 h-10 rounded-full flex items-center justify-center text-[13px] font-bold shrink-0 shadow-sm"
              style={{ background: creator.avatarBg, color: creator.avatarColor }}
            >
              {creator.avatarInitials}
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5 flex-wrap">
                <span
                  className="text-[14px] font-semibold text-[#07074E] truncate"
                  style={{ fontFamily: "ui-monospace, monospace" }}
                >
                  {creator.handle}
                </span>
                {creator.verified && (
                  <BadgeCheck className="w-4 h-4 shrink-0" strokeWidth={2} style={{ color: "#7387FF" }} />
                )}
                {creator.available && (
                  <span
                    className="w-2 h-2 rounded-full shrink-0"
                    style={{ background: "#27AE60", boxShadow: "0 0 0 2px rgba(39,174,96,0.25)" }}
                    title="Available now"
                  />
                )}
                {!creator.available && (
                  <span
                    className="px-2 py-0.5 rounded-full text-[10px] font-semibold"
                    style={{ background: "#F3F3FF", color: "#9F9FD1" }}
                  >
                    Busy
                  </span>
                )}
              </div>
              <div className="flex items-center gap-3 mt-0.5">
                <div className="flex items-center gap-1">
                  <MapPin className="w-3 h-3" style={{ color: "#9F9FD1" }} strokeWidth={2} />
                  <span className="text-[11px] font-medium" style={{ color: "#9F9FD1" }}>{creator.city}</span>
                </div>
                <span className="text-[11px] font-semibold" style={{ color: "#27AE60" }}>
                  {creator.responseRate}% resp.
                </span>
              </div>
            </div>
          </div>

          {/* Row 2: Stats */}
          <div className="flex items-center gap-2 mb-3">
            {/* Rating */}
            <div
              className="flex items-center gap-1 px-2.5 py-1 rounded-full"
              style={{ background: "#FFF8E8" }}
            >
              <Star className="w-3 h-3 fill-current" style={{ color: "#F39C12" }} />
              <span className="text-[12px] font-semibold" style={{ color: "#07074E" }}>{creator.rating}</span>
            </div>
            {/* Deals */}
            <div
              className="flex items-center gap-1 px-2.5 py-1 rounded-full"
              style={{ background: "#F3F3FF" }}
            >
              <span className="text-[12px] font-semibold" style={{ color: "#07074E" }}>{creator.deals}</span>
              <span className="text-[11px] font-medium" style={{ color: "#9F9FD1" }}>deals</span>
            </div>
            {/* Quality tier */}
            <div
              className="px-2.5 py-1 rounded-full text-[11px] font-semibold ml-auto"
              style={{ background: qtStyle.bg, color: qtStyle.text }}
            >
              {creator.qualityTier}
            </div>
          </div>

          {/* Row 3: Past Brands */}
          <div className="flex flex-wrap gap-1.5 mb-3">
            {creator.pastBrands.map((b) => (
              <span
                key={b}
                className="px-2 py-0.5 rounded-md text-[11px] font-medium border"
                style={{ background: "#FAFAFE", color: "#9F9FD1", borderColor: "#EAEAF5" }}
              >
                {b}
              </span>
            ))}
          </div>

          {/* Row 4: Actions */}
          {applied ? (
            <div className="flex flex-col gap-2">
              <div className="flex items-center">
                <div
                  className="flex items-center gap-1.5 rounded-full px-3 py-1.5"
                  style={{ background: "#EEF0FF" }}
                >
                  <span
                    className="w-1.5 h-1.5 rounded-full"
                    style={{ background: "#7387FF", animation: "pulse 1.4s ease-in-out infinite" }}
                  />
                  <span className="text-[11px] font-semibold" style={{ color: "#7387FF" }}>
                    Applied {creator.appliedHoursAgo}h ago
                  </span>
                </div>
              </div>
              <div className="flex gap-2">
                <button
                  className="flex-1 h-9 rounded-[10px] text-[12px] font-semibold flex items-center justify-center gap-1.5 transition-all"
                  style={{
                    background: "#27AE60",
                    color: "#fff",
                    boxShadow: "0 4px 12px rgba(39,174,96,0.28)",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "#219a52")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "#27AE60")}
                >
                  <Check className="w-3.5 h-3.5" strokeWidth={2.5} />
                  Accept
                </button>
                <button
                  className="flex-1 h-9 rounded-[10px] text-[12px] font-semibold flex items-center justify-center gap-1.5 border transition-all"
                  style={{ borderColor: "rgba(231,76,60,0.35)", color: "#E74C3C", background: "transparent" }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = "#FCEAEA"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                >
                  <X className="w-3.5 h-3.5" strokeWidth={2} />
                  Decline
                </button>
              </div>
            </div>
          ) : (
            <div className="flex gap-2">
              <button
                onClick={(e) => { e.stopPropagation(); onInvite(); }}
                className="flex-1 h-9 rounded-[10px] text-[12px] font-semibold flex items-center justify-center gap-1.5 transition-all"
                style={
                  invited
                    ? { background: "#E8F8EE", color: "#27AE60", border: "1px solid rgba(39,174,96,0.3)" }
                    : { background: "#7387FF", color: "#fff", boxShadow: "0 4px 12px rgba(115,135,255,0.32)" }
                }
                onMouseEnter={(e) => {
                  if (!invited) e.currentTarget.style.background = "#5a6de0";
                }}
                onMouseLeave={(e) => {
                  if (!invited) e.currentTarget.style.background = "#7387FF";
                }}
              >
                {invited
                  ? <><CheckCircle2 className="w-3.5 h-3.5" strokeWidth={2} /> Invited</>
                  : <><Zap className="w-3.5 h-3.5" strokeWidth={2} /> Invite</>
                }
              </button>
              <button
                className="h-9 px-3 rounded-[10px] border text-[12px] font-semibold flex items-center gap-1 transition-all"
                style={{ borderColor: "#E2E4F0", color: "#9F9FD1" }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.borderColor = "#7387FF";
                  e.currentTarget.style.color = "#7387FF";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.borderColor = "#E2E4F0";
                  e.currentTarget.style.color = "#9F9FD1";
                }}
              >
                <ArrowUpRight className="w-3.5 h-3.5" />
                Profile
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────
export function BrandBrowseCreators() {
  const [selectedLevels, setSelectedLevels] = useState<string[]>([]);
  const [selectedTiers, setSelectedTiers]   = useState<string[]>([]);
  const [selectedCategory, setSelectedCategory] = useState("");
  const [selectedCity, setSelectedCity]     = useState("");
  const [availableOnly, setAvailableOnly]   = useState(false);
  const [sortBy, setSortBy]                 = useState("Best Match");
  const [searchQuery, setSearchQuery]       = useState("");
  const [invitedIds, setInvitedIds]         = useState<Set<number>>(new Set());
  const [shortlistedIds, setShortlistedIds] = useState<Set<number>>(new Set());

  const toggleLevel = (l: string) =>
    setSelectedLevels((p) => p.includes(l) ? p.filter((x) => x !== l) : [...p, l]);
  const toggleTier = (t: string) =>
    setSelectedTiers((p) => p.includes(t) ? p.filter((x) => x !== t) : [...p, t]);
  const toggleInvite = (id: number) =>
    setInvitedIds((p) => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const toggleShortlist = (id: number) =>
    setShortlistedIds((p) => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });

  const resetFilters = () => {
    setSelectedLevels([]);
    setSelectedTiers([]);
    setSelectedCategory("");
    setSelectedCity("");
    setAvailableOnly(false);
    setSortBy("Best Match");
    setSearchQuery("");
  };

  const filtered = CREATORS.filter((c) => {
    if (selectedLevels.length && !selectedLevels.includes(c.level)) return false;
    if (selectedTiers.length && !selectedTiers.includes(c.qualityTier)) return false;
    if (selectedCategory && c.category !== selectedCategory) return false;
    if (selectedCity && selectedCity !== "All Cities" && !c.city.includes(selectedCity)) return false;
    if (availableOnly && !c.available) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      if (!c.handle.toLowerCase().includes(q) && !c.category.toLowerCase().includes(q) && !c.city.toLowerCase().includes(q)) return false;
    }
    return true;
  });

  const activeFiltersCount =
    selectedLevels.length + selectedTiers.length +
    (selectedCategory ? 1 : 0) + (selectedCity ? 1 : 0) + (availableOnly ? 1 : 0);

  const TOP_NICHES = [
    { label: "Beauty",    count: 320, pct: 100 },
    { label: "Tech",      count: 210, pct: 66  },
    { label: "Fitness",   count: 180, pct: 56  },
    { label: "Lifestyle", count: 145, pct: 45  },
    { label: "Fashion",   count: 120, pct: 38  },
  ];

  const LEVEL_FILTER_COLORS: Record<string, { bg: string; text: string; dot: string }> = {
    "New":       { bg: "#F3F3FF", text: "#9F9FD1", dot: "#9F9FD1" },
    "Verified":  { bg: "#EEF0FF", text: "#7387FF", dot: "#7387FF" },
    "L1 Rising": { bg: "#E8F8EE", text: "#27AE60", dot: "#27AE60" },
    "L2 Pro":    { bg: "#FFF8E8", text: "#F39C12", dot: "#F39C12" },
    "Elite":     { bg: "#EEF0FF", text: "#7387FF", dot: "#7387FF" },
  };

  return (
    <div
      className="flex gap-5 items-start"
      style={{ fontFamily: "'Inter', 'Just Sans', sans-serif" }}
    >
      {/* ══ LEFT FILTER PANEL ════════════════════════════════════════════ */}
      <aside className="w-[228px] shrink-0 sticky top-0 flex flex-col gap-4">
        <div className="bg-white rounded-[18px] shadow-[0_2px_12px_rgba(7,7,78,0.06)] border border-[#EAEAF5] overflow-hidden">

          {/* Header */}
          <div className="flex items-center justify-between px-5 py-4 border-b border-[#F3F3FF]">
            <div className="flex items-center gap-2">
              <SlidersHorizontal className="w-4 h-4" style={{ color: "#7387FF" }} strokeWidth={2} />
              <span className="text-[14px] font-semibold" style={{ color: "#07074E" }}>Filters</span>
              {activeFiltersCount > 0 && (
                <span className="w-5 h-5 rounded-full bg-[#7387FF] text-white text-[10px] font-bold flex items-center justify-center">
                  {activeFiltersCount}
                </span>
              )}
            </div>
            {activeFiltersCount > 0 && (
              <button onClick={resetFilters} className="flex items-center gap-1 text-[11px] font-semibold text-[#9F9FD1] hover:text-[#E74C3C] transition-colors">
                <RotateCcw className="w-3 h-3" /> Reset
              </button>
            )}
          </div>

          <div className="p-5 flex flex-col gap-5">

            {/* Creator Level */}
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider mb-2.5" style={{ color: "#9F9FD1" }}>Creator Level</div>
              <div className="flex flex-col gap-1.5">
                {LEVELS.map((l) => {
                  const active = selectedLevels.includes(l);
                  const st = LEVEL_FILTER_COLORS[l];
                  return (
                    <button
                      key={l}
                      onClick={() => toggleLevel(l)}
                      className="flex items-center gap-2.5 px-3 py-2 rounded-[10px] text-left transition-all text-[12px] font-semibold"
                      style={
                        active
                          ? { background: st.bg, color: st.text, outline: `1px solid ${st.dot}30` }
                          : { color: "#9F9FD1" }
                      }
                      onMouseEnter={(e) => { if (!active) e.currentTarget.style.background = "#F9F9FF"; }}
                      onMouseLeave={(e) => { if (!active) e.currentTarget.style.background = "transparent"; }}
                    >
                      <div className="w-2 h-2 rounded-full shrink-0" style={{ background: active ? st.dot : "#D8D8E8" }} />
                      {l}
                      {active && <Check className="w-3.5 h-3.5 ml-auto" strokeWidth={2.5} />}
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="h-px bg-[#F3F3FF]" />

            {/* Quality Tier */}
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider mb-2.5" style={{ color: "#9F9FD1" }}>Quality Tier</div>
              <div className="flex gap-2">
                {Q_TIERS.map((t) => {
                  const active = selectedTiers.includes(t);
                  return (
                    <button
                      key={t}
                      onClick={() => toggleTier(t)}
                      className="flex-1 h-9 rounded-[10px] border-2 text-[12px] font-semibold transition-all"
                      style={{
                        borderColor: active ? "#7387FF" : "#E8E8F0",
                        background:  active ? "#EEF0FF" : "transparent",
                        color:       active ? "#7387FF" : "#9F9FD1",
                      }}
                    >
                      {t}
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="h-px bg-[#F3F3FF]" />

            {/* Category */}
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider mb-2.5" style={{ color: "#9F9FD1" }}>Category</div>
              <div className="relative">
                <select
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                  className="w-full h-10 pl-3 pr-8 rounded-[10px] border text-[12px] font-semibold focus:outline-none transition-all appearance-none cursor-pointer"
                  style={{ borderColor: "#E2E4F0", background: "#FAFAFE", color: "#07074E" }}
                >
                  <option value="">All Categories</option>
                  {CATEGORIES.map((c) => <option key={c}>{c}</option>)}
                </select>
                <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 pointer-events-none" style={{ color: "#9F9FD1" }} />
              </div>
            </div>

            {/* City */}
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider mb-2.5" style={{ color: "#9F9FD1" }}>City</div>
              <div className="relative">
                <select
                  value={selectedCity}
                  onChange={(e) => setSelectedCity(e.target.value)}
                  className="w-full h-10 pl-3 pr-8 rounded-[10px] border text-[12px] font-semibold focus:outline-none transition-all appearance-none cursor-pointer"
                  style={{ borderColor: "#E2E4F0", background: "#FAFAFE", color: "#07074E" }}
                >
                  {CITIES.map((c) => <option key={c}>{c}</option>)}
                </select>
                <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 pointer-events-none" style={{ color: "#9F9FD1" }} />
              </div>
            </div>

            <div className="h-px bg-[#F3F3FF]" />

            {/* Available toggle */}
            <div className="flex items-center justify-between">
              <div>
                <div className="text-[12px] font-semibold" style={{ color: "#07074E" }}>Available Now</div>
                <div className="text-[11px] font-medium" style={{ color: "#9F9FD1" }}>Exclude busy creators</div>
              </div>
              <button
                onClick={() => setAvailableOnly((p) => !p)}
                className="w-11 h-6 rounded-full relative transition-all duration-300"
                style={{ background: availableOnly ? "#7387FF" : "#E2E4F0" }}
              >
                <div
                  className="absolute top-1 w-4 h-4 rounded-full bg-white shadow-sm transition-all duration-300"
                  style={{ left: availableOnly ? 24 : 4 }}
                />
              </button>
            </div>

            <div className="h-px bg-[#F3F3FF]" />

            {/* Sort */}
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider mb-2.5" style={{ color: "#9F9FD1" }}>Sort By</div>
              <div className="relative">
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value)}
                  className="w-full h-10 pl-3 pr-8 rounded-[10px] border text-[12px] font-semibold focus:outline-none transition-all appearance-none cursor-pointer"
                  style={{ borderColor: "#E2E4F0", background: "#FAFAFE", color: "#07074E" }}
                >
                  {SORT_OPTS.map((s) => <option key={s}>{s}</option>)}
                </select>
                <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 pointer-events-none" style={{ color: "#9F9FD1" }} />
              </div>
            </div>
          </div>

          {/* Apply button */}
          <div className="px-5 pb-5">
            <button
              className="w-full h-10 rounded-[10px] text-white text-[13px] font-semibold flex items-center justify-center gap-2 transition-all"
              style={{ background: "#7387FF", boxShadow: "0 4px 12px rgba(115,135,255,0.30)" }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "#5a6de0")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "#7387FF")}
            >
              <Filter className="w-3.5 h-3.5" />
              Apply Filters
            </button>
          </div>
        </div>
      </aside>

      {/* ══ CENTER: SEARCH + VIDEO GRID ══════════════════════════════════ */}
      <div className="flex-1 min-w-0 flex flex-col gap-5">

        {/* Search bar + count */}
        <div className="flex items-center gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: "#9F9FD1" }} strokeWidth={2} />
            <input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search creators, niches, cities..."
              className="w-full h-11 pl-11 pr-10 rounded-[12px] bg-white border text-[13px] font-medium focus:outline-none transition-all"
              style={{
                borderColor: "#E2E4F0",
                color: "#07074E",
                boxShadow: "0 2px 8px rgba(7,7,78,0.04)",
              }}
              onFocus={(e) => { e.currentTarget.style.borderColor = "#7387FF"; e.currentTarget.style.boxShadow = "0 0 0 3px rgba(115,135,255,0.10)"; }}
              onBlur={(e)  => { e.currentTarget.style.borderColor = "#E2E4F0"; e.currentTarget.style.boxShadow = "0 2px 8px rgba(7,7,78,0.04)"; }}
            />
            {searchQuery && (
              <button onClick={() => setSearchQuery("")} className="absolute right-3 top-1/2 -translate-y-1/2 w-5 h-5 rounded-full bg-[#E2E4F0] flex items-center justify-center hover:bg-[#9F9FD1] transition-colors">
                <X className="w-3 h-3 text-[#07074E]" />
              </button>
            )}
          </div>
          <div className="flex items-center gap-2 bg-white rounded-[10px] px-4 h-11 border border-[#EAEAF5] shadow-[0_2px_8px_rgba(7,7,78,0.04)] shrink-0">
            <Users className="w-4 h-4" style={{ color: "#7387FF" }} strokeWidth={2} />
            <span className="text-[13px] font-semibold" style={{ color: "#07074E" }}>{filtered.length}</span>
            <span className="text-[12px] font-medium" style={{ color: "#9F9FD1" }}>creators</span>
          </div>
          {shortlistedIds.size > 0 && (
            <div className="flex items-center gap-2 rounded-[10px] px-4 h-11 border shrink-0" style={{ background: "#EEF0FF", borderColor: "rgba(115,135,255,0.2)" }}>
              <BookmarkCheck className="w-4 h-4" style={{ color: "#7387FF" }} strokeWidth={2} />
              <span className="text-[13px] font-semibold" style={{ color: "#7387FF" }}>{shortlistedIds.size} saved</span>
            </div>
          )}
        </div>

        {/* Active filter chips */}
        {activeFiltersCount > 0 && (
          <div className="flex flex-wrap gap-2">
            {selectedLevels.map((l) => (
              <button key={l} onClick={() => toggleLevel(l)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-semibold border transition-colors" style={{ background: "#EEF0FF", color: "#7387FF", borderColor: "rgba(115,135,255,0.2)" }}>
                {l} <X className="w-3 h-3" />
              </button>
            ))}
            {selectedTiers.map((t) => (
              <button key={t} onClick={() => toggleTier(t)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-semibold border transition-colors" style={{ background: "#EEF0FF", color: "#7387FF", borderColor: "rgba(115,135,255,0.2)" }}>
                {t} <X className="w-3 h-3" />
              </button>
            ))}
            {selectedCategory && (
              <button onClick={() => setSelectedCategory("")} className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-semibold border transition-colors" style={{ background: "#EEF0FF", color: "#7387FF", borderColor: "rgba(115,135,255,0.2)" }}>
                {selectedCategory} <X className="w-3 h-3" />
              </button>
            )}
            {availableOnly && (
              <button onClick={() => setAvailableOnly(false)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-semibold border transition-colors" style={{ background: "#E8F8EE", color: "#27AE60", borderColor: "rgba(39,174,96,0.2)" }}>
                Available Only <X className="w-3 h-3" />
              </button>
            )}
          </div>
        )}

        {/* Video Grid or Empty State */}
        {filtered.length === 0 ? (
          <div className="bg-white rounded-[18px] border border-[#EAEAF5] shadow-[0_2px_12px_rgba(7,7,78,0.06)] flex flex-col items-center justify-center py-20 gap-5">
            <div className="w-20 h-20 rounded-full bg-[#F3F3FF] flex items-center justify-center">
              <Users className="w-9 h-9" style={{ color: "#C0C0D8" }} strokeWidth={1.5} />
            </div>
            <div className="text-center">
              <div className="text-[18px] font-semibold mb-2" style={{ color: "#07074E", fontFamily: "'Readex Pro', sans-serif" }}>
                No creators match your filters
              </div>
              <div className="text-[14px] font-medium max-w-xs mx-auto leading-relaxed" style={{ color: "#9F9FD1" }}>
                Try widening your filters or reducing the creator level requirement.
              </div>
            </div>
            <button
              onClick={resetFilters}
              className="flex items-center gap-2 px-5 py-2.5 text-white rounded-[10px] text-[13px] font-semibold transition-all"
              style={{ background: "#7387FF", boxShadow: "0 4px 12px rgba(115,135,255,0.3)" }}
            >
              <RotateCcw className="w-4 h-4" /> Reset All Filters
            </button>
          </div>
        ) : (
          <div
            className="grid gap-5"
            style={{ gridTemplateColumns: "repeat(3, 1fr)", paddingBottom: 32 }}
          >
            {filtered.map((creator) => (
              <VideoCreatorCard
                key={creator.id}
                creator={creator}
                invited={invitedIds.has(creator.id)}
                shortlisted={shortlistedIds.has(creator.id)}
                onInvite={() => toggleInvite(creator.id)}
                onShortlist={() => toggleShortlist(creator.id)}
              />
            ))}
          </div>
        )}
      </div>

      {/* ══ RIGHT INSIGHTS PANEL ═════════════════════════════════════════ */}
      <aside className="w-[240px] shrink-0 sticky top-0 flex flex-col gap-4">

        {/* Match Summary */}
        <div className="bg-white rounded-[18px] shadow-[0_2px_12px_rgba(7,7,78,0.06)] border border-[#EAEAF5] p-5">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="w-4 h-4" style={{ color: "#7387FF" }} strokeWidth={2} />
            <span className="text-[12px] font-semibold uppercase tracking-wide" style={{ color: "#07074E" }}>Match Summary</span>
          </div>
          <div className="flex items-center gap-3">
            <DonutChart value={86} />
            <div>
              <div className="text-[26px] font-semibold leading-none mb-1" style={{ color: "#07074E", fontFamily: "'Readex Pro', sans-serif" }}>1,248</div>
              <div className="text-[11px] font-medium" style={{ color: "#9F9FD1" }}>creators found</div>
              <div className="mt-3 flex flex-col gap-1.5">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-[#7387FF]" />
                  <span className="text-[11px] font-medium" style={{ color: "#9F9FD1" }}>86% avg match</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-[#27AE60]" />
                  <span className="text-[11px] font-medium" style={{ color: "#9F9FD1" }}>{filtered.length} showing</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Top Niches */}
        <div className="bg-white rounded-[18px] shadow-[0_2px_12px_rgba(7,7,78,0.06)] border border-[#EAEAF5] p-5">
          <div className="flex items-center gap-2 mb-4">
            <Zap className="w-4 h-4" style={{ color: "#F39C12" }} strokeWidth={2} />
            <span className="text-[12px] font-semibold uppercase tracking-wide" style={{ color: "#07074E" }}>Top Niches</span>
          </div>
          <div className="flex flex-col gap-3">
            {TOP_NICHES.map((n) => (
              <div key={n.label}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[12px] font-semibold" style={{ color: "#07074E" }}>{n.label}</span>
                  <span className="text-[11px] font-medium" style={{ color: "#9F9FD1" }}>{n.count}</span>
                </div>
                <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "#F3F3FF" }}>
                  <div
                    className="h-full rounded-full"
                    style={{ width: `${n.pct}%`, background: "linear-gradient(90deg, #7387FF, #9F9FD1)" }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Quick Actions */}
        <div className="bg-white rounded-[18px] shadow-[0_2px_12px_rgba(7,7,78,0.06)] border border-[#EAEAF5] p-5">
          <div className="flex items-center gap-2 mb-4">
            <Zap className="w-4 h-4" style={{ color: "#7387FF" }} strokeWidth={2} />
            <span className="text-[12px] font-semibold uppercase tracking-wide" style={{ color: "#07074E" }}>Quick Actions</span>
          </div>
          <div className="flex flex-col gap-2">
            {[
              { icon: <BookmarkCheck className="w-4 h-4" style={{ color: "#7387FF" }} />, label: "View Shortlisted", sub: `${shortlistedIds.size} saved`, iconBg: "rgba(115,135,255,0.1)" },
              { icon: <Zap className="w-4 h-4" style={{ color: "#27AE60" }} />,         label: "Invite Top Matches", sub: "Send to top 5",   iconBg: "rgba(39,174,96,0.1)"  },
              { icon: <Download className="w-4 h-4" style={{ color: "#9F9FD1" }} />,    label: "Export List",        sub: "CSV with matches", iconBg: "rgba(159,159,209,0.15)" },
            ].map((a) => (
              <button
                key={a.label}
                className="w-full flex items-center gap-3 p-3 rounded-[10px] text-left transition-colors"
                style={{ background: "#F3F3FF" }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "#EEF0FF")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "#F3F3FF")}
              >
                <div className="w-8 h-8 rounded-[8px] flex items-center justify-center shrink-0" style={{ background: a.iconBg }}>
                  {a.icon}
                </div>
                <div>
                  <div className="text-[12px] font-semibold" style={{ color: "#07074E" }}>{a.label}</div>
                  <div className="text-[11px] font-medium" style={{ color: "#9F9FD1" }}>{a.sub}</div>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Campaign Notice */}
        <div className="rounded-[18px] p-5" style={{ background: "#07074E" }}>
          <div className="flex items-center gap-2 mb-3">
            <span className="w-2 h-2 rounded-full bg-[#27AE60]" style={{ animation: "pulse 1.4s ease-in-out infinite" }} />
            <span className="text-[11px] font-semibold uppercase tracking-wide" style={{ color: "#9F9FD1" }}>Campaign Status</span>
          </div>
          <div className="text-[14px] font-semibold text-white mb-1">Live Matching</div>
          <div className="text-[12px] font-medium leading-relaxed mb-4" style={{ color: "#9F9FD1" }}>
            Your brief is live. Creators are actively applying.
          </div>
          <div className="flex flex-col gap-2.5">
            {[
              { icon: <Clock className="w-3.5 h-3.5" style={{ color: "#F39C12" }} />, label: "Window closes", val: "12 hrs", valColor: "#F39C12" },
              { icon: <Users className="w-3.5 h-3.5" style={{ color: "#7387FF" }} />, label: "Applications",  val: "7 received", valColor: "#fff" },
              { icon: <CheckCircle2 className="w-3.5 h-3.5" style={{ color: "#27AE60" }} />, label: "Brief status", val: "Approved", valColor: "#27AE60" },
            ].map((row) => (
              <div key={row.label} className="flex items-center justify-between">
                <div className="flex items-center gap-1.5">
                  {row.icon}
                  <span className="text-[11px] font-medium" style={{ color: "#9F9FD1" }}>{row.label}</span>
                </div>
                <span className="text-[12px] font-semibold" style={{ color: row.valColor }}>{row.val}</span>
              </div>
            ))}
          </div>
          <div className="mt-4 pt-4 border-t border-white/10">
            <div className="text-[11px] font-medium mb-2" style={{ color: "#9F9FD1" }}>Application window</div>
            <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.1)" }}>
              <div className="h-full w-[75%] rounded-full" style={{ background: "linear-gradient(90deg, #7387FF, #27AE60)" }} />
            </div>
            <div className="flex justify-between mt-1">
              <span className="text-[10px]" style={{ color: "#9F9FD1" }}>75% filled</span>
              <span className="text-[10px]" style={{ color: "#9F9FD1" }}>36h total</span>
            </div>
          </div>
        </div>

      </aside>
    </div>
  );
}
