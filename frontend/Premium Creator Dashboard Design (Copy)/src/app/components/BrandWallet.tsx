import { useState } from "react";
import {
  Wallet,
  TrendingUp,
  AlertCircle,
  CheckCircle2,
  ArrowUpRight,
  ArrowDownLeft,
  RefreshCw,
  CreditCard,
  Plus,
  ChevronRight,
  Star,
  Zap,
  Info,
  Lock,
  ExternalLink,
  Gift,
  Sparkles,
  RotateCcw,
  Shield,
  Clock,
} from "lucide-react";

// ─── Mock Data ────────────────────────────────────────────────────────────────

const TRANSACTIONS = [
  {
    id: "TXN-001",
    date: "20 May 2025",
    type: "Wallet Recharge",
    typeKey: "recharge",
    amount: "+₹25,000",
    raw: 25000,
    status: "Success",
    statusKey: "success",
    icon: ArrowUpRight,
    ref: "REF#8821A",
  },
  {
    id: "TXN-002",
    date: "20 May 2025",
    type: "Recharge Bonus Credited",
    typeKey: "bonus",
    amount: "+₹1,750",
    raw: 1750,
    status: "Credited",
    statusKey: "credited",
    icon: Gift,
    ref: "+7% Bonus",
  },
  {
    id: "TXN-003",
    date: "18 May 2025",
    type: "Escrow Lock • Deal Accepted",
    typeKey: "escrow",
    amount: "−₹15,000",
    raw: -15000,
    status: "Processing",
    statusKey: "processing",
    icon: Lock,
    ref: "Deal #D-4412",
  },
  {
    id: "TXN-004",
    date: "15 May 2025",
    type: "Listing Fee Charged",
    typeKey: "fee",
    amount: "−₹500",
    raw: -500,
    status: "Paid",
    statusKey: "paid",
    icon: ArrowDownLeft,
    ref: "Brief #B-1093",
  },
  {
    id: "TXN-005",
    date: "14 May 2025",
    type: "Listing Fee Refunded",
    typeKey: "refund",
    amount: "+₹500",
    raw: 500,
    status: "Returned",
    statusKey: "returned",
    icon: RotateCcw,
    ref: "Creator Hired",
  },
  {
    id: "TXN-006",
    date: "13 May 2025",
    type: "Wallet Recharge",
    typeKey: "recharge",
    amount: "+₹10,000",
    raw: 10000,
    status: "Success",
    statusKey: "success",
    icon: ArrowUpRight,
    ref: "REF#7743B",
  },
  {
    id: "TXN-007",
    date: "12 May 2025",
    type: "Escrow Release • Deal Refunded",
    typeKey: "escrow_release",
    amount: "+₹8,000",
    raw: 8000,
    status: "Returned",
    statusKey: "returned",
    icon: RefreshCw,
    ref: "Deal #D-3891",
  },
];

const BONUS_TIERS = [
  { amount: "₹10,000", bonus: "+5%", value: "₹500", active: false },
  { amount: "₹25,000", bonus: "+7%", value: "₹1,750", active: true },
  { amount: "₹50,000", bonus: "+10%", value: "₹5,000", active: false, best: true },
  { amount: "₹1,00,000", bonus: "+12.5%", value: "₹12,500", active: false },
];

const SPEND_DATA = [
  { month: "Jan", escrow: 42000, recharges: 50000, bonuses: 2500 },
  { month: "Feb", escrow: 58000, recharges: 75000, bonuses: 5250 },
  { month: "Mar", escrow: 35000, recharges: 40000, bonuses: 2000 },
  { month: "Apr", escrow: 71000, recharges: 85000, bonuses: 5950 },
  { month: "May", escrow: 15000, recharges: 35000, bonuses: 1750 },
];

const PAYMENT_METHODS = [
  { id: 1, type: "visa", label: "Visa ending 2456", icon: "💳", active: true },
  { id: 2, type: "upi", label: "brand@upi", icon: "⚡", active: false },
];

// ─── Status badge helper ───��──────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { bg: string; text: string; dot: string }> = {
    Success:    { bg: "#E8F8EE", text: "#27AE60", dot: "#27AE60" },
    Credited:   { bg: "#EEF0FF", text: "#7387FF", dot: "#7387FF" },
    Processing: { bg: "#FFF8E8", text: "#F39C12", dot: "#F39C12" },
    Paid:       { bg: "#EEEEFF", text: "#07074E", dot: "#9F9FD1" },
    Returned:   { bg: "#F0FFF4", text: "#27AE60", dot: "#27AE60" },
  };
  const s = map[status] ?? { bg: "#F0F0F0", text: "#888", dot: "#888" };
  return (
    <span
      className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-semibold tracking-wide"
      style={{ background: s.bg, color: s.text }}
    >
      <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: s.dot }} />
      {status}
    </span>
  );
}

// ─── Custom Recharts Tooltip ──────────────────────────────────────────────────

function SpendTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-white rounded-2xl shadow-[0_8px_32px_rgba(7,7,78,0.12)] border border-[#E9EBEF]/60 p-4 min-w-[160px]">
      <p className="text-[12px] font-semibold text-[#9F9FD1] mb-2">{label}</p>
      {payload.map((p: any) => (
        <div key={p.name} className="flex items-center justify-between gap-4 mb-1">
          <span className="flex items-center gap-1.5 text-[12px] text-[#07074E] font-medium">
            <span className="w-2 h-2 rounded-full" style={{ background: p.color }} />
            {p.name}
          </span>
          <span className="text-[12px] font-semibold text-[#07074E]">
            ₹{(p.value / 1000).toFixed(0)}K
          </span>
        </div>
      ))}
    </div>
  );
}

// ─── SVG Donut Ring (replaces Recharts PieChart to avoid duplicate-key bug) ───
function DonutRing({ pct, color, track, size = 88, stroke = 12 }: {
  pct: number; color: string; track: string; size?: number; stroke?: number;
}) {
  const r = (size - stroke) / 2;
  const cx = size / 2;
  const circ = 2 * Math.PI * r;
  const filled = circ * (pct / 100);
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle cx={cx} cy={cx} r={r} fill="none" stroke={track} strokeWidth={stroke} />
      <circle
        cx={cx} cy={cx} r={r}
        fill="none"
        stroke={color}
        strokeWidth={stroke}
        strokeDasharray={`${filled} ${circ}`}
        strokeLinecap="round"
        transform={`rotate(-90 ${cx} ${cx})`}
      />
    </svg>
  );
}

// ─── Pure SVG Area Chart (replaces Recharts AreaChart to avoid duplicate-key bug) ───
function MiniAreaChart({ data }: { data: typeof SPEND_DATA }) {
  const W = 272;
  const H = 140;
  const PAD = { top: 8, right: 8, bottom: 24, left: 30 };
  const iW = W - PAD.left - PAD.right;
  const iH = H - PAD.top - PAD.bottom;
  const maxVal = Math.max(...data.flatMap((d) => [d.escrow, d.recharges]));

  const xS = (i: number) => PAD.left + (i / (data.length - 1)) * iW;
  const yS = (v: number) => PAD.top + iH - (v / maxVal) * iH;

  const linePath = (key: "escrow" | "recharges") =>
    data.map((d, i) => `${i === 0 ? "M" : "L"}${xS(i).toFixed(1)},${yS(d[key]).toFixed(1)}`).join(" ");

  const areaPath = (key: "escrow" | "recharges") => {
    const pts = data.map((d, i) => `${xS(i).toFixed(1)},${yS(d[key]).toFixed(1)}`).join(" L ");
    const bot = (PAD.top + iH).toFixed(1);
    return `M${PAD.left},${bot} L${pts} L${xS(data.length - 1).toFixed(1)},${bot}Z`;
  };

  const yTicks = [0, Math.round(maxVal / 2 / 10000) * 10000, maxVal];

  return (
    <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
      <defs>
        <linearGradient id="wlt-escrow" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#7387FF" stopOpacity={0.28} />
          <stop offset="100%" stopColor="#7387FF" stopOpacity={0} />
        </linearGradient>
        <linearGradient id="wlt-recharge" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#07074E" stopOpacity={0.15} />
          <stop offset="100%" stopColor="#07074E" stopOpacity={0} />
        </linearGradient>
      </defs>

      {/* Grid */}
      {[0, 0.5, 1].map((t) => (
        <line
          key={`grid-${t}`}
          x1={PAD.left} x2={PAD.left + iW}
          y1={PAD.top + iH * (1 - t)} y2={PAD.top + iH * (1 - t)}
          stroke="#F3F3FF" strokeWidth={1}
        />
      ))}

      {/* Areas */}
      <path d={areaPath("recharges")} fill="url(#wlt-recharge)" />
      <path d={areaPath("escrow")} fill="url(#wlt-escrow)" />

      {/* Lines */}
      <path d={linePath("recharges")} fill="none" stroke="#07074E" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" />
      <path d={linePath("escrow")} fill="none" stroke="#7387FF" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" />

      {/* X labels */}
      {data.map((d, i) => (
        <text key={`x-${d.month}`} x={xS(i)} y={H - 5} textAnchor="middle" fill="#C4C4E8" fontSize={10} fontFamily="'Inter',sans-serif">
          {d.month}
        </text>
      ))}

      {/* Y labels */}
      {yTicks.map((v) => (
        <text key={`y-${v}`} x={PAD.left - 4} y={yS(v) + 3} textAnchor="end" fill="#C4C4E8" fontSize={9} fontFamily="'Inter',sans-serif">
          {v === 0 ? "0" : `${v / 1000}K`}
        </text>
      ))}
    </svg>
  );
}

// ─── Component ────────────────────────────────────────────────────────────────

export function BrandWallet() {
  const [customAmount, setCustomAmount] = useState("");
  const [selectedMethod, setSelectedMethod] = useState(1);
  const [activeTab, setActiveTab] = useState<"all" | "in" | "out">("all");

  const filteredTxns = TRANSACTIONS.filter((t) => {
    if (activeTab === "in")  return t.raw > 0;
    if (activeTab === "out") return t.raw < 0;
    return true;
  });

  const presets = ["₹10K", "₹25K", "₹50K"];

  return (
    <div className="flex gap-6 min-h-0 w-full" style={{ fontFamily: "'Inter', sans-serif" }}>

      {/* ── CENTER AREA ─────────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col gap-5 min-w-0">

        {/* ── HERO BALANCE CARD ── */}
        <div
          className="relative rounded-[24px] overflow-hidden p-8 flex flex-col gap-6"
          style={{
            background: "linear-gradient(135deg, #07074E 0%, #0F0F6E 40%, #1A1A8A 70%, #2A2AA0 100%)",
            boxShadow: "0 20px 60px rgba(7,7,78,0.30), 0 4px 16px rgba(115,135,255,0.15)",
          }}
        >
          {/* Decorative orbs */}
          <div
            className="absolute top-[-60px] right-[-60px] w-[240px] h-[240px] rounded-full opacity-20 pointer-events-none"
            style={{ background: "radial-gradient(circle, #7387FF 0%, transparent 70%)" }}
          />
          <div
            className="absolute bottom-[-40px] left-[30%] w-[180px] h-[180px] rounded-full opacity-10 pointer-events-none"
            style={{ background: "radial-gradient(circle, #9F9FD1 0%, transparent 70%)" }}
          />

          {/* Top row */}
          <div className="relative flex items-start justify-between">
            <div>
              <div className="flex items-center gap-2 mb-3">
                <div className="w-8 h-8 rounded-xl bg-[#7387FF]/20 flex items-center justify-center">
                  <Wallet className="w-4 h-4 text-[#7387FF]" />
                </div>
                <span className="text-[13px] font-semibold text-white/60 tracking-wide uppercase" style={{ fontFamily: "'Inter', sans-serif" }}>
                  Brand Wallet • UGCad
                </span>
              </div>

              <div className="text-[13px] font-medium text-white/50 mb-1" style={{ fontFamily: "'Inter', sans-serif" }}>
                Available Balance
              </div>
              <div
                className="text-[52px] font-semibold text-white tracking-tight leading-none"
                style={{ fontFamily: "'Readex Pro', sans-serif" }}
              >
                ₹4,25,600
              </div>
              <div className="mt-2 text-[13px] text-white/40 font-medium" style={{ fontFamily: "'Inter', sans-serif" }}>
                Updated just now
              </div>
            </div>

            <div className="flex flex-col items-end gap-2">
              <div
                className="flex items-center gap-2 px-4 py-2 rounded-full border"
                style={{ background: "rgba(115,135,255,0.15)", borderColor: "rgba(115,135,255,0.3)" }}
              >
                <Sparkles className="w-3.5 h-3.5 text-[#7387FF]" />
                <span className="text-[12px] font-semibold text-[#7387FF]">+10% Recharge Bonus Live</span>
              </div>
              <div
                className="flex items-center gap-2 px-4 py-2 rounded-full border"
                style={{ background: "rgba(39,174,96,0.12)", borderColor: "rgba(39,174,96,0.25)" }}
              >
                <CheckCircle2 className="w-3.5 h-3.5 text-[#27AE60]" />
                <span className="text-[12px] font-semibold text-[#27AE60]">Brand Pro Plan Active</span>
              </div>
            </div>
          </div>

          {/* Stats row */}
          <div className="relative grid grid-cols-3 gap-4">
            {[
              { label: "In Escrow", value: "₹1,25,000", sub: "8 active deals", color: "#F39C12" },
              { label: "Bonus Earned", value: "₹3,750", sub: "This month", color: "#7387FF" },
              { label: "Total Spent", value: "₹2,18,000", sub: "All time", color: "#27AE60" },
            ].map((stat) => (
              <div
                key={stat.label}
                className="rounded-[16px] p-4"
                style={{ background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.08)" }}
              >
                <div className="text-[12px] font-medium text-white/50 mb-1" style={{ fontFamily: "'Inter', sans-serif" }}>
                  {stat.label}
                </div>
                <div
                  className="text-[20px] font-semibold text-white"
                  style={{ fontFamily: "'Readex Pro', sans-serif" }}
                >
                  {stat.value}
                </div>
                <div className="text-[11px] text-white/35 mt-0.5" style={{ fontFamily: "'Inter', sans-serif" }}>
                  {stat.sub}
                </div>
              </div>
            ))}
          </div>

          {/* Action row */}
          <div className="relative flex items-center gap-3">
            <button
              className="flex items-center gap-2 px-6 py-3 rounded-[12px] text-[13px] font-semibold text-[#07074E] transition-all hover:brightness-105 active:scale-[0.98]"
              style={{ background: "#FFFFFF", fontFamily: "'Inter', sans-serif", boxShadow: "0 4px 16px rgba(255,255,255,0.15)" }}
            >
              <Plus className="w-4 h-4" />
              Recharge ₹10K
            </button>
            <button
              className="flex items-center gap-2 px-6 py-3 rounded-[12px] text-[13px] font-semibold text-white transition-all hover:brightness-110 active:scale-[0.98]"
              style={{ background: "#7387FF", fontFamily: "'Inter', sans-serif", boxShadow: "0 4px 16px rgba(115,135,255,0.35)" }}
            >
              <Zap className="w-4 h-4" />
              Recharge ₹25K
            </button>
            <button
              className="flex items-center gap-1.5 px-5 py-3 rounded-[12px] text-[13px] font-semibold transition-all hover:bg-white/10"
              style={{ color: "rgba(255,255,255,0.55)", fontFamily: "'Inter', sans-serif", border: "1px solid rgba(255,255,255,0.12)" }}
            >
              View All Plans
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Footer note */}
          <div className="relative flex items-center gap-2 pt-1 border-t border-white/8">
            <Shield className="w-3.5 h-3.5 text-white/30 flex-shrink-0" />
            <p className="text-[11px] text-white/30" style={{ fontFamily: "'Inter', sans-serif" }}>
              Wallet credits are non-refundable and carry forward indefinitely. Escrow funds are held until deal completion.
            </p>
          </div>
        </div>

        {/* ── MINIMUM NOTICE ── */}
        <div
          className="flex items-center gap-3 px-5 py-3.5 rounded-[14px] border"
          style={{ background: "#FFFBF0", borderColor: "#F39C12", borderWidth: "1px" }}
        >
          <div className="w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0" style={{ background: "#FFF4D9" }}>
            <AlertCircle className="w-4 h-4" style={{ color: "#F39C12" }} />
          </div>
          <div className="flex-1">
            <p className="text-[13px] font-semibold" style={{ color: "#B7770A", fontFamily: "'Inter', sans-serif" }}>
              ₹5,000 minimum recharge required to unlock platform chat.
            </p>
            <p className="text-[11.5px] font-medium mt-0.5" style={{ color: "#C8890E", fontFamily: "'Inter', sans-serif" }}>
              Wallet credits are non-refundable. Add funds to activate messaging with creators.
            </p>
          </div>
          <button className="text-[12px] font-semibold px-4 py-2 rounded-[10px] transition-all hover:brightness-105 flex-shrink-0"
            style={{ background: "#F39C12", color: "#FFFFFF", fontFamily: "'Inter', sans-serif" }}>
            Add Funds
          </button>
        </div>

        {/* ── RECHARGE BONUS TIERS ── */}
        <div
          className="bg-white rounded-[20px] overflow-hidden"
          style={{ boxShadow: "0 2px 16px rgba(7,7,78,0.06)", border: "1px solid rgba(7,7,78,0.05)" }}
        >
          <div className="px-7 py-5 flex items-center justify-between border-b border-[#F3F3FF]">
            <div>
              <h3 className="text-[16px] font-semibold text-[#07074E]" style={{ fontFamily: "'Readex Pro', sans-serif" }}>
                Recharge Bonus Tiers
              </h3>
              <p className="text-[12.5px] text-[#9F9FD1] mt-0.5" style={{ fontFamily: "'Inter', sans-serif" }}>
                Get more with bigger recharges. Bonus credited instantly.
              </p>
            </div>
            <div
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-semibold"
              style={{ background: "#EEF0FF", color: "#7387FF" }}
            >
              <TrendingUp className="w-3 h-3" />
              Active: +7%
            </div>
          </div>

          <div className="px-7 py-2">
            {/* Table header */}
            <div className="grid grid-cols-4 py-3 border-b border-[#F3F3FF]">
              {["Recharge Amount", "Bonus %", "Bonus Value", "Status"].map((h) => (
                <span key={h} className="text-[11px] font-semibold uppercase tracking-wider text-[#9F9FD1]"
                  style={{ fontFamily: "'Inter', sans-serif" }}>
                  {h}
                </span>
              ))}
            </div>

            {BONUS_TIERS.map((tier, i) => (
              <div
                key={i}
                className="grid grid-cols-4 items-center py-4 border-b border-[#F3F3FF]/70 last:border-0 rounded-[12px] transition-all hover:bg-[#F8F9FF]"
                style={tier.active ? { background: "#F3F4FF" } : {}}
              >
                <span className="text-[14px] font-semibold text-[#07074E]" style={{ fontFamily: "'Inter', sans-serif" }}>
                  {tier.amount}
                </span>
                <span className="text-[14px] font-semibold" style={{ color: tier.best ? "#27AE60" : "#7387FF", fontFamily: "'Inter', sans-serif" }}>
                  {tier.bonus}
                </span>
                <span className="text-[14px] font-semibold text-[#07074E]" style={{ fontFamily: "'Inter', sans-serif" }}>
                  {tier.value}
                </span>
                <div className="flex items-center gap-2">
                  {tier.active ? (
                    <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-semibold"
                      style={{ background: "#EEF0FF", color: "#7387FF" }}>
                      <span className="w-1.5 h-1.5 rounded-full bg-[#7387FF]" />
                      Current Tier
                    </span>
                  ) : tier.best ? (
                    <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-semibold"
                      style={{ background: "#E8F8EE", color: "#27AE60" }}>
                      <Star className="w-3 h-3" />
                      Best Value
                    </span>
                  ) : (
                    <span className="text-[12px] font-medium text-[#C4C4E8]" style={{ fontFamily: "'Inter', sans-serif" }}>
                      —
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ── TRANSACTION HISTORY ── */}
        <div
          className="bg-white rounded-[20px] overflow-hidden flex flex-col"
          style={{ 
            height: "640px",
            boxShadow: "0 2px 16px rgba(7,7,78,0.06)", 
            border: "1px solid rgba(7,7,78,0.05)" 
          }}
        >
          <div className="px-7 py-5 flex items-center justify-between border-b border-[#F3F3FF] flex-shrink-0">
            <div>
              <h3 className="text-[16px] font-semibold text-[#07074E]" style={{ fontFamily: "'Readex Pro', sans-serif" }}>
                Transaction History
              </h3>
              <p className="text-[12.5px] text-[#9F9FD1] mt-0.5" style={{ fontFamily: "'Inter', sans-serif" }}>
                All wallet activity across recharges, escrow, and fees
              </p>
            </div>
            <div className="flex items-center gap-2">
              {(["all", "in", "out"] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className="px-4 py-1.5 rounded-full text-[12px] font-semibold transition-all capitalize"
                  style={
                    activeTab === tab
                      ? { background: "#07074E", color: "#FFFFFF", fontFamily: "'Inter', sans-serif" }
                      : { background: "#F3F3FF", color: "#9F9FD1", fontFamily: "'Inter', sans-serif" }
                  }
                >
                  {tab === "all" ? "All" : tab === "in" ? "Credits" : "Debits"}
                </button>
              ))}
            </div>
          </div>

          <div className="px-7 flex-1 overflow-y-auto custom-scrollbar">
            {/* Header - Sticky */}
            <div className="sticky top-0 bg-white z-10 grid py-4 border-b border-[#F3F3FF]"
              style={{ gridTemplateColumns: "1.2fr 2.2fr 1.2fr 1fr 1.2fr" }}>
              {["Date", "Type", "Reference", "Amount", "Status"].map((h) => (
                <span key={h} className="text-[11px] font-semibold uppercase tracking-wider text-[#9F9FD1]"
                  style={{ fontFamily: "'Inter', sans-serif" }}>
                  {h}
                </span>
              ))}
            </div>

            <div className="divide-y divide-[#F3F3FF]/70">
              {filteredTxns.map((txn) => (
                <div
                  key={txn.id}
                  className="grid items-center py-5 group hover:bg-[#F8F9FF] rounded-[12px] transition-all cursor-pointer -mx-2 px-2"
                  style={{ gridTemplateColumns: "1.2fr 2.2fr 1.2fr 1fr 1.2fr" }}
                >
                  {/* Date */}
                  <div>
                    <div className="text-[13px] font-semibold text-[#07074E]" style={{ fontFamily: "'Inter', sans-serif" }}>
                      {txn.date}
                    </div>
                    <div className="text-[11px] text-[#C4C4E8] font-mono mt-0.5">{txn.id}</div>
                  </div>

                  {/* Type */}
                  <div className="flex items-center gap-3 pr-2">
                    <div
                      className="w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0"
                      style={{
                        background: txn.raw > 0 ? "#E8F8EE" : "#FFF0F0",
                      }}
                    >
                      <txn.icon
                        className="w-4 h-4"
                        style={{ color: txn.raw > 0 ? "#27AE60" : "#E74C3C" }}
                      />
                    </div>
                    <span className="text-[13.5px] font-medium text-[#07074E] leading-tight" style={{ fontFamily: "'Inter', sans-serif" }}>
                      {txn.type}
                    </span>
                  </div>

                  {/* Reference */}
                  <span className="text-[12px] font-medium text-[#9F9FD1] font-mono truncate pr-2">{txn.ref}</span>

                  {/* Amount */}
                  <span
                    className="text-[14px] font-bold"
                    style={{
                      color: txn.raw > 0 ? "#27AE60" : "#E74C3C",
                      fontFamily: "'Inter', sans-serif",
                    }}
                  >
                    {txn.amount}
                  </span>

                  {/* Status */}
                  <div className="flex justify-start">
                    <StatusBadge status={txn.status} />
                  </div>
                </div>
              ))}
              
              {filteredTxns.length === 0 && (
                <div className="py-20 flex flex-col items-center justify-center text-center">
                  <div className="w-12 h-12 rounded-full bg-[#F3F3FF] flex items-center justify-center mb-3">
                    <Clock className="w-6 h-6 text-[#9F9FD1]" />
                  </div>
                  <p className="text-[14px] font-medium text-[#07074E]">No transactions found</p>
                  <p className="text-[12px] text-[#9F9FD1] mt-1">Try changing your filters</p>
                </div>
              )}
            </div>
          </div>

          <div className="px-7 py-4 flex items-center justify-between border-t border-[#F3F3FF] flex-shrink-0 bg-white">
            <span className="text-[12px] text-[#9F9FD1]" style={{ fontFamily: "'Inter', sans-serif" }}>
              Showing {filteredTxns.length} of {TRANSACTIONS.length} transactions
            </span>
            <button className="flex items-center gap-1.5 text-[12px] font-semibold text-[#7387FF] hover:text-[#5B71FF] transition-colors"
              style={{ fontFamily: "'Inter', sans-serif" }}>
              View All
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* ── RIGHT PANEL ─────────────────────────────────────────────────────── */}
      <div className="w-[320px] flex-shrink-0 flex flex-col gap-5">

        {/* CARD A: Quick Recharge */}
        <div
          className="bg-white rounded-[20px] p-6"
          style={{ boxShadow: "0 2px 16px rgba(7,7,78,0.06)", border: "1px solid rgba(7,7,78,0.05)" }}
        >
          <div className="flex items-center justify-between mb-5">
            <h4 className="text-[15px] font-semibold text-[#07074E]" style={{ fontFamily: "'Readex Pro', sans-serif" }}>
              Quick Recharge
            </h4>
            <div className="w-8 h-8 rounded-xl bg-[#EEF0FF] flex items-center justify-center">
              <Plus className="w-4 h-4 text-[#7387FF]" />
            </div>
          </div>

          {/* Amount input */}
          <div className="mb-4">
            <label className="text-[11px] font-semibold uppercase tracking-wider text-[#9F9FD1] mb-2 block"
              style={{ fontFamily: "'Inter', sans-serif" }}>
              Enter Amount
            </label>
            <div
              className="flex items-center gap-2 h-12 rounded-[12px] border px-4 bg-[#F8F9FF]"
              style={{ borderColor: customAmount ? "#7387FF" : "rgba(7,7,78,0.08)" }}
            >
              <span className="text-[16px] font-semibold text-[#07074E]" style={{ fontFamily: "'Readex Pro', sans-serif" }}>₹</span>
              <input
                type="text"
                value={customAmount}
                onChange={(e) => setCustomAmount(e.target.value.replace(/[^0-9]/g, ""))}
                placeholder="Enter amount"
                className="flex-1 bg-transparent text-[14px] font-semibold text-[#07074E] placeholder-[#C4C4E8] outline-none"
                style={{ fontFamily: "'Inter', sans-serif" }}
              />
            </div>
          </div>

          {/* Preset chips */}
          <div className="flex gap-2 mb-5">
            {presets.map((p) => (
              <button
                key={p}
                onClick={() => setCustomAmount(p.replace("₹", "").replace("K", "000"))}
                className="flex-1 py-2 rounded-[10px] text-[12px] font-semibold transition-all hover:brightness-105 active:scale-[0.97]"
                style={{
                  background: customAmount === p.replace("₹", "").replace("K", "000") ? "#7387FF" : "#F3F3FF",
                  color: customAmount === p.replace("₹", "").replace("K", "000") ? "#FFFFFF" : "#9F9FD1",
                  fontFamily: "'Inter', sans-serif",
                }}
              >
                {p}
              </button>
            ))}
          </div>

          <button
            className="w-full h-11 rounded-[12px] text-[13px] font-semibold text-white flex items-center justify-center gap-2 transition-all hover:brightness-110 active:scale-[0.98]"
            style={{
              background: "linear-gradient(135deg, #7387FF 0%, #5B71FF 100%)",
              boxShadow: "0 4px 16px rgba(115,135,255,0.35)",
              fontFamily: "'Inter', sans-serif",
            }}
          >
            <Zap className="w-4 h-4" />
            Add Funds
          </button>

          <p className="text-[11px] text-[#C4C4E8] text-center mt-3" style={{ fontFamily: "'Inter', sans-serif" }}>
            Minimum ₹5,000 • Instant credit
          </p>
        </div>

        {/* CARD B: Bonus Insight */}
        <div
          className="bg-white rounded-[20px] p-6"
          style={{ boxShadow: "0 2px 16px rgba(7,7,78,0.06)", border: "1px solid rgba(7,7,78,0.05)" }}
        >
          <div className="flex items-center justify-between mb-4">
            <h4 className="text-[15px] font-semibold text-[#07074E]" style={{ fontFamily: "'Readex Pro', sans-serif" }}>
              Bonus Progress
            </h4>
            <div className="w-8 h-8 rounded-xl bg-[#EEF0FF] flex items-center justify-center">
              <Sparkles className="w-4 h-4 text-[#7387FF]" />
            </div>
          </div>

          <div className="flex items-center gap-5">
            {/* Donut */}
            <div className="relative w-[88px] h-[88px] flex-shrink-0">
              <DonutRing pct={65} color="#7387FF" track="#F3F3FF" />
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-[15px] font-semibold text-[#07074E]" style={{ fontFamily: "'Readex Pro', sans-serif" }}>
                  +7%
                </span>
              </div>
            </div>

            <div className="flex-1">
              <div className="text-[12px] font-semibold text-[#9F9FD1] mb-1" style={{ fontFamily: "'Inter', sans-serif" }}>
                Current Bonus Tier
              </div>
              <div className="text-[22px] font-semibold text-[#7387FF]" style={{ fontFamily: "'Readex Pro', sans-serif" }}>
                +7% Live
              </div>
              <div className="text-[11.5px] text-[#9F9FD1] mt-1 leading-snug" style={{ fontFamily: "'Inter', sans-serif" }}>
                Recharge ₹50K to unlock <span className="font-semibold text-[#27AE60]">+10%</span> tier
              </div>
            </div>
          </div>

          {/* Tier progress bar */}
          <div className="mt-4">
            <div className="flex justify-between text-[11px] font-medium text-[#C4C4E8] mb-2" style={{ fontFamily: "'Inter', sans-serif" }}>
              <span>₹25K tier</span>
              <span>₹50K tier</span>
            </div>
            <div className="h-2 bg-[#F3F3FF] rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all"
                style={{
                  width: "50%",
                  background: "linear-gradient(90deg, #7387FF 0%, #9F9FD1 100%)",
                }}
              />
            </div>
            <p className="text-[11px] text-[#C4C4E8] mt-1.5" style={{ fontFamily: "'Inter', sans-serif" }}>
              ₹25,000 more to unlock best value tier
            </p>
          </div>
        </div>

        {/* CARD C: Payment Methods */}
        <div
          className="bg-white rounded-[20px] p-6"
          style={{ boxShadow: "0 2px 16px rgba(7,7,78,0.06)", border: "1px solid rgba(7,7,78,0.05)" }}
        >
          <div className="flex items-center justify-between mb-4">
            <h4 className="text-[15px] font-semibold text-[#07074E]" style={{ fontFamily: "'Readex Pro', sans-serif" }}>
              Payment Methods
            </h4>
            <div className="w-8 h-8 rounded-xl bg-[#EEF0FF] flex items-center justify-center">
              <CreditCard className="w-4 h-4 text-[#7387FF]" />
            </div>
          </div>

          <div className="flex flex-col gap-2.5 mb-4">
            {PAYMENT_METHODS.map((pm) => (
              <button
                key={pm.id}
                onClick={() => setSelectedMethod(pm.id)}
                className="flex items-center gap-3 p-3 rounded-[12px] border transition-all text-left"
                style={{
                  borderColor: selectedMethod === pm.id ? "#7387FF" : "rgba(7,7,78,0.06)",
                  background: selectedMethod === pm.id ? "#F3F4FF" : "#FAFAFA",
                }}
              >
                <div
                  className="w-9 h-9 rounded-[10px] flex items-center justify-center text-[18px] flex-shrink-0"
                  style={{ background: selectedMethod === pm.id ? "#EEF0FF" : "#F0F0F0" }}
                >
                  {pm.icon}
                </div>
                <div className="flex-1">
                  <div className="text-[13px] font-semibold text-[#07074E]" style={{ fontFamily: "'Inter', sans-serif" }}>
                    {pm.label}
                  </div>
                  <div className="text-[11px] text-[#9F9FD1] font-medium" style={{ fontFamily: "'Inter', sans-serif" }}>
                    {pm.type === "visa" ? "Credit / Debit" : "UPI"}
                  </div>
                </div>
                {selectedMethod === pm.id && (
                  <CheckCircle2 className="w-4 h-4 text-[#7387FF] flex-shrink-0" />
                )}
              </button>
            ))}
          </div>

          <button
            className="w-full h-10 rounded-[12px] text-[12.5px] font-semibold transition-all hover:brightness-105 flex items-center justify-center gap-2"
            style={{
              background: "#F3F3FF",
              color: "#7387FF",
              border: "1px dashed #C4C4F8",
              fontFamily: "'Inter', sans-serif",
            }}
          >
            <Plus className="w-3.5 h-3.5" />
            Manage Methods
          </button>
        </div>

        {/* CARD D: Monthly Spend Snapshot */}
        <div
          className="bg-white rounded-[20px] p-6"
          style={{ boxShadow: "0 2px 16px rgba(7,7,78,0.06)", border: "1px solid rgba(7,7,78,0.05)" }}
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <h4 className="text-[15px] font-semibold text-[#07074E]" style={{ fontFamily: "'Readex Pro', sans-serif" }}>
                Monthly Spend
              </h4>
              <p className="text-[11.5px] text-[#9F9FD1] mt-0.5" style={{ fontFamily: "'Inter', sans-serif" }}>
                Jan – May 2025
              </p>
            </div>
            <div className="w-8 h-8 rounded-xl bg-[#EEF0FF] flex items-center justify-center">
              <TrendingUp className="w-4 h-4 text-[#7387FF]" />
            </div>
          </div>

          <div className="h-[140px]">
            <MiniAreaChart data={SPEND_DATA} />
          </div>

          <div className="flex items-center gap-4 mt-3">
            {[
              { color: "#07074E", label: "Recharges" },
              { color: "#7387FF", label: "Escrow" },
            ].map((l) => (
              <div key={l.label} className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: l.color }} />
                <span className="text-[11px] font-medium text-[#9F9FD1]" style={{ fontFamily: "'Inter', sans-serif" }}>
                  {l.label}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* CARD E: Security note */}
        <div
          className="rounded-[20px] p-5"
          style={{ background: "linear-gradient(135deg, #F3F4FF 0%, #EEF0FF 100%)", border: "1px solid rgba(115,135,255,0.15)" }}
        >
          <div className="flex items-start gap-3">
            <div className="w-9 h-9 rounded-xl bg-white flex items-center justify-center flex-shrink-0 shadow-sm">
              <Shield className="w-4 h-4 text-[#7387FF]" />
            </div>
            <div>
              <div className="text-[13px] font-semibold text-[#07074E] mb-1" style={{ fontFamily: "'Inter', sans-serif" }}>
                Funds are secure
              </div>
              <p className="text-[11.5px] text-[#9F9FD1] leading-relaxed" style={{ fontFamily: "'Inter', sans-serif" }}>
                Escrow is held by UGCad.io and only released on your approval or after the 5-day auto-approve window.
              </p>
              <button className="flex items-center gap-1 mt-2 text-[11.5px] font-semibold text-[#7387FF] hover:text-[#5B71FF] transition-colors"
                style={{ fontFamily: "'Inter', sans-serif" }}>
                Learn more <ChevronRight className="w-3 h-3" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}