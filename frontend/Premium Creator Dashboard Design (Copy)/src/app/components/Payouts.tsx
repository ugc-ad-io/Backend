import { useState } from "react";
import {
  IndianRupee,
  Clock,
  TrendingUp,
  Zap,
  Search,
  SlidersHorizontal,
  ChevronDown,
  ArrowUpRight,
  Shield,
  ShieldCheck,
  Building2,
  CreditCard,
  Smartphone,
  ExternalLink,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  XCircle,
  Star,
  Trophy,
  Sparkles,
  Lock,
  Calendar,
  ChevronRight,
  BarChart3,
  Wallet,
  CircleDot,
  BadgeCheck,
} from "lucide-react";

// ─── Data ────────────────────────────────────────────────────────────────────

const PAYMENT_HISTORY = [
  {
    id: "TXN-1042",
    campaign: "Summer Hydration Routine",
    brand: "@glowandco",
    approvalDate: "Apr 18, 2026",
    gross: 15000,
    fee: 1500,
    net: 13500,
    status: "Paid",
  },
  {
    id: "TXN-1039",
    campaign: "Smart Home Reel",
    brand: "@technova",
    approvalDate: "Apr 14, 2026",
    gross: 9500,
    fee: 950,
    net: 8550,
    status: "Processing",
  },
  {
    id: "TXN-1035",
    campaign: "Fitness Haul YT Shorts",
    brand: "@fitlife",
    approvalDate: "Apr 10, 2026",
    gross: 21000,
    fee: 2100,
    net: 18900,
    status: "Paid",
  },
  {
    id: "TXN-1031",
    campaign: "Organic Coffee ASMR",
    brand: "@beanroast",
    approvalDate: "Apr 6, 2026",
    gross: 6000,
    fee: 600,
    net: 5400,
    status: "Disputed",
  },
  {
    id: "TXN-1028",
    campaign: "Travel Essentials Pack",
    brand: "@packwise",
    approvalDate: "Mar 30, 2026",
    gross: 12500,
    fee: 1250,
    net: 11250,
    status: "Paid",
  },
  {
    id: "TXN-1024",
    campaign: "Eco Skincare Haul",
    brand: "@greenglow",
    approvalDate: "Mar 22, 2026",
    gross: 8000,
    fee: 800,
    net: 7200,
    status: "Pending",
  },
  {
    id: "TXN-1020",
    campaign: "Wireless Earbuds Review",
    brand: "@soundpeak",
    approvalDate: "Mar 15, 2026",
    gross: 18500,
    fee: 1850,
    net: 16650,
    status: "Paid",
  },
];

const PAYOUT_LEVELS = [
  { level: "New",      days: "12 business days", icon: CircleDot,  color: "#9F9FD1", current: false },
  { level: "Verified", days: "7 business days",  icon: BadgeCheck, color: "#B7B7E6", current: false },
  { level: "L1 Rising",days: "5 business days",  icon: Star,       color: "#7387FF", current: true  },
  { level: "L2 Pro",   days: "3 business days",  icon: Trophy,     color: "#F59E0B", current: false },
  { level: "Elite",    days: "48 hours",          icon: Zap,        color: "#22C55E", current: false },
];

type StatusType = "Paid" | "Processing" | "Disputed" | "Pending";

const STATUS_STYLES: Record<StatusType, { bg: string; text: string; border: string; icon: React.ElementType }> = {
  Paid:       { bg: "#22C55E12", text: "#22C55E", border: "#22C55E25", icon: CheckCircle2 },
  Processing: { bg: "#7387FF12", text: "#7387FF", border: "#7387FF25", icon: RefreshCw    },
  Disputed:   { bg: "#EF444412", text: "#EF4444", border: "#EF444425", icon: XCircle      },
  Pending:    { bg: "#F59E0B12", text: "#F59E0B", border: "#F59E0B25", icon: AlertCircle  },
};

// ─── Sub-components ──────────────────────────────────────────────────────────

function StatusChip({ status }: { status: string }) {
  const s = STATUS_STYLES[status as StatusType] ?? STATUS_STYLES.Pending;
  const Icon = s.icon;
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11.5px] font-semibold border whitespace-nowrap"
      style={{ backgroundColor: s.bg, color: s.text, borderColor: s.border }}
    >
      <Icon strokeWidth={2} className="w-3 h-3" />
      {status}
    </span>
  );
}

function KPICard({
  label,
  value,
  sub,
  subPositive,
  icon: Icon,
  iconColor,
  accent,
}: {
  label: string;
  value: string;
  sub: string;
  subPositive?: boolean;
  icon: React.ElementType;
  iconColor: string;
  accent: string;
}) {
  return (
    <div className="bg-white rounded-[20px] p-6 shadow-[0_4px_24px_rgba(7,7,78,0.05)] border border-[#E9EBEF]/50 flex flex-col justify-between group hover:-translate-y-0.5 hover:shadow-[0_8px_32px_rgba(7,7,78,0.09)] transition-all duration-300 relative overflow-hidden">
      <div
        className="absolute top-0 right-0 w-28 h-28 rounded-full blur-2xl opacity-60 pointer-events-none -mr-10 -mt-10"
        style={{ background: `${accent}18` }}
      />
      <div className="flex items-start justify-between mb-5 relative z-10">
        <div
          className="w-11 h-11 rounded-[14px] flex items-center justify-center group-hover:scale-105 transition-transform duration-300"
          style={{ backgroundColor: `${iconColor}12`, color: iconColor }}
        >
          <Icon strokeWidth={1.5} className="w-5 h-5" />
        </div>
        <span
          className="text-[11.5px] font-semibold flex items-center gap-1 px-2.5 py-1 rounded-[8px]"
          style={{
            color: subPositive === false ? "#9F9FD1" : subPositive ? "#22C55E" : "#9F9FD1",
            backgroundColor: subPositive === false ? "#F3F3FF" : subPositive ? "#22C55E12" : "#F3F3FF",
          }}
        >
          {subPositive && <TrendingUp strokeWidth={2} className="w-3 h-3" />}
          {sub}
        </span>
      </div>
      <div className="relative z-10">
        <p className="text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-1.5">{label}</p>
        <p className="text-[28px] font-semibold text-[#07074E] tracking-tight font-heading">{value}</p>
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export function Payouts() {
  const [statusFilter, setStatusFilter] = useState("All");
  const [searchQuery, setSearchQuery] = useState("");
  const [dateFilter, setDateFilter] = useState("All Time");
  const [showStatusDrop, setShowStatusDrop] = useState(false);
  const [showDateDrop, setShowDateDrop] = useState(false);

  const filtered = PAYMENT_HISTORY.filter((row) => {
    const matchStatus = statusFilter === "All" || row.status === statusFilter;
    const matchSearch =
      searchQuery === "" ||
      row.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      row.campaign.toLowerCase().includes(searchQuery.toLowerCase());
    return matchStatus && matchSearch;
  });

  return (
    <div className="flex flex-col gap-6 max-w-[1440px] mx-auto w-full pb-10 pt-2 font-sans">

      {/* ══════════════════════════════════
          SECTION 1 — KPI CARDS
      ══════════════════════════════════ */}
      <div className="grid grid-cols-4 gap-5">
        <KPICard
          label="Pending Release"
          value="₹28,500"
          sub="2 deals pending"
          icon={Wallet}
          iconColor="#F59E0B"
          accent="#F59E0B"
        />
        <KPICard
          label="Paid This Month"
          value="₹45,200"
          sub="+12% vs last month"
          subPositive={true}
          icon={IndianRupee}
          iconColor="#22C55E"
          accent="#22C55E"
        />
        <KPICard
          label="All Time Earnings"
          value="₹1,24,000"
          sub="Since Jan 2025"
          icon={BarChart3}
          iconColor="#7387FF"
          accent="#7387FF"
        />
        <KPICard
          label="Payout Window"
          value="5 Business Days"
          sub="Fastest payout unlocked"
          subPositive={true}
          icon={Zap}
          iconColor="#07074E"
          accent="#07074E"
        />
      </div>

      {/* ══════════════════════════════════
          SECTION 2 — TWO COLUMN LAYOUT
      ══════════════════════════════════ */}
      <div className="flex gap-6 items-start">

        {/* ── LEFT: Payment History ── */}
        <div className="flex flex-col gap-5 min-w-0" style={{ flex: "0 0 60%" }}>
          <div className="bg-white rounded-[20px] shadow-[0_4px_24px_rgba(7,7,78,0.05)] border border-[#E9EBEF]/50 overflow-hidden">

            {/* Table Header */}
            <div className="px-7 pt-6 pb-5 border-b border-[#F3F3FF]">
              <div className="flex items-center justify-between mb-5">
                <div>
                  <h2 className="text-[18px] font-semibold text-[#07074E] font-heading tracking-tight">Payment History</h2>
                  <p className="text-[12.5px] text-[#9F9FD1] font-medium mt-0.5">{filtered.length} transactions found</p>
                </div>
                <button className="flex items-center gap-1.5 bg-[#F3F3FF] hover:bg-[#E9EBEF] text-[#07074E] px-4 py-2 rounded-[10px] text-[13px] font-semibold transition-colors">
                  <ArrowUpRight strokeWidth={2} className="w-3.5 h-3.5" />
                  Export CSV
                </button>
              </div>

              {/* Filters row */}
              <div className="flex items-center gap-3">
                {/* Search */}
                <div className="flex items-center gap-2.5 bg-[#F3F3FF] rounded-[11px] px-3.5 py-2.5 flex-1 min-w-0">
                  <Search strokeWidth={1.8} className="w-4 h-4 text-[#9F9FD1] flex-shrink-0" />
                  <input
                    type="text"
                    placeholder="Search deal ID or campaign…"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="bg-transparent text-[13px] font-medium text-[#07074E] placeholder-[#B7B7E6] outline-none w-full"
                  />
                </div>

                {/* Status filter */}
                <div className="relative">
                  <button
                    onClick={() => { setShowStatusDrop(!showStatusDrop); setShowDateDrop(false); }}
                    className="flex items-center gap-2 bg-[#F3F3FF] hover:bg-[#E9EBEF] rounded-[11px] px-4 py-2.5 text-[13px] font-semibold text-[#07074E] transition-colors whitespace-nowrap"
                  >
                    <SlidersHorizontal strokeWidth={1.8} className="w-3.5 h-3.5 text-[#9F9FD1]" />
                    {statusFilter === "All" ? "All Status" : statusFilter}
                    <ChevronDown className={`w-3.5 h-3.5 text-[#9F9FD1] transition-transform ${showStatusDrop ? "rotate-180" : ""}`} />
                  </button>
                  {showStatusDrop && (
                    <div className="absolute top-full mt-2 right-0 bg-white rounded-[14px] shadow-[0_8px_32px_rgba(7,7,78,0.12)] border border-[#E9EBEF]/60 z-20 overflow-hidden min-w-[160px]">
                      {["All", "Paid", "Processing", "Pending", "Disputed"].map((s) => (
                        <button
                          key={s}
                          onClick={() => { setStatusFilter(s); setShowStatusDrop(false); }}
                          className={`w-full text-left px-4 py-2.5 text-[13px] font-medium transition-colors flex items-center gap-2.5 ${
                            statusFilter === s ? "bg-[#7387FF]/8 text-[#7387FF] font-semibold" : "text-[#07074E] hover:bg-[#F3F3FF]"
                          }`}
                        >
                          {statusFilter === s && <div className="w-1.5 h-1.5 rounded-full bg-[#7387FF]" />}
                          {s === "All" ? "All Status" : s}
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                {/* Date filter */}
                <div className="relative">
                  <button
                    onClick={() => { setShowDateDrop(!showDateDrop); setShowStatusDrop(false); }}
                    className="flex items-center gap-2 bg-[#F3F3FF] hover:bg-[#E9EBEF] rounded-[11px] px-4 py-2.5 text-[13px] font-semibold text-[#07074E] transition-colors whitespace-nowrap"
                  >
                    <Calendar strokeWidth={1.8} className="w-3.5 h-3.5 text-[#9F9FD1]" />
                    {dateFilter}
                    <ChevronDown className={`w-3.5 h-3.5 text-[#9F9FD1] transition-transform ${showDateDrop ? "rotate-180" : ""}`} />
                  </button>
                  {showDateDrop && (
                    <div className="absolute top-full mt-2 right-0 bg-white rounded-[14px] shadow-[0_8px_32px_rgba(7,7,78,0.12)] border border-[#E9EBEF]/60 z-20 overflow-hidden min-w-[160px]">
                      {["All Time", "This Month", "Last Month", "Last 3 Months", "This Year"].map((d) => (
                        <button
                          key={d}
                          onClick={() => { setDateFilter(d); setShowDateDrop(false); }}
                          className={`w-full text-left px-4 py-2.5 text-[13px] font-medium transition-colors flex items-center gap-2.5 ${
                            dateFilter === d ? "bg-[#7387FF]/8 text-[#7387FF] font-semibold" : "text-[#07074E] hover:bg-[#F3F3FF]"
                          }`}
                        >
                          {dateFilter === d && <div className="w-1.5 h-1.5 rounded-full bg-[#7387FF]" />}
                          {d}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Table */}
            {filtered.length === 0 ? (
              /* Empty State */
              <div className="flex flex-col items-center justify-center py-20 px-8">
                <div className="w-16 h-16 rounded-[20px] bg-[#F3F3FF] flex items-center justify-center mb-5">
                  <Wallet strokeWidth={1.2} className="w-7 h-7 text-[#B7B7E6]" />
                </div>
                <p className="text-[16px] font-semibold text-[#07074E] font-heading mb-2">No transactions found</p>
                <p className="text-[13px] text-[#9F9FD1] font-medium text-center max-w-xs">
                  Complete your first deal to receive payouts. Your payment history will appear here.
                </p>
                <button
                  onClick={() => { setStatusFilter("All"); setSearchQuery(""); }}
                  className="mt-6 px-5 py-2.5 rounded-[12px] bg-[#7387FF]/10 text-[#7387FF] text-[13px] font-semibold hover:bg-[#7387FF]/15 transition-colors"
                >
                  Clear Filters
                </button>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-[#F3F3FF]/50 border-b border-[#E9EBEF]/60">
                      {["Deal ID", "Campaign", "Approval Date", "Gross", "Fee (10%)", "Net Paid", "Status", ""].map((col) => (
                        <th
                          key={col}
                          className="px-5 py-3.5 text-[11px] font-semibold text-[#9F9FD1] uppercase tracking-wider whitespace-nowrap first:pl-7 last:pr-7"
                        >
                          {col}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((row, i) => (
                      <tr
                        key={row.id}
                        className="border-b border-[#F3F3FF] last:border-0 hover:bg-[#F3F3FF]/40 transition-colors group"
                      >
                        {/* Deal ID */}
                        <td className="px-5 py-4 pl-7">
                          <span className="text-[12px] font-semibold text-[#7387FF] font-mono bg-[#7387FF]/8 px-2 py-0.5 rounded-[6px]">
                            {row.id}
                          </span>
                        </td>
                        {/* Campaign */}
                        <td className="px-5 py-4 max-w-[180px]">
                          <p className="text-[13px] font-semibold text-[#07074E] truncate group-hover:text-[#7387FF] transition-colors">
                            {row.campaign}
                          </p>
                          <p className="text-[11px] font-medium text-[#9F9FD1] mt-0.5">{row.brand}</p>
                        </td>
                        {/* Approval Date */}
                        <td className="px-5 py-4 whitespace-nowrap">
                          <span className="text-[12.5px] font-medium text-[#9F9FD1]">{row.approvalDate}</span>
                        </td>
                        {/* Gross */}
                        <td className="px-5 py-4">
                          <span className="text-[13px] font-semibold text-[#07074E]">
                            ₹{row.gross.toLocaleString("en-IN")}
                          </span>
                        </td>
                        {/* Fee */}
                        <td className="px-5 py-4">
                          <span className="text-[12.5px] font-medium text-[#EF4444]">
                            –₹{row.fee.toLocaleString("en-IN")}
                          </span>
                        </td>
                        {/* Net Paid */}
                        <td className="px-5 py-4">
                          <span className="text-[14px] font-semibold text-[#07074E] font-heading">
                            ₹{row.net.toLocaleString("en-IN")}
                          </span>
                        </td>
                        {/* Status */}
                        <td className="px-5 py-4">
                          <StatusChip status={row.status} />
                        </td>
                        {/* Action */}
                        <td className="px-5 py-4 pr-7 text-right">
                          <button className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-[9px] bg-white border border-[#E9EBEF] text-[12px] font-semibold text-[#07074E] hover:bg-[#07074E] hover:text-white hover:border-[#07074E] shadow-sm transition-all duration-200 whitespace-nowrap">
                            View
                            <ExternalLink strokeWidth={2} className="w-3 h-3" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Table Footer */}
            {filtered.length > 0 && (
              <div className="px-7 py-4 border-t border-[#F3F3FF] flex items-center justify-between">
                <span className="text-[12px] font-medium text-[#9F9FD1]">
                  Showing {filtered.length} of {PAYMENT_HISTORY.length} transactions
                </span>
                <div className="flex items-center gap-1.5">
                  {["1", "2", "3"].map((p, i) => (
                    <button
                      key={p}
                      className={`w-7 h-7 rounded-[7px] text-[12px] font-semibold transition-all ${
                        i === 0
                          ? "bg-[#07074E] text-white shadow-sm"
                          : "bg-[#F3F3FF] text-[#9F9FD1] hover:bg-[#E9EBEF] hover:text-[#07074E]"
                      }`}
                    >
                      {p}
                    </button>
                  ))}
                  <button className="w-7 h-7 rounded-[7px] bg-[#F3F3FF] text-[#9F9FD1] hover:bg-[#E9EBEF] hover:text-[#07074E] transition-all flex items-center justify-center">
                    <ChevronRight strokeWidth={2} className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* ── RIGHT COLUMN (sticky) ── */}
        <div
          className="flex flex-col gap-5 flex-shrink-0"
          style={{ flex: "0 0 38%", position: "sticky", top: "0", alignSelf: "flex-start" }}
        >

          {/* A. Bank Account Card */}
          <div className="bg-white rounded-[20px] shadow-[0_4px_24px_rgba(7,7,78,0.05)] border border-[#E9EBEF]/50 overflow-hidden">
            {/* Card top band */}
            <div className="bg-gradient-to-r from-[#07074E] to-[#0D0D6B] px-6 py-5 relative overflow-hidden">
              <div className="absolute right-0 top-0 w-40 h-40 bg-[#7387FF]/15 blur-3xl rounded-full -mr-10 -mt-10 pointer-events-none" />
              <div className="flex items-center justify-between relative z-10">
                <div>
                  <p className="text-[11px] font-semibold text-white/50 uppercase tracking-wider mb-1">Linked Bank Account</p>
                  <h3 className="text-[16px] font-semibold text-white font-heading">Payment Details</h3>
                </div>
                <div className="flex items-center gap-1.5 bg-[#22C55E]/15 border border-[#22C55E]/25 px-3 py-1.5 rounded-full">
                  <ShieldCheck strokeWidth={2} className="w-3.5 h-3.5 text-[#22C55E]" />
                  <span className="text-[11px] font-semibold text-[#22C55E]">Verified</span>
                </div>
              </div>
            </div>

            <div className="px-6 py-5 flex flex-col gap-4">
              {/* Account fields */}
              {[
                { icon: Shield,      label: "Account Holder",  value: "Alex Rivera",       mono: false },
                { icon: Building2,   label: "Bank Name",       value: "HDFC Bank Ltd.",     mono: false },
                { icon: CreditCard,  label: "Account Number",  value: "XXXX XXXX 4821",     mono: true  },
                { icon: Lock,        label: "IFSC Code",       value: "HDFC0001042",         mono: true  },
                { icon: Smartphone,  label: "UPI ID",          value: "alex@hdfcbank",       mono: false },
              ].map((field, i) => (
                <div key={i} className="flex items-center gap-3.5">
                  <div className="w-8 h-8 rounded-[9px] bg-[#F3F3FF] flex items-center justify-center flex-shrink-0">
                    <field.icon strokeWidth={1.5} className="w-3.5 h-3.5 text-[#7387FF]" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-[10.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider">{field.label}</p>
                    <p className={`text-[13.5px] font-semibold text-[#07074E] mt-0.5 truncate ${field.mono ? "font-mono tracking-wide" : ""}`}>
                      {field.value}
                    </p>
                  </div>
                </div>
              ))}

              {/* Divider */}
              <div className="h-px bg-[#F3F3FF] my-1" />

              {/* Action buttons */}
              <div className="flex gap-3">
                <button className="flex-1 py-2.5 rounded-[12px] bg-[#07074E] text-white text-[13px] font-semibold hover:bg-[#0D0D6B] shadow-[0_4px_16px_rgba(7,7,78,0.18)] hover:-translate-y-0.5 transition-all flex items-center justify-center gap-2">
                  <CreditCard strokeWidth={1.8} className="w-3.5 h-3.5" />
                  Edit Details
                </button>
                <button className="flex-1 py-2.5 rounded-[12px] bg-[#F3F3FF] text-[#07074E] text-[13px] font-semibold hover:bg-[#E9EBEF] transition-colors flex items-center justify-center gap-2">
                  <Shield strokeWidth={1.8} className="w-3.5 h-3.5" />
                  Add Account
                </button>
              </div>
            </div>
          </div>

          {/* B. Payout Window by Level */}
          <div className="bg-white rounded-[20px] shadow-[0_4px_24px_rgba(7,7,78,0.05)] border border-[#E9EBEF]/50 overflow-hidden">
            <div className="px-6 pt-5 pb-4 border-b border-[#F3F3FF]">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-[15px] font-semibold text-[#07074E] font-heading">Payout Speed by Level</h3>
                  <p className="text-[11.5px] text-[#9F9FD1] font-medium mt-0.5">Unlock faster payouts as you grow</p>
                </div>
                <div className="w-8 h-8 rounded-[9px] bg-[#7387FF]/10 flex items-center justify-center">
                  <Zap strokeWidth={1.5} className="w-4 h-4 text-[#7387FF]" />
                </div>
              </div>
            </div>

            <div className="px-6 py-4 flex flex-col gap-2">
              {PAYOUT_LEVELS.map((lvl) => {
                const Icon = lvl.icon;
                return (
                  <div
                    key={lvl.level}
                    className={`flex items-center gap-3.5 px-4 py-3 rounded-[13px] transition-all ${
                      lvl.current
                        ? "bg-[#7387FF]/8 border border-[#7387FF]/20"
                        : "hover:bg-[#F3F3FF]/60"
                    }`}
                  >
                    <div
                      className="w-8 h-8 rounded-[9px] flex items-center justify-center flex-shrink-0"
                      style={{ backgroundColor: `${lvl.color}15` }}
                    >
                      <Icon strokeWidth={1.8} className="w-4 h-4" style={{ color: lvl.color }} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className={`text-[13px] font-semibold ${lvl.current ? "text-[#7387FF]" : "text-[#07074E]"}`}>
                        {lvl.level}
                      </p>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span
                        className={`text-[12px] font-semibold ${lvl.current ? "text-[#7387FF]" : "text-[#9F9FD1]"}`}
                      >
                        {lvl.days}
                      </span>
                      {lvl.current && (
                        <span className="bg-[#7387FF] text-white text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full">
                          You
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Note */}
            <div className="mx-6 mb-5 flex items-start gap-2.5 bg-[#F3F3FF]/80 rounded-[12px] px-4 py-3.5 border border-[#E9EBEF]/50">
              <AlertCircle strokeWidth={1.5} className="w-4 h-4 text-[#B7B7E6] flex-shrink-0 mt-0.5" />
              <p className="text-[11.5px] font-medium text-[#9F9FD1] leading-relaxed">
                Payout starts after brand approval. Disputed deals remain on hold until resolved.
              </p>
            </div>
          </div>

          {/* C. Quick Earnings Insight */}
          <div className="bg-gradient-to-br from-[#7387FF] to-[#4A63FF] rounded-[20px] px-6 py-5 shadow-[0_8px_32px_rgba(115,135,255,0.22)] relative overflow-hidden">
            <div className="absolute right-0 bottom-0 w-40 h-40 bg-white/10 blur-3xl rounded-full -mr-10 -mb-10 pointer-events-none" />
            <div className="absolute left-0 top-0 w-24 h-24 bg-[#07074E]/10 blur-2xl rounded-full -ml-6 -mt-6 pointer-events-none" />
            <div className="relative z-10">
              <div className="flex items-center gap-2 mb-4">
                <Sparkles strokeWidth={1.5} className="w-4 h-4 text-white/80" />
                <p className="text-[12px] font-semibold text-white/80 uppercase tracking-wider">Earnings Insight</p>
              </div>
              <p className="text-[24px] font-semibold text-white font-heading mb-1">+12% Growth</p>
              <p className="text-[13px] text-white/70 font-medium mb-5">vs. last month · April 2026</p>

              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: "Avg. Per Deal", value: "₹10,580" },
                  { label: "Deals Paid",    value: "4 this month" },
                ].map((m, i) => (
                  <div key={i} className="bg-white/12 backdrop-blur-sm rounded-[12px] px-4 py-3 border border-white/15">
                    <p className="text-[10.5px] font-semibold text-white/60 uppercase tracking-wider mb-1">{m.label}</p>
                    <p className="text-[15px] font-semibold text-white font-heading">{m.value}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
