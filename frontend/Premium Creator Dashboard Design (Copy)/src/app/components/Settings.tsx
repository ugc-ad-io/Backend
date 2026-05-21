import { useState } from "react";
import {
  User,
  Mail,
  Phone,
  Lock,
  Monitor,
  ShieldCheck,
  Bell,
  FileText,
  MessageSquare,
  IndianRupee,
  Award,
  BadgeCheck,
  Eye,
  EyeOff,
  Smartphone,
  ChevronRight,
  ExternalLink,
  LogOut,
  HelpCircle,
  AlertTriangle,
  Ban,
  Filter,
  Building2,
  Zap,
  Star,
  TrendingUp,
  Briefcase,
  RefreshCw,
  Key,
  Globe,
  LifeBuoy,
  BookOpen,
  Scale,
  CheckCircle2,
  AlertCircle,
  Sparkles,
  CreditCard,
  ArrowRight,
} from "lucide-react";

// ─── Sub-components ────────────────────────────────────────────────────────────

function Toggle({ active, onToggle }: { active: boolean; onToggle: () => void }) {
  return (
    <button
      onClick={onToggle}
      className={`relative w-11 h-6 rounded-full transition-all duration-300 focus:outline-none flex-shrink-0 ${
        active ? "bg-[#7387FF] shadow-[0_0_12px_rgba(115,135,255,0.35)]" : "bg-[#E2E2F0]"
      }`}
    >
      <span
        className={`absolute top-1/2 left-[3px] w-[18px] h-[18px] bg-white rounded-full shadow-md transition-transform duration-300 ${
          active ? "translate-x-5 -translate-y-1/2" : "-translate-y-1/2"
        }`}
      />
    </button>
  );
}

function SectionHeader({
  icon: Icon,
  title,
  subtitle,
  badge,
}: {
  icon: React.ElementType;
  title: string;
  subtitle: string;
  badge?: React.ReactNode;
}) {
  return (
    <div className="px-7 pt-6 pb-5 border-b border-[#F3F3FF] flex items-center justify-between">
      <div className="flex items-center gap-3.5">
        <div className="w-9 h-9 rounded-[11px] bg-[#F3F3FF] flex items-center justify-center">
          <Icon strokeWidth={1.6} className="w-[18px] h-[18px] text-[#7387FF]" />
        </div>
        <div>
          <h3 className="text-[15.5px] font-semibold text-[#07074E] font-heading leading-tight">{title}</h3>
          <p className="text-[12px] font-medium text-[#9F9FD1] mt-[1px]">{subtitle}</p>
        </div>
      </div>
      {badge}
    </div>
  );
}

function RowDivider() {
  return <div className="h-px bg-[#F3F3FF] mx-7" />;
}

// ─── Main Component ───────────────────────────────────────────────────────────

export function Settings() {
  // Notifications
  const [notifs, setNotifs] = useState({
    briefMatches: true,
    messages: true,
    dealUpdates: true,
    payoutAlerts: true,
    badgeUnlocks: false,
    emailUpdates: true,
  });

  // Privacy
  const [privacy, setPrivacy] = useState({
    contactProtection: true,
    hidePersonalDetails: true,
    contentFilter: false,
  });

  const [showAccount, setShowAccount] = useState(false);
  const [show2FA, setShow2FA] = useState(false);

  const toggleNotif = (key: keyof typeof notifs) =>
    setNotifs((prev) => ({ ...prev, [key]: !prev[key] }));

  const togglePrivacy = (key: keyof typeof privacy) =>
    setPrivacy((prev) => ({ ...prev, [key]: !prev[key] }));

  return (
    <div className="flex flex-col gap-6 pb-14 pt-1 font-sans">

      {/* ══════════════════════════════════════════
          SECTION 1 — PROFILE & ACCOUNT
      ══════════════════════════════════════════ */}
      <div className="bg-white rounded-[22px] shadow-[0_4px_28px_rgba(7,7,78,0.07)] border border-[#EDEDF8]/60 overflow-hidden">

        {/* Profile content — gradient header */}
        <div
          className="relative px-7 py-6 flex items-center gap-6 overflow-hidden"
          style={{ background: "linear-gradient(130deg, #07074E 0%, #1a2090 50%, #7387FF 85%, #B7B7E6 100%)" }}
        >
          {/* Decorative blobs */}
          <div className="absolute -top-10 left-[22%] w-52 h-52 rounded-full bg-[#7387FF]/20 blur-3xl pointer-events-none" />
          <div className="absolute top-0 right-[18%] w-32 h-32 rounded-full bg-[#B7B7E6]/20 blur-2xl pointer-events-none" />

          {/* Avatar */}
          <div className="relative flex-shrink-0">
            <img
              src="https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=192&h=192"
              alt="Alex Rivera"
              className="w-[76px] h-[76px] rounded-full object-cover ring-[3px] ring-white/30 shadow-[0_6px_20px_rgba(7,7,78,0.30)]"
            />
            <div className="absolute bottom-0.5 right-0.5 w-5 h-5 bg-[#27AE60] rounded-full border-2 border-white" />
          </div>

          {/* Identity info */}
          <div className="flex-1 min-w-0 relative z-10">
            <div className="flex items-center gap-3 flex-wrap">
              <span className="text-[20px] font-semibold text-white font-heading tracking-tight leading-none">Alex Rivera</span>
              <span className="inline-flex items-center gap-1.5 bg-[#27AE60]/20 text-[#6EFFA8] border border-[#27AE60]/30 px-2.5 py-[4px] rounded-full text-[11px] font-semibold">
                <BadgeCheck strokeWidth={2} className="w-3 h-3" />
                Verified Creator
              </span>
              <span className="inline-flex items-center gap-1.5 bg-white/15 text-white border border-white/20 px-2.5 py-[4px] rounded-full text-[11px] font-semibold">
                <Star strokeWidth={2} className="w-3 h-3 fill-white" />
                L1 Rising
              </span>
            </div>
            <div className="flex items-center gap-5 mt-3 flex-wrap">
              <div className="flex items-center gap-2 text-[13px] font-medium text-white/70">
                <div className="w-6 h-6 rounded-[7px] bg-white/15 flex items-center justify-center">
                  <User strokeWidth={1.5} className="w-3.5 h-3.5 text-white/80" />
                </div>
                @alexrivera.ugc
                <span className="text-[10.5px] font-semibold text-white/50 bg-white/10 border border-white/15 px-2 py-0.5 rounded-full uppercase tracking-wider">Permanent</span>
              </div>
              <div className="flex items-center gap-2 text-[13px] font-medium text-white/70">
                <div className="w-6 h-6 rounded-[7px] bg-white/15 flex items-center justify-center">
                  <Mail strokeWidth={1.5} className="w-3.5 h-3.5 text-white/80" />
                </div>
                {showAccount ? "alex.rivera@gmail.com" : "al••••••er@gmail.com"}
              </div>
              <div className="flex items-center gap-2 text-[13px] font-medium text-white/70">
                <div className="w-6 h-6 rounded-[7px] bg-white/15 flex items-center justify-center">
                  <Phone strokeWidth={1.5} className="w-3.5 h-3.5 text-white/80" />
                </div>
                {showAccount ? "+91 98765 43210" : "+91 ••••• 43210"}
              </div>
              <button
                onClick={() => setShowAccount(!showAccount)}
                className="flex items-center gap-1 text-[12px] font-semibold text-white/60 hover:text-white transition-colors"
              >
                {showAccount ? <EyeOff strokeWidth={1.8} className="w-3.5 h-3.5" /> : <Eye strokeWidth={1.8} className="w-3.5 h-3.5" />}
                {showAccount ? "Hide" : "Reveal"}
              </button>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-2.5 flex-shrink-0 relative z-10">
            <button className="flex items-center gap-2 bg-white/12 text-white px-4 py-2.5 rounded-[12px] text-[12.5px] font-semibold border border-white/20 hover:bg-white/20 hover:border-white/35 transition-all backdrop-blur-sm">
              <Key strokeWidth={1.8} className="w-3.5 h-3.5 text-white/80" />
              Change Password
            </button>
            <button className="flex items-center gap-2 bg-white/12 text-white px-4 py-2.5 rounded-[12px] text-[12.5px] font-semibold border border-white/20 hover:bg-white/20 hover:border-white/35 transition-all backdrop-blur-sm">
              <Monitor strokeWidth={1.8} className="w-3.5 h-3.5 text-white/80" />
              Manage Devices
            </button>
            <button
              onClick={() => setShow2FA(!show2FA)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-[12px] text-[12.5px] font-semibold transition-all ${
                show2FA
                  ? "bg-white text-[#07074E] shadow-[0_4px_14px_rgba(0,0,0,0.20)]"
                  : "bg-white/20 text-white border border-white/30 hover:bg-white/30"
              }`}
            >
              <Smartphone strokeWidth={1.8} className="w-3.5 h-3.5" />
              Two-Factor Auth
              {show2FA && <CheckCircle2 strokeWidth={2} className="w-3.5 h-3.5 text-[#27AE60]" />}
            </button>
          </div>
        </div>
      </div>

      {/* ══ ROW 2: Notifications + Privacy ══ */}
      <div className="flex gap-6">

        {/* LEFT COLUMN */}
        <div className="flex-1 flex flex-col gap-6">

        {/* ══════════════════════════════════════════
            SECTION 2 — NOTIFICATIONS
        ══════════════════════════════════════════ */}
        <div className="bg-white rounded-[22px] shadow-[0_4px_28px_rgba(7,7,78,0.07)] border border-[#EDEDF8]/60 overflow-hidden">
          <SectionHeader
            icon={Bell}
            title="Notification Preferences"
            subtitle="Control what updates reach you"
            badge={
              <span className="text-[11.5px] font-semibold text-[#7387FF] bg-[#7387FF]/10 border border-[#7387FF]/20 px-3 py-1 rounded-full">
                {Object.values(notifs).filter(Boolean).length} active
              </span>
            }
          />

          <div className="py-2">
            {[
              { key: "briefMatches",  icon: Briefcase,     label: "New Brief Matches",   sub: "Get notified when new briefs match your niche"  },
              { key: "messages",      icon: MessageSquare, label: "Messages",             sub: "Alerts for new brand messages"                   },
              { key: "dealUpdates",   icon: FileText,      label: "Deal Updates",         sub: "Milestone approvals, revision requests"          },
              { key: "payoutAlerts",  icon: IndianRupee,   label: "Payout Alerts",        sub: "Payment received and processing updates"         },
              { key: "badgeUnlocks",  icon: Award,         label: "Badge Unlocks",        sub: "Celebrate new achievements and level-ups"        },
              { key: "emailUpdates",  icon: Mail,          label: "Email Digest",         sub: "Weekly performance summary via email"            },
            ].map((item, i, arr) => {
              const isActive = notifs[item.key as keyof typeof notifs];
              return (
                <div key={item.key}>
                  <div className="flex items-center gap-4 px-7 py-4 hover:bg-[#F9F9FF] transition-colors group">
                    <div className={`w-9 h-9 rounded-[10px] flex items-center justify-center flex-shrink-0 transition-colors ${isActive ? "bg-[#7387FF]/12 border border-[#7387FF]/18" : "bg-[#F3F3FF] border border-[#EDEDF8]"}`}>
                      <item.icon strokeWidth={1.5} className={`w-4 h-4 transition-colors ${isActive ? "text-[#7387FF]" : "text-[#B7B7E6]"}`} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className={`text-[13.5px] font-semibold transition-colors ${isActive ? "text-[#07074E]" : "text-[#9F9FD1]"}`}>{item.label}</p>
                      <p className="text-[11.5px] font-medium text-[#B7B7E6] mt-0.5">{item.sub}</p>
                    </div>
                    <Toggle active={isActive} onToggle={() => toggleNotif(item.key as keyof typeof notifs)} />
                  </div>
                  {i < arr.length - 1 && <RowDivider />}
                </div>
              );
            })}
          </div>
        </div>

        {/* ══════════════════════════════════════════
            SECTION 4 — PAYOUT & BANK DETAILS
        ══════════════════════════════════════════ */}
        <div className="flex flex-col flex-1 bg-white rounded-[22px] shadow-[0_4px_28px_rgba(7,7,78,0.07)] border border-[#EDEDF8]/60 overflow-hidden">
          <SectionHeader
            icon={CreditCard}
            title="Payout & Bank Details"
            subtitle="Manage how you receive earnings"
            badge={
              <div className="flex items-center gap-1.5 bg-[#27AE60]/10 border border-[#27AE60]/20 px-3 py-1 rounded-full">
                <CheckCircle2 strokeWidth={2} className="w-3.5 h-3.5 text-[#27AE60]" />
                <span className="text-[11.5px] font-semibold text-[#27AE60]">Bank Linked</span>
              </div>
            }
          />

          <div className="px-7 py-5 flex flex-col flex-1 gap-5">
            {/* Bank info cards */}
            <div className="grid grid-cols-3 gap-4">
              {[
                { label: "Account Number", value: "•••• •••• 4821", icon: Building2, note: "HDFC Bank" },
                { label: "IFSC Code",      value: "HDFC000••••",    icon: Globe,     note: "Branch: Bandra" },
                { label: "Payout Speed",   value: "T + 3 Days",     icon: Zap,       note: "L1 Creator Speed" },
              ].map((item) => (
                <div key={item.label} className="bg-[#F8F8FF] rounded-[16px] border border-[#EDEDF8] px-5 py-4 flex flex-col gap-2.5">
                  <div className="flex items-center justify-between">
                    <p className="text-[11px] font-semibold text-[#9F9FD1] uppercase tracking-[0.07em]">{item.label}</p>
                    <div className="w-7 h-7 rounded-[8px] bg-white border border-[#EDEDF8] flex items-center justify-center">
                      <item.icon strokeWidth={1.5} className="w-3.5 h-3.5 text-[#7387FF]" />
                    </div>
                  </div>
                  <p className="text-[17px] font-semibold text-[#07074E] font-heading leading-none">{item.value}</p>
                  <p className="text-[11px] font-medium text-[#B7B7E6]">{item.note}</p>
                </div>
              ))}
            </div>

            {/* Payout speed note */}
            <div className="flex items-start gap-3 bg-[#7387FF]/6 border border-[#7387FF]/15 rounded-[14px] px-4 py-3.5">
              <Zap strokeWidth={1.5} className="w-4 h-4 text-[#7387FF] flex-shrink-0 mt-0.5" />
              <p className="text-[12.5px] font-medium text-[#4A4A7A]">
                Upgrade to <span className="font-semibold text-[#07074E]">L2 Creator</span> to unlock same-day payouts and priority processing. Complete 10 deals to qualify.
              </p>
            </div>

            {/* Action */}
            <div className="flex items-center gap-3">
              <button className="flex items-center gap-2 bg-[#07074E] text-white px-5 py-2.5 rounded-[12px] text-[13px] font-semibold hover:bg-[#0D0D6B] shadow-[0_4px_16px_rgba(7,7,78,0.18)] hover:-translate-y-0.5 transition-all">
                <CreditCard strokeWidth={1.8} className="w-4 h-4" />
                Update Bank Details
              </button>
              <button className="flex items-center gap-2 text-[13px] font-semibold text-[#7387FF] hover:text-[#5A6EED] transition-colors">
                View Payout History
                <ArrowRight strokeWidth={2} className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>

        </div>{/* end LEFT COLUMN */}

        {/* RIGHT COLUMN */}
        <div className="flex flex-col gap-6 flex-shrink-0" style={{ flex: "0 0 38%" }}>

        {/* ══════════════════════════════════════════
            SECTION 3 — PRIVACY & SAFETY
        ══════════════════════════════════════════ */}
        <div className="bg-white rounded-[22px] shadow-[0_4px_28px_rgba(7,7,78,0.07)] border border-[#EDEDF8]/60 overflow-hidden">
          <SectionHeader
            icon={ShieldCheck}
            title="Privacy & Safety"
            subtitle="Control your data and visibility"
            badge={
              <div className="flex items-center gap-1.5 bg-[#27AE60]/10 border border-[#27AE60]/20 px-3 py-1 rounded-full">
                <ShieldCheck strokeWidth={2} className="w-3.5 h-3.5 text-[#27AE60]" />
                <span className="text-[11.5px] font-semibold text-[#27AE60]">Protected</span>
              </div>
            }
          />

          <div className="py-2">
            {/* Toggle rows */}
            {[
              { key: "contactProtection",  icon: Lock,    label: "Contact Protection",     sub: "Hide email & phone from brands" },
              { key: "hidePersonalDetails", icon: EyeOff, label: "Hide Personal Details",  sub: "Name, city visible only to verified brands" },
              { key: "contentFilter",      icon: Filter,  label: "Content Filter",         sub: "Block adult or restricted briefs" },
            ].map((item, i) => {
              const isActive = privacy[item.key as keyof typeof privacy];
              return (
                <div key={item.key}>
                  <div className="flex items-center gap-4 px-7 py-4 hover:bg-[#F9F9FF] transition-colors">
                    <div className={`w-9 h-9 rounded-[10px] flex items-center justify-center flex-shrink-0 transition-colors ${isActive ? "bg-[#7387FF]/12 border border-[#7387FF]/18" : "bg-[#F3F3FF] border border-[#EDEDF8]"}`}>
                      <item.icon strokeWidth={1.5} className={`w-4 h-4 transition-colors ${isActive ? "text-[#7387FF]" : "text-[#B7B7E6]"}`} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className={`text-[13.5px] font-semibold transition-colors ${isActive ? "text-[#07074E]" : "text-[#9F9FD1]"}`}>{item.label}</p>
                      <p className="text-[11.5px] font-medium text-[#B7B7E6] mt-0.5">{item.sub}</p>
                    </div>
                    <Toggle active={isActive} onToggle={() => togglePrivacy(item.key as keyof typeof privacy)} />
                  </div>
                  <RowDivider />
                </div>
              );
            })}

            {/* Action rows */}
            {[
              { icon: AlertTriangle, label: "Report Abuse",        sub: "Flag harmful or fraudulent brands",    color: "#E74C3C" },
              { icon: Ban,           label: "Blocked Brands List", sub: "3 brands currently blocked",           color: "#F39C12" },
            ].map((item, i, arr) => (
              <div key={item.label}>
                <button className="w-full flex items-center gap-4 px-7 py-4 hover:bg-[#F9F9FF] transition-colors text-left group">
                  <div className="w-9 h-9 rounded-[10px] flex items-center justify-center flex-shrink-0 border border-[#EDEDF8]" style={{ backgroundColor: `${item.color}10` }}>
                    <item.icon strokeWidth={1.5} className="w-4 h-4" style={{ color: item.color }} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-[13.5px] font-semibold text-[#07074E]">{item.label}</p>
                    <p className="text-[11.5px] font-medium text-[#B7B7E6] mt-0.5">{item.sub}</p>
                  </div>
                  <ChevronRight strokeWidth={2} className="w-4 h-4 text-[#B7B7E6] group-hover:text-[#7387FF] group-hover:translate-x-0.5 transition-all" />
                </button>
                {i < arr.length - 1 && <RowDivider />}
              </div>
            ))}
          </div>
        </div>

        {/* ══════════════════════════════════════════
            SECTION 5 — PERFORMANCE & LEVEL
        ══════════════════════════════════════════ */}
        <div className="flex-1 bg-white rounded-[22px] shadow-[0_4px_28px_rgba(7,7,78,0.07)] border border-[#EDEDF8]/60 overflow-hidden">
          <SectionHeader
            icon={TrendingUp}
            title="Performance & Level"
            subtitle="Your creator growth snapshot"
          />

          <div className="px-7 py-5 flex flex-col gap-4">
            {/* Level badge — hero */}
            <div
              className="relative rounded-[18px] overflow-hidden px-6 py-5 flex items-center gap-5"
              style={{ background: "linear-gradient(130deg, #07074E 0%, #1a2090 55%, #7387FF 100%)" }}
            >
              <div className="absolute -top-6 -right-6 w-28 h-28 rounded-full bg-white/8 blur-2xl pointer-events-none" />
              <div className="w-12 h-12 rounded-[14px] bg-white/15 border border-white/20 flex items-center justify-center flex-shrink-0">
                <Award strokeWidth={1.5} className="w-6 h-6 text-white" />
              </div>
              <div>
                <p className="text-[11px] font-semibold text-white/60 uppercase tracking-widest mb-1">Current Level</p>
                <p className="text-[22px] font-semibold text-white font-heading leading-none">L1 Rising Creator</p>
                <p className="text-[11.5px] font-medium text-white/60 mt-1">Complete 10 deals to reach L2</p>
              </div>
              <div className="ml-auto flex-shrink-0">
                <div className="w-10 h-10 rounded-full bg-white/15 border border-white/20 flex items-center justify-center">
                  <Sparkles strokeWidth={1.5} className="w-5 h-5 text-white" />
                </div>
              </div>
            </div>

            {/* Stats row */}
            <div className="grid grid-cols-3 gap-3">
              {[
                { icon: Star,      label: "Rating",    value: "4.9",  sub: "/ 5.0", color: "#F39C12" },
                { icon: Briefcase, label: "Deals Done", value: "12",  sub: "total", color: "#7387FF" },
                { icon: RefreshCw, label: "Repeat Hire", value: "3",  sub: "brands", color: "#27AE60" },
              ].map((stat) => (
                <div key={stat.label} className="bg-[#F8F8FF] rounded-[14px] border border-[#EDEDF8] px-4 py-3.5 flex flex-col items-center gap-2">
                  <div className="w-8 h-8 rounded-full bg-white border border-[#EDEDF8] flex items-center justify-center">
                    <stat.icon strokeWidth={1.5} className="w-3.5 h-3.5" style={{ color: stat.color }} />
                  </div>
                  <div className="flex items-baseline gap-[2px]">
                    <span className="text-[18px] font-semibold text-[#07074E] font-heading leading-none">{stat.value}</span>
                    <span className="text-[9px] font-medium text-[#C4C4E8]">{stat.sub}</span>
                  </div>
                  <p className="text-[9.5px] font-semibold text-[#B7B7E6] uppercase tracking-[0.07em]">{stat.label}</p>
                </div>
              ))}
            </div>

            {/* Next level progress */}
            <div className="bg-[#F8F8FF] rounded-[16px] border border-[#EDEDF8] px-5 py-4">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <p className="text-[13px] font-semibold text-[#07074E]">Next Level Progress</p>
                  <p className="text-[11.5px] font-medium text-[#9F9FD1] mt-0.5">L1 → L2 Rising Star</p>
                </div>
                <span className="text-[18px] font-semibold text-[#7387FF] font-heading">72%</span>
              </div>
              <div className="h-2 bg-[#E8E8F8] rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-700"
                  style={{
                    width: "72%",
                    background: "linear-gradient(90deg, #7387FF 0%, #B7B7E6 100%)",
                  }}
                />
              </div>
              <div className="flex items-center justify-between mt-2">
                <p className="text-[10.5px] font-medium text-[#B7B7E6]">12 / 17 deals completed</p>
                <p className="text-[10.5px] font-semibold text-[#7387FF]">5 more to unlock</p>
              </div>
            </div>
          </div>
        </div>

        </div>{/* end RIGHT COLUMN */}

      </div>

      {/* ══════════════════════════════════════════
          SECTION 6 — SUPPORT & LEGAL
      ══════════════════════════════════════════ */}
      <div className="bg-white rounded-[22px] shadow-[0_4px_28px_rgba(7,7,78,0.07)] border border-[#EDEDF8]/60 overflow-hidden">
        <SectionHeader
          icon={LifeBuoy}
          title="Support & Legal"
          subtitle="Help, documentation, and account actions"
        />

        <div className="px-7 py-4 grid grid-cols-6 gap-3">
          {[
            { icon: HelpCircle, label: "Help Center",     sub: "FAQs & guides",         color: "#7387FF", href: "#" },
            { icon: BookOpen,   label: "Documentation",   sub: "Creator handbook",       color: "#7387FF", href: "#" },
            { icon: Scale,      label: "Terms of Service", sub: "Platform agreement",    color: "#9F9FD1", href: "#" },
            { icon: Lock,       label: "Privacy Policy",  sub: "Data & rights",          color: "#9F9FD1", href: "#" },
            { icon: MessageSquare, label: "Contact Support", sub: "Avg reply 2h",        color: "#27AE60", href: "#" },
            { icon: AlertCircle, label: "Report a Bug",   sub: "Help us improve",        color: "#F39C12", href: "#" },
          ].map((item) => (
            <a
              key={item.label}
              href={item.href}
              className="flex flex-col items-center gap-2.5 px-4 py-4 rounded-[16px] bg-[#F8F8FF] border border-[#EDEDF8] hover:bg-white hover:border-[#7387FF]/25 hover:shadow-[0_4px_16px_rgba(115,135,255,0.10)] hover:-translate-y-0.5 transition-all group text-center"
            >
              <div className="w-10 h-10 rounded-[12px] flex items-center justify-center" style={{ backgroundColor: `${item.color}12`, border: `1px solid ${item.color}20` }}>
                <item.icon strokeWidth={1.5} className="w-5 h-5" style={{ color: item.color }} />
              </div>
              <div>
                <p className="text-[12.5px] font-semibold text-[#07074E] group-hover:text-[#7387FF] transition-colors">{item.label}</p>
                <p className="text-[10.5px] font-medium text-[#B7B7E6] mt-0.5">{item.sub}</p>
              </div>
              <ExternalLink strokeWidth={1.8} className="w-3 h-3 text-[#C4C4E8] group-hover:text-[#7387FF] transition-colors mt-auto" />
            </a>
          ))}
        </div>

        {/* Logout row */}
        <div className="mx-7 mb-6 mt-1">
          <div className="flex items-center justify-between bg-[#E74C3C]/6 border border-[#E74C3C]/15 rounded-[16px] px-6 py-4">
            <div className="flex items-center gap-3.5">
              <div className="w-9 h-9 rounded-[10px] bg-[#E74C3C]/10 border border-[#E74C3C]/20 flex items-center justify-center">
                <LogOut strokeWidth={1.6} className="w-4 h-4 text-[#E74C3C]" />
              </div>
              <div>
                <p className="text-[13.5px] font-semibold text-[#07074E]">Sign Out</p>
                <p className="text-[11.5px] font-medium text-[#9F9FD1]">Logged in as @alexrivera.ugc · Last active just now</p>
              </div>
            </div>
            <button className="flex items-center gap-2 bg-[#E74C3C] text-white px-5 py-2.5 rounded-[12px] text-[13px] font-semibold hover:bg-[#C0392B] shadow-[0_4px_14px_rgba(231,76,60,0.25)] hover:-translate-y-0.5 transition-all">
              <LogOut strokeWidth={1.8} className="w-3.5 h-3.5" />
              Log Out
            </button>
          </div>
        </div>
      </div>

    </div>
  );
}