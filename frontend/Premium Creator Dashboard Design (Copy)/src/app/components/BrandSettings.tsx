import { useState } from "react";
import {
  User,
  Mail,
  Phone,
  Globe,
  Building2,
  FileText,
  CreditCard,
  Users,
  Bell,
  Lock,
  MessageSquare,
  Smartphone,
  ShieldCheck,
  ChevronRight,
  Plus,
  ArrowUpRight,
  TrendingUp,
  History,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
  Search,
  Settings as SettingsIcon,
  Trash2,
  MoreVertical,
  Zap,
  Star,
  Download,
  UploadCloud,
  MapPin,
  Briefcase,
  Sparkles,
  RefreshCw,
} from "lucide-react";

// ─── Sub-components ────────────────────────────────────────────────────────────

function Toggle({ active, onToggle }: { active: boolean; onToggle: () => void }) {
  return (
    <button
      onClick={onToggle}
      className={`relative w-10 h-5.5 rounded-full transition-all duration-300 focus:outline-none flex-shrink-0 ${
        active ? "bg-[#7387FF] shadow-[0_0_10px_rgba(115,135,255,0.3)]" : "bg-[#E2E2F0]"
      }`}
    >
      <span
        className={`absolute top-1/2 left-[2px] w-[18px] h-[18px] bg-white rounded-full shadow-sm transition-transform duration-300 ${
          active ? "translate-x-[18px] -translate-y-1/2" : "-translate-y-1/2"
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
    <div className="px-7 py-5 border-b border-[#F3F3FF] flex items-center justify-between">
      <div className="flex items-center gap-3.5">
        <div className="w-9 h-9 rounded-[12px] bg-[#F3F3FF] flex items-center justify-center">
          <Icon strokeWidth={1.6} className="w-[18px] h-[18px] text-[#7387FF]" />
        </div>
        <div>
          <h3 className="text-[16px] font-semibold text-[#07074E]" style={{ fontFamily: "'Readex Pro', sans-serif" }}>
            {title}
          </h3>
          <p className="text-[12px] font-medium text-[#9F9FD1] mt-0.5">{subtitle}</p>
        </div>
      </div>
      {badge}
    </div>
  );
}

// ─── Mock Data ─────────────────────────────────────────────────────────────

const TEAM_MEMBERS = [
  {
    id: 1,
    name: "Priya Sharma",
    email: "priya@urbanic.in",
    role: "Admin",
    status: "Active",
    avatar: "https://images.unsplash.com/photo-1697780871128-14146e7398fb?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&w=64&q=80",
  },
  {
    id: 2,
    name: "Rohan Mehta",
    email: "rohan.m@urbanic.in",
    role: "Editor",
    status: "Active",
    avatar: "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&w=64&q=80",
  },
  {
    id: 3,
    name: "Anjali Gupta",
    email: "anjali.g@urbanic.in",
    role: "Viewer",
    status: "Invited",
    avatar: "https://images.unsplash.com/photo-1494790108377-be9c29b29330?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&w=64&q=80",
  },
];

const SESSIONS = [
  { id: 1, device: "MacBook Pro • Mumbai, India", current: true, time: "Active now" },
  { id: 2, device: "iPhone 15 Pro • Delhi, India", current: false, time: "2 hours ago" },
];

// ─── Main Component ───────────────────────────────────────────────────────────

export function BrandSettings() {
  const [activeTab, setActiveTab] = useState("profile");
  const [notifs, setNotifs] = useState({
    applications: true,
    dealUpdates: true,
    payments: true,
    messages: true,
    weeklyReports: false,
  });

  const toggleNotif = (key: keyof typeof notifs) =>
    setNotifs((prev) => ({ ...prev, [key]: !prev[key] }));

  return (
    <div className="flex gap-6 pb-20 w-full" style={{ fontFamily: "'Inter', sans-serif" }}>
      
      {/* ── LEFT AREA ─────────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col gap-6 min-w-0">
        
        {/* Navigation Tabs */}
        <div className="flex items-center gap-1 bg-white p-1 rounded-2xl shadow-[0_2px_12px_rgba(7,7,78,0.04)] border border-[#EDEDF8]/60 w-fit">
          {[
            { id: "profile", label: "Profile", icon: User },
            { id: "company", label: "Company", icon: Building2 },
            { id: "team", label: "Team Members", icon: Users },
            { id: "billing", label: "Billing", icon: CreditCard },
            { id: "notifications", label: "Notifications", icon: Bell },
            { id: "security", label: "Security", icon: Lock },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-5 py-2.5 rounded-[12px] text-[13px] font-semibold transition-all ${
                activeTab === tab.id
                  ? "bg-[#7387FF] text-white shadow-[0_4px_12px_rgba(115,135,255,0.25)]"
                  : "text-[#9F9FD1] hover:text-[#07074E] hover:bg-[#F3F3FF]"
              }`}
            >
              <tab.icon strokeWidth={2} className="w-[15px] h-[15px]" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* 1. Profile Card */}
        {activeTab === "profile" && (
          <div className="bg-white rounded-[24px] shadow-[0_4px_28px_rgba(7,7,78,0.07)] border border-[#EDEDF8]/60 overflow-hidden">
            <SectionHeader
              icon={User}
              title="Profile Settings"
              subtitle="Update your basic brand information and workspace presence"
            />
            <div className="p-8 flex flex-col gap-8">
              <div className="flex items-start gap-10">
                {/* Logo Upload Area */}
                <div className="flex flex-col items-center gap-4">
                  <div className="relative group">
                    <div className="w-24 h-24 rounded-[28px] bg-[#F3F3FF] border-2 border-dashed border-[#B7B7E6] flex items-center justify-center overflow-hidden transition-all group-hover:border-[#7387FF] group-hover:bg-[#F3F3FF]/50">
                      <div className="w-16 h-16 rounded-[20px] bg-white shadow-sm flex items-center justify-center text-[24px] font-bold text-[#7387FF]">
                        U
                      </div>
                      <div className="absolute inset-0 bg-[#07074E]/40 flex flex-col items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer">
                        <UploadCloud className="w-6 h-6 text-white mb-1" />
                        <span className="text-[10px] font-bold text-white uppercase tracking-wider">Change</span>
                      </div>
                    </div>
                  </div>
                  <button className="text-[12px] font-semibold text-[#7387FF] hover:text-[#07074E] transition-colors">
                    Remove Logo
                  </button>
                </div>

                {/* Form Fields */}
                <div className="flex-1 grid grid-cols-2 gap-x-6 gap-y-5">
                  <div className="flex flex-col gap-1.5">
                    <label className="text-[12px] font-semibold text-[#07074E] ml-1">Brand Name</label>
                    <input
                      type="text"
                      defaultValue="Urbanic"
                      className="h-11 bg-[#F8F8FF] border border-[#EDEDF8] rounded-[12px] px-4 text-[14px] font-medium text-[#07074E] focus:outline-none focus:border-[#7387FF] focus:ring-4 focus:ring-[#7387FF]/5 transition-all"
                    />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <label className="text-[12px] font-semibold text-[#07074E] ml-1">Contact Person</label>
                    <input
                      type="text"
                      defaultValue="Priya Sharma"
                      className="h-11 bg-[#F8F8FF] border border-[#EDEDF8] rounded-[12px] px-4 text-[14px] font-medium text-[#07074E] focus:outline-none focus:border-[#7387FF] focus:ring-4 focus:ring-[#7387FF]/5 transition-all"
                    />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <label className="text-[12px] font-semibold text-[#07074E] ml-1">Work Email</label>
                    <input
                      type="email"
                      defaultValue="priya@urbanic.in"
                      className="h-11 bg-[#F8F8FF] border border-[#EDEDF8] rounded-[12px] px-4 text-[14px] font-medium text-[#07074E] focus:outline-none focus:border-[#7387FF] focus:ring-4 focus:ring-[#7387FF]/5 transition-all"
                    />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <label className="text-[12px] font-semibold text-[#07074E] ml-1">Phone Number</label>
                    <input
                      type="text"
                      defaultValue="+91 98765 43210"
                      className="h-11 bg-[#F8F8FF] border border-[#EDEDF8] rounded-[12px] px-4 text-[14px] font-medium text-[#07074E] focus:outline-none focus:border-[#7387FF] focus:ring-4 focus:ring-[#7387FF]/5 transition-all"
                    />
                  </div>
                  <div className="flex flex-col gap-1.5 col-span-2">
                    <label className="text-[12px] font-semibold text-[#07074E] ml-1">Website URL</label>
                    <div className="relative">
                      <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-[#9F9FD1]" />
                      <input
                        type="text"
                        defaultValue="https://urbanic.in"
                        className="w-full h-11 bg-[#F8F8FF] border border-[#EDEDF8] rounded-[12px] pl-11 pr-4 text-[14px] font-medium text-[#07074E] focus:outline-none focus:border-[#7387FF] focus:ring-4 focus:ring-[#7387FF]/5 transition-all"
                      />
                    </div>
                  </div>
                </div>
              </div>

              <div className="pt-6 border-t border-[#F3F3FF] flex justify-end gap-3">
                <button className="px-6 py-2.5 rounded-[12px] text-[13px] font-semibold text-[#9F9FD1] hover:bg-[#F3F3FF] transition-all">
                  Cancel
                </button>
                <button className="px-8 py-2.5 rounded-[12px] bg-[#7387FF] text-white text-[13px] font-semibold shadow-[0_4px_16px_rgba(115,135,255,0.25)] hover:brightness-105 active:scale-[0.98] transition-all">
                  Save Changes
                </button>
              </div>
            </div>
          </div>
        )}

        {/* 2. Company Details Card */}
        {activeTab === "company" && (
          <div className="bg-white rounded-[24px] shadow-[0_4px_28px_rgba(7,7,78,0.07)] border border-[#EDEDF8]/60 overflow-hidden">
            <SectionHeader
              icon={Building2}
              title="Company Details"
              subtitle="Official information for billing, verification, and legal compliance"
              badge={
                <div className="flex items-center gap-1.5 bg-[#E8F8EE] border border-[#27AE60]/20 px-3 py-1.5 rounded-full">
                  <CheckCircle2 className="w-4 h-4 text-[#27AE60]" />
                  <span className="text-[11px] font-bold text-[#27AE60] uppercase tracking-wider">KYB Verified</span>
                </div>
              }
            />
            <div className="p-8 grid grid-cols-2 gap-x-6 gap-y-6">
              <div className="flex flex-col gap-1.5">
                <label className="text-[12px] font-semibold text-[#07074E] ml-1">Business Type</label>
                <select className="h-11 bg-[#F8F8FF] border border-[#EDEDF8] rounded-[12px] px-4 text-[14px] font-medium text-[#07074E] focus:outline-none focus:border-[#7387FF] transition-all appearance-none">
                  <option>D2C E-commerce</option>
                  <option>Digital Agency</option>
                  <option>SaaS Platform</option>
                  <option>Lifestyle Brand</option>
                </select>
              </div>
              <div className="flex flex-col gap-1.5">
                <label className="text-[12px] font-semibold text-[#07074E] ml-1">GST Number</label>
                <input
                  type="text"
                  defaultValue="27AABCU1234F1Z5"
                  className="h-11 bg-[#F8F8FF] border border-[#EDEDF8] rounded-[12px] px-4 text-[14px] font-medium text-[#07074E] focus:outline-none focus:border-[#7387FF] transition-all"
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <label className="text-[12px] font-semibold text-[#07074E] ml-1">Business Category</label>
                <select className="h-11 bg-[#F8F8FF] border border-[#EDEDF8] rounded-[12px] px-4 text-[14px] font-medium text-[#07074E] focus:outline-none focus:border-[#7387FF] transition-all appearance-none">
                  <option>Fashion & Apparel</option>
                  <option>Beauty & Wellness</option>
                  <option>Home & Living</option>
                  <option>Food & Beverage</option>
                </select>
              </div>
              <div className="flex flex-col gap-1.5">
                <label className="text-[12px] font-semibold text-[#07074E] ml-1">Country</label>
                <input
                  type="text"
                  defaultValue="India"
                  readOnly
                  className="h-11 bg-[#F3F3FF] border border-[#EDEDF8] rounded-[12px] px-4 text-[14px] font-medium text-[#9F9FD1]"
                />
              </div>
              <div className="flex flex-col gap-1.5 col-span-2">
                <label className="text-[12px] font-semibold text-[#07074E] ml-1">Billing Address</label>
                <textarea
                  defaultValue="4th Floor, Urbanic HQ, Phase II, Bandra East"
                  rows={2}
                  className="bg-[#F8F8FF] border border-[#EDEDF8] rounded-[12px] px-4 py-3 text-[14px] font-medium text-[#07074E] focus:outline-none focus:border-[#7387FF] transition-all"
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <label className="text-[12px] font-semibold text-[#07074E] ml-1">City</label>
                <input
                  type="text"
                  defaultValue="Mumbai"
                  className="h-11 bg-[#F8F8FF] border border-[#EDEDF8] rounded-[12px] px-4 text-[14px] font-medium text-[#07074E] focus:outline-none focus:border-[#7387FF] transition-all"
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <label className="text-[12px] font-semibold text-[#07074E] ml-1">State</label>
                <input
                  type="text"
                  defaultValue="Maharashtra"
                  className="h-11 bg-[#F8F8FF] border border-[#EDEDF8] rounded-[12px] px-4 text-[14px] font-medium text-[#07074E] focus:outline-none focus:border-[#7387FF] transition-all"
                />
              </div>
              <div className="col-span-2 pt-4 flex justify-end gap-3">
                <button className="px-8 py-2.5 rounded-[12px] bg-[#07074E] text-white text-[13px] font-semibold hover:brightness-110 transition-all">
                  Update Official Info
                </button>
              </div>
            </div>
          </div>
        )}

        {/* 3. Team Members Card */}
        {activeTab === "team" && (
          <div className="bg-white rounded-[24px] shadow-[0_4px_28px_rgba(7,7,78,0.07)] border border-[#EDEDF8]/60 overflow-hidden">
            <SectionHeader
              icon={Users}
              title="Team Members"
              subtitle="Invite and manage workspace collaborators and their permissions"
              badge={
                <button className="flex items-center gap-2 bg-[#7387FF] text-white px-4 py-2 rounded-[10px] text-[12px] font-semibold shadow-[0_4px_10px_rgba(115,135,255,0.2)] hover:brightness-105 active:scale-[0.98] transition-all">
                  <Plus className="w-3.5 h-3.5" />
                  Invite Member
                </button>
              }
            />
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="bg-[#F8F8FF] border-b border-[#F3F3FF]">
                    <th className="px-7 py-4 text-left text-[11px] font-bold text-[#9F9FD1] uppercase tracking-wider">Member</th>
                    <th className="px-7 py-4 text-left text-[11px] font-bold text-[#9F9FD1] uppercase tracking-wider">Role</th>
                    <th className="px-7 py-4 text-left text-[11px] font-bold text-[#9F9FD1] uppercase tracking-wider">Status</th>
                    <th className="px-7 py-4 text-right text-[11px] font-bold text-[#9F9FD1] uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#F3F3FF]">
                  {TEAM_MEMBERS.map((member) => (
                    <tr key={member.id} className="hover:bg-[#F9F9FF] transition-colors group">
                      <td className="px-7 py-4">
                        <div className="flex items-center gap-3">
                          <img
                            src={member.avatar}
                            className="w-10 h-10 rounded-full object-cover ring-2 ring-[#F3F3FF]"
                            alt={member.name}
                          />
                          <div>
                            <p className="text-[14px] font-semibold text-[#07074E]">{member.name}</p>
                            <p className="text-[12px] font-medium text-[#9F9FD1]">{member.email}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-7 py-4">
                        <span className={`inline-flex px-2.5 py-1 rounded-full text-[11px] font-bold uppercase tracking-wider ${
                          member.role === 'Admin' ? 'bg-[#7387FF]/10 text-[#7387FF]' : 'bg-[#F3F3FF] text-[#9F9FD1]'
                        }`}>
                          {member.role}
                        </span>
                      </td>
                      <td className="px-7 py-4">
                        <span className={`inline-flex items-center gap-1.5 text-[12px] font-semibold ${
                          member.status === 'Active' ? 'text-[#27AE60]' : 'text-[#F39C12]'
                        }`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${member.status === 'Active' ? 'bg-[#27AE60]' : 'bg-[#F39C12]'}`} />
                          {member.status}
                        </span>
                      </td>
                      <td className="px-7 py-4 text-right">
                        <button className="w-8 h-8 rounded-full flex items-center justify-center text-[#9F9FD1] hover:bg-[#F3F3FF] hover:text-[#07074E] transition-all">
                          <MoreVertical className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="px-7 py-4 border-t border-[#F3F3FF] bg-[#F8F8FF]/50">
              <p className="text-[12px] text-[#9F9FD1] font-medium">
                Workspace limit: <span className="text-[#07074E] font-semibold">3 / 10 seats used</span>. Pro plan allows up to 10 members.
              </p>
            </div>
          </div>
        )}

        {/* 4. Billing & Plan Card */}
        {activeTab === "billing" && (
          <div className="bg-white rounded-[24px] shadow-[0_4px_28px_rgba(7,7,78,0.07)] border border-[#EDEDF8]/60 overflow-hidden">
            <SectionHeader
              icon={CreditCard}
              title="Billing & Subscription"
              subtitle="Manage your current plan, payment methods, and view billing history"
            />
            <div className="p-8 flex flex-col gap-8">
              {/* Plan Hero Card */}
              <div className="bg-gradient-to-br from-[#07074E] to-[#1A1A8A] rounded-[22px] p-7 text-white flex items-center justify-between relative overflow-hidden">
                <div className="absolute top-[-40px] right-[-20px] w-48 h-48 rounded-full bg-[#7387FF]/20 blur-3xl" />
                <div className="flex flex-col gap-1 relative z-10">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="px-3 py-1 rounded-full bg-white/20 border border-white/30 text-[11px] font-bold uppercase tracking-wider backdrop-blur-sm">
                      Current Plan
                    </div>
                    <Sparkles className="w-4 h-4 text-[#F39C12] fill-[#F39C12]" />
                  </div>
                  <h4 className="text-[28px] font-bold font-heading">Brand Pro</h4>
                  <p className="text-white/60 text-[14px] font-medium">Next billing: <span className="text-white">June 15, 2026</span></p>
                </div>
                <div className="flex flex-col items-end gap-3 relative z-10">
                  <div className="text-right">
                    <p className="text-white/50 text-[11px] font-bold uppercase tracking-widest">Commission Rate</p>
                    <p className="text-[24px] font-bold">20%</p>
                  </div>
                  <button className="bg-white text-[#07074E] px-6 py-2.5 rounded-[12px] text-[13px] font-bold hover:shadow-lg hover:-translate-y-0.5 active:scale-[0.98] transition-all">
                    Upgrade to Enterprise
                  </button>
                </div>
              </div>

              {/* Usage Progress */}
              <div className="bg-[#F8F8FF] rounded-[20px] p-6 border border-[#EDEDF8]">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <TrendingUp className="w-4 h-4 text-[#7387FF]" />
                    <span className="text-[14px] font-semibold text-[#07074E]">Monthly Campaign Budget Progress</span>
                  </div>
                  <span className="text-[14px] font-bold text-[#7387FF]">₹1,25,000 / ₹5,00,000</span>
                </div>
                <div className="h-2.5 bg-[#E8E8F8] rounded-full overflow-hidden">
                  <div className="h-full bg-gradient-to-r from-[#7387FF] to-[#B0BAFF] rounded-full transition-all duration-1000" style={{ width: '25%' }} />
                </div>
                <div className="flex items-center justify-between mt-3">
                  <p className="text-[12px] text-[#9F9FD1] font-medium">25% of budget used this month</p>
                  <p className="text-[12px] text-[#27AE60] font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Normal usage
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-4">
                <button className="flex items-center gap-2 px-5 py-2.5 rounded-[12px] border border-[#EDEDF8] text-[13px] font-semibold text-[#07074E] hover:bg-[#F3F3FF] transition-all">
                  <History className="w-4 h-4 text-[#7387FF]" />
                  Billing History
                </button>
                <button className="flex items-center gap-2 px-5 py-2.5 rounded-[12px] border border-[#EDEDF8] text-[13px] font-semibold text-[#07074E] hover:bg-[#F3F3FF] transition-all">
                  <CreditCard className="w-4 h-4 text-[#7387FF]" />
                  Payment Methods
                </button>
              </div>
            </div>
          </div>
        )}

        {/* 5. Notifications Card */}
        {activeTab === "notifications" && (
          <div className="bg-white rounded-[24px] shadow-[0_4px_28px_rgba(7,7,78,0.07)] border border-[#EDEDF8]/60 overflow-hidden">
            <SectionHeader
              icon={Bell}
              title="Notification Settings"
              subtitle="Configure how and when you want to be notified about workspace activities"
            />
            <div className="py-4">
              {[
                { key: "applications", icon: Users, label: "New Creator Applications", sub: "Alert when a creator applies to your brief" },
                { key: "dealUpdates", icon: RefreshCw, label: "Deal Status Updates", sub: "Milestone changes and content delivery alerts" },
                { key: "payments", icon: IndianRupeeIcon, label: "Payment & Escrow Alerts", sub: "Wallet recharges and escrow lock notifications" },
                { key: "messages", icon: MessageSquare, label: "Direct Messages", sub: "Instant alerts for new chat messages from creators" },
                { key: "weeklyReports", icon: FileText, label: "Weekly Workspace Reports", sub: "Summarized digest of your campaign performance" },
              ].map((item, i, arr) => (
                <div key={item.key}>
                  <div className="px-8 py-5 flex items-center justify-between hover:bg-[#F9F9FF] transition-colors group">
                    <div className="flex items-center gap-4">
                      <div className={`w-10 h-10 rounded-[14px] flex items-center justify-center transition-colors ${notifs[item.key as keyof typeof notifs] ? 'bg-[#7387FF]/10 text-[#7387FF]' : 'bg-[#F3F3FF] text-[#B7B7E6]'}`}>
                        <item.icon className="w-5 h-5" strokeWidth={1.8} />
                      </div>
                      <div>
                        <p className={`text-[14px] font-semibold transition-colors ${notifs[item.key as keyof typeof notifs] ? 'text-[#07074E]' : 'text-[#9F9FD1]'}`}>{item.label}</p>
                        <p className="text-[12px] font-medium text-[#9F9FD1] mt-0.5">{item.sub}</p>
                      </div>
                    </div>
                    <Toggle active={notifs[item.key as keyof typeof notifs]} onToggle={() => toggleNotif(item.key as keyof typeof notifs)} />
                  </div>
                  {i < arr.length - 1 && <div className="h-px bg-[#F3F3FF] mx-8" />}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* 6. Security Card */}
        {activeTab === "security" && (
          <div className="bg-white rounded-[24px] shadow-[0_4px_28px_rgba(7,7,78,0.07)] border border-[#EDEDF8]/60 overflow-hidden">
            <SectionHeader
              icon={Lock}
              title="Security & Access"
              subtitle="Manage your credentials, authentication methods, and active login sessions"
            />
            <div className="p-8 flex flex-col gap-8">
              {/* Row 1: Password & 2FA */}
              <div className="grid grid-cols-2 gap-6">
                <div className="p-6 rounded-[20px] bg-[#F8F8FF] border border-[#EDEDF8] flex flex-col gap-4">
                  <div className="w-10 h-10 rounded-[14px] bg-[#7387FF]/10 flex items-center justify-center">
                    <ShieldCheck className="w-5 h-5 text-[#7387FF]" />
                  </div>
                  <div>
                    <h5 className="text-[15px] font-bold text-[#07074E]">Login Password</h5>
                    <p className="text-[12px] font-medium text-[#9F9FD1] mt-1">Last updated: 3 months ago</p>
                  </div>
                  <button className="w-fit bg-white border border-[#EDEDF8] px-5 py-2.5 rounded-[12px] text-[13px] font-bold text-[#07074E] hover:bg-[#F3F3FF] transition-all">
                    Change Password
                  </button>
                </div>
                <div className="p-6 rounded-[20px] bg-[#F8F8FF] border border-[#EDEDF8] flex flex-col gap-4">
                  <div className="w-10 h-10 rounded-[14px] bg-[#27AE60]/10 flex items-center justify-center">
                    <Smartphone className="w-5 h-5 text-[#27AE60]" />
                  </div>
                  <div className="flex items-center justify-between">
                    <div>
                      <h5 className="text-[15px] font-bold text-[#07074E]">Two-Factor Auth</h5>
                      <p className="text-[12px] font-medium text-[#27AE60] mt-1 font-bold">Currently Enabled</p>
                    </div>
                    <Toggle active={true} onToggle={() => {}} />
                  </div>
                  <button className="w-fit bg-white border border-[#EDEDF8] px-5 py-2.5 rounded-[12px] text-[13px] font-bold text-[#07074E] hover:bg-[#F3F3FF] transition-all">
                    Configure SMS/App
                  </button>
                </div>
              </div>

              {/* Row 2: Active Sessions */}
              <div className="flex flex-col gap-4">
                <h5 className="text-[14px] font-bold text-[#07074E] ml-1">Active Login Sessions</h5>
                <div className="flex flex-col gap-2.5">
                  {SESSIONS.map((session) => (
                    <div key={session.id} className="flex items-center justify-between p-4 rounded-[16px] border border-[#F3F3FF] hover:border-[#EDEDF8] transition-all">
                      <div className="flex items-center gap-3.5">
                        <div className="w-9 h-9 rounded-full bg-[#F3F3FF] flex items-center justify-center text-[#9F9FD1]">
                          <Monitor className="w-4 h-4" />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <p className="text-[13.5px] font-semibold text-[#07074E]">{session.device}</p>
                            {session.current && <span className="px-2 py-0.5 rounded-full bg-[#E8F8EE] text-[#27AE60] text-[9px] font-bold uppercase tracking-wider">Current</span>}
                          </div>
                          <p className="text-[11.5px] font-medium text-[#9F9FD1]">{session.time}</p>
                        </div>
                      </div>
                      <button className="p-2 rounded-lg text-[#9F9FD1] hover:bg-[#FFF0F0] hover:text-[#E74C3C] transition-all">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── RIGHT AREA ────────────────────────────────────────────────────── */}
      <div className="w-[300px] flex-shrink-0 flex flex-col gap-6">
        
        {/* Workspace Status Card */}
        <div className="bg-[#07074E] rounded-[24px] p-6 text-white shadow-[0_12px_40px_rgba(7,7,78,0.25)] relative overflow-hidden">
          <div className="absolute top-[-20px] right-[-20px] w-24 h-24 rounded-full bg-white/5" />
          <h4 className="text-[15px] font-bold font-heading mb-5 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-[#7387FF]" />
            Workspace Status
          </h4>
          <div className="flex flex-col gap-4">
            <div className="flex items-center justify-between py-2 border-b border-white/10">
              <span className="text-[12px] text-white/50 font-medium uppercase tracking-wider">Active Plan</span>
              <span className="text-[13px] font-bold text-[#7387FF]">Pro</span>
            </div>
            <div className="flex items-center justify-between py-2 border-b border-white/10">
              <span className="text-[12px] text-white/50 font-medium uppercase tracking-wider">Wallet</span>
              <span className="text-[13px] font-bold">₹4,25,600</span>
            </div>
            <div className="flex items-center justify-between py-2">
              <span className="text-[12px] text-white/50 font-medium uppercase tracking-wider">Team Count</span>
              <span className="text-[13px] font-bold">3 Members</span>
            </div>
          </div>
          <button className="w-full mt-6 py-3 rounded-[12px] bg-white/10 border border-white/20 text-[12.5px] font-bold hover:bg-white/20 transition-all">
            View Workspace Analytics
          </button>
        </div>

        {/* Quick Actions Card */}
        <div className="bg-white rounded-[24px] p-6 shadow-[0_4px_20px_rgba(7,7,78,0.05)] border border-[#EDEDF8]/60">
          <h4 className="text-[15px] font-bold text-[#07074E] mb-4">Quick Actions</h4>
          <div className="flex flex-col gap-2">
            {[
              { label: "Invite Team", icon: Users, color: "#7387FF", bg: "#EEF0FF" },
              { label: "Upgrade Plan", icon: Zap, color: "#F39C12", bg: "#FFF8E8" },
              { label: "Contact Support", icon: LifeBuoy, color: "#27AE60", bg: "#E8F8EE" },
              { label: "Download Reports", icon: Download, color: "#9F9FD1", bg: "#F3F3FF" },
            ].map((action) => (
              <button
                key={action.label}
                className="flex items-center gap-3 p-3 rounded-[14px] hover:bg-[#F9F9FF] transition-all group"
              >
                <div className="w-9 h-9 rounded-[11px] flex items-center justify-center transition-transform group-hover:scale-110" style={{ background: action.bg }}>
                  <action.icon className="w-4 h-4" style={{ color: action.color }} />
                </div>
                <span className="text-[13px] font-semibold text-[#4A4A7A] group-hover:text-[#07074E]">{action.label}</span>
                <ChevronRight className="w-3.5 h-3.5 ml-auto text-[#C4C4E8] group-hover:translate-x-0.5 transition-all" />
              </button>
            ))}
          </div>
        </div>

        {/* Help Banner */}
        <div className="bg-[#7387FF]/5 rounded-[24px] p-5 border border-[#7387FF]/15 text-center">
          <div className="w-10 h-10 rounded-full bg-white mx-auto mb-3 flex items-center justify-center shadow-sm">
            <HelpCircle className="w-5 h-5 text-[#7387FF]" />
          </div>
          <p className="text-[14px] font-bold text-[#07074E]">Need Help?</p>
          <p className="text-[11.5px] font-medium text-[#9F9FD1] mt-1 mb-4 leading-relaxed">
            Our support team is here to help you optimize your workspace.
          </p>
          <button className="text-[12px] font-bold text-[#7387FF] hover:text-[#07074E] transition-colors underline decoration-2 underline-offset-4">
            Visit Help Center
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Extra Icons for dynamic usage ───
function IndianRupeeIcon(props: any) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M6 3h12" />
      <path d="M6 8h12" />
      <path d="m6 13 8.5 8" />
      <path d="M6 13h3" />
      <path d="M9 13c6.667 0 6.667-10 0-10" />
    </svg>
  );
}

function HelpCircle(props: any) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="10" />
      <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
      <path d="M12 17h.01" />
    </svg>
  );
}

function LifeBuoy(props: any) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="10" />
      <circle cx="12" cy="12" r="4" />
      <path d="m4.93 4.93 4.24 4.24" />
      <path d="m14.83 9.17 4.24-4.24" />
      <path d="m14.83 14.83 4.24 4.24" />
      <path d="m9.17 14.83-4.24 4.24" />
    </svg>
  );
}
