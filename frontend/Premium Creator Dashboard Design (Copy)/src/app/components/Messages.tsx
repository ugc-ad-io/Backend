import { useState } from "react";
import {
  Search,
  Phone,
  MoreHorizontal,
  Paperclip,
  Smile,
  Mic,
  Send,
  FileText,
  HelpCircle,
  CheckCheck,
  Play,
  ChevronRight,
  CalendarDays,
  AlertCircle,
  Zap,
  IndianRupee,
  ExternalLink,
  Image as ImageIcon,
  RotateCcw,
  Box,
  Truck,
  ShieldAlert,
  History,
  TrendingUp,
  MessageSquare,
} from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────

interface Conversation {
  id: number;
  name: string;
  role: string;
  initial: string;
  color: string;
  preview: string;
  time: string;
  unread: number;
  deal: boolean;
  online: boolean;
}

interface Message {
  id: number;
  sender: "brand" | "creator" | "system";
  type: "text" | "action" | "system";
  text?: string;
  time?: string;

  // Action card specific
  actionTitle?: string;
  actionDesc?: string;
  actionMeta?: string;
  actionCta?: string;
  actionIcon?: any;
}

// ─── Mock Data ─────────────────────────────────────────────────────────────────

const CONVERSATIONS: Conversation[] = [
  {
    id: 1,
    name: "Glow & Co",
    role: "UGC Creator",
    initial: "G",
    color: "#7387FF",
    preview: "Just submitted the final delivery — please review when you get a chance! 🙏",
    time: "2m",
    unread: 2,
    deal: true,
    online: true,
  },
  {
    id: 2,
    name: "Alex Fitness",
    role: "Fitness Creator",
    initial: "A",
    color: "#27AE60",
    preview: "Payment has been processed successfully.",
    time: "1h",
    unread: 0,
    deal: true,
    online: false,
  },
  {
    id: 3,
    name: "Sarah Styles",
    role: "Fashion Creator",
    initial: "S",
    color: "#F39C12",
    preview: "Hey! We'd like to revise the color grading on reel 2.",
    time: "3h",
    unread: 1,
    deal: false,
    online: true,
  },
  {
    id: 4,
    name: "Tech Reviews",
    role: "Tech Creator",
    initial: "T",
    color: "#E74C3C",
    preview: "Thanks for submitting the final deliverable!",
    time: "Yesterday",
    unread: 0,
    deal: true,
    online: false,
  },
  {
    id: 5,
    name: "UGCad Support",
    role: "Platform Support",
    initial: "U",
    color: "#9F9FD1",
    preview: "Your support ticket #4821 has been resolved.",
    time: "2d",
    unread: 0,
    deal: false,
    online: false,
  },
];

const MESSAGES: Message[] = [
  {
    id: 1,
    sender: "system",
    type: "system",
    text: "Deal moved to Production Stage",
    time: "10:20 AM",
  },
  {
    id: 2,
    sender: "creator",
    type: "text",
    text: "Hey! I've received the product and it looks great. Planning to shoot the main hooks tomorrow morning.",
    time: "10:24 AM",
  },
  {
    id: 3,
    sender: "brand",
    type: "text",
    text: "Perfect! Please remember to emphasize the summer discount code in the first 3 seconds.",
    time: "10:31 AM",
  },
  {
    id: 4,
    sender: "creator",
    type: "text",
    text: "Will do! Just to be sure, the code is SUMMER25, right?",
    time: "10:32 AM",
  },
  {
    id: 5,
    sender: "brand",
    type: "text",
    text: "Yes, that's correct.",
    time: "10:45 AM",
  },
  {
    id: 6,
    sender: "creator",
    type: "action",
    actionTitle: "Milestone Update",
    actionDesc: "A-Roll and B-Roll footage completed. Moving to editing phase.",
    actionMeta: "Production Phase · May 12",
    actionCta: "View Drafts",
    actionIcon: TrendingUp,
    time: "2:15 PM",
  },
  {
    id: 7,
    sender: "system",
    type: "system",
    text: "Deal moved to Review Stage",
    time: "4:00 PM",
  },
  {
    id: 8,
    sender: "creator",
    type: "action",
    actionTitle: "Delivery Submitted",
    actionDesc: "Final UGC Reel (15s) has been uploaded for your review.",
    actionMeta: "184 MB · MP4 Format",
    actionCta: "Review Content",
    actionIcon: Play,
    time: "4:05 PM",
  },
  {
    id: 9,
    sender: "creator",
    type: "text",
    text: "Just submitted the final delivery — please review when you get a chance! 🙏",
    time: "4:06 PM",
  },
];

const FILES = [
  { name: "Campaign_Brief_Summer.pdf", size: "2.4 MB", icon: FileText, color: "#E74C3C" },
  { name: "Script_v2_Final.docx", size: "340 KB", icon: FileText, color: "#7387FF" },
  { name: "Reference_Moodboard.jpg", size: "1.2 MB", icon: ImageIcon, color: "#27AE60" },
];

const TABS = ["All", "Unread", "Deals", "Support"];

const ACTION_PILLS = [
  "Custom Offer",
  "Revision Request",
  "Milestone Update",
  "Damage Report",
  "Escalate",
  "Dispute",
];

// ─── Component ────────────────────────────────────────────────────────────────

export function Messages() {
  const [activeTab, setActiveTab] = useState("all");
  const [activeConv, setActiveConv] = useState(1);
  const [inputValue, setInputValue] = useState("");
  const [searchQuery, setSearchQuery] = useState("");

  const activeConversation = CONVERSATIONS.find((c) => c.id === activeConv)!;

  const filteredConversations = CONVERSATIONS.filter((c) => {
    if (activeTab === "unread") return c.unread > 0;
    if (activeTab === "deals") return c.deal;
    if (activeTab === "support") return !c.deal;
    return true;
  }).filter((c) =>
    searchQuery ? c.name.toLowerCase().includes(searchQuery.toLowerCase()) : true
  );

  return (
    <div className="h-full flex gap-5 min-h-0 font-sans text-[#07074E]">
      
      {/* ══════════════════════════════════════════
          CHAT LIST PANEL
      ══════════════════════════════════════════ */}
      <div className="w-[320px] flex-shrink-0 flex flex-col h-full min-h-0">
        <div className="bg-white rounded-[20px] shadow-[0_2px_16px_rgba(7,7,78,0.04)] border border-[#EAEAF5] flex flex-col h-full min-h-0 overflow-hidden">
          
          {/* Panel header */}
          <div className="px-6 pt-6 pb-4 flex-shrink-0">
            <h2 className="text-[20px] font-bold text-[#07074E] tracking-tight mb-1">Messages</h2>
            <p className="text-[12px] font-medium text-[#9F9FD1] mb-5">Manage your campaign conversations</p>
            
            {/* Search */}
            <div className="flex items-center gap-2.5 bg-[#F5F6FF] rounded-[12px] px-3.5 py-2.5 mb-4 border border-[#EAEAF5]/60">
              <Search strokeWidth={1.8} className="w-4 h-4 text-[#9F9FD1] flex-shrink-0" />
              <input
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search messages..."
                className="flex-1 bg-transparent text-[13px] font-medium text-[#07074E] placeholder-[#9F9FD1] outline-none"
              />
            </div>

            {/* Tab pills */}
            <div className="flex gap-1.5">
              {TABS.map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab.toLowerCase())}
                  className={`flex-1 py-1.5 rounded-full text-[12px] font-semibold transition-colors ${
                    activeTab === tab.toLowerCase()
                      ? "bg-[#F3F3FF] text-[#7387FF] border border-[#7387FF]/20"
                      : "text-[#9F9FD1] hover:bg-[#F5F6FF] hover:text-[#07074E] border border-transparent"
                  }`}
                >
                  {tab}
                </button>
              ))}
            </div>
          </div>

          <div className="h-px bg-[#EAEAF5] mx-6 mb-2 flex-shrink-0" />

          {/* Conversation list */}
          <div className="flex-1 overflow-y-auto min-h-0 py-2 px-3">
            {filteredConversations.map((conv) => (
              <button
                key={conv.id}
                onClick={() => setActiveConv(conv.id)}
                className={`w-full flex items-start gap-4 p-3 rounded-[16px] transition-all text-left mb-2 border ${
                  activeConv === conv.id 
                    ? "bg-[#EEF0FF] border-[#7387FF]/20 shadow-[0_2px_8px_rgba(115,135,255,0.08)]" 
                    : "bg-transparent border-transparent hover:bg-[#F5F6FF]"
                }`}
              >
                {/* Avatar */}
                <div className="relative flex-shrink-0 mt-0.5">
                  <div
                    className="w-11 h-11 rounded-full flex items-center justify-center text-white text-[15px] font-bold shadow-sm"
                    style={{ backgroundColor: conv.color }}
                  >
                    {conv.initial}
                  </div>
                  {conv.online && (
                    <div className="absolute bottom-0 right-0 w-3 h-3 bg-[#27AE60] rounded-full border-2 border-white" />
                  )}
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-0.5">
                    <span className={`text-[14px] font-bold truncate ${activeConv === conv.id ? "text-[#7387FF]" : "text-[#07074E]"}`}>
                      {conv.name}
                    </span>
                    <span className="text-[11px] font-semibold text-[#9F9FD1] flex-shrink-0 ml-2">
                      {conv.time}
                    </span>
                  </div>
                  <div className="flex items-start justify-between gap-2">
                    <p className={`text-[12px] font-medium truncate flex-1 ${activeConv === conv.id ? "text-[#07074E]/80" : "text-[#9F9FD1]"}`}>
                      {conv.preview}
                    </p>
                    {conv.unread > 0 && (
                      <span className="min-w-[20px] h-5 px-1.5 rounded-full bg-[#7387FF] text-white text-[11px] font-bold flex items-center justify-center flex-shrink-0 shadow-sm mt-0.5">
                        {conv.unread}
                      </span>
                    )}
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* ══════════════════════════════════════════
          ACTIVE CONVERSATION AREA
      ══════════════════════════════════════════ */}
      <div className="flex-1 flex flex-col h-full min-h-0">
        <div className="bg-white rounded-[20px] shadow-[0_2px_16px_rgba(7,7,78,0.04)] border border-[#EAEAF5] flex flex-col h-full min-h-0 overflow-hidden relative">
          
          {/* Chat Header */}
          <div className="px-6 py-4 border-b border-[#EAEAF5] flex items-center justify-between flex-shrink-0 bg-white z-10">
            <div className="flex items-center gap-4">
              <div className="relative flex-shrink-0">
                <div
                  className="w-[46px] h-[46px] rounded-full flex items-center justify-center text-white text-[16px] font-bold shadow-sm"
                  style={{ backgroundColor: activeConversation.color }}
                >
                  {activeConversation.initial}
                </div>
                {activeConversation.online && (
                  <div className="absolute bottom-0 right-0 w-3 h-3 bg-[#27AE60] rounded-full border-2 border-white" />
                )}
              </div>

              <div className="flex flex-col justify-center">
                <div className="flex items-center gap-2.5">
                  <h2 className="text-[16px] font-bold text-[#07074E]">
                    {activeConversation.name}
                  </h2>
                  {activeConversation.deal && (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#EEF0FF] text-[#7387FF] text-[11px] font-bold border border-[#7387FF]/20">
                      <Zap strokeWidth={2.5} className="w-3 h-3" />
                      Live Deal
                    </span>
                  )}
                </div>
                <p className="text-[12px] font-semibold text-[#9F9FD1] mt-0.5 flex items-center gap-1.5">
                  {activeConversation.online ? (
                    <>
                      <span className="w-1.5 h-1.5 rounded-full bg-[#27AE60]" />
                      <span className="text-[#27AE60]">Online now</span>
                    </>
                  ) : (
                    <span>Offline</span>
                  )}
                </p>
              </div>
            </div>

            {/* Quick Icons */}
            <div className="flex items-center gap-2 flex-shrink-0">
              {[
                { icon: Phone, label: "Call" },
                { icon: Search, label: "Search" },
                { icon: FileText, label: "Files" },
                { icon: MoreHorizontal, label: "More" },
              ].map(({ icon: Icon, label }) => (
                <button
                  key={label}
                  title={label}
                  className="w-10 h-10 rounded-full border border-[#EAEAF5] bg-white flex items-center justify-center hover:bg-[#F5F6FF] hover:border-[#7387FF]/30 transition-all text-[#07074E]"
                >
                  <Icon strokeWidth={2} className="w-[18px] h-[18px]" />
                </button>
              ))}
            </div>
          </div>

          {/* Messages Area */}
          <div className="flex-1 overflow-y-auto min-h-0 px-8 py-8 flex flex-col gap-6 bg-[#FAFAFE]">
            {MESSAGES.map((msg) => {
              if (msg.type === "system") {
                return (
                  <div key={msg.id} className="flex justify-center my-2">
                    <span className="px-4 py-1.5 rounded-full bg-[#EAEAF5]/60 border border-[#D4D4E8]/50 text-[11px] font-bold text-[#9F9FD1] uppercase tracking-wider">
                      {msg.text}
                    </span>
                  </div>
                );
              }

              const isBrand = msg.sender === "brand";

              return (
                <div key={msg.id} className={`flex flex-col gap-1.5 max-w-[70%] ${isBrand ? "self-end items-end" : "self-start items-start"}`}>
                  
                  {msg.type === "action" ? (
                    // Action Card
                    <div className="bg-white rounded-[16px] border border-[#EAEAF5] shadow-[0_4px_20px_rgba(7,7,78,0.05)] w-[340px] overflow-hidden mb-1">
                      <div className="px-5 py-4 border-b border-[#EAEAF5] flex items-center gap-3 bg-[#FAFAFE]">
                        <div className="w-8 h-8 rounded-full bg-[#EEF0FF] flex items-center justify-center text-[#7387FF]">
                          {msg.actionIcon && <msg.actionIcon strokeWidth={2.5} className="w-4 h-4" />}
                        </div>
                        <span className="text-[12px] font-bold text-[#7387FF] uppercase tracking-wider">
                          {msg.actionTitle}
                        </span>
                      </div>
                      <div className="p-5">
                        <p className="text-[14px] font-medium text-[#07074E] leading-relaxed mb-3">
                          {msg.actionDesc}
                        </p>
                        <p className="text-[12px] font-medium text-[#9F9FD1] mb-4">
                          {msg.actionMeta}
                        </p>
                        <button className="w-full py-2.5 rounded-[10px] bg-[#07074E] text-white text-[13px] font-bold shadow-sm hover:bg-[#7387FF] transition-colors">
                          {msg.actionCta}
                        </button>
                      </div>
                    </div>
                  ) : (
                    // Text Bubble
                    <div
                      className={`px-5 py-3.5 rounded-[20px] text-[14px] font-medium leading-relaxed shadow-sm
                        ${isBrand 
                          ? "bg-[#7387FF] text-white rounded-br-[6px]" 
                          : "bg-white text-[#07074E] border border-[#EAEAF5] rounded-bl-[6px]"
                        }
                      `}
                    >
                      {msg.text}
                    </div>
                  )}

                  {/* Timestamp */}
                  <span className={`text-[11px] font-semibold text-[#9F9FD1] px-1 ${isBrand ? "text-right" : "text-left"}`}>
                    {msg.time}
                  </span>
                </div>
              );
            })}
          </div>

          {/* Composer Area */}
          <div className="bg-white border-t border-[#EAEAF5] flex-shrink-0 pb-4 pt-3 px-6">
            
            {/* Action Pills */}
            <div className="flex gap-2 overflow-x-auto pb-3 scrollbar-hide">
              {ACTION_PILLS.map((pill) => (
                <button
                  key={pill}
                  className="whitespace-nowrap px-4 py-1.5 rounded-full border border-[#EAEAF5] bg-white text-[12px] font-bold text-[#07074E] hover:border-[#7387FF]/50 hover:bg-[#F5F6FF] transition-all shadow-sm"
                >
                  {pill}
                </button>
              ))}
            </div>

            {/* Input Row */}
            <div className="flex items-end gap-3 bg-[#F5F6FF] rounded-[20px] border border-[#EAEAF5] p-2 focus-within:border-[#7387FF]/50 focus-within:ring-2 focus-within:ring-[#7387FF]/10 transition-all">
              <div className="flex items-center gap-1 pb-1 pl-1">
                <button className="w-9 h-9 rounded-full flex items-center justify-center hover:bg-white text-[#9F9FD1] hover:text-[#7387FF] transition-colors">
                  <Smile strokeWidth={2} className="w-5 h-5" />
                </button>
                <button className="w-9 h-9 rounded-full flex items-center justify-center hover:bg-white text-[#9F9FD1] hover:text-[#7387FF] transition-colors">
                  <Paperclip strokeWidth={2} className="w-5 h-5" />
                </button>
              </div>

              <textarea
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                placeholder="Type a message..."
                rows={1}
                className="flex-1 bg-transparent text-[14px] font-medium text-[#07074E] placeholder-[#9F9FD1] outline-none resize-none py-2.5 leading-snug min-h-[44px] max-h-[120px]"
              />

              <button
                className={`w-11 h-11 rounded-full flex items-center justify-center flex-shrink-0 transition-all shadow-sm ${
                  inputValue.trim()
                    ? "bg-[#7387FF] text-white hover:bg-[#5A6EED] hover:shadow-[0_4px_12px_rgba(115,135,255,0.4)]"
                    : "bg-white border border-[#EAEAF5] text-[#9F9FD1]"
                }`}
              >
                <Send strokeWidth={2} className={`w-5 h-5 ${inputValue.trim() ? "ml-0.5" : ""}`} />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ══════════════════════════════════════════
          RIGHT CONTEXT PANEL (SLIM)
      ══════════════════════════════════════════ */}
      <div className="w-[260px] flex-shrink-0 flex flex-col gap-4 h-full overflow-y-auto pb-4">
        
        {/* Card 1 — Active Deal */}
        <div className="bg-white rounded-[20px] shadow-[0_2px_16px_rgba(7,7,78,0.04)] border border-[#EAEAF5] p-5 flex-shrink-0">
          <p className="text-[10px] font-bold text-[#9F9FD1] uppercase tracking-[0.12em] mb-4">
            Active Deal
          </p>
          
          <h3 className="text-[14px] font-bold text-[#07074E] mb-4 leading-snug">
            Summer Hydration Routine
          </h3>

          <div className="flex flex-col gap-3 mb-5">
            <div>
              <p className="text-[11px] font-medium text-[#9F9FD1] mb-0.5">Due Date</p>
              <p className="text-[13px] font-bold text-[#07074E]">May 15, 2026</p>
            </div>
            <div>
              <p className="text-[11px] font-medium text-[#9F9FD1] mb-0.5">Payout</p>
              <p className="text-[13px] font-bold text-[#27AE60]">₹18,750</p>
            </div>
            <div>
              <p className="text-[11px] font-medium text-[#9F9FD1] mb-1">Status</p>
              <span className="inline-flex items-center px-2.5 py-1 rounded-full bg-[#EEF0FF] text-[#7387FF] text-[11px] font-bold border border-[#7387FF]/20">
                In Review
              </span>
            </div>
          </div>

          <button className="w-full flex items-center justify-center gap-2 bg-[#F5F6FF] text-[#7387FF] py-2.5 rounded-[12px] text-[13px] font-bold hover:bg-[#EEF0FF] transition-all border border-[#7387FF]/10">
            Open Deal Room
          </button>
        </div>

        {/* Card 2 — Shared Files */}
        <div className="bg-white rounded-[20px] shadow-[0_2px_16px_rgba(7,7,78,0.04)] border border-[#EAEAF5] p-5 flex-shrink-0">
          <div className="flex items-center justify-between mb-4">
            <p className="text-[10px] font-bold text-[#9F9FD1] uppercase tracking-[0.12em]">
              Shared Files
            </p>
            <span className="text-[11px] font-bold text-[#7387FF] bg-[#EEF0FF] px-2 py-0.5 rounded-md">3</span>
          </div>

          <div className="flex flex-col gap-2.5">
            {FILES.map((file, i) => (
              <div key={i} className="flex items-center gap-3 p-2.5 rounded-[12px] hover:bg-[#F5F6FF] transition-colors cursor-pointer border border-transparent hover:border-[#EAEAF5]">
                <div 
                  className="w-9 h-9 rounded-[10px] flex items-center justify-center flex-shrink-0"
                  style={{ backgroundColor: `${file.color}15`, color: file.color }}
                >
                  <file.icon strokeWidth={2} className="w-4 h-4" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-[12px] font-bold text-[#07074E] truncate">{file.name}</p>
                  <p className="text-[11px] font-medium text-[#9F9FD1]">{file.size}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Card 3 — Quick Actions */}
        <div className="bg-white rounded-[20px] shadow-[0_2px_16px_rgba(7,7,78,0.04)] border border-[#EAEAF5] p-5 flex-shrink-0">
          <p className="text-[10px] font-bold text-[#9F9FD1] uppercase tracking-[0.12em] mb-4">
            Quick Actions
          </p>

          <div className="flex flex-col gap-2">
            {[
              { icon: AlertCircle, label: "Raise Issue", color: "#E74C3C" },
              { icon: History, label: "View Timeline", color: "#7387FF" },
              { icon: Truck, label: "Track Status", color: "#27AE60" },
            ].map((action, i) => (
              <button
                key={i}
                className="flex items-center gap-3 p-2.5 rounded-[12px] hover:bg-[#F5F6FF] transition-colors text-left border border-transparent hover:border-[#EAEAF5] group"
              >
                <div 
                  className="w-8 h-8 rounded-[8px] flex items-center justify-center flex-shrink-0"
                  style={{ backgroundColor: `${action.color}15`, color: action.color }}
                >
                  <action.icon strokeWidth={2} className="w-[15px] h-[15px]" />
                </div>
                <span className="text-[12.5px] font-bold text-[#07074E] flex-1">{action.label}</span>
                <ChevronRight strokeWidth={2} className="w-3.5 h-3.5 text-[#D4D4E8] group-hover:text-[#7387FF] transition-colors" />
              </button>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}