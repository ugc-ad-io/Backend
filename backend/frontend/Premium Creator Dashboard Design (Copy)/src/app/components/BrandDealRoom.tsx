import { useState } from "react";
import {
  Check,
  CheckCircle2,
  Clock,
  MessageSquare,
  Download,
  AlertTriangle,
  Play,
  RotateCcw,
  Truck,
  ShieldAlert,
  Info,
  FileVideo,
  Box,
  CreditCard,
  History,
  ExternalLink,
  ChevronRight,
  FileText,
  Send,
  Package,
  Zap,
  Shield,
  Star,
  MapPin,
  Hash,
  X,
  ThumbsUp,
} from "lucide-react";

/* ─────────────────────── DATA ─────────────────────── */

const STAGES = [
  { id: 1, label: "Brief",      icon: FileText   },
  { id: 2, label: "Matched",    icon: Star       },
  { id: 3, label: "Escrow",     icon: Shield     },
  { id: 4, label: "Shipping",   icon: Truck      },
  { id: 5, label: "Received",   icon: Package    },
  { id: 6, label: "Production", icon: Zap        },
  { id: 7, label: "In Review",  icon: Play       },
  { id: 8, label: "Approved",   icon: ThumbsUp   },
  { id: 9, label: "Completed",  icon: CheckCircle2 },
];

const CURRENT_STAGE = 7;

const QUICK_LINKS = [
  { icon: MessageSquare, label: "Chat with Creator", badge: 2       },
  { icon: FileText,      label: "Files",             badge: null    },
  { icon: Truck,         label: "Shipping",          badge: null    },
  { icon: RotateCcw,     label: "Revisions",         badge: 1       },
  { icon: CreditCard,    label: "Payment",           badge: null    },
];

/* ─────────────────────── COMPONENT ─────────────────────── */

export function BrandDealRoom() {
  const [showApproveModal, setShowApproveModal] = useState(false);
  const [showDisputeModal, setShowDisputeModal] = useState(false);
  const [chatMsg, setChatMsg] = useState("");

  return (
    <div
      className="flex gap-0 h-full font-sans text-[#07074E]"
      style={{ fontFamily: "'Inter', 'Just Sans', sans-serif" }}
    >
      {/* ══════════════════ LEFT PANEL — Deal Timeline ══════════════════ */}
      <aside className="w-[220px] flex-shrink-0 flex flex-col gap-6 pr-5">

        {/* Deal Journey heading */}
        <div>
          <p className="text-[10px] font-semibold text-[#9F9FD1] uppercase tracking-[0.12em] mb-4">
            Deal Journey
          </p>

          {/* Vertical Stage Timeline */}
          <div className="relative flex flex-col">
            {/* Connecting track */}
            <div
              className="absolute left-[13px] top-3 bottom-3 w-[2px] rounded-full"
              style={{
                background:
                  "linear-gradient(to bottom, #27AE60 0%, #27AE60 66%, #EAEAF5 66%)",
              }}
            />

            {STAGES.map((stage) => {
              const isCompleted = stage.id < CURRENT_STAGE;
              const isCurrent  = stage.id === CURRENT_STAGE;
              const isPending   = stage.id > CURRENT_STAGE;

              return (
                <div
                  key={stage.id}
                  className={`relative flex items-center gap-3 py-[9px] pl-[2px] group cursor-pointer rounded-[10px] pr-2 transition-all duration-150
                    ${isCurrent ? "bg-[#EEF0FF]" : "hover:bg-[#F5F6FF]"}
                  `}
                >
                  {/* Node */}
                  <div
                    className={`relative z-10 w-[26px] h-[26px] rounded-full flex items-center justify-center border-2 shrink-0 transition-all duration-300
                      ${isCompleted
                        ? "bg-[#27AE60] border-[#27AE60] shadow-[0_2px_8px_rgba(39,174,96,0.30)]"
                        : isCurrent
                        ? "bg-white border-[#7387FF] shadow-[0_0_0_4px_rgba(115,135,255,0.15),0_2px_12px_rgba(115,135,255,0.35)]"
                        : "bg-white border-[#EAEAF5]"
                      }
                    `}
                  >
                    {isCompleted ? (
                      <Check className="w-3 h-3 text-white stroke-[3]" />
                    ) : (
                      <span
                        className={`text-[10px] font-bold ${
                          isCurrent ? "text-[#7387FF]" : "text-[#C4C4E8]"
                        }`}
                      >
                        {stage.id}
                      </span>
                    )}
                  </div>

                  {/* Label */}
                  <div className="flex flex-col">
                    <span
                      className={`text-[13px] font-semibold transition-colors leading-tight
                        ${isCompleted
                          ? "text-[#07074E]"
                          : isCurrent
                          ? "text-[#7387FF]"
                          : "text-[#C4C4E8]"
                        }
                      `}
                    >
                      {stage.label}
                    </span>
                    {isCurrent && (
                      <span className="text-[10px] font-medium text-[#9F9FD1] mt-0.5">
                        Active — action needed
                      </span>
                    )}
                    {isCompleted && (
                      <span className="text-[10px] font-medium text-[#27AE60]/70 mt-0.5">
                        Completed
                      </span>
                    )}
                  </div>

                  {/* Active dot */}
                  {isCurrent && (
                    <div className="ml-auto w-1.5 h-1.5 rounded-full bg-[#7387FF] animate-pulse shrink-0" />
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Divider */}
        <div className="h-px bg-[#EAEAF5]" />

        {/* Quick Links */}
        <div>
          <p className="text-[10px] font-semibold text-[#9F9FD1] uppercase tracking-[0.12em] mb-3">
            Quick Links
          </p>
          <div className="flex flex-col gap-1">
            {QUICK_LINKS.map(({ icon: Icon, label, badge }) => (
              <button
                key={label}
                className="flex items-center gap-3 px-3 py-2.5 rounded-[10px] text-[13px] font-medium text-[#07074E]/70 hover:text-[#7387FF] hover:bg-[#F3F3FF] transition-all duration-150 group text-left"
              >
                <Icon className="w-4 h-4 text-[#9F9FD1] group-hover:text-[#7387FF] transition-colors shrink-0" />
                <span className="flex-1">{label}</span>
                {badge && (
                  <span className="w-5 h-5 rounded-full bg-[#7387FF] text-white text-[10px] font-bold flex items-center justify-center shrink-0">
                    {badge}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Deal ID badge */}
        <div className="mt-auto bg-[#F5F6FF] rounded-[12px] p-3 border border-[#EAEAF5]">
          <p className="text-[10px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-1">Deal ID</p>
          <p className="text-[14px] font-bold text-[#07074E] font-mono">#UGC2048</p>
          <p className="text-[11px] font-medium text-[#9F9FD1] mt-0.5">Started Apr 28, 2026</p>
        </div>
      </aside>

      {/* ══════════════════ CENTER PANEL — Main Workspace ══════════════════ */}
      <main className="flex-1 min-w-0 flex flex-col gap-5 px-6 overflow-y-auto pb-10">

        {/* ── Deal Header Card ── */}
        <div className="bg-white rounded-[20px] border border-[#EAEAF5] shadow-[0_2px_20px_rgba(7,7,78,0.05)] p-6">
          <div className="flex items-start justify-between">
            <div className="flex flex-col gap-3">
              {/* Title + status */}
              <div className="flex items-center gap-3 flex-wrap">
                <h1 className="text-[22px] font-bold text-[#07074E] tracking-tight">
                  Summer Hydration Routine
                </h1>
                <span className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#EEF0FF] text-[#7387FF] text-[11px] font-bold border border-[#7387FF]/20">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#7387FF] animate-pulse" />
                  In Review
                </span>
              </div>

              {/* Meta row */}
              <div className="flex items-center gap-5 flex-wrap">
                <div className="flex items-center gap-2">
                  <div className="w-7 h-7 rounded-full bg-[#EEF0FF] flex items-center justify-center">
                    <span className="text-[11px] font-bold text-[#7387FF]">GC</span>
                  </div>
                  <span className="text-[13px] font-bold text-[#7387FF] font-mono">@glowcreator.ugc</span>
                </div>
                <Dot />
                <div className="flex items-center gap-1.5">
                  <FileVideo className="w-3.5 h-3.5 text-[#9F9FD1]" />
                  <span className="text-[12px] font-medium text-[#9F9FD1]">UGC Reel · 15s · 9:16</span>
                </div>
                <Dot />
                <div className="flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5 text-[#9F9FD1]" />
                  <span className="text-[12px] font-medium text-[#9F9FD1]">
                    Due <span className="text-[#07074E] font-semibold">May 15, 2026</span>
                  </span>
                </div>
                <Dot />
                <div className="flex items-center gap-1.5">
                  <MapPin className="w-3.5 h-3.5 text-[#9F9FD1]" />
                  <span className="text-[12px] font-medium text-[#9F9FD1]">Mumbai</span>
                </div>
              </div>
            </div>

            {/* Action pills */}
            <div className="flex items-center gap-2 shrink-0">
              <button className="flex items-center gap-2 px-4 py-2 rounded-[10px] border border-[#EAEAF5] text-[12px] font-semibold text-[#07074E] hover:bg-[#F5F6FF] transition-colors">
                <MessageSquare className="w-3.5 h-3.5 text-[#7387FF]" />
                Chat
                <span className="w-4 h-4 rounded-full bg-[#F39C12] text-white text-[9px] font-bold flex items-center justify-center">2</span>
              </button>
              <button className="flex items-center gap-2 px-4 py-2 rounded-[10px] border border-[#EAEAF5] text-[12px] font-semibold text-[#07074E] hover:bg-[#F5F6FF] transition-colors">
                <FileText className="w-3.5 h-3.5 text-[#7387FF]" />
                Brief Files
              </button>
            </div>
          </div>

          {/* Stage track — mini horizontal */}
          <div className="mt-5 pt-5 border-t border-[#F3F3FF]">
            <div className="relative flex items-center justify-between">
              <div className="absolute left-0 right-0 top-[14px] h-[2px] bg-[#EAEAF5] rounded-full -z-10" />
              <div
                className="absolute left-0 top-[14px] h-[2px] bg-[#7387FF] rounded-full -z-10 transition-all duration-700"
                style={{ width: `${((CURRENT_STAGE - 1) / (STAGES.length - 1)) * 100}%` }}
              />
              {STAGES.map((stage) => {
                const isCompleted = stage.id < CURRENT_STAGE;
                const isCurrent  = stage.id === CURRENT_STAGE;
                return (
                  <div key={stage.id} className="flex flex-col items-center gap-2">
                    <div
                      className={`w-7 h-7 rounded-full flex items-center justify-center border-2 bg-white transition-all
                        ${isCompleted ? "border-[#27AE60]" : isCurrent ? "border-[#7387FF] ring-4 ring-[#7387FF]/10 shadow-[0_0_8px_rgba(115,135,255,0.4)]" : "border-[#EAEAF5]"}
                      `}
                    >
                      {isCompleted ? (
                        <Check className="w-3 h-3 text-[#27AE60] stroke-[3]" />
                      ) : (
                        <span className={`text-[10px] font-bold ${isCurrent ? "text-[#7387FF]" : "text-[#C4C4E8]"}`}>
                          {stage.id}
                        </span>
                      )}
                    </div>
                    <span className={`text-[10px] font-semibold whitespace-nowrap ${isCurrent ? "text-[#7387FF]" : isCompleted ? "text-[#07074E]" : "text-[#C4C4E8]"}`}>
                      {stage.label}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* ── Urgency Notice Banner ── */}
        <div className="bg-[#FFF8E8] border border-[#F39C12]/25 border-l-[4px] border-l-[#F39C12] rounded-[16px] p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-[0_2px_12px_rgba(243,156,18,0.08)]">
          <div className="flex items-start md:items-center gap-3.5 min-w-0">
            <div className="w-9 h-9 rounded-full bg-white shadow-sm flex items-center justify-center shrink-0 mt-0.5 md:mt-0">
              <AlertTriangle className="w-4.5 h-4.5 text-[#F39C12]" strokeWidth={2.5} />
            </div>
            <div className="min-w-0">
              <p className="text-[14px] font-bold text-[#07074E] truncate whitespace-normal">Final delivery submitted — review required</p>
              <p className="text-[12px] font-medium text-[#07074E]/60 mt-0.5 break-words">
                Approve or request revision within 5 days. Auto-approval triggers if no action is taken.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3 shrink-0 md:ml-0 ml-[50px]">
            <div className="flex items-center gap-1.5 px-3 py-1.5 bg-white rounded-full border border-[#F39C12]/20 shadow-sm">
              <Clock className="w-3.5 h-3.5 text-[#F39C12]" />
              <span className="text-[12px] font-bold text-[#F39C12]">23h 14m left</span>
            </div>
            <button className="text-[12px] font-semibold text-[#7387FF] hover:underline whitespace-nowrap">
              View Policy
            </button>
          </div>
        </div>

        {/* ── Final Video Review Card ── */}
        <div className="bg-white rounded-[20px] border border-[#EAEAF5] shadow-[0_2px_20px_rgba(7,7,78,0.05)] overflow-hidden">
          {/* Card header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-[#F3F3FF]">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-[10px] bg-[#EEF0FF] flex items-center justify-center">
                <Play className="w-4 h-4 text-[#7387FF] ml-0.5" />
              </div>
              <div>
                <h2 className="text-[15px] font-bold text-[#07074E]">Final Deliverable</h2>
                <p className="text-[11px] font-medium text-[#9F9FD1]">Review content before releasing payout</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-semibold text-[#9F9FD1] bg-[#F5F6FF] px-3 py-1 rounded-full">
                Uploaded Today · 10:42 AM
              </span>
              <span className="text-[11px] font-bold text-[#7387FF] bg-[#EEF0FF] px-3 py-1 rounded-full border border-[#7387FF]/20">
                1 of 2 revisions used
              </span>
            </div>
          </div>

          <div className="p-6 flex gap-6">
            {/* 9:16 Video Preview */}
            <div className="w-[200px] h-[356px] bg-[#07074E] rounded-[16px] relative overflow-hidden shadow-[0_8px_24px_rgba(7,7,78,0.15)] shrink-0 group cursor-pointer">
              <img
                src="https://images.unsplash.com/photo-1583209814468-fce526b91543?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxza2luY2FyZSUyMGJlYXV0eSUyMHByb2R1Y3QlMjByZWVsJTIwY3JlYXRvcnxlbnwxfHx8fDE3NzcyNzA1OTR8MA&ixlib=rb-4.1.0&q=80&w=400"
                alt="Final video thumbnail"
                className="w-full h-full object-cover opacity-80 group-hover:scale-105 transition-transform duration-500"
              />
              <div className="absolute inset-0 bg-gradient-to-t from-[#07074E]/80 via-transparent to-transparent" />
              {/* Play button */}
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="w-14 h-14 rounded-full bg-white/20 backdrop-blur-md border border-white/30 flex items-center justify-center group-hover:bg-[#7387FF] group-hover:scale-110 transition-all duration-300 shadow-xl">
                  <Play className="w-6 h-6 text-white ml-1" fill="currentColor" />
                </div>
              </div>
              {/* Labels */}
              <div className="absolute bottom-3 left-3 right-3 flex justify-between">
                <span className="text-white text-[11px] font-bold bg-black/50 backdrop-blur-sm px-2 py-0.5 rounded">
                  0:15
                </span>
                <span className="text-white text-[11px] font-bold bg-black/50 backdrop-blur-sm px-2 py-0.5 rounded">
                  9:16 · 1080p
                </span>
              </div>
              {/* Top quality badge */}
              <div className="absolute top-3 right-3 bg-[#7387FF] text-white text-[10px] font-bold px-2 py-0.5 rounded">
                A+
              </div>
            </div>

            {/* Right — info + actions */}
            <div className="flex-1 flex flex-col gap-4">
              {/* Delivery meta */}
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-[#F5F6FF] rounded-[12px] p-3 border border-[#EEF0FF]">
                  <p className="text-[10px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-1">File Size</p>
                  <p className="text-[14px] font-bold text-[#07074E]">184 MB</p>
                </div>
                <div className="bg-[#F5F6FF] rounded-[12px] p-3 border border-[#EEF0FF]">
                  <p className="text-[10px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-1">Resolution</p>
                  <p className="text-[14px] font-bold text-[#07074E]">1080×1920</p>
                </div>
                <div className="bg-[#F5F6FF] rounded-[12px] p-3 border border-[#EEF0FF]">
                  <p className="text-[10px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-1">Duration</p>
                  <p className="text-[14px] font-bold text-[#07074E]">15 seconds</p>
                </div>
                <div className="bg-[#F5F6FF] rounded-[12px] p-3 border border-[#EEF0FF]">
                  <p className="text-[10px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-1">Format</p>
                  <p className="text-[14px] font-bold text-[#07074E]">MP4 · H.264</p>
                </div>
              </div>

              {/* Warning */}
              <div className="flex items-start gap-3 p-3.5 rounded-[12px] bg-[#FCEAEA]/60 border border-[#E74C3C]/10">
                <Info className="w-4 h-4 text-[#E74C3C]/70 shrink-0 mt-0.5" />
                <p className="text-[12px] font-medium text-[#07074E]/70 leading-relaxed">
                  Approving releases <span className="font-bold text-[#07074E]">₹15,000</span> to the creator.{" "}
                  <span className="font-bold text-[#E74C3C]">This action is final and cannot be reversed.</span>
                </p>
              </div>

              {/* CTAs */}
              <div className="flex flex-col gap-3 mt-auto">
                <button
                  onClick={() => setShowApproveModal(true)}
                  className="w-full py-3.5 rounded-[12px] bg-[#27AE60] hover:bg-[#219A52] active:scale-[0.98] text-white text-[14px] font-bold shadow-[0_4px_16px_rgba(39,174,96,0.28)] transition-all flex items-center justify-center gap-2"
                >
                  <CheckCircle2 className="w-5 h-5" />
                  Approve Final Delivery
                </button>
                <div className="flex gap-3">
                  <button className="flex-1 py-3 rounded-[12px] bg-white border-2 border-[#EAEAF5] hover:border-[#7387FF] hover:text-[#7387FF] text-[#07074E] text-[13px] font-bold transition-all flex items-center justify-center gap-2">
                    <RotateCcw className="w-4 h-4" />
                    Request Revision
                  </button>
                  <button
                    onClick={() => setShowDisputeModal(true)}
                    className="flex-1 py-3 rounded-[12px] bg-[#FCEAEA] border border-[#E74C3C]/20 text-[#E74C3C] text-[13px] font-bold hover:bg-[#E74C3C] hover:text-white transition-all flex items-center justify-center gap-2"
                  >
                    <AlertTriangle className="w-4 h-4" />
                    Raise Dispute
                  </button>
                </div>
                <button className="flex items-center justify-center gap-2 py-2 text-[#9F9FD1] hover:text-[#7387FF] text-[12px] font-semibold transition-colors">
                  <Download className="w-3.5 h-3.5" />
                  Download Original File (184 MB)
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* ── Bottom Row: Unboxing + Chat ── */}
        <div className="grid grid-cols-2 gap-5">
          {/* Unboxing Proof */}
          <div className="bg-white rounded-[20px] border border-[#EAEAF5] shadow-[0_2px_16px_rgba(7,7,78,0.04)] p-5 flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-[10px] bg-[#E8F8EE] flex items-center justify-center">
                  <Box className="w-4 h-4 text-[#27AE60]" />
                </div>
                <div>
                  <h3 className="text-[14px] font-bold text-[#07074E]">Unboxing Proof</h3>
                  <p className="text-[11px] font-medium text-[#9F9FD1]">Product receipt confirmed</p>
                </div>
              </div>
              <span className="text-[10px] font-bold text-[#9F9FD1] bg-[#F5F6FF] px-2.5 py-1 rounded-full border border-[#EAEAF5] uppercase tracking-wider">
                Read Only
              </span>
            </div>

            <div className="flex gap-4 p-3 bg-[#F5F6FF] rounded-[14px] border border-[#EEF0FF] items-center">
              <div className="w-[72px] h-[72px] rounded-[12px] overflow-hidden relative shrink-0 shadow-sm">
                <img
                  src="https://images.unsplash.com/photo-1772683709257-5b907b4a65c3?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHx1bmJveGluZyUyMHByb2R1Y3QlMjBwYWNrYWdpbmclMjBoYW5kc3xlbnwxfHx8fDE3NzcyNzA1OTR8MA&ixlib=rb-4.1.0&q=80&w=200"
                  alt="Unboxing thumbnail"
                  className="w-full h-full object-cover"
                />
                <div className="absolute inset-0 flex items-center justify-center bg-black/20">
                  <Play className="w-5 h-5 text-white" fill="white" />
                </div>
              </div>
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-[#27AE60]" />
                  <span className="text-[13px] font-bold text-[#07074E]">Verified Upload</span>
                </div>
                <span className="text-[12px] font-medium text-[#9F9FD1]">May 10, 2026 · 3:22 PM</span>
                <span className="text-[11px] font-medium text-[#9F9FD1]">2 min 14 sec · Sealed packaging shown</span>
              </div>
            </div>

            <div className="flex items-center gap-2 px-3 py-2 bg-[#E8F8EE] rounded-[10px] border border-[#27AE60]/15">
              <Shield className="w-3.5 h-3.5 text-[#27AE60]" />
              <span className="text-[11px] font-semibold text-[#27AE60]">Damage report window expired — product confirmed in good condition</span>
            </div>
          </div>

          {/* Chat Preview */}
          <div className="bg-white rounded-[20px] border border-[#EAEAF5] shadow-[0_2px_16px_rgba(7,7,78,0.04)] p-5 flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-[10px] bg-[#EEF0FF] flex items-center justify-center">
                  <MessageSquare className="w-4 h-4 text-[#7387FF]" />
                </div>
                <div>
                  <h3 className="text-[14px] font-bold text-[#07074E]">Recent Messages</h3>
                  <p className="text-[11px] font-medium text-[#9F9FD1]">@glowcreator.ugc</p>
                </div>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[#27AE60]" />
                <span className="text-[11px] font-semibold text-[#27AE60]">Online</span>
              </div>
            </div>

            {/* Messages */}
            <div className="flex flex-col gap-3 flex-1">
              {[
                { from: "brand", text: "Did you receive the updated brief directions?" },
                { from: "creator", text: "Yes! Shot it this morning. Uploading final video now." },
                { from: "creator", text: "Just submitted the final delivery — please review when you get a chance! 🙏" },
              ].map((msg, i) => (
                <div key={i} className={`flex gap-2 ${msg.from === "brand" ? "" : "flex-row-reverse"}`}>
                  <div
                    className={`w-6 h-6 rounded-full flex items-center justify-center shrink-0 text-[9px] font-bold
                      ${msg.from === "brand" ? "bg-[#7387FF] text-white" : "bg-[#EEF0FF] text-[#7387FF]"}
                    `}
                  >
                    {msg.from === "brand" ? "B" : "C"}
                  </div>
                  <div
                    className={`px-3 py-2 rounded-[12px] text-[12px] font-medium max-w-[75%] leading-relaxed
                      ${msg.from === "brand"
                        ? "bg-[#F5F6FF] text-[#07074E] rounded-tl-none"
                        : "bg-[#07074E] text-white rounded-tr-none"
                      }
                    `}
                  >
                    {msg.text}
                  </div>
                </div>
              ))}
            </div>

            {/* Input preview */}
            <div className="flex gap-2 items-center">
              <input
                type="text"
                value={chatMsg}
                onChange={(e) => setChatMsg(e.target.value)}
                placeholder="Type a message..."
                className="flex-1 bg-[#F5F6FF] border border-[#EAEAF5] rounded-[10px] px-3 py-2 text-[12px] font-medium text-[#07074E] placeholder-[#C4C4E8] focus:outline-none focus:border-[#7387FF] transition-colors"
              />
              <button className="w-9 h-9 rounded-[10px] bg-[#7387FF] flex items-center justify-center hover:bg-[#5E74FF] transition-colors shadow-[0_2px_8px_rgba(115,135,255,0.3)]">
                <Send className="w-4 h-4 text-white" />
              </button>
            </div>

            <button className="w-full py-2.5 rounded-[10px] border border-[#EAEAF5] text-[12px] font-bold text-[#7387FF] hover:bg-[#F3F3FF] transition-colors flex items-center justify-center gap-2">
              <ExternalLink className="w-3.5 h-3.5" />
              Open Full Chat
            </button>
          </div>
        </div>

        {/* ── Revision History ── */}
        <div className="bg-white rounded-[20px] border border-[#EAEAF5] shadow-[0_2px_16px_rgba(7,7,78,0.04)] p-6">
          <div className="flex items-center justify-between mb-5">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-[10px] bg-[#F5F6FF] flex items-center justify-center">
                <History className="w-4 h-4 text-[#9F9FD1]" />
              </div>
              <div>
                <h3 className="text-[15px] font-bold text-[#07074E]">Revision History</h3>
                <p className="text-[11px] font-medium text-[#9F9FD1]">1 free revision remaining after current</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <div className="flex gap-1">
                {[1, 2].map((n) => (
                  <div
                    key={n}
                    className={`w-6 h-6 rounded-full border-2 flex items-center justify-center text-[10px] font-bold
                      ${n === 1 ? "border-[#27AE60] bg-[#E8F8EE] text-[#27AE60]" : "border-[#F39C12] bg-[#FFF8E8] text-[#F39C12]"}
                    `}
                  >
                    {n}
                  </div>
                ))}
                <div className="w-6 h-6 rounded-full border-2 border-dashed border-[#EAEAF5] flex items-center justify-center text-[10px] font-bold text-[#C4C4E8]">
                  +
                </div>
              </div>
              <span className="text-[11px] font-medium text-[#9F9FD1]">2 of 2 free used (1 pending)</span>
            </div>
          </div>

          <div className="relative pl-3">
            <div className="absolute left-[15px] top-4 bottom-4 w-[2px] bg-[#EAEAF5] rounded-full" />

            {/* Rev 2 — Pending */}
            <div className="flex gap-4 relative mb-6">
              <div className="w-[26px] h-[26px] rounded-full bg-white border-2 border-[#F39C12] flex items-center justify-center shrink-0 mt-1 z-10 shadow-sm">
                <div className="w-2.5 h-2.5 rounded-full bg-[#F39C12]" />
              </div>
              <div className="flex-1 bg-[#FFF8E8] border border-[#F39C12]/20 rounded-[14px] p-4">
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <span className="text-[13px] font-bold text-[#07074E]">Revision 2</span>
                    <span className="text-[11px] font-medium text-[#9F9FD1] ml-2">· 2 hours ago</span>
                  </div>
                  <span className="text-[10px] font-bold text-[#F39C12] bg-white px-2.5 py-0.5 rounded-full border border-[#F39C12]/20">
                    Pending Creator Response
                  </span>
                </div>
                <p className="text-[12px] font-medium text-[#07074E]/70 leading-relaxed">
                  Requested adjustment to the lighting in the closing shot — needs more natural daylight feel, less warm filter.
                </p>
                <div className="flex items-center gap-2 mt-2.5">
                  <span className="text-[10px] font-semibold text-[#F39C12] bg-[#FFF0CC] px-2 py-0.5 rounded">
                    Free revision
                  </span>
                </div>
              </div>
            </div>

            {/* Rev 1 — Completed */}
            <div className="flex gap-4 relative">
              <div className="w-[26px] h-[26px] rounded-full bg-[#27AE60] border-2 border-white flex items-center justify-center shrink-0 mt-1 z-10 shadow-[0_2px_8px_rgba(39,174,96,0.25)]">
                <Check className="w-3 h-3 text-white stroke-[3]" />
              </div>
              <div className="flex-1 bg-[#F5F6FF] border border-[#EAEAF5] rounded-[14px] p-4">
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <span className="text-[13px] font-bold text-[#07074E]">Revision 1</span>
                    <span className="text-[11px] font-medium text-[#9F9FD1] ml-2">· May 12</span>
                  </div>
                  <span className="text-[10px] font-bold text-[#27AE60] bg-[#E8F8EE] px-2.5 py-0.5 rounded-full border border-[#27AE60]/20">
                    Completed in 1 day
                  </span>
                </div>
                <p className="text-[12px] font-medium text-[#07074E]/70 leading-relaxed">
                  Requested a stronger opening hook that mentions the summer discount campaign directly in the first 3 seconds.
                </p>
                <div className="flex items-center gap-2 mt-2.5">
                  <span className="text-[10px] font-semibold text-[#27AE60] bg-[#E8F8EE] px-2 py-0.5 rounded">
                    Free revision
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* ══════════════════ RIGHT PANEL — Insight Cards ══════════════════ */}
      <aside className="w-[260px] flex-shrink-0 flex flex-col gap-4 pl-5 overflow-y-auto pb-10">

        {/* CARD 1: Deal Summary */}
        <div className="bg-white rounded-[18px] border border-[#EAEAF5] shadow-[0_2px_16px_rgba(7,7,78,0.05)] p-5">
          <p className="text-[10px] font-bold text-[#9F9FD1] uppercase tracking-[0.12em] mb-4">Deal Summary</p>
          <div className="flex flex-col gap-3">
            <SummaryRow label="Deal ID" value="#UGC2048" mono />
            <SummaryRow
              label="Creator Level"
              value="L1 Rising"
              chip
              chipColor="text-[#27AE60] bg-[#E8F8EE] border-[#27AE60]/20"
            />
            <SummaryRow
              label="Quality Tier"
              value="A+"
              chip
              chipColor="text-[#7387FF] bg-[#EEF0FF] border-[#7387FF]/20"
            />
            <SummaryRow label="City" value="Mumbai, IN" />
            <SummaryRow
              label="Status"
              value="In Review"
              chip
              chipColor="text-[#7387FF] bg-[#EEF0FF] border-[#7387FF]/20"
            />
          </div>
        </div>

        {/* CARD 2: Payment Breakdown */}
        <div className="bg-white rounded-[18px] border border-[#EAEAF5] shadow-[0_2px_16px_rgba(7,7,78,0.05)] p-5">
          <div className="flex items-center gap-2 mb-4">
            <CreditCard className="w-3.5 h-3.5 text-[#9F9FD1]" />
            <p className="text-[10px] font-bold text-[#9F9FD1] uppercase tracking-[0.12em]">Payment Locked</p>
          </div>

          <div className="flex flex-col gap-0 rounded-[12px] overflow-hidden border border-[#EAEAF5]">
            <div className="flex items-center justify-between px-4 py-3 bg-[#F5F6FF]">
              <span className="text-[12px] font-medium text-[#07074E]">Brand Paid</span>
              <span className="text-[13px] font-bold text-[#07074E]">₹18,750</span>
            </div>
            <div className="flex items-center justify-between px-4 py-3 bg-white border-t border-[#EAEAF5]">
              <span className="text-[12px] font-medium text-[#9F9FD1]">Platform Fee (20%)</span>
              <span className="text-[12px] font-medium text-[#9F9FD1]">−₹3,750</span>
            </div>
            <div className="flex items-center justify-between px-4 py-3 bg-[#E8F8EE] border-t border-[#27AE60]/20">
              <span className="text-[12px] font-bold text-[#07074E]">Creator Receives</span>
              <span className="text-[15px] font-bold text-[#27AE60]">₹15,000</span>
            </div>
          </div>

          <p className="text-[10px] font-medium text-[#9F9FD1] mt-2.5 text-center">
            🔒 Held in escrow until approval
          </p>
        </div>

        {/* CARD 3: Shipping */}
        <div className="bg-[#07074E] rounded-[18px] shadow-[0_4px_20px_rgba(7,7,78,0.18)] p-5 relative overflow-hidden">
          {/* Decorative glow */}
          <div className="absolute -right-8 -top-8 w-28 h-28 bg-[#7387FF]/10 rounded-full blur-2xl pointer-events-none" />

          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Truck className="w-3.5 h-3.5 text-[#7387FF]" />
              <p className="text-[10px] font-bold text-[#9F9FD1] uppercase tracking-[0.12em]">Shipping</p>
            </div>
            <span className="text-[10px] font-bold bg-[#27AE60] text-white px-2.5 py-0.5 rounded">Delivered</span>
          </div>

          <div className="flex flex-col gap-3">
            <div>
              <p className="text-[10px] font-medium text-[#9F9FD1] mb-0.5">Carrier & Tracking</p>
              <div className="flex items-center gap-2">
                <span className="text-[13px] font-bold text-white">Shiprocket</span>
                <span className="text-[11px] font-mono text-[#9F9FD1]">SR948284</span>
              </div>
            </div>
            <div className="flex gap-4">
              <div>
                <p className="text-[10px] font-medium text-[#9F9FD1] mb-0.5">Delivered</p>
                <p className="text-[12px] font-bold text-[#27AE60]">May 10, 2026</p>
              </div>
              <div>
                <p className="text-[10px] font-medium text-[#9F9FD1] mb-0.5">Sender</p>
                <div className="flex items-center gap-1">
                  <ShieldAlert className="w-3 h-3 text-[#7387FF]" />
                  <p className="text-[12px] font-bold text-white">Masked</p>
                </div>
              </div>
            </div>
          </div>

          <button className="w-full mt-4 py-2.5 rounded-[10px] bg-white/10 hover:bg-white/18 border border-white/10 text-[12px] font-bold text-white transition-colors flex items-center justify-center gap-2">
            Track Package <ExternalLink className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* CARD 4: Completion Checklist */}
        <div className="bg-white rounded-[18px] border border-[#EAEAF5] shadow-[0_2px_16px_rgba(7,7,78,0.05)] p-5">
          <p className="text-[10px] font-bold text-[#9F9FD1] uppercase tracking-[0.12em] mb-4">Completion Checklist</p>
          <div className="flex flex-col gap-2.5">
            {[
              { label: "Product Shipped",           done: true  },
              { label: "Creator Received",          done: true  },
              { label: "Unboxing Uploaded",         done: true  },
              { label: "Final Delivery Submitted",  done: true  },
              { label: "Brand Approval",            done: false },
              { label: "Payout Released",           done: false },
            ].map(({ label, done }) => (
              <div key={label} className={`flex items-center gap-3 ${!done ? "opacity-45" : ""}`}>
                <div
                  className={`w-[18px] h-[18px] rounded-full flex items-center justify-center shrink-0
                    ${done ? "bg-[#E8F8EE]" : "border-2 border-dashed border-[#EAEAF5]"}
                  `}
                >
                  {done && <Check className="w-2.5 h-2.5 text-[#27AE60] stroke-[3]" />}
                </div>
                <span className="text-[12px] font-semibold text-[#07074E]">{label}</span>
              </div>
            ))}
          </div>

          {/* Progress bar */}
          <div className="mt-4 bg-[#F3F3FF] rounded-full h-1.5 overflow-hidden">
            <div className="h-full bg-[#7387FF] rounded-full" style={{ width: "66.7%" }} />
          </div>
          <p className="text-[10px] font-medium text-[#9F9FD1] mt-1.5 text-right">4 of 6 complete</p>
        </div>

        {/* CARD 5: Risk Center */}
        <div className="bg-[#FAFAFE] rounded-[18px] border border-[#EAEAF5] p-5">
          <div className="flex items-center justify-between mb-4">
            <p className="text-[10px] font-bold text-[#9F9FD1] uppercase tracking-[0.12em]">Risk Center</p>
            <span className="text-[10px] font-bold text-[#F39C12] bg-[#FFF8E8] px-2.5 py-0.5 rounded-full border border-[#F39C12]/20">
              Med Urgency
            </span>
          </div>
          <div className="flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-[#F39C12]" />
                <span className="text-[12px] font-medium text-[#07074E]">Dispute Window</span>
              </div>
              <span className="text-[12px] font-bold text-[#F39C12]">2 days left</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-[#27AE60]" />
                <span className="text-[12px] font-medium text-[#07074E]">Late Risk</span>
              </div>
              <span className="text-[12px] font-bold text-[#27AE60]">None</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-[#7387FF]" />
                <span className="text-[12px] font-medium text-[#07074E]">Auto-Approve</span>
              </div>
              <span className="text-[12px] font-bold text-[#07074E]">Day 1 of 5</span>
            </div>
          </div>

          {/* Countdown ring visual */}
          <div className="mt-4 flex items-center gap-3 p-3 bg-white rounded-[12px] border border-[#EAEAF5]">
            <div className="relative w-10 h-10 shrink-0">
              <svg className="w-10 h-10 -rotate-90" viewBox="0 0 36 36">
                <circle cx="18" cy="18" r="15" fill="none" stroke="#EAEAF5" strokeWidth="3" />
                <circle
                  cx="18" cy="18" r="15"
                  fill="none"
                  stroke="#F39C12"
                  strokeWidth="3"
                  strokeDasharray="94.2"
                  strokeDashoffset={94.2 * (1 - 0.2)}
                  strokeLinecap="round"
                />
              </svg>
              <span className="absolute inset-0 flex items-center justify-center text-[9px] font-bold text-[#F39C12]">
                23h
              </span>
            </div>
            <div>
              <p className="text-[11px] font-bold text-[#07074E]">Review countdown</p>
              <p className="text-[10px] font-medium text-[#9F9FD1]">Auto-approves in 23h 14m</p>
            </div>
          </div>
        </div>
      </aside>

      {/* ══════════════════ MODALS ══════════════════ */}

      {/* Approve Confirm Modal */}
      {showApproveModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-[#07074E]/30 backdrop-blur-sm" onClick={() => setShowApproveModal(false)} />
          <div className="relative bg-white rounded-[24px] shadow-[0_24px_64px_rgba(7,7,78,0.18)] p-8 w-[420px] flex flex-col gap-5">
            <button
              onClick={() => setShowApproveModal(false)}
              className="absolute top-5 right-5 w-8 h-8 rounded-full bg-[#F5F6FF] flex items-center justify-center hover:bg-[#EAEAF5] transition-colors"
            >
              <X className="w-4 h-4 text-[#9F9FD1]" />
            </button>
            <div className="w-14 h-14 rounded-[18px] bg-[#E8F8EE] flex items-center justify-center">
              <CheckCircle2 className="w-7 h-7 text-[#27AE60]" />
            </div>
            <div>
              <h2 className="text-[20px] font-bold text-[#07074E] mb-1.5">Approve Final Delivery?</h2>
              <p className="text-[13px] font-medium text-[#07074E]/60 leading-relaxed">
                This will release{" "}
                <span className="font-bold text-[#07074E]">₹15,000</span> to{" "}
                <span className="font-bold text-[#7387FF]">@glowcreator.ugc</span>. Approval is final
                and cannot be reversed.
              </p>
            </div>
            <div className="flex flex-col gap-2 p-4 bg-[#FFF8E8] rounded-[14px] border border-[#F39C12]/20">
              <p className="text-[12px] font-semibold text-[#07074E]">Before approving, confirm:</p>
              {["Content matches brief requirements", "Video is the correct format (9:16, 15s)", "Brand is not tagged before your posting date"].map((item) => (
                <div key={item} className="flex items-center gap-2">
                  <Check className="w-3.5 h-3.5 text-[#27AE60] stroke-[3] shrink-0" />
                  <span className="text-[11px] font-medium text-[#07074E]/70">{item}</span>
                </div>
              ))}
            </div>
            <div className="flex gap-3">
              <button
                onClick={() => setShowApproveModal(false)}
                className="flex-1 py-3 rounded-[12px] border-2 border-[#EAEAF5] text-[13px] font-bold text-[#07074E] hover:border-[#9F9FD1] transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => setShowApproveModal(false)}
                className="flex-1 py-3 rounded-[12px] bg-[#27AE60] hover:bg-[#219A52] text-white text-[13px] font-bold shadow-[0_4px_12px_rgba(39,174,96,0.3)] transition-all"
              >
                Yes, Approve & Release
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Dispute Confirm Modal */}
      {showDisputeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-[#07074E]/30 backdrop-blur-sm" onClick={() => setShowDisputeModal(false)} />
          <div className="relative bg-white rounded-[24px] shadow-[0_24px_64px_rgba(7,7,78,0.18)] p-8 w-[420px] flex flex-col gap-5">
            <button
              onClick={() => setShowDisputeModal(false)}
              className="absolute top-5 right-5 w-8 h-8 rounded-full bg-[#F5F6FF] flex items-center justify-center hover:bg-[#EAEAF5] transition-colors"
            >
              <X className="w-4 h-4 text-[#9F9FD1]" />
            </button>
            <div className="w-14 h-14 rounded-[18px] bg-[#FCEAEA] flex items-center justify-center">
              <AlertTriangle className="w-7 h-7 text-[#E74C3C]" />
            </div>
            <div>
              <h2 className="text-[20px] font-bold text-[#07074E] mb-1.5">Raise a Dispute?</h2>
              <p className="text-[13px] font-medium text-[#07074E]/60 leading-relaxed">
                Opening a dispute pauses the deal and notifies the admin team. Admin will review within{" "}
                <span className="font-bold text-[#07074E]">48 hours</span>. This cannot be withdrawn.
              </p>
            </div>
            <div className="flex flex-col gap-3">
              <label className="text-[12px] font-semibold text-[#07074E]">Reason for dispute</label>
              <textarea
                rows={3}
                placeholder="Describe the issue in detail..."
                className="w-full bg-[#F5F6FF] border border-[#EAEAF5] rounded-[12px] px-4 py-3 text-[12px] font-medium text-[#07074E] placeholder-[#C4C4E8] focus:outline-none focus:border-[#E74C3C] resize-none transition-colors"
              />
            </div>
            <div className="flex gap-3">
              <button
                onClick={() => setShowDisputeModal(false)}
                className="flex-1 py-3 rounded-[12px] border-2 border-[#EAEAF5] text-[13px] font-bold text-[#07074E] hover:border-[#9F9FD1] transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => setShowDisputeModal(false)}
                className="flex-1 py-3 rounded-[12px] bg-[#E74C3C] hover:bg-[#C0392B] text-white text-[13px] font-bold shadow-[0_4px_12px_rgba(231,76,60,0.3)] transition-all"
              >
                Open Dispute
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ─── Helper sub-components ─── */

function Dot() {
  return <div className="w-1 h-1 rounded-full bg-[#EAEAF5]" />;
}

function SummaryRow({
  label,
  value,
  mono = false,
  chip = false,
  chipColor = "",
}: {
  label: string;
  value: string;
  mono?: boolean;
  chip?: boolean;
  chipColor?: string;
}) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-[12px] font-medium text-[#9F9FD1]">{label}</span>
      {chip ? (
        <span className={`text-[11px] font-bold px-2.5 py-0.5 rounded-full border ${chipColor}`}>
          {value}
        </span>
      ) : mono ? (
        <span className="text-[12px] font-bold text-[#07074E] font-mono bg-[#F5F6FF] px-2 py-0.5 rounded">
          {value}
        </span>
      ) : (
        <span className="text-[12px] font-semibold text-[#07074E]">{value}</span>
      )}
    </div>
  );
}
