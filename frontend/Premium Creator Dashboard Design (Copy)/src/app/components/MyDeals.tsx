import { useState, useRef } from "react";
import {
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  Circle,
  Upload,
  FileVideo,
  FileText,
  Image,
  ToggleLeft,
  ToggleRight,
  Send,
  MessageCircle,
  AlertTriangle,
  Lock,
  Star,
  Clock,
  Calendar,
  IndianRupee,
  RefreshCw,
  Headphones,
  Flag,
  Package,
  CheckCheck,
  ArrowRight,
  Paperclip,
  ShieldAlert,
  Sparkles,
  Play,
  X,
  RotateCcw,
  Info,
} from "lucide-react";

const BRAND_LOGO = "https://images.unsplash.com/photo-1744798516778-22e8b144eab9?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxza2luY2FyZSUyMGJlYXV0eSUyMGJyYW5kJTIwcHJvZHVjdCUyMG1pbmltYWx8ZW58MXx8fHwxNzc3MDkzMTQ1fDA&ixlib=rb-4.1.0&q=80&w=1080&utm_source=figma&utm_medium=referral";

// ─── Sub-components ──────────────────────────────────────────────────────────

function StatusChip({ status }: { status: string }) {
  const map: Record<string, { bg: string; text: string; dot: string }> = {
    "In Production": { bg: "#7387FF15", text: "#7387FF", dot: "#7387FF" },
    "Review":        { bg: "#F59E0B15", text: "#F59E0B", dot: "#F59E0B" },
    "Approved":      { bg: "#22C55E15", text: "#22C55E", dot: "#22C55E" },
    "Revision Needed": { bg: "#EF444415", text: "#EF4444", dot: "#EF4444" },
  };
  const s = map[status] ?? map["In Production"];
  return (
    <span
      className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[12px] font-semibold tracking-wide border"
      style={{ backgroundColor: s.bg, color: s.text, borderColor: `${s.dot}25` }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: s.dot }} />
      {status}
    </span>
  );
}

function SectionCard({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`bg-white rounded-[20px] shadow-[0_4px_24px_rgba(7,7,78,0.05)] border border-[#E9EBEF]/60 overflow-hidden ${className}`}>
      {children}
    </div>
  );
}

function UploadZone({
  label,
  accept,
  note,
  icon: Icon,
  uploaded,
  onUpload,
}: {
  label: string;
  accept: string;
  note?: string;
  icon: React.ElementType;
  uploaded?: boolean;
  onUpload?: () => void;
}) {
  const [dragging, setDragging] = useState(false);
  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => { e.preventDefault(); setDragging(false); onUpload?.(); }}
      onClick={onUpload}
      className={`relative flex flex-col items-center justify-center gap-3 p-8 rounded-[16px] border-2 border-dashed cursor-pointer transition-all group ${
        uploaded
          ? "border-[#22C55E]/50 bg-[#22C55E]/5"
          : dragging
          ? "border-[#7387FF] bg-[#7387FF]/5 scale-[1.01]"
          : "border-[#E9EBEF] bg-[#F3F3FF]/40 hover:border-[#7387FF]/50 hover:bg-[#7387FF]/3"
      }`}
    >
      {uploaded ? (
        <>
          <div className="w-12 h-12 rounded-full bg-[#22C55E]/15 flex items-center justify-center">
            <CheckCheck strokeWidth={2} className="w-5 h-5 text-[#22C55E]" />
          </div>
          <span className="text-[13px] font-semibold text-[#22C55E]">File uploaded successfully</span>
        </>
      ) : (
        <>
          <div className={`w-12 h-12 rounded-[14px] flex items-center justify-center transition-colors ${dragging ? "bg-[#7387FF]/15" : "bg-[#F3F3FF] group-hover:bg-[#7387FF]/10"}`}>
            <Icon strokeWidth={1.5} className={`w-5 h-5 transition-colors ${dragging ? "text-[#7387FF]" : "text-[#9F9FD1] group-hover:text-[#7387FF]"}`} />
          </div>
          <div className="text-center">
            <p className="text-[13px] font-semibold text-[#07074E]">{label}</p>
            <p className="text-[12px] text-[#9F9FD1] font-medium mt-0.5">{accept}</p>
            {note && <p className="text-[11px] text-[#B7B7E6] mt-1">{note}</p>}
          </div>
        </>
      )}
    </div>
  );
}

// ─── Progress Steps ───────────────────────────────────────────────────────────

const STEPS = [
  { id: 1, label: "Applied",          sub: "Apr 10, 2026" },
  { id: 2, label: "Accepted",         sub: "Apr 12, 2026" },
  { id: 3, label: "Product Shipped",  sub: "Apr 15, 2026" },
  { id: 4, label: "Product Received", sub: "Apr 18, 2026" },
  { id: 5, label: "In Production",    sub: "Current Stage" },
  { id: 6, label: "Submitted",        sub: "Pending" },
  { id: 7, label: "Approved",         sub: "Pending" },
  { id: 8, label: "Paid",             sub: "Pending" },
];
const CURRENT_STEP = 5;

// ─── Main Component ───────────────────────────────────────────────────────────

export function MyDeals() {
  // Brief accordion
  const [briefOpen, setBriefOpen] = useState(false);

  // Product tabs
  const [activeTab, setActiveTab] = useState<"receipt" | "unboxing">("receipt");

  // Delivery received toggle
  const [deliveryReceived, setDeliveryReceived] = useState(true);

  // Upload states
  const [invoiceUploaded, setInvoiceUploaded] = useState(false);
  const [unboxingUploaded, setUnboxingUploaded] = useState(false);
  const [finalVideoUploaded, setFinalVideoUploaded] = useState(false);
  const [captionUploaded, setCaptionUploaded] = useState(false);
  const [thumbUploaded, setThumbUploaded] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [unboxingProgress, setUnboxingProgress] = useState(0);
  const [uploading, setUploading] = useState(false);

  // Auto-save label
  const [saved, setSaved] = useState(false);

  const triggerSaved = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2200);
  };

  const handleUnboxingUpload = () => {
    if (unboxingUploaded) return;
    setUploading(true);
    setUnboxingProgress(0);
    const interval = setInterval(() => {
      setUnboxingProgress((p) => {
        if (p >= 100) {
          clearInterval(interval);
          setUploading(false);
          setUnboxingUploaded(true);
          triggerSaved();
          return 100;
        }
        return p + 8;
      });
    }, 90);
  };

  const handleSubmit = () => {
    if (!finalVideoUploaded) return;
    setSubmitting(true);
    setTimeout(() => {
      setSubmitting(false);
      setSubmitted(true);
      triggerSaved();
    }, 1800);
  };

  const allUploaded = finalVideoUploaded && captionUploaded && thumbUploaded;

  return (
    <div className="flex gap-7 items-start pb-10 pt-2 font-sans">

      {/* ═══════════════════════════════════════════
          LEFT COLUMN — 65%
      ═══════════════════════════════════════════ */}
      <div className="flex flex-col gap-5 min-w-0" style={{ flex: "0 0 62%" }}>

        {/* ── 1. Deal Overview Card ── */}
        <SectionCard>
          <div className="p-8">
            {/* Top row: brand + status */}
            <div className="flex items-start justify-between gap-4 mb-6">
              <div className="flex items-center gap-4">
                <div className="w-[64px] h-[64px] rounded-[18px] overflow-hidden shadow-[0_4px_16px_rgba(7,7,78,0.10)] flex-shrink-0 border border-[#E9EBEF]/60">
                  <img src={BRAND_LOGO} alt="GlowCo" className="w-full h-full object-cover" />
                </div>
                <div>
                  <div className="flex items-center gap-2.5 mb-1">
                    <span className="text-[12px] font-semibold text-[#9F9FD1] uppercase tracking-wider">Brand</span>
                    <span className="w-1 h-1 rounded-full bg-[#E9EBEF]" />
                    <span className="text-[12px] font-semibold text-[#7387FF]">@glowandco</span>
                  </div>
                  <h2 className="text-[22px] font-semibold text-[#07074E] font-heading tracking-tight leading-tight">
                    Summer Hydration Routine
                  </h2>
                  <p className="text-[13px] text-[#9F9FD1] font-medium mt-1">Lifestyle & Skincare · Instagram Reels</p>
                </div>
              </div>
              <div className="flex flex-col items-end gap-2.5 flex-shrink-0">
                <StatusChip status="In Production" />
                <div className="flex items-center gap-1.5 bg-[#F3F3FF] px-3 py-1.5 rounded-[10px]">
                  <Sparkles strokeWidth={1.5} className="w-3.5 h-3.5 text-[#F59E0B]" />
                  <span className="text-[11.5px] font-semibold text-[#07074E]">98% Match Score</span>
                </div>
              </div>
            </div>

            {/* Divider */}
            <div className="h-px bg-[#F3F3FF] mb-6" />

            {/* Info grid */}
            <div className="grid grid-cols-3 gap-4">
              {[
                {
                  icon: Calendar,
                  label: "Due Date",
                  value: "May 3, 2026",
                  valueColor: "#EF4444",
                },
                {
                  icon: IndianRupee,
                  label: "Net Payout",
                  value: "₹12,500",
                  valueColor: "#07074E",
                },
                {
                  icon: Star,
                  label: "Quality Tier",
                  value: "UGC Elite",
                  valueColor: "#F59E0B",
                },
              ].map((info, i) => (
                <div
                  key={i}
                  className="flex items-center gap-3.5 bg-[#F3F3FF]/60 rounded-[14px] px-4 py-3.5"
                >
                  <div className="w-9 h-9 rounded-[10px] bg-white flex items-center justify-center shadow-sm flex-shrink-0">
                    <info.icon strokeWidth={1.5} className="w-4 h-4 text-[#7387FF]" />
                  </div>
                  <div>
                    <p className="text-[11px] font-medium text-[#9F9FD1] uppercase tracking-wide mb-0.5">{info.label}</p>
                    <p className="text-[15px] font-semibold font-heading" style={{ color: info.valueColor }}>
                      {info.value}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </SectionCard>

        {/* ── 2. Full Brief Card (Accordion) ── */}
        <SectionCard>
          <button
            onClick={() => setBriefOpen(!briefOpen)}
            className="w-full flex items-center justify-between px-8 py-5 hover:bg-[#F3F3FF]/40 transition-colors group"
          >
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-[10px] bg-[#7387FF]/10 flex items-center justify-center">
                <FileText strokeWidth={1.5} className="w-4.5 h-4.5 text-[#7387FF]" />
              </div>
              <span className="text-[16px] font-semibold text-[#07074E] font-heading">Full Campaign Brief</span>
            </div>
            <ChevronDown
              className={`w-5 h-5 text-[#9F9FD1] transition-transform duration-300 ${briefOpen ? "rotate-180" : ""}`}
            />
          </button>

          {briefOpen && (
            <div className="px-8 pb-8 border-t border-[#F3F3FF]">
              <div className="grid grid-cols-2 gap-5 mt-6">
                {[
                  {
                    label: "Campaign Goal",
                    content: "Drive awareness for the new Summer Hydration Kit. Focus on fresh, glowing skin transformation storytelling.",
                    icon: "🎯",
                  },
                  {
                    label: "Hook / Concept",
                    content: "Open with a close-up of dry skin, transition to dewy glowing results. Use trending audio — linked below.",
                    icon: "💡",
                  },
                ].map((item, i) => (
                  <div key={i} className="bg-[#F3F3FF]/60 rounded-[14px] p-5 col-span-2">
                    <div className="flex items-center gap-2.5 mb-3">
                      <span className="text-[16px]">{item.icon}</span>
                      <span className="text-[13px] font-semibold text-[#07074E] uppercase tracking-wider">{item.label}</span>
                    </div>
                    <p className="text-[13.5px] text-[#4A4A7A] font-medium leading-relaxed">{item.content}</p>
                  </div>
                ))}

                {/* Do's & Don'ts */}
                <div className="bg-[#22C55E]/5 rounded-[14px] p-5 border border-[#22C55E]/15">
                  <div className="flex items-center gap-2 mb-4">
                    <CheckCircle2 strokeWidth={2} className="w-4 h-4 text-[#22C55E]" />
                    <span className="text-[13px] font-semibold text-[#22C55E] uppercase tracking-wider">Do's</span>
                  </div>
                  <ul className="flex flex-col gap-2.5">
                    {["Show all 3 product steps", "Use natural daylight", "Include before / after footage", "Tag @glowandco"].map((d, i) => (
                      <li key={i} className="flex items-start gap-2 text-[13px] text-[#07074E] font-medium">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#22C55E] mt-[5px] flex-shrink-0" />
                        {d}
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="bg-[#EF4444]/5 rounded-[14px] p-5 border border-[#EF4444]/15">
                  <div className="flex items-center gap-2 mb-4">
                    <X strokeWidth={2} className="w-4 h-4 text-[#EF4444]" />
                    <span className="text-[13px] font-semibold text-[#EF4444] uppercase tracking-wider">Don'ts</span>
                  </div>
                  <ul className="flex flex-col gap-2.5">
                    {["No competitor product mentions", "Avoid heavy filters", "No voice-over scripts", "Don't show packaging damage"].map((d, i) => (
                      <li key={i} className="flex items-start gap-2 text-[13px] text-[#07074E] font-medium">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444] mt-[5px] flex-shrink-0" />
                        {d}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Deliverables & Format */}
                <div className="col-span-2 grid grid-cols-3 gap-4">
                  {[
                    { label: "Deliverables", value: "1× Reel (30–60s) + Raw footage" },
                    { label: "Required Format", value: "MP4 · 9:16 · 1080p minimum" },
                    { label: "Platform", value: "Instagram Reels" },
                    { label: "Product Variant", value: "Summer Kit — Rose + Aloe" },
                    { label: "Audio", value: "Trending audio (linked)" },
                    { label: "Deadline", value: "May 3, 2026" },
                  ].map((item, i) => (
                    <div key={i} className="bg-[#F3F3FF]/50 rounded-[12px] p-4 border border-[#E9EBEF]/40">
                      <p className="text-[11px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-1.5">{item.label}</p>
                      <p className="text-[13px] font-semibold text-[#07074E]">{item.value}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </SectionCard>

        {/* ── 3. Product Receipt + Unboxing Card ── */}
        <SectionCard>
          {/* Tab Header */}
          <div className="flex items-center px-8 pt-6 pb-0 gap-1">
            <div className="flex items-center gap-1 bg-[#F3F3FF] p-1 rounded-[12px] mb-0">
              {(["receipt", "unboxing"] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-5 py-2 rounded-[9px] text-[13px] font-semibold transition-all ${
                    activeTab === tab
                      ? "bg-white text-[#07074E] shadow-sm"
                      : "text-[#9F9FD1] hover:text-[#07074E]"
                  }`}
                >
                  {tab === "receipt" ? "📦  Receipt Confirmed" : "🎥  Unboxing Video"}
                </button>
              ))}
            </div>
            <div className="ml-auto mb-0">
              {saved && (
                <span className="flex items-center gap-1.5 text-[12px] font-semibold text-[#22C55E] bg-[#22C55E]/8 px-3 py-1.5 rounded-[8px] animate-pulse">
                  <CheckCircle2 strokeWidth={2} className="w-3.5 h-3.5" />
                  Auto-saved
                </span>
              )}
            </div>
          </div>

          <div className="h-px bg-[#F3F3FF] mt-5" />

          <div className="px-8 py-6">
            {activeTab === "receipt" ? (
              <div className="flex flex-col gap-5">
                {/* Delivery Toggle */}
                <div className="flex items-center justify-between bg-[#F3F3FF]/60 rounded-[14px] px-5 py-4">
                  <div className="flex items-center gap-3">
                    <Package strokeWidth={1.5} className="w-5 h-5 text-[#7387FF]" />
                    <div>
                      <p className="text-[14px] font-semibold text-[#07074E]">Delivery Received</p>
                      <p className="text-[12px] text-[#9F9FD1] font-medium">Confirm you have received the product</p>
                    </div>
                  </div>
                  <button
                    onClick={() => { setDeliveryReceived(!deliveryReceived); triggerSaved(); }}
                    className="flex items-center gap-2 transition-all"
                  >
                    {deliveryReceived ? (
                      <div className="flex items-center gap-2 bg-[#7387FF]/10 px-3 py-1.5 rounded-full">
                        <div className="w-8 h-4 bg-[#7387FF] rounded-full relative flex items-center px-0.5">
                          <div className="w-3 h-3 bg-white rounded-full absolute right-0.5 shadow-sm" />
                        </div>
                        <span className="text-[12px] font-semibold text-[#7387FF]">Yes</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2 bg-[#E9EBEF]/60 px-3 py-1.5 rounded-full">
                        <div className="w-8 h-4 bg-[#D1D5DB] rounded-full relative flex items-center px-0.5">
                          <div className="w-3 h-3 bg-white rounded-full absolute left-0.5 shadow-sm" />
                        </div>
                        <span className="text-[12px] font-semibold text-[#9F9FD1]">No</span>
                      </div>
                    )}
                  </button>
                </div>

                {/* Date Received */}
                <div className="flex items-center gap-3 bg-[#F3F3FF]/40 rounded-[14px] px-5 py-4">
                  <Calendar strokeWidth={1.5} className="w-4.5 h-4.5 text-[#9F9FD1]" />
                  <span className="text-[13px] font-medium text-[#9F9FD1]">Date Received</span>
                  <input
                    type="date"
                    defaultValue="2026-04-18"
                    className="ml-auto bg-white border border-[#E9EBEF] rounded-[10px] px-3 py-1.5 text-[13px] font-semibold text-[#07074E] outline-none focus:border-[#7387FF]/50 cursor-pointer"
                  />
                </div>

                {/* Upload Invoice */}
                <div>
                  <p className="text-[12px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-3">Upload Invoice / Proof</p>
                  <UploadZone
                    label="Drag & drop invoice or click to upload"
                    accept="PDF · JPG · PNG · Max 10MB"
                    icon={Paperclip}
                    uploaded={invoiceUploaded}
                    onUpload={() => { setInvoiceUploaded(true); triggerSaved(); }}
                  />
                </div>
              </div>
            ) : (
              <div className="flex flex-col gap-5">
                {/* Upload zone */}
                <UploadZone
                  label="Upload Unboxing Video"
                  accept="MP4 · MOV · Max 500MB"
                  note="Drag & drop or click to browse"
                  icon={FileVideo}
                  uploaded={unboxingUploaded}
                  onUpload={handleUnboxingUpload}
                />

                {/* Progress bar */}
                {(uploading || unboxingUploaded) && (
                  <div className="flex flex-col gap-2">
                    <div className="flex justify-between items-center">
                      <span className="text-[12px] font-semibold text-[#07074E]">
                        {unboxingUploaded ? "Upload complete" : `Uploading… ${unboxingProgress}%`}
                      </span>
                      <span className="text-[12px] font-medium text-[#9F9FD1]">
                        {unboxingUploaded ? "500MB / 500MB" : `${Math.round(unboxingProgress * 5)}MB / 500MB`}
                      </span>
                    </div>
                    <div className="h-2 bg-[#F3F3FF] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-300"
                        style={{
                          width: `${unboxingProgress}%`,
                          background: unboxingUploaded
                            ? "#22C55E"
                            : "linear-gradient(90deg, #7387FF, #4A63FF)",
                        }}
                      />
                    </div>
                  </div>
                )}

                {/* Warning note */}
                <div className="flex items-start gap-3 bg-[#F59E0B]/8 rounded-[12px] px-4 py-3.5 border border-[#F59E0B]/20">
                  <AlertTriangle strokeWidth={1.5} className="w-4 h-4 text-[#F59E0B] flex-shrink-0 mt-0.5" />
                  <p className="text-[12.5px] font-medium text-[#07074E] leading-relaxed">
                    <span className="font-semibold">Upload within 48 hours</span> of receiving the product. Late submissions may affect your deal standing.
                  </p>
                </div>
              </div>
            )}
          </div>
        </SectionCard>

        {/* ── 4. Final Delivery Card ── */}
        <SectionCard>
          <div className="px-8 py-6">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-[10px] bg-[#7387FF]/10 flex items-center justify-center">
                  <Send strokeWidth={1.5} className="w-4.5 h-4.5 text-[#7387FF]" />
                </div>
                <div>
                  <h3 className="text-[16px] font-semibold text-[#07074E] font-heading">Final Delivery</h3>
                  <p className="text-[12px] text-[#9F9FD1] font-medium">Submit your final campaign assets</p>
                </div>
              </div>
              {submitted && (
                <span className="flex items-center gap-1.5 text-[12px] font-semibold text-[#22C55E] bg-[#22C55E]/8 px-3 py-1.5 rounded-[8px]">
                  <Lock strokeWidth={2} className="w-3.5 h-3.5" />
                  Delivery Locked
                </span>
              )}
            </div>

            <div className="grid grid-cols-3 gap-4 mb-6">
              {/* Final Video */}
              <div className="col-span-3">
                <p className="text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-3">Final Video</p>
                <div className={submitted ? "opacity-60 pointer-events-none" : ""}>
                  <UploadZone
                    label="Final Video Upload"
                    accept="MP4 · MOV · Max 2GB"
                    icon={Play}
                    uploaded={finalVideoUploaded}
                    onUpload={() => { setFinalVideoUploaded(true); triggerSaved(); }}
                  />
                </div>
              </div>

              <div className={submitted ? "opacity-60 pointer-events-none" : ""}>
                <p className="text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-3">Caption File</p>
                <UploadZone
                  label="Caption / Script"
                  accept=".txt · .docx"
                  icon={FileText}
                  uploaded={captionUploaded}
                  onUpload={() => { setCaptionUploaded(true); triggerSaved(); }}
                />
              </div>

              <div className={submitted ? "opacity-60 pointer-events-none" : ""}>
                <p className="text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-3">Thumbnail</p>
                <UploadZone
                  label="Thumbnail Image"
                  accept="JPG · PNG · 1:1"
                  icon={Image}
                  uploaded={thumbUploaded}
                  onUpload={() => { setThumbUploaded(true); triggerSaved(); }}
                />
              </div>

              <div className={submitted ? "opacity-60 pointer-events-none" : ""}>
                <p className="text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-3">Raw Footage</p>
                <UploadZone
                  label="Raw Footage (Optional)"
                  accept="MP4 · ZIP · Max 4GB"
                  icon={FileVideo}
                  uploaded={false}
                  onUpload={() => {}}
                />
              </div>
            </div>

            {!submitted ? (
              <button
                onClick={handleSubmit}
                disabled={!finalVideoUploaded || submitting}
                className={`w-full py-4 rounded-[14px] flex items-center justify-center gap-2.5 text-[14px] font-semibold transition-all ${
                  finalVideoUploaded
                    ? "bg-[#07074E] text-white hover:bg-[#0D0D6B] shadow-[0_4px_20px_rgba(7,7,78,0.18)] hover:-translate-y-0.5"
                    : "bg-[#F3F3FF] text-[#B7B7E6] cursor-not-allowed"
                }`}
              >
                {submitting ? (
                  <>
                    <RefreshCw strokeWidth={2} className="w-4 h-4 animate-spin" />
                    Submitting…
                  </>
                ) : (
                  <>
                    <Send strokeWidth={2} className="w-4 h-4" />
                    Submit Final Delivery
                  </>
                )}
              </button>
            ) : (
              <div className="w-full py-4 rounded-[14px] flex items-center justify-center gap-2.5 bg-[#22C55E]/10 border border-[#22C55E]/25">
                <CheckCheck strokeWidth={2} className="w-4.5 h-4.5 text-[#22C55E]" />
                <span className="text-[14px] font-semibold text-[#22C55E]">Delivery Submitted — Under Review</span>
              </div>
            )}

            {!finalVideoUploaded && (
              <p className="text-center text-[12px] text-[#B7B7E6] font-medium mt-3 flex items-center justify-center gap-1.5">
                <Info strokeWidth={1.5} className="w-3.5 h-3.5" />
                Upload the final video to enable submission
              </p>
            )}
          </div>
        </SectionCard>

        {/* ── 5. Revision Timeline Card ── */}
        <SectionCard>
          <div className="px-8 py-6">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-9 h-9 rounded-[10px] bg-[#F59E0B]/10 flex items-center justify-center">
                <RotateCcw strokeWidth={1.5} className="w-4.5 h-4.5 text-[#F59E0B]" />
              </div>
              <div>
                <h3 className="text-[16px] font-semibold text-[#07074E] font-heading">Revision Timeline</h3>
                <p className="text-[12px] text-[#9F9FD1] font-medium">Feedback from brand</p>
              </div>
            </div>

            <div className="flex flex-col gap-0 relative">
              {/* Vertical line */}
              <div className="absolute left-[19px] top-5 bottom-[88px] w-px bg-[#E9EBEF]" />

              {[
                {
                  author: "GlowCo Brand Team",
                  avatar: "G",
                  avatarColor: "#7387FF",
                  time: "Apr 22 · 2:30 PM",
                  type: "feedback",
                  message: "Great energy and storytelling! However, we noticed the before/after transition was too quick. Could you extend it to at least 3 seconds?",
                },
                {
                  author: "Requested Change",
                  avatar: "!",
                  avatarColor: "#F59E0B",
                  time: "Apr 22 · 2:31 PM",
                  type: "revision",
                  message: "Extend before/after transition to 3+ seconds. Add product name overlay at second 12.",
                },
                {
                  author: "New Deadline Set",
                  avatar: "📅",
                  avatarColor: "#EF4444",
                  time: "Apr 22 · 2:32 PM",
                  type: "deadline",
                  message: "New submission deadline: May 3, 2026 — 11:59 PM IST",
                },
              ].map((item, i) => (
                <div key={i} className="flex gap-4 relative pb-6 last:pb-0">
                  <div
                    className="w-10 h-10 rounded-full flex items-center justify-center text-[13px] font-bold text-white flex-shrink-0 z-10 shadow-sm"
                    style={{ backgroundColor: item.avatarColor }}
                  >
                    {item.avatar}
                  </div>
                  <div className="flex-1 bg-[#F3F3FF]/60 rounded-[14px] p-4 border border-[#E9EBEF]/50">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[13px] font-semibold text-[#07074E]">{item.author}</span>
                      <span className="text-[11px] font-medium text-[#9F9FD1]">{item.time}</span>
                    </div>
                    <p className="text-[13px] text-[#4A4A7A] font-medium leading-relaxed">{item.message}</p>
                  </div>
                </div>
              ))}

              {/* Re-upload CTA */}
              <div className="mt-4 pt-4 border-t border-[#F3F3FF]">
                <button className="flex items-center gap-2.5 bg-[#7387FF] text-white px-5 py-3 rounded-[12px] text-[13px] font-semibold hover:bg-[#5A6EED] shadow-[0_4px_16px_rgba(115,135,255,0.25)] hover:-translate-y-0.5 transition-all">
                  <Upload strokeWidth={2} className="w-4 h-4" />
                  Upload Revised Video
                </button>
              </div>
            </div>
          </div>
        </SectionCard>
      </div>

      {/* ═══════════════════════════════════════════
          RIGHT COLUMN — 35%  (sticky)
      ═══════════════════════════════════════════ */}
      <div
        className="flex flex-col gap-5 flex-shrink-0 self-start"
        style={{ flex: "0 0 36%", position: "sticky", top: "0" }}
      >

        {/* A. Progress Tracker */}
        <SectionCard>
          <div className="px-6 py-6">
            <h3 className="text-[15px] font-semibold text-[#07074E] font-heading mb-5">Deal Progress</h3>
            <div className="flex flex-col gap-0 relative">
              <div className="absolute left-[15px] top-4 bottom-4 w-px bg-[#E9EBEF]" />
              {STEPS.map((step, i) => {
                const done = step.id < CURRENT_STEP;
                const current = step.id === CURRENT_STEP;
                const pending = step.id > CURRENT_STEP;
                return (
                  <div key={step.id} className="flex items-start gap-3.5 relative pb-4 last:pb-0">
                    <div className={`w-[32px] h-[32px] rounded-full flex items-center justify-center z-10 flex-shrink-0 transition-all ${
                      done
                        ? "bg-[#22C55E] shadow-[0_2px_8px_rgba(34,197,94,0.30)]"
                        : current
                        ? "bg-[#7387FF] shadow-[0_2px_12px_rgba(115,135,255,0.40)] ring-4 ring-[#7387FF]/15"
                        : "bg-white border-2 border-[#E9EBEF]"
                    }`}>
                      {done ? (
                        <CheckCheck strokeWidth={2.5} className="w-3.5 h-3.5 text-white" />
                      ) : current ? (
                        <div className="w-2.5 h-2.5 rounded-full bg-white" />
                      ) : (
                        <div className="w-2 h-2 rounded-full bg-[#D1D5DB]" />
                      )}
                    </div>
                    <div className="pt-0.5">
                      <p className={`text-[13px] font-semibold transition-colors ${
                        done ? "text-[#22C55E]" : current ? "text-[#7387FF]" : "text-[#B7B7E6]"
                      }`}>
                        {step.label}
                      </p>
                      <p className={`text-[11px] font-medium mt-0.5 ${current ? "text-[#7387FF]/70" : done ? "text-[#9F9FD1]" : "text-[#D1D5DB]"}`}>
                        {step.sub}
                      </p>
                    </div>
                    {current && (
                      <span className="ml-auto mt-0.5 flex-shrink-0 bg-[#7387FF]/10 text-[#7387FF] text-[10px] font-bold uppercase tracking-wider px-2.5 py-1 rounded-full">
                        Now
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </SectionCard>

        {/* B. Payout Summary */}
        <SectionCard>
          <div className="px-6 py-6">
            <div className="flex items-center gap-3 mb-5">
              <div className="w-8 h-8 rounded-[10px] bg-[#07074E]/8 flex items-center justify-center">
                <IndianRupee strokeWidth={1.5} className="w-4 h-4 text-[#07074E]" />
              </div>
              <h3 className="text-[15px] font-semibold text-[#07074E] font-heading">Payout Summary</h3>
            </div>

            <div className="flex flex-col gap-3 bg-[#F3F3FF]/50 rounded-[14px] p-4 mb-4">
              {[
                { label: "Total Payout", value: "₹15,000", color: "#07074E", size: "text-[16px]" },
                { label: "Platform Fee (10%)", value: "– ₹1,500", color: "#EF4444", size: "text-[13px]" },
                { label: "Tax Deduction (2%)", value: "– ₹300", color: "#EF4444", size: "text-[13px]" },
              ].map((row, i) => (
                <div key={i} className={`flex items-center justify-between ${i > 0 ? "border-t border-[#E9EBEF]/60 pt-3" : ""}`}>
                  <span className="text-[12.5px] font-medium text-[#9F9FD1]">{row.label}</span>
                  <span className={`${row.size} font-semibold font-heading`} style={{ color: row.color }}>{row.value}</span>
                </div>
              ))}
              <div className="border-t border-[#E9EBEF] pt-3 flex items-center justify-between">
                <span className="text-[13px] font-semibold text-[#07074E]">Net Payout to You</span>
                <span className="text-[20px] font-semibold text-[#7387FF] font-heading">₹12,500</span>
              </div>
            </div>

            <div className="flex items-center gap-2.5 bg-[#7387FF]/8 rounded-[12px] px-4 py-3 border border-[#7387FF]/15">
              <Calendar strokeWidth={1.5} className="w-4 h-4 text-[#7387FF] flex-shrink-0" />
              <div>
                <p className="text-[11.5px] font-semibold text-[#07074E]">Estimated Payout</p>
                <p className="text-[11px] text-[#9F9FD1] font-medium">May 17, 2026 · after approval</p>
              </div>
            </div>
          </div>
        </SectionCard>

        {/* C. Deadline Warning */}
        <div className="bg-gradient-to-br from-[#FFF7ED] to-[#FFFBF5] rounded-[20px] border border-[#F59E0B]/25 shadow-[0_4px_20px_rgba(245,158,11,0.10)] px-6 py-5 overflow-hidden relative">
          <div className="absolute top-0 right-0 w-24 h-24 bg-[#F59E0B]/10 blur-2xl rounded-full -mr-6 -mt-6 pointer-events-none" />
          <div className="flex items-start gap-3 relative z-10">
            <div className="w-10 h-10 rounded-[12px] bg-[#F59E0B]/15 flex items-center justify-center flex-shrink-0">
              <AlertTriangle strokeWidth={1.5} className="w-5 h-5 text-[#F59E0B]" />
            </div>
            <div>
              <p className="text-[13px] font-semibold text-[#92400E] mb-1">Deadline Approaching</p>
              <p className="text-[22px] font-semibold text-[#07074E] font-heading">72 hrs left</p>
              <p className="text-[12px] font-medium text-[#9F9FD1] mt-1">Due: May 3, 2026 · 11:59 PM IST</p>
            </div>
          </div>
          <div className="mt-4 h-2 bg-[#F59E0B]/15 rounded-full overflow-hidden">
            <div className="h-full w-[82%] bg-gradient-to-r from-[#F59E0B] to-[#FBBF24] rounded-full" />
          </div>
          <p className="text-[11px] font-medium text-[#9F9FD1] mt-2">82% of time elapsed</p>
        </div>

        {/* D. Help Card */}
        <SectionCard>
          <div className="px-6 py-6">
            <h3 className="text-[15px] font-semibold text-[#07074E] font-heading mb-4">Need Help?</h3>
            <div className="flex flex-col gap-2.5">
              {[
                {
                  icon: Headphones,
                  label: "Chat Support",
                  sub: "Avg. reply in 5 min",
                  color: "#7387FF",
                  bg: "#7387FF",
                  textWhite: true,
                },
                {
                  icon: Flag,
                  label: "Raise an Issue",
                  sub: "Dispute a deadline or brief",
                  color: "#F59E0B",
                  bg: "#F3F3FF",
                  textWhite: false,
                },
                {
                  icon: ShieldAlert,
                  label: "Report Damage",
                  sub: "Product arrived damaged?",
                  color: "#EF4444",
                  bg: "#F3F3FF",
                  textWhite: false,
                },
              ].map((btn, i) => (
                <button
                  key={i}
                  className={`flex items-center gap-3 px-4 py-3.5 rounded-[14px] text-left transition-all hover:-translate-y-0.5 hover:shadow-md ${
                    btn.textWhite
                      ? "bg-[#7387FF] shadow-[0_4px_16px_rgba(115,135,255,0.25)]"
                      : "bg-[#F3F3FF]/80 hover:bg-[#F3F3FF] border border-[#E9EBEF]/60"
                  }`}
                >
                  <div
                    className={`w-9 h-9 rounded-[10px] flex items-center justify-center flex-shrink-0 ${
                      btn.textWhite ? "bg-white/20" : "bg-white"
                    }`}
                  >
                    <btn.icon
                      strokeWidth={1.5}
                      className="w-4.5 h-4.5"
                      style={{ color: btn.textWhite ? "white" : btn.color }}
                    />
                  </div>
                  <div>
                    <p className={`text-[13px] font-semibold ${btn.textWhite ? "text-white" : "text-[#07074E]"}`}>
                      {btn.label}
                    </p>
                    <p className={`text-[11px] font-medium ${btn.textWhite ? "text-white/70" : "text-[#9F9FD1]"}`}>
                      {btn.sub}
                    </p>
                  </div>
                  <ArrowRight
                    strokeWidth={2}
                    className={`w-4 h-4 ml-auto ${btn.textWhite ? "text-white/60" : "text-[#B7B7E6]"}`}
                  />
                </button>
              ))}
            </div>
          </div>
        </SectionCard>

      </div>
    </div>
  );
}