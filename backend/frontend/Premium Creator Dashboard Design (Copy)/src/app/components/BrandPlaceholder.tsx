import { Link, useLocation } from "react-router";
import { ArrowLeft, Hammer } from "lucide-react";

export function BrandPlaceholder() {
  const { pathname } = useLocation();
  const name = pathname.split("/brand/")[1] ?? "page";
  const label = name
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");

  return (
    <div className="flex flex-col items-center justify-center h-full min-h-[400px] gap-5">
      <div className="w-16 h-16 rounded-[20px] bg-[#EEF0FF] flex items-center justify-center shadow-sm">
        <Hammer strokeWidth={1.5} className="w-7 h-7 text-[#7387FF]" />
      </div>
      <div className="text-center">
        <h2 className="text-[22px] font-semibold text-[#07074E] font-heading mb-2">{label}</h2>
        <p className="text-[14px] font-medium text-[#9F9FD1] max-w-xs leading-relaxed">
          This page is coming soon. The full Brand experience is in active development.
        </p>
      </div>
      <Link
        to="/brand"
        className="flex items-center gap-2 px-5 py-2.5 bg-[#07074E] text-white rounded-[12px] text-[13.5px] font-semibold shadow-[0_4px_14px_rgba(7,7,78,0.18)] hover:-translate-y-0.5 transition-all"
      >
        <ArrowLeft strokeWidth={2} className="w-4 h-4" />
        Back to Dashboard
      </Link>
    </div>
  );
}
