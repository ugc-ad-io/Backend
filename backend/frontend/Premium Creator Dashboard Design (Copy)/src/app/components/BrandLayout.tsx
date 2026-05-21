import { Link, Outlet, useLocation, useNavigate } from "react-router";
import {
  LayoutDashboard,
  PenSquare,
  Users,
  ClipboardList,
  MessageSquare,
  Wallet,
  Building2,
  Settings,
  Bell,
  Search,
  ChevronRight,
} from "lucide-react";

const BRAND_NAV = [
  { name: "Brand Dashboard", path: "/brand",              icon: LayoutDashboard },
  { name: "Post a Campaign", path: "/brand/post-brief",   icon: PenSquare       },
  { name: "Creator Bids",    path: "/brand/applications", icon: Users           },
  { name: "Deal Room",       path: "/brand/deals",        icon: ClipboardList   },
  { name: "Messages",        path: "/brand/messages",     icon: MessageSquare   },
  { name: "Wallet",          path: "/brand/wallet",       icon: Wallet          },
  { name: "Settings",        path: "/brand/settings",     icon: Settings        },
];

function getPageMeta(pathname: string) {
  if (pathname === "/brand")                 return { title: "Brand Dashboard",  subtitle: "Manage campaigns, creators, approvals, and spending in one place" };
  if (pathname === "/brand/post-brief")      return { title: "Post a Campaign",  subtitle: "Create a new campaign and attract top creators"              };
  if (pathname === "/brand/applications")    return { title: "Creator Bids",     subtitle: "Review creator bids that match your campaign brief"                  };
  if (pathname === "/brand/deals")           return { title: "Active Deal Workspace", subtitle: "Review progress, approve deliverables, release payout"              };
  if (pathname === "/brand/messages")        return { title: "Messages",         subtitle: "Connect with creators and manage conversations"              };
  if (pathname === "/brand/wallet")          return { title: "Wallet",           subtitle: "Manage balance, recharges, and transaction history"          };
  if (pathname === "/brand/profile")         return { title: "Brand Profile",    subtitle: "Manage how creators see your brand"                          };
  if (pathname === "/brand/settings")        return { title: "Settings",         subtitle: "Manage preferences and notifications"                        };
  return { title: "Brand Dashboard", subtitle: "Manage campaigns, creators, deals, and budget" };
}

export function BrandLayout() {
  const location  = useLocation();
  const navigate  = useNavigate();
  const { title, subtitle } = getPageMeta(location.pathname);

  return (
    <div className="flex h-screen bg-[#F3F3FF] overflow-hidden font-sans">

      {/* ── Sidebar ── */}
      <aside className="w-[260px] flex-shrink-0 bg-[#07074E] text-white flex flex-col justify-between h-full relative z-30 rounded-r-[32px] shadow-[8px_0_32px_rgba(7,7,78,0.10)]">
        <div className="p-8 relative z-10">
          {/* Logo */}
          <div className="flex items-center gap-3 mb-10">
            <div className="w-8 h-8 rounded-[10px] bg-[#7387FF] flex items-center justify-center text-white font-semibold text-[15px] font-heading shadow-md shadow-[#7387FF]/20">
              U
            </div>
            <span className="text-[20px] font-semibold tracking-tight text-white font-heading">UGCad.io</span>
          </div>

          {/* Navigation */}
          <nav className="flex flex-col gap-1.5">
            <div className="text-[11px] font-medium text-[#9F9FD1] uppercase tracking-wider mb-2 px-4">Menu</div>
            {BRAND_NAV.map((item) => {
              const isActive =
                item.path === "/brand"
                  ? location.pathname === "/brand"
                  : location.pathname.startsWith(item.path);
              return (
                <Link
                  key={item.name}
                  to={item.path}
                  className={`flex items-center gap-3.5 px-4 py-3 rounded-full transition-all duration-200 group text-[14px] ${
                    isActive
                      ? "bg-white text-[#07074E] font-semibold shadow-sm"
                      : "text-white/70 hover:bg-white hover:text-[#07074E] font-medium"
                  }`}
                >
                  <item.icon
                    strokeWidth={2}
                    className={`w-[20px] h-[20px] ${isActive ? "text-[#07074E]" : "text-white/70 group-hover:text-[#07074E] transition-colors"}`}
                  />
                  {item.name}
                  {/* Notification badges for demo */}
                  {item.name === "Creator Bids" && (
                    <span className="ml-auto w-5 h-5 rounded-full bg-[#F39C12] text-white text-[10px] font-bold flex items-center justify-center">
                      3
                    </span>
                  )}
                  {item.name === "Messages" && (
                    <span className="ml-auto w-5 h-5 rounded-full bg-[#27AE60] text-white text-[10px] font-bold flex items-center justify-center">
                      2
                    </span>
                  )}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Sidebar footer: brand profile */}
        <div className="p-8 relative z-10">
          <div className="pt-6 border-t border-white/10 flex items-center gap-3.5">
            <img
              src="https://images.unsplash.com/photo-1697780871128-14146e7398fb?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxJbmRpYW4lMjB3b21hbiUyMHByb2Zlc3Npb25hbCUyMGVudHJlcHJlbmV1ciUyMHBvcnRyYWl0fGVufDF8fHx8MTc3NzEwMzE1NXww&ixlib=rb-4.1.0&q=80&w=64"
              alt="Priya Sharma"
              className="w-10 h-10 rounded-full object-cover ring-2 ring-white/20 shadow-sm"
            />
            <div className="flex-1 overflow-hidden">
              <div className="text-[14px] font-semibold text-white truncate">Priya Sharma</div>
              <div className="text-[12px] text-[#9F9FD1] truncate font-medium">D2C Marketing</div>
            </div>
          </div>
        </div>
      </aside>

      {/* ── Main Content ── */}
      <div className="flex-1 flex flex-col min-w-0 h-full relative bg-[#F3F3FF] overflow-x-auto">
        <div className="min-w-[1080px] flex-1 flex flex-col h-full">

          {/* Top Header */}
          <header className="h-[100px] flex items-center justify-between px-10 pt-4 z-20 shrink-0">
            <div className="flex flex-col flex-1">
              {/* Breadcrumb */}
              <div className="flex items-center gap-1.5 mb-1">
                <span className="text-[12px] font-medium text-[#B7B7E6] font-mono">Brand</span>
                <ChevronRight strokeWidth={1.5} className="w-3 h-3 text-[#C4C4E8]" />
                <span className="text-[12px] font-semibold text-[#7387FF] font-mono">
                  {location.pathname === "/brand/deals" ? "Deal Room" : title.split(" ")[0]}
                </span>
              </div>
              <h1 className="text-[26px] font-semibold text-[#07074E] font-heading tracking-tight">{title}</h1>
              <p className="text-[13.5px] font-medium text-[#9F9FD1] mt-0.5">{subtitle}</p>
            </div>

            {/* Search bar centered */}
            <div className="flex-1 flex justify-center max-w-md mx-6">
              <div className="w-full relative flex items-center">
                <Search strokeWidth={1.8} className="w-[18px] h-[18px] text-[#9F9FD1] absolute left-4" />
                <input
                  type="text"
                  placeholder="Search deals, creators, briefs..."
                  className="w-full h-11 bg-white rounded-full pl-11 pr-4 text-[13px] font-medium text-[#07074E] placeholder-[#C4C4E8] shadow-[0_2px_8px_rgba(7,7,78,0.06)] hover:shadow-[0_4px_12px_rgba(7,7,78,0.08)] border border-[#E9EBEF]/50 focus:outline-none focus:border-[#7387FF] focus:ring-1 focus:ring-[#7387FF]/50 transition-all"
                />
              </div>
            </div>

            <div className="flex items-center gap-5 flex-1 justify-end shrink-0">

              {/* Mode switcher */}
              <div className="flex items-center bg-white p-1.5 rounded-full shadow-[0_2px_8px_rgba(7,7,78,0.06)] border border-[#E9EBEF]/50 shrink-0">
                <button
                  onClick={() => navigate("/")}
                  className="px-5 py-2 text-[#9F9FD1] hover:text-[#07074E] rounded-full text-[13px] font-semibold transition-all whitespace-nowrap"
                >
                  Creator
                </button>
                <button className="px-5 py-2 bg-[#07074E] text-white rounded-full text-[13px] font-semibold shadow-sm transition-all whitespace-nowrap">
                  Brand
                </button>
              </div>

              {/* Notification */}
              <button className="relative w-10 h-10 rounded-full bg-white flex items-center justify-center text-[#9F9FD1] shadow-[0_2px_8px_rgba(7,7,78,0.06)] hover:shadow-[0_4px_12px_rgba(7,7,78,0.08)] transition-all">
                <Bell strokeWidth={1.8} className="w-[18px] h-[18px]" />
                <span className="absolute top-2.5 right-2.5 w-2 h-2 bg-[#F39C12] rounded-full ring-2 ring-white" />
              </button>

              {/* Avatar */}
              <img
                src="https://images.unsplash.com/photo-1697780871128-14146e7398fb?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxJbmRpYW4lMjB3b21hbiUyMHByb2Zlc3Npb25hbCUyMGVudHJlcHJlbmV1ciUyMHBvcnRyYWl0fGVufDF8fHx8MTc3NzEwMzE1NXww&ixlib=rb-4.1.0&q=80&w=48"
                alt="Priya"
                className="w-11 h-11 rounded-full object-cover shadow-[0_2px_8px_rgba(7,7,78,0.08)] ring-2 ring-white cursor-pointer"
              />
            </div>
          </header>

          {/* Page Content */}
          <main className="flex-1 overflow-y-auto overflow-x-hidden z-10 px-10 pb-10 pt-2 flex flex-col min-h-0 relative">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  );
}
