import { Link, Outlet, useLocation } from "react-router";
import { 
  LayoutDashboard, 
  Briefcase, 
  ClipboardList, 
  MessageSquare, 
  IndianRupee,
  User,
  Settings,
  Bell,
  Search,
  ChevronDown
} from "lucide-react";

export function RootLayout() {
  const location = useLocation();

  const navItems = [
    { name: "Dashboard", path: "/", icon: LayoutDashboard },
    { name: "Browse Briefs", path: "/briefs", icon: Briefcase },
    { name: "My Deals", path: "/deals", icon: ClipboardList },
    { name: "Messages", path: "/messages", icon: MessageSquare },
    { name: "Payout", path: "/payouts", icon: IndianRupee },
    { name: "Profile", path: "/profile", icon: User },
    { name: "Settings", path: "/settings", icon: Settings },
  ];

  const getPageTitle = () => {
    switch (location.pathname) {
      case "/": return { title: "Creator Dashboard", subtitle: "Welcome back, Creator" };
      case "/briefs": return { title: "Browse Briefs", subtitle: "Find your next campaign" };
      case "/deals": return { title: "Deal Room", subtitle: "Manage your campaign delivery" };
      case "/messages": return { title: "Messages", subtitle: "Connect with brands and manage conversations" };
      case "/payouts": return { title: "Payouts", subtitle: "Track earnings and payment history" };
      case "/profile": return { title: "Creator Profile", subtitle: "Manage how brands see your profile" };
      case "/settings": return { title: "Settings", subtitle: "Manage preferences" };
      default: return { title: "Creator Dashboard", subtitle: "Overview" };
    }
  };

  const { title, subtitle } = getPageTitle();

  return (
    <div className="flex h-screen bg-[#F3F3FF] overflow-hidden font-sans">
      {/* Sidebar */}
      <aside className="w-[260px] flex-shrink-0 bg-[#07074E] text-white flex flex-col justify-between h-full relative z-30 rounded-r-[32px] shadow-[8px_0_32px_rgba(7,7,78,0.08)]">
        <div className="p-8 relative z-10">
          <div className="flex items-center gap-3 mb-10">
            <div className="w-8 h-8 rounded-[10px] bg-[#7387FF] flex items-center justify-center text-white font-semibold text-[15px] font-heading shadow-md shadow-[#7387FF]/20">
              U
            </div>
            <span className="text-[20px] font-semibold tracking-tight text-white font-heading">UGCad.io</span>
          </div>

          <nav className="flex flex-col gap-2">
            <div className="text-[11px] font-medium text-[#9F9FD1] uppercase tracking-wider mb-2 px-4">Menu</div>
            {navItems.map((item) => {
              const isActive = location.pathname === item.path || (item.path !== "/" && location.pathname.startsWith(item.path));
              return (
                <Link
                  key={item.name}
                  to={item.path}
                  className={`flex items-center gap-3.5 px-4 py-3 rounded-full transition-all duration-200 group text-[14px] ${
                    isActive 
                      ? "bg-white text-[#07074E] font-semibold shadow-sm" 
                      : "text-white/70 hover:bg-white/10 hover:text-white font-medium"
                  }`}
                >
                  <item.icon strokeWidth={2} className={`w-[20px] h-[20px] ${isActive ? "text-[#07074E]" : "text-white/70 group-hover:text-white transition-colors"}`} />
                  {item.name}
                </Link>
              );
            })}
          </nav>
        </div>

        <div className="p-8 relative z-10">
          <div className="pt-6 border-t border-white/10 flex items-center gap-3.5">
            <img 
              src="https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=64&h=64" 
              alt="Creator Profile" 
              className="w-10 h-10 rounded-full object-cover ring-2 ring-white/20 shadow-sm"
            />
            <div className="flex-1 overflow-hidden">
              <div className="text-[14px] font-semibold text-white truncate">Alex Rivera</div>
              <div className="text-[12px] text-[#9F9FD1] truncate font-medium">Top Creator</div>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0 h-full relative bg-[#F3F3FF] overflow-x-auto">
        <div className="min-w-[1080px] flex-1 flex flex-col h-full">
          {/* Top Navigation */}
          <header className="h-[100px] flex items-center justify-between px-10 pt-4 z-20 shrink-0">
          <div className="flex flex-col">
            <h1 className="text-[26px] font-semibold text-[#07074E] font-heading tracking-tight mb-1">{title}</h1>
            <p className="text-[14px] font-medium text-[#9F9FD1]">{subtitle}</p>
          </div>
          
          <div className="flex items-center gap-6 shrink-0">
            <button className="w-10 h-10 rounded-full bg-white flex items-center justify-center text-[#07074E] shadow-[0_2px_8px_rgba(7,7,78,0.06)] hover:shadow-[0_4px_12px_rgba(7,7,78,0.08)] transition-all">
              <Search strokeWidth={2} className="w-[18px] h-[18px]" />
            </button>
            
            <div className="flex items-center bg-white p-1.5 rounded-full shadow-[0_2px_8px_rgba(7,7,78,0.06)] border border-[#E9EBEF]/50 shrink-0">
              <button className="px-5 py-2 bg-[#07074E] text-white rounded-full text-[13px] font-semibold shadow-sm transition-all whitespace-nowrap">
                Creator
              </button>
              <Link to="/brand" className="px-5 py-2 text-[#9F9FD1] hover:text-[#07074E] rounded-full text-[13px] font-semibold transition-all whitespace-nowrap">
                Brand
              </Link>
            </div>

            <button className="relative w-10 h-10 rounded-full bg-white flex items-center justify-center text-[#07074E] shadow-[0_2px_8px_rgba(7,7,78,0.06)] hover:shadow-[0_4px_12px_rgba(7,7,78,0.08)] transition-all">
              <Bell strokeWidth={2} className="w-[18px] h-[18px]" />
              <span className="absolute top-2.5 right-2.5 w-2 h-2 bg-[#27AE60] rounded-full ring-2 ring-white"></span>
            </button>
            
            <img 
              src="https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=48&h=48" 
              alt="Profile" 
              className="w-11 h-11 rounded-full object-cover shadow-[0_2px_8px_rgba(7,7,78,0.08)] ring-2 ring-white cursor-pointer"
            />
          </div>
        </header>

        {/* Page Content */}
          <main className="flex-1 overflow-auto z-10 px-10 pb-10 pt-4">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  );
}