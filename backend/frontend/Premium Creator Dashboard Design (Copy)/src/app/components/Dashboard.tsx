import { 
  Briefcase, 
  IndianRupee, 
  Star, 
  TrendingUp, 
  Trophy, 
  Zap, 
  ShieldCheck, 
  Box, 
  Repeat, 
  Layers, 
  ArrowRight,
  ArrowUpRight,
  Clock,
  MessageCircle,
  FileCheck
} from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const earningsData = [
  { name: 'Jan', value: 12000 },
  { name: 'Feb', value: 19000 },
  { name: 'Mar', value: 15000 },
  { name: 'Apr', value: 28000 },
  { name: 'May', value: 22000 },
  { name: 'Jun', value: 34000 },
];

export function Dashboard() {
  return (
    <div className="flex flex-col gap-[24px] max-w-[1440px] mx-auto w-full pb-10 pt-2 font-sans">
      
      {/* Row 1: Stat Cards */}
      <div className="grid grid-cols-4 gap-[24px]">
        {[
          { title: "Active Deals", value: "12", icon: Briefcase, trend: "+2 this week", color: "#7387FF", isPositive: true },
          { title: "Pending Payout", value: "₹45,500", icon: IndianRupee, trend: "Processing", color: "#F59E0B", isPositive: true },
          { title: "Total Earned", value: "₹1,24,000", icon: IndianRupee, trend: "+18% vs last mo", color: "#27AE60", isPositive: true },
          { title: "Creator Rating", value: "4.8", icon: Star, trend: "Top 5% creator", color: "#07074E", isStar: true, isPositive: true }
        ].map((stat, i) => (
          <div 
            key={i} 
            className="bg-white rounded-[24px] p-6 shadow-[0_4px_24px_rgba(7,7,78,0.04)] border border-transparent hover:border-[#E9EBEF] flex flex-col justify-between transition-all relative overflow-hidden group"
          >
            <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-bl from-[#7387FF]/5 to-transparent rounded-full blur-2xl -mr-16 -mt-16 pointer-events-none"></div>
            
            <div className="flex items-start justify-between mb-5 relative z-10">
              <div 
                className="w-[48px] h-[48px] rounded-[16px] flex items-center justify-center bg-[#F3F3FF] group-hover:scale-105 transition-transform duration-300"
                style={{ color: stat.isStar ? "#F59E0B" : stat.color }}
              >
                <stat.icon strokeWidth={1.5} className="w-6 h-6" />
              </div>
              <div className="flex items-center gap-1.5 text-[11.5px] font-medium text-[#07074E] bg-[#F3F3FF] px-2.5 py-1 rounded-[8px]">
                {stat.trend.includes('+') ? <TrendingUp strokeWidth={1.5} className="w-[14px] h-[14px] text-[#27AE60]" /> : null}
                <span className={stat.trend.includes('+') ? "text-[#27AE60]" : "text-[#9F9FD1]"}>{stat.trend}</span>
              </div>
            </div>
            
            <div className="relative z-10">
              <p className="text-[13px] font-medium text-[#9F9FD1] mb-1.5 uppercase tracking-wide">{stat.title}</p>
              <h3 className="text-[28px] font-semibold text-[#07074E] tracking-tight font-heading">
                {stat.value}
              </h3>
            </div>
          </div>
        ))}
      </div>

      {/* Row 2: Level Progress Hero Banner */}
      <div className="bg-gradient-to-r from-[#7387FF] to-[#4A63FF] rounded-[24px] p-8 shadow-[0_8px_32px_rgba(115,135,255,0.2)] relative overflow-hidden flex flex-row items-center justify-between gap-10">
        <div className="absolute right-0 top-0 w-[500px] h-[500px] bg-white/10 blur-[80px] rounded-full pointer-events-none -translate-y-1/3 translate-x-1/4"></div>
        <div className="absolute left-0 bottom-0 w-[300px] h-[300px] bg-[#07074E]/10 blur-[60px] rounded-full pointer-events-none translate-y-1/2 -translate-x-1/4"></div>
        
        {/* Left: Rank & Progress */}
        <div className="flex-1 w-full relative z-10 flex flex-row items-center gap-8">
          <div className="flex items-center gap-5 shrink-0">
            <div className="w-[64px] h-[64px] rounded-[20px] bg-white flex items-center justify-center shadow-lg shadow-black/10">
              <Trophy strokeWidth={1.5} className="w-8 h-8 text-[#F59E0B]" />
            </div>
            <div>
              <div className="flex items-center gap-2.5 mb-1.5">
                <span className="text-[12px] font-medium tracking-wider text-white/80 uppercase">Current Level</span>
                <span className="text-[10px] font-bold px-2.5 py-0.5 rounded-full bg-white text-[#7387FF] uppercase tracking-wider shadow-sm shrink-0">
                  Promo Eligible
                </span>
              </div>
              <h2 className="text-[28px] font-semibold text-white font-heading tracking-tight">L1 Rising Star</h2>
            </div>
          </div>

          <div className="w-full max-w-lg ml-8 border-l border-white/20 pl-8">
            <div className="flex justify-between items-end mb-2.5">
              <span className="text-[13px] font-medium text-white/90">Progress to L2 Professional</span>
              <span className="text-[13px] font-bold text-white">750 / 1000 XP</span>
            </div>
            <div className="w-full h-2.5 bg-[#07074E]/20 rounded-full overflow-hidden mb-3.5 backdrop-blur-sm">
              <div className="h-full bg-white rounded-full shadow-[0_0_10px_rgba(255,255,255,0.8)]" style={{ width: '75%' }}></div>
            </div>
            <div className="flex items-center gap-2 text-[12.5px] font-medium text-white/80">
              <Zap strokeWidth={2} className="w-[14px] h-[14px] text-[#F59E0B]" />
              <span>Next level unlocks: <strong className="text-white font-semibold">Premium Support</strong> & <strong className="text-white font-semibold">10% Higher Base Rates</strong></span>
            </div>
          </div>
        </div>

        {/* Right: Quick Metrics (Optional) */}
        <div className="min-w-[280px] bg-[#07074E]/20 backdrop-blur-md p-5 rounded-[20px] border border-white/10 shadow-lg relative z-10 flex items-center justify-between">
          <div className="flex flex-col gap-1.5 px-3 text-center">
            <span className="text-[11px] font-medium text-white/70 uppercase tracking-wider">Rating</span>
            <span className="text-[18px] font-semibold text-white flex items-center justify-center gap-1.5">
              4.7 <Star strokeWidth={2} className="w-4 h-4 text-[#F59E0B] fill-[#F59E0B]" />
            </span>
          </div>
          <div className="w-px h-10 bg-white/20"></div>
          <div className="flex flex-col gap-1.5 px-3 text-center">
            <span className="text-[11px] font-medium text-white/70 uppercase tracking-wider">Deals</span>
            <span className="text-[18px] font-semibold text-white">8</span>
          </div>
        </div>
      </div>

      {/* Row 3: Active Deals Table */}
      <div className="bg-white rounded-[24px] shadow-[0_4px_24px_rgba(7,7,78,0.04)] overflow-hidden border border-[#E9EBEF]/50">
        <div className="px-8 py-6 flex justify-between items-center bg-white border-b border-[#F3F3FF]">
          <h2 className="text-[18px] font-semibold text-[#07074E] font-heading">Active Campaigns</h2>
          <button className="text-[13px] font-semibold text-[#7387FF] hover:text-[#07074E] transition-colors flex items-center gap-1.5 bg-[#F3F3FF] hover:bg-[#E9EBEF] px-4 py-2 rounded-[10px]">
            View all deals <ArrowRight strokeWidth={2} className="w-[14px] h-[14px]" />
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse whitespace-nowrap">
            <thead>
              <tr className="bg-[#F3F3FF]/50 border-b border-[#E9EBEF]/50">
                <th className="px-8 py-4 text-[11px] font-semibold text-[#9F9FD1] uppercase tracking-wider">Brief Name</th>
                <th className="px-8 py-4 text-[11px] font-semibold text-[#9F9FD1] uppercase tracking-wider">Quality</th>
                <th className="px-8 py-4 text-[11px] font-semibold text-[#9F9FD1] uppercase tracking-wider">Brand Handle</th>
                <th className="px-8 py-4 text-[11px] font-semibold text-[#9F9FD1] uppercase tracking-wider">Stage</th>
                <th className="px-8 py-4 text-[11px] font-semibold text-[#9F9FD1] uppercase tracking-wider">Due Date</th>
                <th className="px-8 py-4 text-[11px] font-semibold text-[#9F9FD1] uppercase tracking-wider">Payout</th>
                <th className="px-8 py-4 text-[11px] font-semibold text-[#9F9FD1] uppercase tracking-wider text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {[
                { name: "Summer Hydration Routine", quality: "UGC Elite", brand: "@glowandco", stage: "Pending", statusColor: "#F59E0B", date: "Oct 12, 2023", payout: "₹12,500" },
                { name: "Smart Home Reel", quality: "Standard", brand: "@technova", stage: "In Review", statusColor: "#7387FF", date: "Oct 15, 2023", payout: "₹8,000" },
                { name: "Fitness Haul YT Shorts", quality: "Premium", brand: "@fitlife", stage: "Approved", statusColor: "#27AE60", date: "Oct 10, 2023", payout: "₹18,000" },
                { name: "Organic Coffee ASMR", quality: "Standard", brand: "@beanroast", stage: "Revision", statusColor: "#D4183D", date: "Oct 18, 2023", payout: "₹5,000" },
              ].map((deal, i) => (
                <tr key={i} className="hover:bg-[#F3F3FF]/30 transition-colors border-b border-[#F3F3FF] last:border-0 group">
                  <td className="px-8 py-5">
                    <span className="text-[14px] font-semibold text-[#07074E] group-hover:text-[#7387FF] transition-colors cursor-pointer">{deal.name}</span>
                  </td>
                  <td className="px-8 py-5">
                    <span className="text-[13px] font-medium text-[#9F9FD1]">{deal.quality}</span>
                  </td>
                  <td className="px-8 py-5">
                    <span className="text-[13px] font-medium text-[#07074E]">{deal.brand}</span>
                  </td>
                  <td className="px-8 py-5">
                    <span 
                      className="inline-flex items-center px-3 py-1 rounded-[8px] text-[11px] font-semibold tracking-wide border"
                      style={{ backgroundColor: `${deal.statusColor}10`, color: deal.statusColor, borderColor: `${deal.statusColor}20` }}
                    >
                      {deal.stage}
                    </span>
                  </td>
                  <td className="px-8 py-5">
                    <span className="text-[13px] font-medium text-[#9F9FD1]">{deal.date}</span>
                  </td>
                  <td className="px-8 py-5">
                    <span className="text-[14px] font-semibold text-[#07074E]">{deal.payout}</span>
                  </td>
                  <td className="px-8 py-5 text-right">
                    <button className="inline-flex items-center justify-center px-5 py-2.5 rounded-[12px] bg-white border border-[#E9EBEF] text-[13px] font-semibold text-[#07074E] hover:bg-[#07074E] hover:text-white shadow-sm transition-all">
                      Open
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Row 4: Earnings Analytics & Notifications */}
      <div className="grid grid-cols-3 gap-[24px]">
        {/* Earnings Analytics */}
        <div className="col-span-2 bg-white rounded-[24px] p-8 shadow-[0_4px_24px_rgba(7,7,78,0.04)] border border-[#E9EBEF]/50 flex flex-col">
          <div className="flex justify-between items-center mb-8">
            <div>
              <h2 className="text-[18px] font-semibold text-[#07074E] font-heading mb-1">Earnings Analytics</h2>
              <p className="text-[13px] text-[#9F9FD1] font-medium">Your payout performance over the last 6 months.</p>
            </div>
            <select className="bg-[#F3F3FF] border-none text-[#07074E] text-[13px] font-semibold py-2 px-4 rounded-[10px] outline-none cursor-pointer">
              <option>Last 6 Months</option>
              <option>This Year</option>
            </select>
          </div>
          <div className="flex-1 w-full min-h-[260px]">
            <ResponsiveContainer width="100%" height={260} minWidth={0}>
              <AreaChart data={earningsData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs key="defs">
                  <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
                    <stop key="stop1" offset="5%" stopColor="#7387FF" stopOpacity={0.3}/>
                    <stop key="stop2" offset="95%" stopColor="#7387FF" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid key="grid" strokeDasharray="3 3" vertical={false} stroke="#E9EBEF" />
                <XAxis key="xaxis" dataKey="name" axisLine={false} tickLine={false} tick={{fill: '#9F9FD1', fontSize: 12}} dy={10} />
                <YAxis key="yaxis" axisLine={false} tickLine={false} tick={{fill: '#9F9FD1', fontSize: 12}} />
                <Tooltip key="tooltip"
                  contentStyle={{ borderRadius: '12px', border: 'none', boxShadow: '0 4px 20px rgba(7,7,78,0.1)' }}
                  itemStyle={{ color: '#07074E', fontWeight: 600 }}
                />
                <Area key="area" type="monotone" dataKey="value" stroke="#7387FF" strokeWidth={3} fillOpacity={1} fill="url(#colorValue)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Notifications / Updates */}
        <div className="bg-white rounded-[24px] p-8 shadow-[0_4px_24px_rgba(7,7,78,0.04)] border border-[#E9EBEF]/50 flex flex-col">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-[18px] font-semibold text-[#07074E] font-heading">Updates</h2>
            <button className="text-[12px] font-semibold text-[#7387FF] hover:underline">Mark all read</button>
          </div>
          
          <div className="space-y-5">
            {[
              { icon: FileCheck, title: "Brief Approved", desc: "@glowandco approved your concept.", time: "2h ago", color: "#27AE60" },
              { icon: IndianRupee, title: "Payout Processed", desc: "₹18,000 sent to your bank account.", time: "5h ago", color: "#7387FF" },
              { icon: MessageCircle, title: "New Message", desc: "You have a message from @technova.", time: "1d ago", color: "#F59E0B" },
              { icon: Trophy, title: "Level Up Pending", desc: "You are 250 XP away from L2.", time: "2d ago", color: "#07074E" }
            ].map((update, i) => (
              <div key={i} className="flex gap-4 group cursor-pointer">
                <div className="w-10 h-10 rounded-full flex items-center justify-center shrink-0 mt-0.5 transition-transform group-hover:scale-110" style={{ backgroundColor: `${update.color}15`, color: update.color }}>
                  <update.icon strokeWidth={2} className="w-[18px] h-[18px]" />
                </div>
                <div>
                  <h4 className="text-[14px] font-semibold text-[#07074E] mb-0.5">{update.title}</h4>
                  <p className="text-[13px] text-[#9F9FD1] font-medium leading-snug mb-1">{update.desc}</p>
                  <span className="text-[11px] font-semibold text-[#9F9FD1] flex items-center gap-1">
                    <Clock strokeWidth={2} className="w-3 h-3" /> {update.time}
                  </span>
                </div>
              </div>
            ))}
          </div>
          <button className="w-full mt-6 py-3 rounded-[12px] bg-[#F3F3FF] text-[#07074E] text-[13px] font-semibold hover:bg-[#E9EBEF] transition-colors">
            View All Notifications
          </button>
        </div>
      </div>

      {/* Row 5: Badge Showcase & Rate Card */}
      <div className="grid grid-cols-3 gap-[24px]">
        {/* Left: Badge Showcase */}
        <div className="col-span-2 bg-white rounded-[24px] p-8 shadow-[0_4px_24px_rgba(7,7,78,0.04)] border border-[#E9EBEF]/50">
          <div className="flex justify-between items-center mb-6">
            <div>
              <h2 className="text-[18px] font-semibold text-[#07074E] font-heading mb-1">Creator Achievements</h2>
              <p className="text-[13px] text-[#9F9FD1] font-medium">Keep completing deals to unlock new badges.</p>
            </div>
            <span className="text-[12px] font-semibold text-[#7387FF] bg-[#7387FF]/10 px-3 py-1.5 rounded-[8px]">4 of 7 Unlocked</span>
          </div>
          
          <div className="grid grid-cols-4 gap-4">
            {/* Earned Badges */}
            {[
              { title: "Fast Deliverer", rule: "< 48h turnaround", icon: Zap },
              { title: "Brief Faithful", rule: "0 revisions needed", icon: ShieldCheck },
              { title: "5 Star Streak", rule: "5x 5-star ratings", icon: Star },
              { title: "Elite Creator", rule: "Top 10% volume", icon: Trophy }
            ].map((badge, i) => (
              <div key={i} className="flex flex-col items-center text-center p-5 rounded-[16px] bg-[#F3F3FF] relative overflow-hidden group hover:-translate-y-1 transition-transform duration-300">
                <div className="w-[48px] h-[48px] rounded-full bg-white shadow-sm flex items-center justify-center mb-3 relative z-10 text-[#7387FF]">
                  <badge.icon strokeWidth={2} className="w-6 h-6" />
                </div>
                <h4 className="text-[13px] font-semibold text-[#07074E] mb-1">{badge.title}</h4>
                <p className="text-[11px] font-medium text-[#9F9FD1]">{badge.rule}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Rate Card */}
        <div className="bg-[#07074E] rounded-[24px] p-8 shadow-[0_8px_32px_rgba(7,7,78,0.15)] relative overflow-hidden flex flex-col justify-between">
          <div className="absolute top-0 right-0 w-64 h-64 bg-[#7387FF]/20 blur-[60px] rounded-full pointer-events-none -translate-y-1/2 translate-x-1/4"></div>
          
          <div className="relative z-10 mb-6">
            <div className="flex justify-between items-center mb-2">
              <h2 className="text-[18px] font-semibold text-white font-heading">Rate Card</h2>
              <span className="bg-[#7387FF] text-white px-2.5 py-1 rounded-[6px] text-[10px] font-bold uppercase tracking-wider">Public</span>
            </div>
            <p className="text-[13px] text-[#9F9FD1] font-medium">Current baseline figures for L1 Rising.</p>
          </div>

          <div className="space-y-4 relative z-10 flex-1 bg-white/5 p-6 rounded-[16px] border border-white/10 backdrop-blur-md">
            <div className="flex justify-between items-center border-b border-white/5 pb-4">
              <span className="text-[13px] font-medium text-[#9F9FD1]">Minimum Rate</span>
              <span className="text-[18px] font-semibold text-white font-heading">₹5,000</span>
            </div>
            <div className="flex justify-between items-center border-b border-white/5 pb-4">
              <span className="text-[13px] font-medium text-[#9F9FD1]">Tier Multiplier</span>
              <span className="text-[18px] font-semibold text-[#27AE60] font-heading">1.2x</span>
            </div>
            <div className="flex justify-between items-center border-b border-white/5 pb-4">
              <span className="text-[13px] font-medium text-[#9F9FD1]">Custom Limit</span>
              <span className="text-[18px] font-semibold text-white font-heading">₹50,000</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-[13px] font-medium text-[#9F9FD1]">Payout Window</span>
              <span className="text-[15px] font-medium text-white">14 Days</span>
            </div>
          </div>

          <button className="w-full mt-6 py-3.5 rounded-[12px] bg-[#7387FF] text-white text-[14px] font-semibold hover:bg-[#5A6EED] shadow-[0_4px_16px_rgba(115,135,255,0.3)] transition-all relative z-10 flex items-center justify-center gap-2">
            Edit Rate Card
            <ArrowUpRight strokeWidth={2} className="w-[16px] h-[16px]" />
          </button>
        </div>
      </div>

    </div>
  );
}