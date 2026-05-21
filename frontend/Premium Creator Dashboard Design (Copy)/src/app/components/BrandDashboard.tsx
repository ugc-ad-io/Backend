import { useState } from "react";
import { Link } from "react-router";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Line,
  ComposedChart,
  Legend,
  Cell
} from "recharts";
import {
  TrendingUp,
  Lock,
  CheckCircle2,
  Wallet,
  Eye,
  MessageSquare,
  Package,
  Check,
  BarChart3,
  Star,
  Zap,
  PenSquare,
  Users,
  Download,
  Activity
} from "lucide-react";

// ─── Data ─────────────────────────────────────────────────────────────────────

const STATS = [
  {
    label:     "Active Deals",
    value:     "8",
    delta:     "+2 this week",
    positive:  true,
    icon:      Activity,
    iconBg:    "#EEF0FF",
    iconColor: "#7387FF",
  },
  {
    label:     "In Escrow",
    value:     "₹1,25,000",
    delta:     "Funds locked in live deals",
    positive:  null,
    icon:      Lock,
    iconBg:    "#F8F8FF",
    iconColor: "#9F9FD1",
  },
  {
    label:     "Delivered This Month",
    value:     "14",
    delta:     "+18% vs last month",
    positive:  true,
    icon:      CheckCircle2,
    iconBg:    "#E8F8EE",
    iconColor: "#27AE60",
  },
  {
    label:     "Wallet Balance",
    value:     "₹52,000",
    delta:     "Available to spend",
    positive:  null,
    icon:      Wallet,
    iconBg:    "#FFF8E8",
    iconColor: "#F39C12",
  },
];

const CAMPAIGN_DATA = [
  { name: "Jan", apps: 40, deals: 15, approved: 12, spend: 30 },
  { name: "Feb", apps: 60, deals: 25, approved: 20, spend: 45 },
  { name: "Mar", apps: 85, deals: 40, approved: 35, spend: 65 },
  { name: "Apr", apps: 75, deals: 35, approved: 30, spend: 55 },
  { name: "May", apps: 110, deals: 50, approved: 45, spend: 80 },
];

const FUNNEL_DATA = [
  { name: "Viewed Brief", value: 850 },
  { name: "Applied", value: 340 },
  { name: "Shortlisted", value: 120 },
  { name: "Accepted", value: 45 },
  { name: "Live", value: 38 },
];

const DEALS = [
  {
    id:       1,
    campaign: "Summer Hydration Reel",
    creator:  "@alexrivera",
    stage:    "Awaiting Review",
    stageKey: "review",
    dueDate:  "May 15",
    escrow:   "₹15,000",
    action:   "Review",
    actionKey:"review",
  },
  {
    id:       2,
    campaign: "Home Decor Unboxing",
    creator:  "@riyaugc",
    stage:    "In Production",
    stageKey: "production",
    dueDate:  "May 18",
    escrow:   "₹10,000",
    action:   "View",
    actionKey:"view",
  },
  {
    id:       3,
    campaign: "Smart Kitchen Demo",
    creator:  "@fitcreator",
    stage:    "Delivered",
    stageKey: "delivered",
    dueDate:  "May 10",
    escrow:   "₹18,000",
    action:   "Approved",
    actionKey:"approved",
  },
];

const PENDING_ACTIONS = [
  {
    id:     1,
    icon:   Eye,
    color:  "#F39C12",
    bg:     "#FFF8E8",
    title:  "Review Submitted Reel",
    cta:    "Review",
    ctaBg:  "#F39C12",
  },
  {
    id:     2,
    icon:   Check,
    color:  "#27AE60",
    bg:     "#E8F8EE",
    title:  "Approve Delivery",
    cta:    "Approve",
    ctaBg:  "#27AE60",
  },
  {
    id:     3,
    icon:   Package,
    color:  "#9F9FD1",
    bg:     "#F3F3FF",
    title:  "Confirm Shipment",
    cta:    "Ship",
    ctaBg:  "#07074E",
  },
  {
    id:     4,
    icon:   MessageSquare,
    color:  "#7387FF",
    bg:     "#EEF0FF",
    title:  "Reply to Creator",
    cta:    "Reply",
    ctaBg:  "#7387FF",
  },
];

const BUDGET_CATEGORIES = [
  { name: "Beauty", fill: 45, color: "#7387FF" },
  { name: "Tech", fill: 25, color: "#9F9FD1" },
  { name: "Lifestyle", fill: 20, color: "#07074E" },
  { name: "Fitness", fill: 10, color: "#27AE60" },
];

const TOP_CAMPAIGNS = [
  "Summer Hydration Reel",
  "Home Decor Unboxing",
  "Kitchen Demo Series",
];

const QUICK_ACTIONS = [
  { label: "Post a Campaign", icon: PenSquare, to: "/brand/post-brief" },
  { label: "Creator Bids",    icon: Users,     to: "/brand/applications" },
  { label: "Top Up Wallet",  icon: Wallet,    to: "/brand/wallet" },
  { label: "Download Report",icon: Download,  to: "/brand/settings" },
];

// ─── Stage chip styles ─────────────────────────────────────────────────────────

const STAGE_STYLES: Record<string, { bg: string; text: string; dot: string }> = {
  review:     { bg: "#FFF8E8", text: "#F39C12", dot: "#F39C12" },
  production: { bg: "#EEF0FF", text: "#7387FF", dot: "#7387FF" },
  delivered:  { bg: "#E8F8EE", text: "#27AE60", dot: "#27AE60" },
  approved:   { bg: "#27AE60", text: "#ffffff", dot: "#ffffff" },
};

// ─── Custom Tooltip ──────────────────────────────────────────────────────────

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-white p-3 rounded-[12px] shadow-[0_4px_20px_rgba(7,7,78,0.12)] border border-[#F0F0F8]">
        <p className="text-[13px] font-semibold text-[#07074E] mb-2">{label}</p>
        {payload.map((entry: any, index: number) => (
          <div key={index} className="flex items-center justify-between gap-4 mb-1">
            <div className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color }} />
              <span className="text-[11px] font-medium text-[#9F9FD1]">{entry.name}</span>
            </div>
            <span className="text-[12px] font-bold text-[#07074E]">
              {entry.name === "Spend (K)" ? `₹${entry.value}K` : entry.value}
            </span>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

// ─── Component ────────────────────────────────────────────────────────────────

export function BrandDashboard() {
  const [chartTab, setChartTab] = useState("Monthly");

  return (
    <div className="flex flex-col gap-6">

      {/* ── SECTION 1: TOP METRIC CARDS ── */}
      <div className="grid grid-cols-4 gap-6">
        {STATS.map((stat) => (
          <div
            key={stat.label}
            className="bg-white rounded-[18px] shadow-[0_4px_24px_rgba(7,7,78,0.04)] border border-[#F3F3FF] p-6 flex flex-col gap-4 hover:shadow-[0_8px_32px_rgba(7,7,78,0.08)] transition-shadow duration-300"
          >
            <div className="flex items-start justify-between">
              <div
                className="w-10 h-10 rounded-[12px] flex items-center justify-center shadow-sm"
                style={{ backgroundColor: stat.iconBg }}
              >
                <stat.icon strokeWidth={2} className="w-5 h-5" style={{ color: stat.iconColor }} />
              </div>
              {stat.positive === true && (
                <div className="flex items-center gap-1 bg-[#27AE60]/10 px-2 py-1 rounded-full">
                  <TrendingUp strokeWidth={2.5} className="w-3 h-3 text-[#27AE60]" />
                  <span className="text-[10px] font-bold text-[#27AE60]">UP</span>
                </div>
              )}
            </div>
            
            <div>
              <p className="text-[13px] font-semibold text-[#9F9FD1] mb-1">{stat.label}</p>
              <h3 className="text-[28px] font-bold text-[#07074E] font-heading leading-tight">
                {stat.value}
              </h3>
            </div>
            
            <div className="pt-3 border-t border-[#F3F3FF] mt-auto">
              <span className="text-[12px] font-medium text-[#9F9FD1]">{stat.delta}</span>
            </div>
          </div>
        ))}
      </div>

      {/* ── SECTION 2: ANALYTICS ROW ── */}
      <div className="flex gap-6 items-stretch">
        
        {/* Left Large Card: Campaign Performance */}
        <div className="flex-[2] bg-white rounded-[18px] shadow-[0_4px_24px_rgba(7,7,78,0.04)] border border-[#F3F3FF] p-6 flex flex-col min-w-0">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-[16px] font-semibold text-[#07074E] font-heading">Campaign Performance</h3>
            <div className="flex items-center bg-[#F3F3FF] p-1 rounded-[10px]">
              {["Weekly", "Monthly", "Quarterly"].map(tab => (
                <button
                  key={tab}
                  onClick={() => setChartTab(tab)}
                  className={`px-3 py-1.5 text-[12px] font-semibold rounded-[8px] transition-all ${
                    chartTab === tab 
                      ? "bg-white text-[#07074E] shadow-sm" 
                      : "text-[#9F9FD1] hover:text-[#07074E]"
                  }`}
                >
                  {tab}
                </button>
              ))}
            </div>
          </div>
          
          <div className="h-[260px] w-full mt-auto">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart data={CAMPAIGN_DATA} margin={{ top: 10, right: 0, left: -20, bottom: 0 }}>
                <CartesianGrid key="grid" strokeDasharray="3 3" vertical={false} stroke="#F0F0F8" />
                <XAxis 
                  key="xaxis"
                  dataKey="name" 
                  axisLine={false} 
                  tickLine={false} 
                  tick={{ fontSize: 11, fill: '#9F9FD1', fontWeight: 500 }} 
                  dy={10}
                />
                <YAxis 
                  key="yaxis-left"
                  yAxisId="left"
                  axisLine={false} 
                  tickLine={false} 
                  tick={{ fontSize: 11, fill: '#9F9FD1', fontWeight: 500 }}
                />
                <YAxis 
                  key="yaxis-right"
                  yAxisId="right"
                  orientation="right"
                  axisLine={false} 
                  tickLine={false} 
                  tick={{ fontSize: 11, fill: '#9F9FD1', fontWeight: 500 }}
                />
                <RechartsTooltip key="tooltip" content={<CustomTooltip />} cursor={{ fill: '#F8F8FF' }} />
                <Legend 
                  key="legend"
                  wrapperStyle={{ fontSize: '11px', fontWeight: 500, color: '#9F9FD1', paddingTop: '10px' }}
                  iconType="circle"
                  iconSize={8}
                />
                <Bar key="bar-deals" yAxisId="left" dataKey="deals" name="Deals Closed" fill="#07074E" radius={[4, 4, 0, 0]} maxBarSize={40} />
                <Bar key="bar-approved" yAxisId="left" dataKey="approved" name="Approved Deliveries" fill="#7387FF" radius={[4, 4, 0, 0]} maxBarSize={40} />
                <Line key="line-apps" yAxisId="left" type="monotone" dataKey="apps" name="Applications Received" stroke="#27AE60" strokeWidth={3} dot={{ r: 4, strokeWidth: 2, fill: '#fff' }} />
                <Line key="line-spend" yAxisId="right" type="monotone" dataKey="spend" name="Spend (K)" stroke="#F39C12" strokeWidth={3} dot={{ r: 4, strokeWidth: 2, fill: '#fff' }} activeDot={{ r: 6, fill: '#F39C12' }} />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Center Card: Creator Funnel */}
        <div className="flex-1 bg-white rounded-[18px] shadow-[0_4px_24px_rgba(7,7,78,0.04)] border border-[#F3F3FF] p-6 flex flex-col min-w-0">
          <h3 className="text-[16px] font-semibold text-[#07074E] font-heading mb-6">Creator Funnel</h3>
          <div className="h-[260px] w-full mt-auto">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={FUNNEL_DATA} margin={{ top: 10, right: 0, left: -20, bottom: 0 }}>
                <CartesianGrid key="grid" strokeDasharray="3 3" vertical={false} stroke="#F0F0F8" />
                <XAxis 
                  key="xaxis"
                  dataKey="name" 
                  axisLine={false} 
                  tickLine={false} 
                  tick={{ fontSize: 10, fill: '#9F9FD1', fontWeight: 600 }} 
                  dy={10}
                />
                <YAxis 
                  key="yaxis"
                  axisLine={false} 
                  tickLine={false} 
                  tick={{ fontSize: 11, fill: '#9F9FD1', fontWeight: 500 }}
                />
                <RechartsTooltip 
                  key="tooltip"
                  cursor={{ fill: '#F8F8FF' }}
                  contentStyle={{ borderRadius: '12px', border: '1px solid #F0F0F8', boxShadow: '0 4px 20px rgba(7,7,78,0.12)', fontSize: '12px', fontWeight: 600, color: '#07074E' }}
                />
                <Bar key="bar" dataKey="value" fill="#7387FF" radius={[6, 6, 0, 0]}>
                  {
                    FUNNEL_DATA.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={
                        index === 0 ? '#EAEAF8' :
                        index === 1 ? '#9F9FD1' :
                        index === 2 ? '#7387FF' :
                        index === 3 ? '#2A3B9A' : '#07074E'
                      } />
                    ))
                  }
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Right Sidebar Stack */}
        <div className="w-[280px] flex-shrink-0 flex flex-col gap-6">
          {/* Card A: Top Campaigns */}
          <div className="bg-white rounded-[18px] shadow-[0_4px_24px_rgba(7,7,78,0.04)] border border-[#F3F3FF] p-5">
            <h3 className="text-[14px] font-semibold text-[#07074E] mb-4">Top Campaigns</h3>
            <div className="flex flex-col gap-3">
              {TOP_CAMPAIGNS.map((campaign, i) => (
                <div key={i} className="flex items-center gap-3">
                  <div className="w-6 h-6 rounded-full bg-[#EEF0FF] text-[#7387FF] text-[10px] font-bold flex items-center justify-center flex-shrink-0">
                    {i + 1}
                  </div>
                  <span className="text-[12.5px] font-medium text-[#07074E] leading-tight">{campaign}</span>
                </div>
              ))}
            </div>
          </div>
          
          <div className="grid grid-cols-2 gap-4 flex-1">
            {/* Card B: Approval Rate */}
            <div className="bg-white rounded-[18px] shadow-[0_4px_24px_rgba(7,7,78,0.04)] border border-[#F3F3FF] p-4 flex flex-col justify-center items-center text-center">
              <span className="text-[12px] font-semibold text-[#9F9FD1] mb-1">Approval Rate</span>
              <div className="text-[24px] font-bold text-[#27AE60] font-heading">92%</div>
            </div>
            
            {/* Card C: Avg Creator Rating */}
            <div className="bg-white rounded-[18px] shadow-[0_4px_24px_rgba(7,7,78,0.04)] border border-[#F3F3FF] p-4 flex flex-col justify-center items-center text-center">
              <span className="text-[12px] font-semibold text-[#9F9FD1] mb-1">Avg Rating</span>
              <div className="flex items-center gap-1.5 text-[24px] font-bold text-[#07074E] font-heading">
                4.8<Star className="w-4 h-4 text-[#F39C12] fill-[#F39C12] -mt-1" />
              </div>
            </div>
          </div>
        </div>

      </div>

      {/* ── SECTION 3: OPERATIONS AREA ── */}
      <div className="flex gap-6 items-start mt-2">
        
        {/* Left Wide Card: Active Deals Table */}
        <div className="flex-[3] bg-white rounded-[18px] shadow-[0_4px_24px_rgba(7,7,78,0.04)] border border-[#F3F3FF] overflow-hidden">
          <div className="px-6 py-5 border-b border-[#F3F3FF] flex items-center justify-between">
            <h3 className="text-[16px] font-semibold text-[#07074E] font-heading">Active Deals</h3>
            <Link to="/brand/deals" className="text-[13px] font-semibold text-[#7387FF] hover:underline">
              View All
            </Link>
          </div>
          <table className="w-full">
            <thead>
              <tr className="bg-[#F8F8FF]">
                {["Campaign", "Creator", "Stage", "Due Date", "Escrow", "Action"].map((h) => (
                  <th key={h} className="px-6 py-3.5 text-left text-[11px] font-bold text-[#9F9FD1] uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {DEALS.map((deal, i) => {
                const stage = STAGE_STYLES[deal.stageKey];
                const isLast = i === DEALS.length - 1;
                return (
                  <tr key={deal.id} className={`hover:bg-[#F9F9FF] transition-colors ${!isLast ? "border-b border-[#F3F3FF]" : ""}`}>
                    <td className="px-6 py-4">
                      <span className="text-[13.5px] font-semibold text-[#07074E]">{deal.campaign}</span>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-[13px] font-semibold text-[#7387FF] font-mono">{deal.creator}</span>
                    </td>
                    <td className="px-6 py-4">
                      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-bold uppercase tracking-wide"
                        style={{ backgroundColor: stage.bg, color: stage.text }}>
                        <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: stage.dot }} />
                        {deal.stage}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-[13px] font-medium text-[#9F9FD1]">{deal.dueDate}</span>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-[13.5px] font-bold text-[#07074E]">{deal.escrow}</span>
                    </td>
                    <td className="px-6 py-4">
                      {deal.actionKey === "approved" ? (
                        <span className="inline-flex items-center gap-1.5 text-[#27AE60] text-[12.5px] font-bold">
                          <CheckCircle2 strokeWidth={2.5} className="w-4 h-4" />
                          Approved
                        </span>
                      ) : deal.actionKey === "review" ? (
                        <button className="px-4 py-1.5 rounded-[8px] bg-[#F39C12] text-white text-[12px] font-bold shadow-[0_2px_8px_rgba(243,156,18,0.3)] hover:shadow-[0_4px_12px_rgba(243,156,18,0.4)] transition-all">
                          Review
                        </button>
                      ) : (
                        <button className="px-4 py-1.5 rounded-[8px] bg-[#F3F3FF] text-[#07074E] text-[12px] font-bold hover:bg-[#E8E8F8] transition-all">
                          View
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Right Column Stack */}
        <div className="flex-[1.2] flex flex-col gap-6">
          
          {/* Card 1: Pending Actions */}
          <div className="bg-white rounded-[18px] shadow-[0_4px_24px_rgba(7,7,78,0.04)] border border-[#F3F3FF] p-5">
            <h3 className="text-[14px] font-semibold text-[#07074E] mb-4">Pending Actions</h3>
            <div className="flex flex-col gap-3">
              {PENDING_ACTIONS.map(a => (
                <div key={a.id} className="flex items-center justify-between group">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-[8px] flex items-center justify-center" style={{ backgroundColor: a.bg }}>
                      <a.icon className="w-4 h-4" style={{ color: a.color }} />
                    </div>
                    <span className="text-[12.5px] font-semibold text-[#07074E]">{a.title}</span>
                  </div>
                  <button 
                    className="opacity-0 group-hover:opacity-100 transition-opacity px-3 py-1 rounded-[6px] text-white text-[11px] font-bold"
                    style={{ backgroundColor: a.ctaBg }}
                  >
                    {a.cta}
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Card 2: Budget Usage */}
          <div className="bg-white rounded-[18px] shadow-[0_4px_24px_rgba(7,7,78,0.04)] border border-[#F3F3FF] p-5">
            <h3 className="text-[14px] font-semibold text-[#07074E] mb-1">Budget Usage</h3>
            <p className="text-[12px] font-medium text-[#9F9FD1] mb-5">₹80,000 / ₹1,00,000 used</p>
            
            <div className="flex flex-col gap-3">
              {BUDGET_CATEGORIES.map(cat => (
                <div key={cat.name}>
                  <div className="flex justify-between text-[11px] font-bold text-[#07074E] mb-1.5">
                    <span>{cat.name}</span>
                    <span>{cat.fill}%</span>
                  </div>
                  <div className="w-full h-1.5 bg-[#F3F3FF] rounded-full overflow-hidden">
                    <div className="h-full rounded-full" style={{ width: `${cat.fill}%`, backgroundColor: cat.color }} />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Card 3: Quick Actions */}
          <div className="bg-white rounded-[18px] shadow-[0_4px_24px_rgba(7,7,78,0.04)] border border-[#F3F3FF] p-5">
            <h3 className="text-[14px] font-semibold text-[#07074E] mb-4">Quick Actions</h3>
            <div className="grid grid-cols-2 gap-3">
              {QUICK_ACTIONS.map(action => (
                <Link 
                  key={action.label} 
                  to={action.to}
                  className="flex flex-col items-center justify-center gap-2 p-3 rounded-[12px] bg-[#F8F8FF] hover:bg-[#EEF0FF] transition-colors border border-[#F0F0F8] hover:border-[#D8D8F0]"
                >
                  <action.icon className="w-5 h-5 text-[#7387FF]" />
                  <span className="text-[11px] font-bold text-[#07074E] text-center">{action.label}</span>
                </Link>
              ))}
            </div>
          </div>

        </div>

      </div>

    </div>
  );
}
