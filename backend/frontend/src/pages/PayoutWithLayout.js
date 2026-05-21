import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import {
  Search,
  ChevronDown,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  XCircle,
  LogOut,
  LayoutDashboard,
  Bookmark,
  Briefcase,
  FileCheck,
  MessageSquare,
  Settings,
  Star,
  User,
  Bell,
  IndianRupee,
  Zap as ZapIcon
} from 'lucide-react';
import DashboardLayout from '../components/DashboardLayout';
import './CreatorDashboard.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const STATUS_STYLES = {
  Paid: { bg: "#22C55E12", text: "#22C55E", border: "#22C55E25", icon: CheckCircle2 },
  Processing: { bg: "#7387FF12", text: "#7387FF", border: "#7387FF25", icon: RefreshCw },
  Disputed: { bg: "#EF444412", text: "#EF4444", border: "#EF444425", icon: XCircle },
  Pending: { bg: "#F59E0B12", text: "#F59E0B", border: "#F59E0B25", icon: AlertCircle },
};

const STATUS_MAP = {
  completed: "Paid",
  processing: "Processing",
  pending: "Pending",
  rejected: "Disputed",
};

function StatusChip({ status }) {
  const s = STATUS_STYLES[status] || STATUS_STYLES.Pending;
  const Icon = s.icon;
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11.5px] font-semibold border whitespace-nowrap"
      style={{ backgroundColor: s.bg, color: s.text, borderColor: s.border }}
    >
      <Icon strokeWidth={2} className="w-3 h-3" />
      {status}
    </span>
  );
}

export default function PayoutWithLayout() {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [withdrawals, setWithdrawals] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState("All");
  const [searchQuery, setSearchQuery] = useState("");
  const [showStatusDrop, setShowStatusDrop] = useState(false);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const withdrawalsRes = await axios.get(`${API}/withdrawal/history`);
      setWithdrawals(withdrawalsRes.data);
    } catch (error) {
      toast.error('Failed to load withdrawal history');
    } finally {
      setLoading(false);
    }
  };

  const navItems = [
    { name: 'Dashboard', icon: LayoutDashboard, action: () => navigate('/dashboard/creator') },
    { name: 'My Active Work', icon: ZapIcon, action: () => navigate('/my-active-work') },
    { name: 'My Bids', icon: Bookmark, action: () => navigate('/my-bids') },
    { name: 'Reviews', icon: Star, action: () => navigate('/reviews') },
    { name: 'Portfolio', icon: User, action: () => navigate('/portfolio') },
    { name: 'Browse Briefs', icon: Briefcase, action: () => navigate('/browse-briefs') },
    { name: 'My Deals', icon: FileCheck, action: () => navigate('/my-deals') },
    { name: 'Messages', icon: MessageSquare, action: () => navigate('/messages') },
    { name: 'Payout', icon: IndianRupee, action: () => {}, active: true },
    { name: 'Settings', icon: Settings, action: () => navigate('/settings') }
  ];

  const getInitial = (name) => {
    if (!name) return 'C';
    return name.charAt(0).toUpperCase();
  };

  const displayName = user?.nickname || 'Creator';

  const filtered = withdrawals.filter((row) => {
    const mappedStatus = STATUS_MAP[row.status] || row.status;
    const matchStatus = statusFilter === "All" || mappedStatus === statusFilter;
    const matchSearch = searchQuery === "" || row.id?.toString().toLowerCase().includes(searchQuery.toLowerCase());
    return matchStatus && matchSearch;
  });

  return (
    <DashboardLayout
      navItems={navItems}
      title="Payout & Withdrawals"
      description="View your withdrawal history"
      topbarExtra={null}
      sidebarExtra={null}
    >
      {loading ? (
        <div className="flex items-center justify-center py-20">Loading...</div>
      ) : (
        <div style={{ padding: '40px 8%' }}>
          <div className="bg-white rounded-[20px] shadow-[0_4px_24px_rgba(7,7,78,0.05)] border border-[#E9EBEF]/50 overflow-hidden">
              <div className="px-6 py-5 border-b border-[#E9EBEF]/60">
                <h2 className="text-[20px] font-semibold text-[#07074E] mb-4">Payment History</h2>
                <div className="flex gap-3">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-[#B7B7E6]" />
                    <input
                      type="text"
                      placeholder="Search withdrawal ID…"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="bg-[#F3F3FF] text-[13px] font-medium text-[#07074E] placeholder-[#B7B7E6] outline-none w-full pl-10 py-2.5 rounded-[11px]"
                    />
                  </div>

                  <div className="relative">
                    <button
                      onClick={() => setShowStatusDrop(!showStatusDrop)}
                      className="flex items-center gap-2 bg-[#F3F3FF] hover:bg-[#E9EBEF] rounded-[11px] px-4 py-2.5 text-[13px] font-semibold text-[#07074E] transition-colors whitespace-nowrap"
                    >
                      <ChevronDown className={`w-3.5 h-3.5 text-[#9F9FD1] transition-transform ${showStatusDrop ? "rotate-180" : ""}`} />
                      {statusFilter === "All" ? "All Status" : statusFilter}
                    </button>
                    {showStatusDrop && (
                      <div className="absolute top-full mt-2 right-0 bg-white rounded-[14px] shadow-[0_8px_32px_rgba(7,7,78,0.12)] border border-[#E9EBEF]/60 z-20 overflow-hidden min-w-[160px]">
                        {["All", "Paid", "Processing", "Pending", "Disputed"].map((s) => (
                          <button
                            key={s}
                            onClick={() => { setStatusFilter(s); setShowStatusDrop(false); }}
                            className={`w-full text-left px-4 py-2.5 text-[13px] font-medium transition-colors ${statusFilter === s ? "bg-[#7387FF]/8 text-[#7387FF]" : "text-[#07074E] hover:bg-[#F3F3FF]"}`}
                          >
                            {s === "All" ? "All Status" : s}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {filtered.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-20 px-8">
                  <p className="text-[16px] font-semibold text-[#07074E] mb-2">No withdrawals found</p>
                  <p className="text-[13px] text-[#9F9FD1] font-medium text-center max-w-xs">
                    You haven't requested any withdrawals yet.
                  </p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead>
                      <tr className="bg-[#F3F3FF]/50 border-b border-[#E9EBEF]/60">
                        {["TXN ID", "Amount", "Status", "Date", "Method"].map((col) => (
                          <th key={col} className="px-5 py-3.5 text-[11px] font-semibold text-[#9F9FD1] uppercase tracking-wider">
                            {col}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {filtered.map((row) => (
                        <tr key={row.id} className="border-b border-[#F3F3FF] hover:bg-[#F3F3FF]/40 transition-colors">
                          <td className="px-5 py-4">
                            <span className="text-[12px] font-semibold text-[#7387FF] font-mono bg-[#7387FF]/8 px-2 py-0.5 rounded-[6px]">
                              TXN-{row.id.slice(-4).toUpperCase()}
                            </span>
                          </td>
                          <td className="px-5 py-4">
                            <span className="text-[13px] font-semibold text-[#07074E]">
                              ₹{row.amount?.toLocaleString('en-IN', { maximumFractionDigits: 0 })}
                            </span>
                          </td>
                          <td className="px-5 py-4">
                            <StatusChip status={STATUS_MAP[row.status] || row.status} />
                          </td>
                          <td className="px-5 py-4">
                            <span className="text-[12.5px] font-medium text-[#9F9FD1]">
                              {new Date(row.requested_at).toLocaleDateString()}
                            </span>
                          </td>
                          <td className="px-5 py-4">
                            <span className="text-[12.5px] font-medium text-[#07074E]">
                              {row.payment_method === 'upi' ? 'UPI' : 'Bank Transfer'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}
    </DashboardLayout>
  );
}
