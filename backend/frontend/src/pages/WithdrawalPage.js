import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import axios from 'axios';
import { toast } from 'sonner';
import {
  IndianRupee,
  TrendingUp,
  Zap,
  Search,
  SlidersHorizontal,
  ChevronDown,
  ArrowUpRight,
  Shield,
  ShieldCheck,
  Building2,
  CreditCard,
  Smartphone,
  ExternalLink,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  XCircle,
  Star,
  Trophy,
  Sparkles,
  Lock,
  Calendar,
  ChevronRight,
  BarChart3,
  Wallet,
  CircleDot,
  BadgeCheck,
  ArrowLeft
} from 'lucide-react';

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

function getCreatorLevel(earnings) {
  if (earnings >= 500000) return "Elite";
  if (earnings >= 100000) return "L2 Pro";
  if (earnings >= 50000) return "L1 Rising";
  if (earnings >= 10000) return "Verified";
  return "New";
}

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

function KPICard({
  label,
  value,
  sub,
  subPositive,
  icon: Icon,
  iconColor,
  accent,
}) {
  return (
    <div className="bg-white rounded-[20px] p-6 shadow-[0_4px_24px_rgba(7,7,78,0.05)] border border-[#E9EBEF]/50 flex flex-col justify-between group hover:-translate-y-0.5 hover:shadow-[0_8px_32px_rgba(7,7,78,0.09)] transition-all duration-300 relative overflow-hidden">
      <div
        className="absolute top-0 right-0 w-28 h-28 rounded-full blur-2xl opacity-60 pointer-events-none -mr-10 -mt-10"
        style={{ background: `${accent}18` }}
      />
      <div className="flex items-start justify-between mb-5 relative z-10">
        <div
          className="w-11 h-11 rounded-[14px] flex items-center justify-center group-hover:scale-105 transition-transform duration-300"
          style={{ backgroundColor: `${iconColor}12`, color: iconColor }}
        >
          <Icon strokeWidth={1.5} className="w-5 h-5" />
        </div>
        <span
          className="text-[11.5px] font-semibold flex items-center gap-1 px-2.5 py-1 rounded-[8px]"
          style={{
            color: subPositive === false ? "#9F9FD1" : subPositive ? "#22C55E" : "#9F9FD1",
            backgroundColor: subPositive === false ? "#F3F3FF" : subPositive ? "#22C55E12" : "#F3F3FF",
          }}
        >
          {subPositive && <TrendingUp strokeWidth={2} className="w-3 h-3" />}
          {sub}
        </span>
      </div>
      <div className="relative z-10">
        <p className="text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-1.5">{label}</p>
        <p className="text-[28px] font-semibold text-[#07074E] tracking-tight font-heading">{value}</p>
      </div>
    </div>
  );
}

export default function WithdrawalPage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [payoutOverview, setPayoutOverview] = useState(null);
  const [withdrawals, setWithdrawals] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showRequestModal, setShowRequestModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [amount, setAmount] = useState('');
  const [paymentMethod, setPaymentMethod] = useState('upi');
  const [accountDetails, setAccountDetails] = useState({ upi: '', account_number: '', ifsc: '' });
  const [bankForm, setBankForm] = useState({ account_holder_name: '', bank_name: '', account_number: '', ifsc_code: '', upi_id: '' });
  const [statusFilter, setStatusFilter] = useState("All");
  const [searchQuery, setSearchQuery] = useState("");
  const [dateFilter, setDateFilter] = useState("All Time");
  const [showStatusDrop, setShowStatusDrop] = useState(false);
  const [showDateDrop, setShowDateDrop] = useState(false);
  const [savingBank, setSavingBank] = useState(false);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [overviewRes, withdrawalsRes] = await Promise.all([
        axios.get(`${API}/payout/overview`),
        axios.get(`${API}/withdrawal/history`)
      ]);

      setPayoutOverview(overviewRes.data);
      setWithdrawals(withdrawalsRes.data);

      if (overviewRes.data.bank_details) {
        setBankForm({
          account_holder_name: overviewRes.data.bank_details.account_holder_name || '',
          bank_name: overviewRes.data.bank_details.bank_name || '',
          account_number: overviewRes.data.bank_details.account_number || '',
          ifsc_code: overviewRes.data.bank_details.ifsc_code || '',
          upi_id: overviewRes.data.upi_id || ''
        });
      }
    } catch (error) {
      toast.error('Failed to load payout data');
    } finally {
      setLoading(false);
    }
  };

  const handleRequestWithdrawal = async (e) => {
    e.preventDefault();

    if (parseFloat(amount) > (payoutOverview?.balance || 0)) {
      toast.error('Insufficient balance');
      return;
    }

    if (parseFloat(amount) < 10) {
      toast.error('Minimum withdrawal amount is ₹10');
      return;
    }

    try {
      await axios.post(`${API}/withdrawal/request`, {
        amount: parseFloat(amount),
        payment_method: paymentMethod,
        account_details: accountDetails
      });
      toast.success('Withdrawal request submitted');
      setShowRequestModal(false);
      setAmount('');
      fetchData();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to request withdrawal');
    }
  };

  const handleSaveBankDetails = async (e) => {
    e.preventDefault();
    setSavingBank(true);

    try {
      await axios.put(`${API}/profile/payment-info`, {
        bank_details: {
          account_holder_name: bankForm.account_holder_name,
          bank_name: bankForm.bank_name,
          account_number: bankForm.account_number,
          ifsc_code: bankForm.ifsc_code
        },
        upi_id: bankForm.upi_id || null
      });
      toast.success('Bank details updated successfully');
      setShowEditModal(false);
      fetchData();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to save bank details');
    } finally {
      setSavingBank(false);
    }
  };

  if (loading || !payoutOverview) {
    return <div className="flex items-center justify-center min-h-screen">Loading...</div>;
  }

  const creatorLevel = getCreatorLevel(payoutOverview.all_time_earnings);
  const PAYOUT_LEVELS = [
    { level: "New", days: "12 business days", icon: CircleDot, color: "#9F9FD1", current: creatorLevel === "New" },
    { level: "Verified", days: "7 business days", icon: BadgeCheck, color: "#B7B7E6", current: creatorLevel === "Verified" },
    { level: "L1 Rising", days: "5 business days", icon: Star, color: "#7387FF", current: creatorLevel === "L1 Rising" },
    { level: "L2 Pro", days: "3 business days", icon: Trophy, color: "#F59E0B", current: creatorLevel === "L2 Pro" },
    { level: "Elite", days: "48 hours", icon: Zap, color: "#22C55E", current: creatorLevel === "Elite" },
  ];

  const growthPct = payoutOverview.last_month_paid > 0
    ? Math.round(((payoutOverview.paid_this_month - payoutOverview.last_month_paid) / payoutOverview.last_month_paid) * 100)
    : 0;
  const avgPerDeal = payoutOverview.deals_paid_this_month > 0
    ? (payoutOverview.paid_this_month / payoutOverview.deals_paid_this_month).toFixed(0)
    : 0;

  const filtered = withdrawals.filter((row) => {
    const matchStatus = statusFilter === "All" || STATUS_MAP[row.status] === statusFilter;
    const matchSearch =
      searchQuery === "" ||
      row.id?.toString().toLowerCase().includes(searchQuery.toLowerCase());
    return matchStatus && matchSearch;
  });

  const maskAccountNumber = (num) => {
    if (!num) return "Not set";
    const str = num.toString().replace(/\s/g, '');
    return `XXXX XXXX ${str.slice(-4)}`;
  };

  return (
    <div className="flex flex-col gap-6 max-w-[1440px] mx-auto w-full pb-10 pt-2 font-sans" style={{ padding: '40px 8%' }}>
      <div className="max-w-[1440px] mx-auto w-full mb-2">
        <button
          className="flex items-center gap-2 px-4 py-2 bg-white border border-[#E9EBEF] rounded-[12px] text-[#4a5568] font-semibold hover:border-[#7387FF] hover:text-[#7387FF] transition-all"
          onClick={() => navigate(-1)}
        >
          <ArrowLeft size={18} /> Back to Dashboard
        </button>
      </div>

      <div className="grid grid-cols-4 gap-5 max-w-[1440px] mx-auto w-full">
        <KPICard
          label="Pending Release"
          value={`₹${payoutOverview.pending_release.toLocaleString('en-IN', { maximumFractionDigits: 0 })}`}
          sub={`${payoutOverview.pending_deals_count} deals pending`}
          icon={Wallet}
          iconColor="#F59E0B"
          accent="#F59E0B"
        />
        <KPICard
          label="Paid This Month"
          value={`₹${payoutOverview.paid_this_month.toLocaleString('en-IN', { maximumFractionDigits: 0 })}`}
          sub={`${growthPct > 0 ? '+' : ''}${growthPct}% vs last month`}
          subPositive={growthPct > 0}
          icon={IndianRupee}
          iconColor="#22C55E"
          accent="#22C55E"
        />
        <KPICard
          label="All Time Earnings"
          value={`₹${payoutOverview.all_time_earnings.toLocaleString('en-IN', { maximumFractionDigits: 0 })}`}
          sub="Since Jan 2025"
          icon={BarChart3}
          iconColor="#7387FF"
          accent="#7387FF"
        />
        <KPICard
          label="Payout Window"
          value={PAYOUT_LEVELS.find(l => l.current)?.days || "12 business days"}
          sub="Fastest payout unlocked"
          subPositive={true}
          icon={Zap}
          iconColor="#07074E"
          accent="#07074E"
        />
      </div>

      <div className="flex gap-6 items-start max-w-[1440px] mx-auto w-full">
        <div className="flex flex-col gap-5 min-w-0" style={{ flex: "0 0 60%" }}>
          <div className="bg-white rounded-[20px] shadow-[0_4px_24px_rgba(7,7,78,0.05)] border border-[#E9EBEF]/50 overflow-hidden">
            <div className="px-7 pt-6 pb-5 border-b border-[#F3F3FF]">
              <div className="flex items-center justify-between mb-5">
                <div>
                  <h2 className="text-[18px] font-semibold text-[#07074E] font-heading tracking-tight">Payment History</h2>
                  <p className="text-[12.5px] text-[#9F9FD1] font-medium mt-0.5">{filtered.length} transactions found</p>
                </div>
                <button className="flex items-center gap-1.5 bg-[#F3F3FF] hover:bg-[#E9EBEF] text-[#07074E] px-4 py-2 rounded-[10px] text-[13px] font-semibold transition-colors">
                  <ArrowUpRight strokeWidth={2} className="w-3.5 h-3.5" />
                  Export CSV
                </button>
              </div>

              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2.5 bg-[#F3F3FF] rounded-[11px] px-3.5 py-2.5 flex-1 min-w-0">
                  <Search strokeWidth={1.8} className="w-4 h-4 text-[#9F9FD1] flex-shrink-0" />
                  <input
                    type="text"
                    placeholder="Search withdrawal ID…"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="bg-transparent text-[13px] font-medium text-[#07074E] placeholder-[#B7B7E6] outline-none w-full"
                  />
                </div>

                <div className="relative">
                  <button
                    onClick={() => { setShowStatusDrop(!showStatusDrop); setShowDateDrop(false); }}
                    className="flex items-center gap-2 bg-[#F3F3FF] hover:bg-[#E9EBEF] rounded-[11px] px-4 py-2.5 text-[13px] font-semibold text-[#07074E] transition-colors whitespace-nowrap"
                  >
                    <SlidersHorizontal strokeWidth={1.8} className="w-3.5 h-3.5 text-[#9F9FD1]" />
                    {statusFilter === "All" ? "All Status" : statusFilter}
                    <ChevronDown className={`w-3.5 h-3.5 text-[#9F9FD1] transition-transform ${showStatusDrop ? "rotate-180" : ""}`} />
                  </button>
                  {showStatusDrop && (
                    <div className="absolute top-full mt-2 right-0 bg-white rounded-[14px] shadow-[0_8px_32px_rgba(7,7,78,0.12)] border border-[#E9EBEF]/60 z-20 overflow-hidden min-w-[160px]">
                      {["All", "Paid", "Processing", "Pending", "Disputed"].map((s) => (
                        <button
                          key={s}
                          onClick={() => { setStatusFilter(s); setShowStatusDrop(false); }}
                          className={`w-full text-left px-4 py-2.5 text-[13px] font-medium transition-colors flex items-center gap-2.5 ${statusFilter === s ? "bg-[#7387FF]/8 text-[#7387FF] font-semibold" : "text-[#07074E] hover:bg-[#F3F3FF]"}`}
                        >
                          {statusFilter === s && <div className="w-1.5 h-1.5 rounded-full bg-[#7387FF]" />}
                          {s === "All" ? "All Status" : s}
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                <div className="relative">
                  <button
                    onClick={() => { setShowDateDrop(!showDateDrop); setShowStatusDrop(false); }}
                    className="flex items-center gap-2 bg-[#F3F3FF] hover:bg-[#E9EBEF] rounded-[11px] px-4 py-2.5 text-[13px] font-semibold text-[#07074E] transition-colors whitespace-nowrap"
                  >
                    <Calendar strokeWidth={1.8} className="w-3.5 h-3.5 text-[#9F9FD1]" />
                    {dateFilter}
                    <ChevronDown className={`w-3.5 h-3.5 text-[#9F9FD1] transition-transform ${showDateDrop ? "rotate-180" : ""}`} />
                  </button>
                  {showDateDrop && (
                    <div className="absolute top-full mt-2 right-0 bg-white rounded-[14px] shadow-[0_8px_32px_rgba(7,7,78,0.12)] border border-[#E9EBEF]/60 z-20 overflow-hidden min-w-[160px]">
                      {["All Time", "This Month", "Last Month", "Last 3 Months", "This Year"].map((d) => (
                        <button
                          key={d}
                          onClick={() => { setDateFilter(d); setShowDateDrop(false); }}
                          className={`w-full text-left px-4 py-2.5 text-[13px] font-medium transition-colors flex items-center gap-2.5 ${dateFilter === d ? "bg-[#7387FF]/8 text-[#7387FF] font-semibold" : "text-[#07074E] hover:bg-[#F3F3FF]"}`}
                        >
                          {dateFilter === d && <div className="w-1.5 h-1.5 rounded-full bg-[#7387FF]" />}
                          {d}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {filtered.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-20 px-8">
                <div className="w-16 h-16 rounded-[20px] bg-[#F3F3FF] flex items-center justify-center mb-5">
                  <Wallet strokeWidth={1.2} className="w-7 h-7 text-[#B7B7E6]" />
                </div>
                <p className="text-[16px] font-semibold text-[#07074E] font-heading mb-2">No transactions found</p>
                <p className="text-[13px] text-[#9F9FD1] font-medium text-center max-w-xs">
                  Complete your first deal to receive payouts. Your payment history will appear here.
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-[#F3F3FF]/50 border-b border-[#E9EBEF]/60">
                      {["TXN ID", "Amount", "Status", "Date", "Method", ""].map((col) => (
                        <th
                          key={col}
                          className="px-5 py-3.5 text-[11px] font-semibold text-[#9F9FD1] uppercase tracking-wider whitespace-nowrap first:pl-7 last:pr-7"
                        >
                          {col}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((row) => (
                      <tr
                        key={row.id}
                        className="border-b border-[#F3F3FF] last:border-0 hover:bg-[#F3F3FF]/40 transition-colors group"
                      >
                        <td className="px-5 py-4 pl-7">
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
                        <td className="px-5 py-4 whitespace-nowrap">
                          <span className="text-[12.5px] font-medium text-[#9F9FD1]">
                            {new Date(row.requested_at).toLocaleDateString()}
                          </span>
                        </td>
                        <td className="px-5 py-4">
                          <span className="text-[12.5px] font-medium text-[#07074E]">
                            {row.payment_method === 'upi' ? 'UPI' : 'Bank Transfer'}
                          </span>
                        </td>
                        <td className="px-5 py-4 pr-7 text-right">
                          <button className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-[9px] bg-white border border-[#E9EBEF] text-[12px] font-semibold text-[#07074E] hover:bg-[#07074E] hover:text-white hover:border-[#07074E] shadow-sm transition-all duration-200 whitespace-nowrap">
                            View
                            <ExternalLink strokeWidth={2} className="w-3 h-3" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {filtered.length > 0 && (
              <div className="px-7 py-4 border-t border-[#F3F3FF] flex items-center justify-between">
                <span className="text-[12px] font-medium text-[#9F9FD1]">
                  Showing {filtered.length} of {withdrawals.length} transactions
                </span>
              </div>
            )}
          </div>
        </div>

        <div
          className="flex flex-col gap-5 flex-shrink-0"
          style={{ flex: "0 0 38%", position: "sticky", top: "0", alignSelf: "flex-start" }}
        >
          <div className="bg-white rounded-[20px] shadow-[0_4px_24px_rgba(7,7,78,0.05)] border border-[#E9EBEF]/50 overflow-hidden">
            <div className="bg-gradient-to-r from-[#07074E] to-[#0D0D6B] px-6 py-5 relative overflow-hidden">
              <div className="absolute right-0 top-0 w-40 h-40 bg-[#7387FF]/15 blur-3xl rounded-full -mr-10 -mt-10 pointer-events-none" />
              <div className="flex items-center justify-between relative z-10">
                <div>
                  <p className="text-[11px] font-semibold text-white/50 uppercase tracking-wider mb-1">Linked Bank Account</p>
                  <h3 className="text-[16px] font-semibold text-white font-heading">Payment Details</h3>
                </div>
                {payoutOverview.bank_details?.bank_name && (
                  <div className="flex items-center gap-1.5 bg-[#22C55E]/15 border border-[#22C55E]/25 px-3 py-1.5 rounded-full">
                    <ShieldCheck strokeWidth={2} className="w-3.5 h-3.5 text-[#22C55E]" />
                    <span className="text-[11px] font-semibold text-[#22C55E]">Verified</span>
                  </div>
                )}
              </div>
            </div>

            <div className="px-6 py-5 flex flex-col gap-4">
              {[
                { icon: Shield, label: "Account Holder", value: payoutOverview.bank_details?.account_holder_name || user?.nickname || "N/A", mono: false },
                { icon: Building2, label: "Bank Name", value: payoutOverview.bank_details?.bank_name || "Not set", mono: false },
                { icon: CreditCard, label: "Account Number", value: maskAccountNumber(payoutOverview.bank_details?.account_number), mono: true },
                { icon: Lock, label: "IFSC Code", value: payoutOverview.bank_details?.ifsc_code || "Not set", mono: true },
                { icon: Smartphone, label: "UPI ID", value: payoutOverview.upi_id || "Not set", mono: false },
              ].map((field, i) => (
                <div key={i} className="flex items-center gap-3.5">
                  <div className="w-8 h-8 rounded-[9px] bg-[#F3F3FF] flex items-center justify-center flex-shrink-0">
                    <field.icon strokeWidth={1.5} className="w-3.5 h-3.5 text-[#7387FF]" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-[10.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider">{field.label}</p>
                    <p className={`text-[13.5px] font-semibold text-[#07074E] mt-0.5 truncate ${field.mono ? "font-mono tracking-wide" : ""}`}>
                      {field.value}
                    </p>
                  </div>
                </div>
              ))}

              <div className="h-px bg-[#F3F3FF] my-1" />

              <div className="flex gap-3">
                <button
                  onClick={() => setShowEditModal(true)}
                  className="flex-1 py-2.5 rounded-[12px] bg-[#07074E] text-white text-[13px] font-semibold hover:bg-[#0D0D6B] shadow-[0_4px_16px_rgba(7,7,78,0.18)] hover:-translate-y-0.5 transition-all flex items-center justify-center gap-2"
                >
                  <CreditCard strokeWidth={1.8} className="w-3.5 h-3.5" />
                  Edit Details
                </button>
                <button
                  onClick={() => setShowEditModal(true)}
                  className="flex-1 py-2.5 rounded-[12px] bg-[#F3F3FF] text-[#07074E] text-[13px] font-semibold hover:bg-[#E9EBEF] transition-colors flex items-center justify-center gap-2"
                >
                  <Shield strokeWidth={1.8} className="w-3.5 h-3.5" />
                  Add Account
                </button>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-[20px] shadow-[0_4px_24px_rgba(7,7,78,0.05)] border border-[#E9EBEF]/50 overflow-hidden">
            <div className="px-6 pt-5 pb-4 border-b border-[#F3F3FF]">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-[15px] font-semibold text-[#07074E] font-heading">Payout Speed by Level</h3>
                  <p className="text-[11.5px] text-[#9F9FD1] font-medium mt-0.5">Unlock faster payouts as you grow</p>
                </div>
                <div className="w-8 h-8 rounded-[9px] bg-[#7387FF]/10 flex items-center justify-center">
                  <Zap strokeWidth={1.5} className="w-4 h-4 text-[#7387FF]" />
                </div>
              </div>
            </div>

            <div className="px-6 py-4 flex flex-col gap-2">
              {PAYOUT_LEVELS.map((lvl) => {
                const Icon = lvl.icon;
                return (
                  <div
                    key={lvl.level}
                    className={`flex items-center gap-3.5 px-4 py-3 rounded-[13px] transition-all ${lvl.current
                      ? "bg-[#7387FF]/8 border border-[#7387FF]/20"
                      : "hover:bg-[#F3F3FF]/60"
                      }`}
                  >
                    <div
                      className="w-8 h-8 rounded-[9px] flex items-center justify-center flex-shrink-0"
                      style={{ backgroundColor: `${lvl.color}15` }}
                    >
                      <Icon strokeWidth={1.8} className="w-4 h-4" style={{ color: lvl.color }} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className={`text-[13px] font-semibold ${lvl.current ? "text-[#7387FF]" : "text-[#07074E]"}`}>
                        {lvl.level}
                      </p>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span
                        className={`text-[12px] font-semibold ${lvl.current ? "text-[#7387FF]" : "text-[#9F9FD1]"}`}
                      >
                        {lvl.days}
                      </span>
                      {lvl.current && (
                        <span className="bg-[#7387FF] text-white text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full">
                          You
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="mx-6 mb-5 flex items-start gap-2.5 bg-[#F3F3FF]/80 rounded-[12px] px-4 py-3.5 border border-[#E9EBEF]/50">
              <AlertCircle strokeWidth={1.5} className="w-4 h-4 text-[#B7B7E6] flex-shrink-0 mt-0.5" />
              <p className="text-[11.5px] font-medium text-[#9F9FD1] leading-relaxed">
                Payout starts after brand approval. Disputed deals remain on hold until resolved.
              </p>
            </div>
          </div>

          <div className="bg-gradient-to-br from-[#7387FF] to-[#4A63FF] rounded-[20px] px-6 py-5 shadow-[0_8px_32px_rgba(115,135,255,0.22)] relative overflow-hidden">
            <div className="absolute right-0 bottom-0 w-40 h-40 bg-white/10 blur-3xl rounded-full -mr-10 -mb-10 pointer-events-none" />
            <div className="absolute left-0 top-0 w-24 h-24 bg-[#07074E]/10 blur-2xl rounded-full -ml-6 -mt-6 pointer-events-none" />
            <div className="relative z-10">
              <div className="flex items-center gap-2 mb-4">
                <Sparkles strokeWidth={1.5} className="w-4 h-4 text-white/80" />
                <p className="text-[12px] font-semibold text-white/80 uppercase tracking-wider">Earnings Insight</p>
              </div>
              <p className="text-[24px] font-semibold text-white font-heading mb-1">{growthPct > 0 ? '+' : ''}{growthPct}% Growth</p>
              <p className="text-[13px] text-white/70 font-medium mb-5">vs. last month · {new Date().toLocaleString('en-IN', { month: 'long', year: 'numeric' })}</p>

              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: "Avg. Per Deal", value: `₹${avgPerDeal.toLocaleString('en-IN')}` },
                  { label: "Deals Paid", value: `${payoutOverview.deals_paid_this_month} this month` },
                ].map((m, i) => (
                  <div key={i} className="bg-white/12 backdrop-blur-sm rounded-[12px] px-4 py-3 border border-white/15">
                    <p className="text-[10.5px] font-semibold text-white/60 uppercase tracking-wider mb-1">{m.label}</p>
                    <p className="text-[15px] font-semibold text-white font-heading">{m.value}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {showRequestModal && (
        <div className="fixed inset-0 bg-black/40 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={() => setShowRequestModal(false)}>
          <div
            className="bg-white rounded-[24px] shadow-[0_24px_64px_rgba(7,7,78,0.18)] border border-[#E9EBEF]/60 w-full max-w-md p-7 relative"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              onClick={() => setShowRequestModal(false)}
              className="absolute top-5 right-5 w-8 h-8 rounded-full bg-[#F3F3FF] hover:bg-[#E9EBEF] flex items-center justify-center transition-colors"
            >
              <XCircle strokeWidth={2} className="w-4 h-4 text-[#9F9FD1]" />
            </button>

            <h2 className="text-[18px] font-semibold text-[#07074E] font-heading mb-1">Request Withdrawal</h2>
            <p className="text-[13px] text-[#9F9FD1] font-medium mb-6">
              Available balance: <span className="text-[#07074E] font-semibold">₹{payoutOverview.balance.toLocaleString('en-IN', { maximumFractionDigits: 0 })}</span>
            </p>

            <form onSubmit={handleRequestWithdrawal} className="flex flex-col gap-4">
              <div>
                <label className="text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-2 block">Amount (₹)</label>
                <div className="flex items-center gap-2.5 bg-[#F3F3FF] rounded-[12px] px-4 py-3">
                  <IndianRupee strokeWidth={1.8} className="w-4 h-4 text-[#9F9FD1]" />
                  <input
                    type="number"
                    min="10"
                    step="0.01"
                    placeholder="0.00"
                    value={amount}
                    onChange={(e) => setAmount(e.target.value)}
                    className="bg-transparent text-[14px] font-semibold text-[#07074E] placeholder-[#B7B7E6] outline-none w-full"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-2 block">Payment Method</label>
                <div className="flex gap-2">
                  {['upi', 'bank'].map((method) => (
                    <button
                      key={method}
                      type="button"
                      onClick={() => setPaymentMethod(method)}
                      className={`flex-1 py-2.5 rounded-[12px] text-[13px] font-semibold flex items-center justify-center gap-2 transition-all ${
                        paymentMethod === method
                          ? 'bg-[#07074E] text-white shadow-[0_4px_16px_rgba(7,7,78,0.18)]'
                          : 'bg-[#F3F3FF] text-[#07074E] hover:bg-[#E9EBEF]'
                      }`}
                    >
                      {method === 'upi'
                        ? <Smartphone strokeWidth={1.8} className="w-3.5 h-3.5" />
                        : <Building2 strokeWidth={1.8} className="w-3.5 h-3.5" />}
                      {method === 'upi' ? 'UPI' : 'Bank Transfer'}
                    </button>
                  ))}
                </div>
              </div>

              {paymentMethod === 'upi' ? (
                <div>
                  <label className="text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-2 block">UPI ID</label>
                  <input
                    type="text"
                    placeholder="yourname@bank"
                    value={accountDetails.upi}
                    onChange={(e) => setAccountDetails({ ...accountDetails, upi: e.target.value })}
                    className="w-full bg-[#F3F3FF] rounded-[12px] px-4 py-3 text-[13.5px] font-medium text-[#07074E] placeholder-[#B7B7E6] outline-none"
                    required
                  />
                </div>
              ) : (
                <div className="flex flex-col gap-3">
                  <div>
                    <label className="text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-2 block">Account Number</label>
                    <input
                      type="text"
                      placeholder="XXXX XXXX XXXX"
                      value={accountDetails.account_number}
                      onChange={(e) => setAccountDetails({ ...accountDetails, account_number: e.target.value })}
                      className="w-full bg-[#F3F3FF] rounded-[12px] px-4 py-3 text-[13.5px] font-medium text-[#07074E] placeholder-[#B7B7E6] outline-none font-mono"
                      required
                    />
                  </div>
                  <div>
                    <label className="text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-2 block">IFSC Code</label>
                    <input
                      type="text"
                      placeholder="HDFC0001042"
                      value={accountDetails.ifsc}
                      onChange={(e) => setAccountDetails({ ...accountDetails, ifsc: e.target.value })}
                      className="w-full bg-[#F3F3FF] rounded-[12px] px-4 py-3 text-[13.5px] font-medium text-[#07074E] placeholder-[#B7B7E6] outline-none font-mono"
                      required
                    />
                  </div>
                </div>
              )}

              <button
                type="submit"
                className="mt-2 w-full py-3 rounded-[14px] bg-[#07074E] text-white text-[14px] font-semibold hover:bg-[#0D0D6B] shadow-[0_4px_16px_rgba(7,7,78,0.18)] hover:-translate-y-0.5 transition-all flex items-center justify-center gap-2"
              >
                <Wallet strokeWidth={1.8} className="w-4 h-4" />
                Submit Withdrawal Request
              </button>
            </form>
          </div>
        </div>
      )}

      {showEditModal && (
        <div className="fixed inset-0 bg-black/40 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={() => setShowEditModal(false)}>
          <div
            className="bg-white rounded-[24px] shadow-[0_24px_64px_rgba(7,7,78,0.18)] border border-[#E9EBEF]/60 w-full max-w-md p-7 relative"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              onClick={() => setShowEditModal(false)}
              className="absolute top-5 right-5 w-8 h-8 rounded-full bg-[#F3F3FF] hover:bg-[#E9EBEF] flex items-center justify-center transition-colors"
            >
              <XCircle strokeWidth={2} className="w-4 h-4 text-[#9F9FD1]" />
            </button>

            <h2 className="text-[18px] font-semibold text-[#07074E] font-heading mb-1">Edit Bank Details</h2>
            <p className="text-[13px] text-[#9F9FD1] font-medium mb-6">Update your payment information</p>

            <form onSubmit={handleSaveBankDetails} className="flex flex-col gap-4">
              <div>
                <label className="text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-2 block">Account Holder Name</label>
                <input
                  type="text"
                  placeholder="Full name"
                  value={bankForm.account_holder_name}
                  onChange={(e) => setBankForm({ ...bankForm, account_holder_name: e.target.value })}
                  className="w-full bg-[#F3F3FF] rounded-[12px] px-4 py-3 text-[13.5px] font-medium text-[#07074E] placeholder-[#B7B7E6] outline-none"
                />
              </div>

              <div>
                <label className="text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-2 block">Bank Name</label>
                <input
                  type="text"
                  placeholder="e.g., HDFC Bank"
                  value={bankForm.bank_name}
                  onChange={(e) => setBankForm({ ...bankForm, bank_name: e.target.value })}
                  className="w-full bg-[#F3F3FF] rounded-[12px] px-4 py-3 text-[13.5px] font-medium text-[#07074E] placeholder-[#B7B7E6] outline-none"
                />
              </div>

              <div>
                <label className="text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-2 block">Account Number</label>
                <input
                  type="text"
                  placeholder="Account number"
                  value={bankForm.account_number}
                  onChange={(e) => setBankForm({ ...bankForm, account_number: e.target.value })}
                  className="w-full bg-[#F3F3FF] rounded-[12px] px-4 py-3 text-[13.5px] font-medium text-[#07074E] placeholder-[#B7B7E6] outline-none font-mono"
                />
              </div>

              <div>
                <label className="text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-2 block">IFSC Code</label>
                <input
                  type="text"
                  placeholder="HDFC0001042"
                  value={bankForm.ifsc_code}
                  onChange={(e) => setBankForm({ ...bankForm, ifsc_code: e.target.value })}
                  className="w-full bg-[#F3F3FF] rounded-[12px] px-4 py-3 text-[13.5px] font-medium text-[#07074E] placeholder-[#B7B7E6] outline-none font-mono"
                />
              </div>

              <div>
                <label className="text-[11.5px] font-semibold text-[#9F9FD1] uppercase tracking-wider mb-2 block">UPI ID (Optional)</label>
                <input
                  type="text"
                  placeholder="yourname@bank"
                  value={bankForm.upi_id}
                  onChange={(e) => setBankForm({ ...bankForm, upi_id: e.target.value })}
                  className="w-full bg-[#F3F3FF] rounded-[12px] px-4 py-3 text-[13.5px] font-medium text-[#07074E] placeholder-[#B7B7E6] outline-none"
                />
              </div>

              <button
                type="submit"
                disabled={savingBank}
                className="mt-2 w-full py-3 rounded-[14px] bg-[#07074E] text-white text-[14px] font-semibold hover:bg-[#0D0D6B] shadow-[0_4px_16px_rgba(7,7,78,0.18)] hover:-translate-y-0.5 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {savingBank ? 'Saving...' : 'Save Details'}
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
