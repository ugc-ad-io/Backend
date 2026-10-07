import { startLiveUpdates } from "./lib/liveUpdates";
import { useState, useEffect, createContext, useContext, lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import axios from 'axios';
import './App.css';
import Landing from './pages/Landing';
import Auth from './pages/Auth';
import AdminLayout from './components/AdminLayout';
import { Toaster } from 'sonner';

const CreatorProfileSetup = lazy(() => import('./pages/CreatorProfileSetup'));
const BusinessProfileSetup = lazy(() => import('./pages/BusinessProfileSetup'));
const CreatorDashboard = lazy(() => import('./pages/CreatorDashboard'));
const BusinessDashboard = lazy(() => import('./pages/BusinessDashboard'));
const BrandWelcomePage = lazy(() => import('./pages/BrandWelcomePage'));
const AdminDashboard = lazy(() => import('./pages/AdminDashboard'));
const ProfileSettings = lazy(() => import('./pages/ProfileSettings'));
const PublicProfile = lazy(() => import('./pages/PublicProfile'));
const CampaignDetails = lazy(() => import('./pages/CampaignDetails'));
const BrandShortlist = lazy(() => import('./pages/BrandShortlist'));
const AdminMatchQueue = lazy(() => import('./pages/AdminMatchQueue'));
const AdminDisputes = lazy(() => import('./pages/AdminDisputes'));
const RaiseDispute = lazy(() => import('./pages/RaiseDispute'));
const MessagesPage = lazy(() => import('./pages/MessagesPage'));
const ChatPage = lazy(() => import('./pages/ChatPage'));
const WorkSubmission = lazy(() => import('./pages/WorkSubmission'));
const WorkReview = lazy(() => import('./pages/WorkReview'));
const PayoutWithLayout = lazy(() => import('./pages/PayoutWithLayout'));
const ShipmentTracking = lazy(() => import('./pages/ShipmentTracking'));
const BrowseBriefs = lazy(() => import('./pages/BrowseBriefs'));
const MyDealsPage = lazy(() => import('./pages/MyDealsPage'));
const BrandDealRoom = lazy(() => import('./pages/BrandDealRoom'));
const AdminDealRoom = lazy(() => import('./pages/AdminDealRoom'));
const AdminChat = lazy(() => import('./pages/AdminChat'));
const MyBidsPage = lazy(() => import('./pages/MyBidsPage'));
const MyActiveWorkPage = lazy(() => import('./pages/MyActiveWorkPage'));
const ReviewsPage = lazy(() => import('./pages/ReviewsPage'));
const PortfolioPage = lazy(() => import('./pages/PortfolioPage'));
const CreateGig = lazy(() => import('./pages/CreateGig'));
const AdminGigManagement = lazy(() => import('./pages/AdminGigManagement'));
const BrowseApprovedGigs = lazy(() => import('./pages/BrowseApprovedGigs'));
const ApplicationsPage = lazy(() => import('./pages/ApplicationsPage'));

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export const AuthContext = createContext();

export const useAuth = () => useContext(AuthContext);

axios.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

function AuthProvider({ children }) {
  useEffect(() => startLiveUpdates(), []);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      axios.get(`${API}/auth/me`)
        .then(res => {
          setUser(res.data);
        })
        .catch(() => {
          localStorage.removeItem('token');
        })
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const refresh = () => {
      if (document.visibilityState !== 'visible' || !localStorage.getItem('token')) return;
      axios.get(`${API}/auth/me`).then(res => setUser(res.data)).catch(() => {});
    };
    const interval = setInterval(refresh, 60000);
    window.addEventListener('focus', refresh);
    return () => {
      clearInterval(interval);
      window.removeEventListener('focus', refresh);
    };
  }, []);

  const login = (token, userData) => {
    localStorage.setItem('token', token);
    setUser(userData);
  };

  const logout = () => {
    localStorage.removeItem('token');
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, setUser, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

function ProtectedRoute({ children, allowedRoles }) {
  const { user, loading } = useAuth();

  if (loading) return <div className="loading-screen" role="status">Loading account...</div>;

  if (!user) {
    return <Navigate to="/auth" />;
  }

  if (allowedRoles && !allowedRoles.includes(user.role)) {
    return <Navigate to="/" />;
  }

  return children;
}

function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <AuthProvider>
          <Toaster position="top-right" richColors />
          <Suspense fallback={<div className="loading-screen" role="status">Loading page...</div>}>
          <Routes>
            <Route path="/" element={<Landing />} />
            <Route path="/auth" element={<Auth />} />
            <Route
              path="/profile-setup/creator"
              element={
                <ProtectedRoute allowedRoles={['creator']}>
                  <CreatorProfileSetup />
                </ProtectedRoute>
              }
            />
            <Route
              path="/profile-setup/business"
              element={
                <ProtectedRoute allowedRoles={['business']}>
                  <BusinessProfileSetup />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/creator"
              element={
                <ProtectedRoute allowedRoles={['creator']}>
                  <CreatorDashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/browse-briefs"
              element={
                <ProtectedRoute allowedRoles={['creator']}>
                  <BrowseBriefs />
                </ProtectedRoute>
              }
            />
            <Route
              path="/my-deals"
              element={
                <ProtectedRoute allowedRoles={['creator']}>
                  <MyDealsPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/my-bids"
              element={
                <ProtectedRoute allowedRoles={['creator']}>
                  <MyBidsPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/my-active-work"
              element={
                <ProtectedRoute allowedRoles={['creator']}>
                  <MyActiveWorkPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/reviews"
              element={
                <ProtectedRoute allowedRoles={['creator']}>
                  <ReviewsPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/portfolio"
              element={
                <ProtectedRoute allowedRoles={['creator']}>
                  <PortfolioPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/create-gig"
              element={
                <ProtectedRoute allowedRoles={['creator']}>
                  <CreateGig />
                </ProtectedRoute>
              }
            />
            <Route
              path="/brand-home"
              element={
                <ProtectedRoute allowedRoles={['business']}>
                  <BrandWelcomePage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/business"
              element={
                <ProtectedRoute allowedRoles={['business']}>
                  <BusinessDashboard page="overview" />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/business/all-campaigns"
              element={
                <ProtectedRoute allowedRoles={['business']}>
                  <BusinessDashboard page="all-campaigns" />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/business/post-brief"
              element={
                <ProtectedRoute allowedRoles={['business']}>
                  <BusinessDashboard page="post-brief" />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/business/pending-bids"
              element={
                <ProtectedRoute allowedRoles={['business']}>
                  <BusinessDashboard page="pending-bids" />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/business/browse-creator"
              element={
                <ProtectedRoute allowedRoles={['business']}>
                  <BusinessDashboard page="browse-creator" />
                </ProtectedRoute>
              }
            />
            <Route
              path="/browse-approved-gigs"
              element={
                <ProtectedRoute allowedRoles={['business']}>
                  <BrowseApprovedGigs />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/business/work-review"
              element={
                <ProtectedRoute allowedRoles={['business']}>
                  <BusinessDashboard page="work-review" />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/business/shipments"
              element={
                <ProtectedRoute allowedRoles={['business']}>
                  <BusinessDashboard page="shipments" />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/business/wallet"
              element={
                <ProtectedRoute allowedRoles={['business']}>
                  <BusinessDashboard page="wallet" />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/business/deal-room"
              element={
                <ProtectedRoute allowedRoles={['business']}>
                  <BrandDealRoom />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/business/campaigns/:id/shortlist"
              element={
                <ProtectedRoute allowedRoles={['business']}>
                  <BrandShortlist />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/admin"
              element={
                <ProtectedRoute allowedRoles={['admin', 'campaign_manager', 'support_staff']}>
                  <AdminDashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/admin/:adminPage"
              element={
                <ProtectedRoute allowedRoles={['admin', 'campaign_manager', 'support_staff']}>
                  <AdminDashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/admin/applications"
              element={
                <ProtectedRoute allowedRoles={['admin', 'campaign_manager', 'support_staff']}>
                  <AdminLayout isApplicationsPage={true}>
                    <ApplicationsPage />
                  </AdminLayout>
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/admin/gig-management"
              element={
                <ProtectedRoute allowedRoles={['admin', 'campaign_manager', 'support_staff']}>
                  <AdminGigManagement />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/admin/deal-room"
              element={
                <ProtectedRoute allowedRoles={['admin', 'campaign_manager', 'support_staff']}>
                  <AdminDealRoom />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/admin/chat-oversight"
              element={
                <ProtectedRoute allowedRoles={['admin', 'campaign_manager', 'support_staff']}>
                  <AdminChat />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/admin/match-queue"
              element={
                <ProtectedRoute allowedRoles={['admin', 'campaign_manager', 'support_staff']}>
                  <AdminMatchQueue />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/admin/disputes"
              element={
                <ProtectedRoute allowedRoles={['admin', 'campaign_manager', 'support_staff']}>
                  <AdminDisputes />
                </ProtectedRoute>
              }
            />
            <Route
              path="/disputes/new/:dealId"
              element={
                <ProtectedRoute allowedRoles={['creator', 'business']}>
                  <RaiseDispute />
                </ProtectedRoute>
              }
            />
            <Route
              path="/campaign/:id"
              element={
                <ProtectedRoute>
                  <CampaignDetails />
                </ProtectedRoute>
              }
            />
            <Route
              path="/messages"
              element={
                <ProtectedRoute allowedRoles={['creator', 'business']}>
                  <MessagesPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/chat/:userId"
              element={
                <ProtectedRoute>
                  <ChatPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/work/submit"
              element={
                <ProtectedRoute allowedRoles={['creator']}>
                  <WorkSubmission />
                </ProtectedRoute>
              }
            />
            <Route
              path="/work-review/:id"
              element={
                <ProtectedRoute allowedRoles={['business']}>
                  <WorkReview />
                </ProtectedRoute>
              }
            />
            <Route
              path="/withdrawal"
              element={
                <ProtectedRoute allowedRoles={['creator']}>
                  <PayoutWithLayout />
                </ProtectedRoute>
              }
            />
            <Route
              path="/shipment"
              element={
                <ProtectedRoute allowedRoles={['business', 'creator', 'admin', 'campaign_manager', 'support_staff']}>
                  <ShipmentTracking />
                </ProtectedRoute>
              }
            />
            <Route
              path="/settings"
              element={
                <ProtectedRoute allowedRoles={['business', 'creator', 'admin', 'campaign_manager', 'support_staff']}>
                  <ProfileSettings />
                </ProtectedRoute>
              }
            />
            <Route path="/profile/:id" element={<ProtectedRoute allowedRoles={['business', 'creator', 'admin', 'campaign_manager', 'support_staff']}><PublicProfile /></ProtectedRoute>} />
          </Routes>
          </Suspense>
        </AuthProvider>
      </BrowserRouter>
    </div>
  );
}

export default App;
