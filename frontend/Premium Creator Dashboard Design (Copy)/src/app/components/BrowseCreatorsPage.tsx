// Browsing page
import { useState, useRef, useEffect } from "react";
import { Link, useNavigate } from "react-router";
import {
  LayoutDashboard, PenSquare, Users, ClipboardList,
  MessageSquare, Wallet, Settings, Search, Bell,
  Star, MapPin, BadgeCheck, Bookmark, BookmarkCheck,
  X, ChevronDown, Check, Zap, RotateCcw, TrendingUp,
  Download, CheckCircle2, Clock, ArrowUpRight, SlidersHorizontal,
  Filter, VolumeX, Volume2,
} from "lucide-react";

// ─── Video pool ───────────────────────────────────────────────────────────────
const V = {
  blaze:  "https://assets.mixkit.co/videos/preview/mixkit-skincare-routine-of-a-woman-42211-large.mp4",
  escape: "https://assets.mixkit.co/videos/preview/mixkit-portrait-of-a-fashion-woman-with-silver-makeup-39875-large.mp4",
  joy:    "https://assets.mixkit.co/videos/preview/mixkit-woman-doing-yoga-on-a-mat-in-the-middle-of-40-large.mp4",
  melt:   "https://assets.mixkit.co/videos/preview/mixkit-very-close-shot-of-the-face-of-a-young-woman-3200-large.mp4",
  fun:    "https://assets.mixkit.co/videos/preview/mixkit-hands-of-a-woman-applying-lotion-to-her-arm-4148-large.mp4",
  subie:  "https://assets.mixkit.co/videos/preview/mixkit-woman-with-a-brush-applying-makeup-to-her-face-42212-large.mp4",
  bull:   "https://assets.mixkit.co/videos/preview/mixkit-beautiful-woman-in-a-neon-illuminated-city-at-night-4309-large.mp4",
  vw:     "https://assets.mixkit.co/videos/preview/mixkit-woman-putting-on-makeup-42213-large.mp4",
  grand:  "https://assets.mixkit.co/videos/preview/mixkit-portrait-of-a-woman-in-a-pool-1259-large.mp4",
};

// ─── Types ────────────────────────────────────────────────────────────────────
interface Creator {
  id: number;
  handle: string;
  city: string;
  level: "New" | "Verified" | "L1 Rising" | "L2 Pro" | "Elite";
  qualityTier: "A" | "A+" | "A++";
  category: string;
  categoryEmoji: string;
  rating: number;
  deals: number;
  responseRate: number;
  pastBrands: string[];
  avatarInitials: string;
  avatarBg: string;
  verified: boolean;
  available: boolean;
  appliedHoursAgo?: number;
  videoUrl: string;
  videoDuration: string;
  posterColors: [string, string];
}

// ─── Creator data ─────────────────────────────────────────────────────────────
const CREATORS: Creator[] = [
  { id:1, handle:"@glowskin.ugc",    city:"Mumbai",     level:"Elite",     qualityTier:"A++", category:"Beauty",    categoryEmoji:"✨", rating:4.9, deals:48, responseRate:99, pastBrands:["Mamaearth","Minimalist","Dot & Key"],   avatarInitials:"GS", avatarBg:"#7387FF", verified:true,  available:true,  videoUrl:V.blaze,  videoDuration:"0:32", posterColors:["#FFAFC5","#FF758C"] },
  { id:2, handle:"@fitpulse.ugc",    city:"Bengaluru",  level:"L2 Pro",    qualityTier:"A+",  category:"Fitness",   categoryEmoji:"💪", rating:4.8, deals:32, responseRate:96, pastBrands:["HealthKart","Muscle Blaze","Fittr"],    avatarInitials:"FP", avatarBg:"#F39C12", verified:true,  available:true,  appliedHoursAgo:3,  videoUrl:V.joy,    videoDuration:"0:47", posterColors:["#FFD166","#F39C12"] },
  { id:3, handle:"@techgeek.ugc",    city:"Delhi",      level:"L1 Rising", qualityTier:"A",   category:"Tech",      categoryEmoji:"⚡", rating:4.7, deals:18, responseRate:94, pastBrands:["boAt","Noise","Realme"],               avatarInitials:"TG", avatarBg:"#27AE60", verified:true,  available:false, videoUrl:V.vw,     videoDuration:"1:02", posterColors:["#56AB2F","#1DB954"] },
  { id:4, handle:"@styleframe.ugc",  city:"Mumbai",     level:"Verified",  qualityTier:"A+",  category:"Fashion",   categoryEmoji:"👗", rating:4.6, deals:11, responseRate:91, pastBrands:["Myntra","Nykaa Fashion","H&M"],        avatarInitials:"SF", avatarBg:"#9F9FD1", verified:true,  available:true,  videoUrl:V.escape, videoDuration:"0:29", posterColors:["#A18CD1","#7387FF"] },
  { id:5, handle:"@tastecraft.ugc",  city:"Hyderabad",  level:"L2 Pro",    qualityTier:"A++", category:"Food",      categoryEmoji:"🍽️", rating:4.9, deals:41, responseRate:98, pastBrands:["Swiggy","Zomato","Licious"],           avatarInitials:"TC", avatarBg:"#E74C3C", verified:true,  available:true,  appliedHoursAgo:8,  videoUrl:V.subie,  videoDuration:"0:55", posterColors:["#FF6B6B","#F39C12"] },
  { id:6, handle:"@wandershot.ugc",  city:"Pune",       level:"L1 Rising", qualityTier:"A",   category:"Travel",    categoryEmoji:"✈️", rating:4.5, deals:9,  responseRate:88, pastBrands:["MakeMyTrip","Airbnb"],                avatarInitials:"WS", avatarBg:"#3498DB", verified:false, available:true,  videoUrl:V.bull,   videoDuration:"0:38", posterColors:["#48C6EF","#3498DB"] },
  { id:7, handle:"@nestlife.ugc",    city:"Chennai",    level:"Verified",  qualityTier:"A+",  category:"Home Decor",categoryEmoji:"🏠", rating:4.7, deals:15, responseRate:93, pastBrands:["IKEA","Pepperfry","Urban Ladder"],    avatarInitials:"NL", avatarBg:"#16A085", verified:true,  available:true,  videoUrl:V.grand,  videoDuration:"0:42", posterColors:["#0F9B8E","#A8E6CF"] },
  { id:8, handle:"@zenflow.ugc",     city:"Delhi",      level:"L1 Rising", qualityTier:"A",   category:"Wellness",  categoryEmoji:"🧘", rating:4.8, deals:22, responseRate:97, pastBrands:["Cult.fit","Yoga Bar","Kapiva"],       avatarInitials:"ZF", avatarBg:"#8E44AD", verified:true,  available:false, videoUrl:V.melt,   videoDuration:"1:08", posterColors:["#DA8FFF","#8E44AD"] },
  { id:9, handle:"@pixelpress.ugc",  city:"Bengaluru",  level:"New",       qualityTier:"A",   category:"Gaming",    categoryEmoji:"🎮", rating:4.3, deals:5,  responseRate:85, pastBrands:["Razer","Steam"],                      avatarInitials:"PP", avatarBg:"#2C3E50", verified:false, available:true,  videoUrl:V.fun,    videoDuration:"0:50", posterColors:["#373B44","#4286F4"] },
];

// ─── Static config ────────────────────────────────────────────────────────────
const LEVELS     = ["New","Verified","L1 Rising","L2 Pro","Elite"] as const;
const Q_TIERS    = ["A","A+","A++"] as const;
const CATEGORIES = ["Beauty","Fitness","Tech","Fashion","Food","Travel","Home Decor","Wellness","Gaming","Lifestyle"];
const CITIES     = ["All Cities","Mumbai","Delhi","Bengaluru","Hyderabad","Chennai","Pune"];
const SORT_OPTS  = ["Best Match","Highest Rated","Most Deals","Newest"];

const NAV = [
  { label:"Brand Dashboard", path:"/brand",              icon:LayoutDashboard },
  { label:"Post a Brief",    path:"/brand/post-brief",   icon:PenSquare       },
  { label:"Creator Bids",    path:"/brand/applications", icon:Users,  badge:"3" },
  { label:"Deal Room",       path:"/brand/deals",        icon:ClipboardList   },
  { label:"Messages",        path:"/brand/messages",     icon:MessageSquare, badge:"2" },
  { label:"Wallet",          path:"/brand/wallet",       icon:Wallet          },
  { label:"Settings",        path:"/brand/settings",     icon:Settings        },
];

const LEVEL_BADGE: Record<string,{bg:string;text:string}> = {
  "New":       {bg:"rgba(243,243,255,0.9)", text:"#9F9FD1"},
  "Verified":  {bg:"rgba(238,240,255,0.9)", text:"#7387FF"},
  "L1 Rising": {bg:"rgba(232,248,238,0.9)", text:"#27AE60"},
  "L2 Pro":    {bg:"rgba(255,248,232,0.9)", text:"#F39C12"},
  "Elite":     {bg:"rgba(238,240,255,0.9)", text:"#7387FF"},
};
const QT_BADGE: Record<string,{bg:string;text:string}> = {
  "A":   {bg:"#F3F3FF", text:"#9F9FD1"},
  "A+":  {bg:"#EEF0FF", text:"#7387FF"},
  "A++": {bg:"#FFF8E8", text:"#F39C12"},
};

// ─── Donut chart (right panel) ────────────────────────────────────────────────
function DonutChart({value}:{value:number}) {
  const r=34, cx=44, cy=44, circ=2*Math.PI*r;
  const offset=circ*(1-value/100);
  return (
    <svg width="88" height="88" viewBox="0 0 88 88">
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#F0F1FF" strokeWidth="9"/>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#7387FF" strokeWidth="9"
        strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
        transform={`rotate(-90 ${cx} ${cy})`} style={{transition:"stroke-dashoffset .5s ease"}}/>
      <text x={cx} y={cy-5} textAnchor="middle" fill="#07074E" fontSize="15" fontWeight="700">{value}%</text>
      <text x={cx} y={cy+10} textAnchor="middle" fill="#9F9FD1" fontSize="9" fontWeight="500">match</text>
    </svg>
  );
}

// ─── Creator Card ─────────────────────────────────────────────────────────────
function CreatorCard({
  creator, invited, shortlisted, onInvite, onShortlist,
}:{
  creator:Creator; invited:boolean; shortlisted:boolean;
  onInvite:()=>void; onShortlist:()=>void;
}) {
  const videoRef  = useRef<HTMLVideoElement>(null);
  const cardRef   = useRef<HTMLDivElement>(null);
  const [loaded, setLoaded]   = useState(false);
  const [muted,  setMuted]    = useState(true);
  const [hovered,setHovered]  = useState(false);

  useEffect(() => {
    const el=videoRef.current, con=cardRef.current;
    if (!el||!con) return;
    const obs=new IntersectionObserver(
      ([e])=>{ e.isIntersecting ? el.play().catch(()=>{}) : el.pause(); },
      {threshold:0.2}
    );
    obs.observe(con);
    return ()=>obs.disconnect();
  },[]);

  useEffect(()=>{ if(videoRef.current) videoRef.current.muted=muted; },[muted]);

  const applied  = creator.appliedHoursAgo!==undefined;
  const lvlStyle = LEVEL_BADGE[creator.level]  ?? LEVEL_BADGE["New"];
  const qtStyle  = QT_BADGE[creator.qualityTier] ?? QT_BADGE["A"];
  const [c1,c2]  = creator.posterColors;

  return (
    <div
      ref={cardRef}
      className="bg-white rounded-[18px] overflow-hidden border border-[#EAECF5] flex flex-col"
      onMouseEnter={()=>setHovered(true)}
      onMouseLeave={()=>setHovered(false)}
      style={{
        boxShadow: hovered
          ? "0 12px 36px rgba(115,135,255,0.16), 0 2px 8px rgba(7,7,78,0.06)"
          : "0 2px 10px rgba(7,7,78,0.06)",
        transform: hovered ? "translateY(-4px)" : "translateY(0)",
        transition: "transform .3s ease, box-shadow .3s ease",
      }}
    >
      {/* ── VIDEO AREA ─────────────────────────────────────────────────── */}
      <div className="relative w-full overflow-hidden bg-black" style={{aspectRatio: "9/16"}}>
        {/* Gradient fallback */}
        <div style={{
          position:"absolute",inset:0,
          background:`linear-gradient(135deg,${c1},${c2})`,
        }}/>
        {/* Video */}
        <video ref={videoRef} autoPlay muted loop playsInline preload="auto"
          onCanPlay={()=>setLoaded(true)}
          style={{
            position:"absolute",inset:0,width:"100%",height:"100%",
            objectFit:"cover",
            opacity: loaded?1:0,
            transform: hovered?"scale(1.05)":"scale(1)",
            transition:"opacity .6s ease, transform .45s ease",
          }}
        ><source src={creator.videoUrl} type="video/mp4"/></video>

        {/* Gradient overlay */}
        <div style={{position:"absolute",inset:0,background:"linear-gradient(to top,rgba(0,0,0,0.55) 0%,rgba(0,0,0,0.05) 50%,rgba(0,0,0,0.18) 100%)"}}/>

        {/* Category chip – top left */}
        <div className="absolute top-3 left-3 flex items-center gap-1.5 px-2.5 py-1 rounded-full"
          style={{background:"rgba(0,0,0,0.32)",backdropFilter:"blur(8px)"}}>
          <span className="text-[12px]">{creator.categoryEmoji}</span>
          <span className="text-white text-[11px] font-semibold">{creator.category}</span>
        </div>

        {/* Duration – top right */}
        <div className="absolute top-3 right-3 px-2.5 py-1 rounded-full"
          style={{background:"rgba(0,0,0,0.35)",backdropFilter:"blur(8px)"}}>
          <span className="text-white text-[11px] font-semibold">{creator.videoDuration}</span>
        </div>

        {/* Preview live dot – bottom left */}
        <div className="absolute bottom-3 left-3 flex items-center gap-1.5 px-2.5 py-1 rounded-full"
          style={{background:"rgba(115,135,255,0.72)",backdropFilter:"blur(8px)"}}>
          <span className="w-1.5 h-1.5 rounded-full bg-white" style={{animation:"bcPulse 1.4s ease-in-out infinite"}}/>
          <span className="text-white text-[10px] font-semibold tracking-wide">PREVIEW</span>
        </div>

        {/* Mute + bookmark – bottom right */}
        <div className="absolute bottom-3 right-3 flex items-center gap-1.5">
          <button onClick={(e)=>{e.stopPropagation();setMuted(p=>!p);}}
            className="w-7 h-7 rounded-full flex items-center justify-center transition-all"
            style={{
              background:"rgba(0,0,0,0.35)",backdropFilter:"blur(8px)",
              opacity:hovered?1:0,transform:hovered?"scale(1)":"scale(0.8)",
              transition:"opacity .25s ease, transform .25s ease",
            }}>
            {muted
              ? <VolumeX className="w-3.5 h-3.5 text-white" strokeWidth={2}/>
              : <Volume2  className="w-3.5 h-3.5 text-white" strokeWidth={2}/>}
          </button>
          <button onClick={(e)=>{e.stopPropagation();onShortlist();}}
            className="w-7 h-7 rounded-full flex items-center justify-center transition-all"
            style={{background:shortlisted?"#7387FF":"rgba(0,0,0,0.35)",backdropFilter:"blur(8px)"}}>
            {shortlisted
              ? <BookmarkCheck className="w-3.5 h-3.5 text-white" strokeWidth={2}/>
              : <Bookmark       className="w-3.5 h-3.5 text-white" strokeWidth={2}/>}
          </button>
        </div>
      </div>

      {/* ── INFO PANEL ─────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-2 p-3 flex-1">

        {/* Row 1: Avatar + handle + verified + available */}
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-full flex items-center justify-center text-white text-[10px] font-bold shrink-0 shadow-sm"
            style={{background:creator.avatarBg}}>
            {creator.avatarInitials}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-[12px] font-semibold text-[#07074E] truncate"
                style={{fontFamily:"ui-monospace, monospace"}}>
                {creator.handle}
              </span>
              {creator.verified && <BadgeCheck className="w-3.5 h-3.5 shrink-0" strokeWidth={2} style={{color:"#7387FF"}}/>}
              {creator.available
                ? <span className="w-2 h-2 rounded-full shrink-0" style={{background:"#27AE60",boxShadow:"0 0 0 2px rgba(39,174,96,0.2)"}}/>
                : <span className="px-1.5 py-0.5 rounded text-[9px] font-semibold" style={{background:"#F3F3FF",color:"#9F9FD1"}}>Busy</span>
              }
            </div>
          </div>
        </div>

        {/* Row 2: City */}
        <div className="flex items-center gap-1">
          <MapPin className="w-3 h-3 shrink-0" style={{color:"#C0C0D8"}} strokeWidth={2}/>
          <span className="text-[10px] font-medium" style={{color:"#9F9FD1"}}>{creator.city}, India</span>
        </div>

        {/* Row 3: Stats */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-0.5">
            <Star className="w-3 h-3 fill-current" style={{color:"#F39C12"}}/>
            <span className="text-[11px] font-semibold" style={{color:"#07074E"}}>{creator.rating}</span>
          </div>
          <span className="text-[10px] font-medium" style={{color:"#9F9FD1"}}>{creator.deals} deals</span>
          <span className="text-[10px] font-semibold" style={{color:"#27AE60"}}>{creator.responseRate}% resp.</span>
        </div>

        {/* Row 4: Quality badge + Level badge */}
        <div className="flex items-center gap-1.5 mt-0.5">
          <span className="px-1.5 py-0.5 rounded-full text-[9px] font-semibold"
            style={{background:qtStyle.bg, color:qtStyle.text}}>
            Quality {creator.qualityTier}
          </span>
          <span className="px-1.5 py-0.5 rounded-full text-[9px] font-semibold"
            style={{background:lvlStyle.bg, color:lvlStyle.text}}>
            {creator.level}
          </span>
        </div>

        {/* Row 5: Past brands */}
        <div className="flex flex-wrap gap-1 mt-0.5">
          {creator.pastBrands.slice(0,3).map(b=>(
            <span key={b} className="px-1.5 py-[2px] rounded-[4px] text-[9px] font-medium border"
              style={{background:"#FAFAFE",color:"#9F9FD1",borderColor:"#EAECF5"}}>
              {b}
            </span>
          ))}
        </div>

        {/* Divider */}
        <div style={{height:1,background:"#F3F4FC",margin:"4px 0"}}/>

        {/* Row 6: Actions */}
        {applied ? (
          <div className="flex flex-col gap-1.5 mt-auto">
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full" style={{background:"#7387FF",animation:"bcPulse 1.4s ease-in-out infinite"}}/>
              <span className="text-[10px] font-semibold" style={{color:"#7387FF"}}>Applied {creator.appliedHoursAgo}h ago</span>
            </div>
            <div className="flex gap-1.5">
              <button
                className="flex-1 h-7 rounded-[6px] text-[11px] font-semibold flex items-center justify-center gap-1 transition-all"
                style={{background:"#27AE60",color:"#fff",boxShadow:"0 3px 8px rgba(39,174,96,0.2)"}}
                onMouseEnter={e=>(e.currentTarget.style.background="#219a52")}
                onMouseLeave={e=>(e.currentTarget.style.background="#27AE60")}
              >
                <Check className="w-3 h-3" strokeWidth={2.5}/> Accept
              </button>
              <button
                className="flex-1 h-7 rounded-[6px] text-[11px] font-semibold flex items-center justify-center gap-1 border transition-all"
                style={{borderColor:"rgba(231,76,60,0.3)",color:"#E74C3C"}}
                onMouseEnter={e=>{e.currentTarget.style.background="#FCEAEA";}}
                onMouseLeave={e=>{e.currentTarget.style.background="transparent";}}
              >
                <X className="w-3 h-3" strokeWidth={2}/> Decline
              </button>
            </div>
          </div>
        ) : (
          <div className="flex gap-1.5 mt-auto">
            <button onClick={onInvite}
              className="flex-1 h-7 rounded-[6px] text-[11px] font-semibold flex items-center justify-center gap-1 transition-all"
              style={invited
                ? {background:"#E8F8EE",color:"#27AE60",border:"1px solid rgba(39,174,96,0.25)"}
                : {background:"#7387FF",color:"#fff",boxShadow:"0 3px 8px rgba(115,135,255,0.2)"}
              }
              onMouseEnter={e=>{if(!invited)e.currentTarget.style.background="#5a6de0";}}
              onMouseLeave={e=>{if(!invited)e.currentTarget.style.background="#7387FF";}}
            >
              {invited
                ? <><CheckCircle2 className="w-3 h-3" strokeWidth={2}/> Invited</>
                : <><Zap className="w-3 h-3" strokeWidth={2}/> Invite</>
              }
            </button>
            <button
              className="h-7 px-2.5 rounded-[6px] border text-[11px] font-semibold flex items-center gap-0.5 transition-all"
              style={{borderColor:"#E2E4F0",color:"#9F9FD1"}}
              onMouseEnter={e=>{e.currentTarget.style.borderColor="#7387FF";e.currentTarget.style.color="#7387FF";}}
              onMouseLeave={e=>{e.currentTarget.style.borderColor="#E2E4F0";e.currentTarget.style.color="#9F9FD1";}}
            >
              <ArrowUpRight className="w-3.5 h-3.5"/>
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Right panel ──────────────────────────────────────────────────────────────
function RightPanel({shortlisted,filtered}:{shortlisted:number;filtered:number}) {
  const NICHES=[
    {label:"Beauty",count:320,pct:100},
    {label:"Tech",count:210,pct:66},
    {label:"Fitness",count:180,pct:56},
    {label:"Lifestyle",count:145,pct:45},
    {label:"Fashion",count:120,pct:38},
  ];
  return (
    <div className="flex flex-col gap-4">

      {/* Match Summary */}
      <div className="bg-white rounded-[16px] border border-[#EAECF5] p-5 shadow-[0_2px_10px_rgba(7,7,78,0.05)]">
        <div className="flex items-center gap-2 mb-4">
          <TrendingUp className="w-4 h-4" style={{color:"#7387FF"}} strokeWidth={2}/>
          <span className="text-[11px] font-semibold uppercase tracking-wider" style={{color:"#07074E"}}>Match Summary</span>
        </div>
        <div className="flex flex-col items-center gap-3">
          <DonutChart value={86}/>
          <div className="w-full flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full" style={{background:"#7387FF"}}/>
                <span className="text-[11px] font-medium" style={{color:"#9F9FD1"}}>Total creators</span>
              </div>
              <span className="text-[12px] font-semibold" style={{color:"#07074E"}}>1,248</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full" style={{background:"#27AE60"}}/>
                <span className="text-[11px] font-medium" style={{color:"#9F9FD1"}}>Showing now</span>
              </div>
              <span className="text-[12px] font-semibold" style={{color:"#07074E"}}>{filtered}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full" style={{background:"#F39C12"}}/>
                <span className="text-[11px] font-medium" style={{color:"#9F9FD1"}}>Shortlisted</span>
              </div>
              <span className="text-[12px] font-semibold" style={{color:"#07074E"}}>{shortlisted}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Top Niches */}
      <div className="bg-white rounded-[16px] border border-[#EAECF5] p-5 shadow-[0_2px_10px_rgba(7,7,78,0.05)]">
        <div className="flex items-center gap-2 mb-4">
          <Zap className="w-4 h-4" style={{color:"#F39C12"}} strokeWidth={2}/>
          <span className="text-[11px] font-semibold uppercase tracking-wider" style={{color:"#07074E"}}>Top Niches</span>
        </div>
        <div className="flex flex-col gap-3">
          {NICHES.map(n=>(
            <div key={n.label}>
              <div className="flex justify-between mb-1">
                <span className="text-[11px] font-semibold" style={{color:"#07074E"}}>{n.label}</span>
                <span className="text-[10px] font-medium" style={{color:"#9F9FD1"}}>{n.count}</span>
              </div>
              <div className="h-1.5 rounded-full overflow-hidden" style={{background:"#F3F4FC"}}>
                <div className="h-full rounded-full" style={{width:`${n.pct}%`,background:"linear-gradient(90deg,#7387FF,#B0BAFF)"}}/>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-white rounded-[16px] border border-[#EAECF5] p-5 shadow-[0_2px_10px_rgba(7,7,78,0.05)]">
        <div className="flex items-center gap-2 mb-3">
          <Zap className="w-4 h-4" style={{color:"#7387FF"}} strokeWidth={2}/>
          <span className="text-[11px] font-semibold uppercase tracking-wider" style={{color:"#07074E"}}>Quick Actions</span>
        </div>
        <div className="flex flex-col gap-1.5">
          {[
            {icon:<BookmarkCheck className="w-4 h-4" style={{color:"#7387FF"}}/>,label:"View Shortlisted",ib:"rgba(115,135,255,0.1)"},
            {icon:<Zap className="w-4 h-4" style={{color:"#27AE60"}}/>,label:"Invite Top Matches",ib:"rgba(39,174,96,0.1)"},
            {icon:<Download className="w-4 h-4" style={{color:"#9F9FD1"}}/>,label:"Export CSV List",ib:"rgba(159,159,209,0.12)"},
          ].map(a=>(
            <button key={a.label}
              className="flex items-center gap-3 p-2.5 rounded-[10px] text-left transition-all"
              style={{background:"#F5F6FF"}}
              onMouseEnter={e=>(e.currentTarget.style.background="#EEF0FF")}
              onMouseLeave={e=>(e.currentTarget.style.background="#F5F6FF")}
            >
              <div className="w-7 h-7 rounded-[7px] flex items-center justify-center shrink-0" style={{background:a.ib}}>
                {a.icon}
              </div>
              <span className="text-[11px] font-semibold" style={{color:"#07074E"}}>{a.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Campaign Notice */}
      <div className="rounded-[16px] p-4" style={{background:"#07074E"}}>
        <div className="flex items-center gap-2 mb-2">
          <span className="w-1.5 h-1.5 rounded-full" style={{background:"#27AE60",animation:"bcPulse 1.4s ease-in-out infinite"}}/>
          <span className="text-[10px] font-semibold uppercase tracking-wide" style={{color:"#9F9FD1"}}>Campaign Status</span>
        </div>
        <div className="text-[13px] font-semibold text-white mb-1">Live Matching</div>
        <div className="flex flex-col gap-2 mt-3">
          {[
            {icon:<Clock className="w-3 h-3" style={{color:"#F39C12"}}/>,label:"Closes",val:"12 hrs",vc:"#F39C12"},
            {icon:<Users className="w-3 h-3" style={{color:"#7387FF"}}/>,label:"Applications",val:"7",vc:"#fff"},
            {icon:<CheckCircle2 className="w-3 h-3" style={{color:"#27AE60"}}/>,label:"Status",val:"Live",vc:"#27AE60"},
          ].map(r=>(
            <div key={r.label} className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                {r.icon}
                <span className="text-[11px] font-medium" style={{color:"#9F9FD1"}}>{r.label}</span>
              </div>
              <span className="text-[11px] font-semibold" style={{color:r.vc}}>{r.val}</span>
            </div>
          ))}
        </div>
        <div className="mt-3 pt-3 border-t border-white/10">
          <div className="h-1 rounded-full overflow-hidden" style={{background:"rgba(255,255,255,0.1)"}}>
            <div className="h-full w-3/4 rounded-full" style={{background:"linear-gradient(90deg,#7387FF,#27AE60)"}}/>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────
export function BrowseCreatorsPage() {
  const navigate = useNavigate();

  // Filter state
  const [selLevels, setSelLevels]   = useState<string[]>([]);
  const [selTiers,  setSelTiers]    = useState<string[]>([]);
  const [selCat,    setSelCat]      = useState("");
  const [selCity,   setSelCity]     = useState("");
  const [avail,     setAvail]       = useState(false);
  const [sortBy,    setSortBy]      = useState("Best Match");
  const [query,     setQuery]       = useState("");
  const [invitedIds,    setInvitedIds]    = useState<Set<number>>(new Set());
  const [shortlistedIds,setShortlistedIds]= useState<Set<number>>(new Set());
  const [showFilters, setShowFilters] = useState(false);

  const toggleLevel = (l:string) => setSelLevels(p=>p.includes(l)?p.filter(x=>x!==l):[...p,l]);
  const toggleTier  = (t:string) => setSelTiers(p=>p.includes(t)?p.filter(x=>x!==t):[...p,t]);
  const toggleInvite    = (id:number) => setInvitedIds(p=>{const n=new Set(p);n.has(id)?n.delete(id):n.add(id);return n;});
  const toggleShortlist = (id:number) => setShortlistedIds(p=>{const n=new Set(p);n.has(id)?n.delete(id):n.add(id);return n;});
  const reset = ()=>{setSelLevels([]);setSelTiers([]);setSelCat("");setSelCity("");setAvail(false);setSortBy("Best Match");setQuery("");};

  const filtered = CREATORS.filter(c=>{
    if (selLevels.length && !selLevels.includes(c.level)) return false;
    if (selTiers.length  && !selTiers.includes(c.qualityTier))  return false;
    if (selCat  && c.category!==selCat)    return false;
    if (selCity && selCity!=="All Cities" && !c.city.includes(selCity)) return false;
    if (avail   && !c.available)           return false;
    if (query) {
      const q=query.toLowerCase();
      if(!c.handle.toLowerCase().includes(q)&&!c.category.toLowerCase().includes(q)&&!c.city.toLowerCase().includes(q)) return false;
    }
    return true;
  });

  const activeFilters = selLevels.length+selTiers.length+(selCat?1:0)+(selCity?1:0)+(avail?1:0);

  const LEVEL_CHIP: Record<string,{active:string;text:string;activeBg:string}> = {
    "New":       {active:"#9F9FD1",text:"#9F9FD1",activeBg:"#F3F3FF"},
    "Verified":  {active:"#7387FF",text:"#9F9FD1",activeBg:"#EEF0FF"},
    "L1 Rising": {active:"#27AE60",text:"#9F9FD1",activeBg:"#E8F8EE"},
    "L2 Pro":    {active:"#F39C12",text:"#9F9FD1",activeBg:"#FFF8E8"},
    "Elite":     {active:"#7387FF",text:"#9F9FD1",activeBg:"#EEF0FF"},
  };

  return (
    <div
      className="flex h-screen overflow-hidden"
      style={{fontFamily:"'Inter','Just Sans',sans-serif",background:"#F5F6FF"}}
    >
      {/* ═══════════════════════════════════════════════════════
          SIDEBAR
      ═══════════════════════════════════════════════════════ */}
      <aside
        className="flex flex-col h-full shrink-0"
        style={{
          width:260,
          background:"#07074E",
          borderRadius:"0 32px 32px 0",
          boxShadow:"8px 0 32px rgba(7,7,78,0.10)",
          zIndex:30,
        }}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 p-8 shrink-0">
          <div className="w-8 h-8 rounded-[10px] bg-[#7387FF] flex items-center justify-center text-white font-semibold text-[15px] font-heading shadow-md shadow-[#7387FF]/20">
            U
          </div>
          <span className="text-[20px] font-semibold tracking-tight text-white font-heading">UGCad.io</span>
        </div>

        {/* Nav */}
        <nav className="flex-1 flex flex-col gap-1.5 px-4 overflow-y-auto">
          <div className="text-[11px] font-medium text-[#9F9FD1] uppercase tracking-wider mb-2 px-4">Menu</div>
          {NAV.map(item=>{
            const isActive = item.path==="/brand/applications";
            return (
              <Link key={item.path} to={item.path}
                className={`flex items-center gap-3.5 px-4 py-3 rounded-full transition-all duration-200 group text-[14px] ${
                  isActive
                    ? "bg-white text-[#07074E] font-semibold shadow-sm"
                    : "text-white/70 hover:bg-white hover:text-[#07074E] font-medium"
                }`}
              >
                <item.icon className={`w-[20px] h-[20px] ${isActive ? "text-[#07074E]" : "text-white/70 group-hover:text-[#07074E] transition-colors"}`}
                  strokeWidth={isActive?2.2:1.8}
                />
                <span className="truncate">{item.label}</span>
                {item.badge && (
                  <span className="ml-auto w-5 h-5 rounded-full text-white text-[10px] font-bold flex items-center justify-center"
                    style={{background:isActive?"#7387FF":"#F39C12"}}>
                    {item.badge}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>

        {/* User profile */}
        <div className="p-8 shrink-0">
          <div className="pt-6 border-t border-white/10 flex items-center gap-3.5">
            <img
              src="https://images.unsplash.com/photo-1697780871128-14146e7398fb?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&w=64&q=80"
              alt="Priya" className="w-10 h-10 rounded-full object-cover ring-2 ring-white/20 shadow-sm"
            />
            <div className="min-w-0 flex-1">
              <div className="text-[14px] font-semibold text-white truncate">Priya Sharma</div>
              <div className="text-[12px] text-[#9F9FD1] truncate font-medium">D2C Marketing</div>
            </div>
            <Settings className="w-4 h-4 shrink-0 text-[#9F9FD1]" strokeWidth={1.8}/>
          </div>
        </div>
      </aside>

      {/* ═══════════════════════════════════════════════════════
          MAIN AREA
      ═══════════════════════════════════════════════════════ */}
      <div className="flex-1 flex flex-col min-w-0 h-full overflow-hidden">

        {/* ── Topbar ── */}
        <header
          className="shrink-0 flex items-center gap-4 px-6"
          style={{
            height:60,
            background:"rgba(255,255,255,0.88)",
            backdropFilter:"blur(12px)",
            borderBottom:"1px solid rgba(234,236,245,0.8)",
            boxShadow:"0 1px 8px rgba(7,7,78,0.05)",
          }}
        >
          {/* Title */}
          <div className="shrink-0">
            <div className="text-[15px] font-semibold" style={{color:"#07074E",fontFamily:"'Readex Pro',sans-serif"}}>
              Creator Bids
            </div>
            <div className="text-[11px] font-medium" style={{color:"#9F9FD1"}}>
              Discover verified creators for your campaign
            </div>
          </div>

          {/* Divider */}
          <div className="w-px h-7 shrink-0" style={{background:"#EAECF5"}}/>

          {/* Search – takes remaining width */}
          <div className="flex-1 relative max-w-[480px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{color:"#C0C0D8"}} strokeWidth={2}/>
            <input
              value={query}
              onChange={e=>setQuery(e.target.value)}
              placeholder="Search creators, niches, cities..."
              className="w-full h-9 pl-10 pr-9 rounded-[10px] border text-[13px] font-medium focus:outline-none transition-all"
              style={{borderColor:"#E2E4F0",background:"#F5F6FF",color:"#07074E"}}
              onFocus={e=>{e.currentTarget.style.borderColor="#7387FF";e.currentTarget.style.background="#fff";e.currentTarget.style.boxShadow="0 0 0 3px rgba(115,135,255,0.10)";}}
              onBlur={e=>{e.currentTarget.style.borderColor="#E2E4F0";e.currentTarget.style.background="#F5F6FF";e.currentTarget.style.boxShadow="none";}}
            />
            {query && (
              <button onClick={()=>setQuery("")}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 rounded-full flex items-center justify-center"
                style={{background:"#E2E4F0"}}>
                <X className="w-2.5 h-2.5" style={{color:"#07074E"}}/>
              </button>
            )}
          </div>

          {/* Right actions */}
          <div className="flex items-center gap-3 ml-auto shrink-0">
            {/* Toggle */}
            <div className="flex items-center p-1 rounded-full" style={{background:"#F5F6FF",border:"1px solid #E2E4F0"}}>
              <button onClick={()=>navigate("/")}
                className="px-4 py-1.5 rounded-full text-[12px] font-semibold transition-all"
                style={{color:"#9F9FD1"}}>Creator</button>
              <button className="px-4 py-1.5 rounded-full text-[12px] font-semibold"
                style={{background:"#07074E",color:"#fff"}}>Brand</button>
            </div>
            {/* Bell */}
            <button className="relative w-9 h-9 rounded-full flex items-center justify-center transition-all"
              style={{background:"#fff",border:"1px solid #EAECF5",boxShadow:"0 1px 6px rgba(7,7,78,0.05)"}}>
              <Bell className="w-4 h-4" style={{color:"#9F9FD1"}} strokeWidth={1.8}/>
              <span className="absolute top-2 right-2 w-1.5 h-1.5 rounded-full" style={{background:"#F39C12"}}/>
            </button>
            {/* Avatar */}
            <img src="https://images.unsplash.com/photo-1697780871128-14146e7398fb?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&w=64&q=80"
              alt="Priya" className="w-9 h-9 rounded-full object-cover ring-2 ring-white shadow-sm cursor-pointer"/>
          </div>
        </header>

        {/* ── Content ── */}
        <div className="flex-1 overflow-y-auto">
          <div className="flex gap-5 p-6 items-start">

            {/* ── CENTER ──────────────────────────────────────── */}
            <div className="flex-1 min-w-0 flex flex-col gap-4">

              {/* Filter bar */}
              <div className="bg-white rounded-[14px] border border-[#EAECF5] shadow-[0_2px_10px_rgba(7,7,78,0.05)] px-4 py-3">
                <div className="flex items-center gap-3 flex-wrap">

                  {/* Level chips */}
                  <div className="flex items-center gap-1.5">
                    {LEVELS.map(l=>{
                      const a=selLevels.includes(l);
                      const s=LEVEL_CHIP[l];
                      return (
                        <button key={l} onClick={()=>toggleLevel(l)}
                          className="px-2.5 py-1 rounded-full text-[11px] font-semibold border transition-all"
                          style={a
                            ?{background:s.activeBg,color:s.active,borderColor:`${s.active}30`}
                            :{background:"transparent",color:"#9F9FD1",borderColor:"#E2E4F0"}
                          }>
                          {l}
                        </button>
                      );
                    })}
                  </div>

                  <div style={{width:1,height:20,background:"#EAECF5"}}/>

                  {/* Quality tier */}
                  <div className="flex items-center gap-1.5">
                    {Q_TIERS.map(t=>{
                      const a=selTiers.includes(t);
                      return (
                        <button key={t} onClick={()=>toggleTier(t)}
                          className="px-2.5 py-1 rounded-full text-[11px] font-semibold border transition-all"
                          style={a
                            ?{background:"#EEF0FF",color:"#7387FF",borderColor:"rgba(115,135,255,0.3)"}
                            :{background:"transparent",color:"#9F9FD1",borderColor:"#E2E4F0"}
                          }>
                          {t}
                        </button>
                      );
                    })}
                  </div>

                  <div style={{width:1,height:20,background:"#EAECF5"}}/>

                  {/* Category */}
                  <div className="relative">
                    <select value={selCat} onChange={e=>setSelCat(e.target.value)}
                      className="h-8 pl-3 pr-7 rounded-full border text-[11px] font-semibold focus:outline-none transition-all appearance-none cursor-pointer"
                      style={{borderColor:"#E2E4F0",background:"transparent",color:selCat?"#7387FF":"#9F9FD1"}}>
                      <option value="">All Categories</option>
                      {CATEGORIES.map(c=><option key={c}>{c}</option>)}
                    </select>
                    <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 pointer-events-none" style={{color:"#9F9FD1"}}/>
                  </div>

                  {/* City */}
                  <div className="relative">
                    <select value={selCity} onChange={e=>setSelCity(e.target.value)}
                      className="h-8 pl-3 pr-7 rounded-full border text-[11px] font-semibold focus:outline-none transition-all appearance-none cursor-pointer"
                      style={{borderColor:"#E2E4F0",background:"transparent",color:selCity&&selCity!=="All Cities"?"#7387FF":"#9F9FD1"}}>
                      {CITIES.map(c=><option key={c}>{c}</option>)}
                    </select>
                    <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 pointer-events-none" style={{color:"#9F9FD1"}}/>
                  </div>

                  {/* Available toggle */}
                  <button onClick={()=>setAvail(p=>!p)}
                    className="flex items-center gap-1.5 h-8 px-3 rounded-full border text-[11px] font-semibold transition-all"
                    style={avail
                      ?{background:"#E8F8EE",color:"#27AE60",borderColor:"rgba(39,174,96,0.3)"}
                      :{background:"transparent",color:"#9F9FD1",borderColor:"#E2E4F0"}
                    }>
                    <span className="w-1.5 h-1.5 rounded-full" style={{background:avail?"#27AE60":"#C0C0D8"}}/>
                    Available
                  </button>

                  {/* Sort */}
                  <div className="relative ml-auto">
                    <select value={sortBy} onChange={e=>setSortBy(e.target.value)}
                      className="h-8 pl-3 pr-7 rounded-full border text-[11px] font-semibold focus:outline-none transition-all appearance-none cursor-pointer"
                      style={{borderColor:"#E2E4F0",background:"transparent",color:"#07074E"}}>
                      {SORT_OPTS.map(s=><option key={s}>{s}</option>)}
                    </select>
                    <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 pointer-events-none" style={{color:"#9F9FD1"}}/>
                  </div>

                  {activeFilters>0 && (
                    <button onClick={reset}
                      className="flex items-center gap-1 h-8 px-3 rounded-full text-[11px] font-semibold border transition-all"
                      style={{borderColor:"rgba(231,76,60,0.25)",color:"#E74C3C",background:"#FCEAEA"}}>
                      <RotateCcw className="w-3 h-3"/> Reset
                    </button>
                  )}
                </div>
              </div>

              {/* Result count + active chip pills */}
              <div className="flex items-center gap-3 flex-wrap">
                <span className="text-[13px] font-semibold" style={{color:"#07074E"}}>
                  {filtered.length} creators
                </span>
                {shortlistedIds.size>0 && (
                  <span className="flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-semibold"
                    style={{background:"#EEF0FF",color:"#7387FF"}}>
                    <BookmarkCheck className="w-3 h-3"/> {shortlistedIds.size} saved
                  </span>
                )}
                {selLevels.map(l=>(
                  <button key={l} onClick={()=>toggleLevel(l)}
                    className="flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-semibold border"
                    style={{background:"#EEF0FF",color:"#7387FF",borderColor:"rgba(115,135,255,0.2)"}}>
                    {l}<X className="w-2.5 h-2.5"/>
                  </button>
                ))}
                {selTiers.map(t=>(
                  <button key={t} onClick={()=>toggleTier(t)}
                    className="flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-semibold border"
                    style={{background:"#EEF0FF",color:"#7387FF",borderColor:"rgba(115,135,255,0.2)"}}>
                    {t}<X className="w-2.5 h-2.5"/>
                  </button>
                ))}
              </div>

              {/* Creator grid */}
              {filtered.length===0 ? (
                <div className="bg-white rounded-[18px] border border-[#EAECF5] flex flex-col items-center justify-center py-20 gap-5"
                  style={{boxShadow:"0 2px 10px rgba(7,7,78,0.05)"}}>
                  <div className="w-16 h-16 rounded-full flex items-center justify-center" style={{background:"#F3F3FF"}}>
                    <Users className="w-7 h-7" style={{color:"#C0C0D8"}} strokeWidth={1.5}/>
                  </div>
                  <div className="text-center">
                    <div className="text-[17px] font-semibold mb-2" style={{color:"#07074E"}}>No creators found</div>
                    <div className="text-[13px] font-medium" style={{color:"#9F9FD1"}}>Try widening your filters or adjusting the level requirement.</div>
                  </div>
                  <button onClick={reset}
                    className="flex items-center gap-2 px-5 py-2.5 rounded-[10px] text-white text-[13px] font-semibold transition-all"
                    style={{background:"#7387FF",boxShadow:"0 4px 12px rgba(115,135,255,0.28)"}}>
                    <RotateCcw className="w-4 h-4"/> Reset Filters
                  </button>
                </div>
              ) : (
                <div className="grid gap-4 pb-6" style={{gridTemplateColumns:"repeat(3,1fr)"}}>
                  {filtered.map(creator=>(
                    <CreatorCard key={creator.id} creator={creator}
                      invited={invitedIds.has(creator.id)}
                      shortlisted={shortlistedIds.has(creator.id)}
                      onInvite={()=>toggleInvite(creator.id)}
                      onShortlist={()=>toggleShortlist(creator.id)}
                    />
                  ))}
                </div>
              )}
            </div>

            {/* ── RIGHT PANEL ──────────────────────────────────── */}
            <div className="shrink-0 sticky top-0 self-start" style={{width:216}}>
              <RightPanel shortlisted={shortlistedIds.size} filtered={filtered.length}/>
            </div>
          </div>
        </div>
      </div>

      {/* Pulse keyframe (injected inline for isolation) */}
      <style>{`
        @keyframes bcPulse {
          0%,100%{opacity:1;transform:scale(1);}
          50%{opacity:.4;transform:scale(.85);}
        }
      `}</style>
    </div>
  );
}
