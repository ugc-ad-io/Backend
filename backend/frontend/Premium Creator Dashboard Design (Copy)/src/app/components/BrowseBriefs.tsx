import { useState } from "react";
import { 
  Search, 
  MapPin, 
  Clock, 
  Star,
  Bookmark,
  CheckCircle2,
  SlidersHorizontal,
  Zap,
  Repeat,
  ArrowRight,
  ChevronDown,
  LayoutGrid,
  List,
  Sparkles,
  Filter
} from "lucide-react";

const FilterSection = ({ title, defaultOpen = false, children }: { title: string, defaultOpen?: boolean, children: React.ReactNode }) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  return (
    <div className="flex flex-col border-b border-[#E9EBEF]/60 pb-5 mb-5 last:border-0 last:pb-0 last:mb-0">
      <button 
        onClick={() => setIsOpen(!isOpen)} 
        className="flex items-center justify-between w-full py-1 text-left group outline-none"
      >
        <span className="text-[14px] font-semibold text-[#07074E] group-hover:text-[#7387FF] transition-colors font-['Readex_Pro']">{title}</span>
        <ChevronDown className={`w-4 h-4 text-[#9F9FD1] transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>
      {isOpen && (
        <div className="pt-4 flex flex-col gap-3.5">
          {children}
        </div>
      )}
    </div>
  );
};

const Checkbox = ({ label, count, checked = false }: { label: string, count?: string, checked?: boolean }) => (
  <label className="flex items-center justify-between cursor-pointer group">
    <div className="flex items-center gap-3">
      <div className={`w-[18px] h-[18px] rounded-[5px] border ${checked ? 'bg-[#7387FF] border-[#7387FF]' : 'border-[#E9EBEF] bg-white group-hover:border-[#7387FF]/50'} flex items-center justify-center transition-colors shadow-sm`}>
        {checked && <div className="w-[10px] h-[10px] bg-white rounded-[2px]" />}
      </div>
      <span className={`text-[13px] font-medium transition-colors ${checked ? 'text-[#07074E]' : 'text-[#9F9FD1] group-hover:text-[#07074E]'}`}>{label}</span>
    </div>
    {count && <span className="text-[11px] text-[#9F9FD1] font-semibold bg-[#F3F3FF] px-2 py-0.5 rounded-[4px]">{count}</span>}
  </label>
);

const Radio = ({ label, checked = false }: { label: string, checked?: boolean }) => (
  <label className="flex items-center gap-3 cursor-pointer group">
    <div className={`w-[18px] h-[18px] rounded-full border ${checked ? 'border-[#7387FF] bg-white' : 'border-[#E9EBEF] bg-white group-hover:border-[#7387FF]/50'} flex items-center justify-center transition-colors shadow-sm`}>
      {checked && <div className="w-[8px] h-[8px] rounded-full bg-[#7387FF]" />}
    </div>
    <span className={`text-[13px] font-medium transition-colors ${checked ? 'text-[#07074E]' : 'text-[#9F9FD1] group-hover:text-[#07074E]'}`}>{label}</span>
  </label>
);

export function BrowseBriefs() {
  const [viewMode, setViewMode] = useState<"grid" | "list">("grid");

  const briefs = [
    {
      id: 1,
      brand: "Glow & Co",
      logo: "https://images.unsplash.com/photo-1556228578-0d85b1a4d571?auto=format&fit=crop&q=80&w=128&h=128",
      cover: "https://images.unsplash.com/photo-1581182800629-7d90925ad072?auto=format&fit=crop&q=80&w=600&h=400",
      title: "Summer Skincare Routine TikTok",
      description: "Looking for energetic creators to showcase our new summer hydration line in a 30-60s TikTok video. Focus on the glowing finish.",
      tags: ["Beauty", "TikTok", "Skincare"],
      budget: "$800 - $1,200",
      location: "US/Canada",
      deadline: "Closes in 3d",
      matchScore: 98,
      verified: true,
      fastPayment: true,
      repeatHirer: true,
      featured: true
    },
    {
      id: 2,
      brand: "TechNova",
      logo: "https://images.unsplash.com/photo-1546868871-7041f2a55e12?auto=format&fit=crop&q=80&w=128&h=128",
      cover: "https://images.unsplash.com/photo-1558002038-1055907df827?auto=format&fit=crop&q=80&w=600&h=400",
      title: "Smart Home Setup Reel",
      description: "Create an aesthetic Instagram Reel demonstrating how our smart bulbs integrate into your morning routine.",
      tags: ["Tech", "Instagram", "Smart Home"],
      budget: "$1,200",
      location: "Global",
      deadline: "Closes in 5d",
      matchScore: 92,
      verified: true,
      fastPayment: false,
      repeatHirer: true,
      featured: false
    },
    {
      id: 3,
      brand: "FitLife Apparel",
      logo: "https://images.unsplash.com/photo-1517836357463-d25dfeac3438?auto=format&fit=crop&q=80&w=128&h=128",
      cover: "https://images.unsplash.com/photo-1645318801217-143533cb559f?auto=format&fit=crop&q=80&w=600&h=400",
      title: "Activewear Haul & Try-On",
      description: "We need a YouTube Shorts creator to do a quick-paced haul and styling of our new spring collection.",
      tags: ["Fashion", "YouTube", "Fitness"],
      budget: "$800",
      location: "US Only",
      deadline: "1 week left",
      matchScore: 85,
      verified: false,
      fastPayment: true,
      repeatHirer: false,
      featured: false
    },
    {
      id: 4,
      brand: "BeanRoast Coffee",
      logo: "https://images.unsplash.com/photo-1559525839-b184a4d698c7?auto=format&fit=crop&q=80&w=128&h=128",
      cover: "https://images.unsplash.com/photo-1663958749441-926bbef7cd0c?auto=format&fit=crop&q=80&w=600&h=400",
      title: "Morning Pour-Over Aesthetic",
      description: "Seeking lifestyle creators to film a high-quality, ASMR-style coffee brewing routine featuring our single-origin beans.",
      tags: ["Food", "TikTok", "ASMR"],
      budget: "$500",
      location: "Global",
      deadline: "Closes in 2d",
      matchScore: 78,
      verified: true,
      fastPayment: true,
      repeatHirer: true,
      featured: false
    },
    {
      id: 5,
      brand: "Wanderlust Gear",
      logo: "https://images.unsplash.com/photo-1526779259212-939e64788e3c?auto=format&fit=crop&q=80&w=128&h=128",
      cover: "https://images.unsplash.com/photo-1491637639811-60e2756cc1c7?auto=format&fit=crop&q=80&w=600&h=400",
      title: "Travel Backpack Review",
      description: "Looking for travel vloggers to review our new 40L carry-on backpack in an authentic, engaging way. Must feature outdoor settings.",
      tags: ["Travel", "YouTube", "Review"],
      budget: "$1,500",
      location: "Global",
      deadline: "2 weeks left",
      matchScore: 95,
      verified: true,
      fastPayment: false,
      repeatHirer: true,
      featured: false
    },
    {
      id: 6,
      brand: "PurePlant",
      logo: "https://images.unsplash.com/photo-1580635766551-5e3a8ca8b21d?auto=format&fit=crop&q=80&w=128&h=128",
      cover: "https://images.unsplash.com/photo-1580635766551-5e3a8ca8b21d?auto=format&fit=crop&q=80&w=600&h=400",
      title: "Vegan Snack Unboxing",
      description: "Create an exciting unboxing experience of our new protein snack variety pack. Emphasize taste and texture.",
      tags: ["Food", "Instagram", "Unboxing"],
      budget: "$600",
      location: "US/UK",
      deadline: "Closes in 4d",
      matchScore: 88,
      verified: true,
      fastPayment: true,
      repeatHirer: false,
      featured: false
    }
  ];

  return (
    <div className="flex h-full w-full max-w-[1440px] mx-auto gap-8 pt-4 pb-12">
      
      {/* Left Filter Panel (Fixed Width) */}
      <div className="w-[280px] shrink-0 sticky top-0 self-start max-h-[calc(100vh-140px)] overflow-y-auto hidden lg:flex flex-col bg-white rounded-[24px] shadow-[0_4px_24px_rgba(7,7,78,0.03)] border border-[#E9EBEF]/60 [&::-webkit-scrollbar]:w-[6px] [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:bg-[#7387FF] [&::-webkit-scrollbar-thumb]:rounded-full">
        
        {/* Header & Sticky Top Area */}
        <div className="sticky top-0 bg-white/90 backdrop-blur-md z-10 px-6 pt-6 pb-4 border-b border-[#E9EBEF]/60 rounded-t-[24px]">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-[#07074E]" />
              <h2 className="text-[16px] font-semibold text-[#07074E] font-['Readex_Pro']">Filters</h2>
            </div>
            <button className="text-[12px] font-semibold text-[#7387FF] hover:underline">Clear all</button>
          </div>
          
          <div className="relative">
            <Search className="w-4 h-4 text-[#9F9FD1] absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input 
              type="text" 
              placeholder="Search opportunities..." 
              className="w-full bg-[#F3F3FF] rounded-[10px] py-2.5 pl-9 pr-3 text-[13px] text-[#07074E] placeholder:text-[#9F9FD1] outline-none focus:ring-1 focus:ring-[#7387FF]/50 transition-all font-medium" 
            />
          </div>
        </div>

        {/* Scrollable Filter Content */}
        <div className="p-6 pt-5">
          <FilterSection title="Category" defaultOpen>
            <Checkbox label="Beauty & Skincare" count="124" checked />
            <Checkbox label="Tech & Gadgets" count="86" />
            <Checkbox label="Fashion & Apparel" count="210" />
            <Checkbox label="Food & Beverage" count="54" />
            <Checkbox label="Travel & Lifestyle" count="32" />
          </FilterSection>

          <FilterSection title="Platform Type" defaultOpen>
            <Checkbox label="TikTok" count="198" checked />
            <Checkbox label="Instagram" count="156" checked />
            <Checkbox label="YouTube" count="45" />
            <Checkbox label="User Generated" count="210" />
          </FilterSection>
          
          <FilterSection title="Payout Range">
            <Radio label="Any Budget" checked />
            <Radio label="$100 - $500" />
            <Radio label="$500 - $1,000" />
            <Radio label="$1,000+" />
          </FilterSection>
          
          <FilterSection title="Deadline">
            <Radio label="Any time" checked />
            <Radio label="Closing this week" />
            <Radio label="Closing next week" />
          </FilterSection>
          
          <FilterSection title="Match Score">
            <Radio label="Any match score" />
            <Radio label="80% and above" checked />
            <Radio label="90% and above" />
          </FilterSection>

          <FilterSection title="Brand Type">
            <Checkbox label="Verified Brands" checked />
            <Checkbox label="Repeat Hirer" />
            <Checkbox label="Premium Client" />
          </FilterSection>
        </div>
      </div>

      {/* Right Brand Grid Area */}
      <div className="flex-1 flex flex-col min-w-0 pb-10">
        
        {/* Top Toolbar */}
        <div className="flex items-center justify-between mb-8 bg-white px-5 py-3.5 rounded-[16px] shadow-[0_2px_16px_rgba(7,7,78,0.03)] border border-[#E9EBEF]/60 sticky top-0 z-40">
          <div className="flex items-center gap-3">
            <span className="text-[15px] text-[#07074E] font-medium">
              Showing <span className="font-semibold text-[#7387FF]">246</span> matching opportunities
            </span>
          </div>
          
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 bg-[#F3F3FF] px-4 py-2 rounded-[10px] hover:bg-[#E9EBEF]/50 transition-colors">
              <span className="text-[13px] text-[#9F9FD1] font-medium">Sort by:</span>
              <select className="bg-transparent text-[13px] font-bold text-[#07074E] outline-none cursor-pointer border-none focus:ring-0">
                <option>Recommended</option>
                <option>Highest Payout</option>
                <option>Closing Soon</option>
                <option>Newest</option>
              </select>
            </div>
            
            <div className="w-px h-6 bg-[#E9EBEF]"></div>
            
            <div className="flex bg-[#F3F3FF] p-1 rounded-[10px]">
              <button 
                onClick={() => setViewMode('grid')}
                className={`p-1.5 rounded-[6px] transition-all shadow-sm ${viewMode === 'grid' ? 'bg-white text-[#07074E]' : 'text-[#9F9FD1] hover:text-[#07074E] hover:bg-white/50 shadow-none'}`}
              >
                <LayoutGrid className="w-4 h-4" />
              </button>
              <button 
                onClick={() => setViewMode('list')}
                className={`p-1.5 rounded-[6px] transition-all shadow-sm ${viewMode === 'list' ? 'bg-white text-[#07074E]' : 'text-[#9F9FD1] hover:text-[#07074E] hover:bg-white/50 shadow-none'}`}
              >
                <List className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>

        {/* Opportunity Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-2 xl:grid-cols-3 gap-6">
          {briefs.map((brief, index) => {
            const isFeatured = brief.featured;

            return (
              <div 
                key={brief.id} 
                className={`group bg-white rounded-[20px] flex flex-col h-[440px] overflow-hidden relative cursor-pointer border transition-all duration-300
                  ${isFeatured 
                    ? 'border-[#7387FF]/30 shadow-[0_8px_32px_rgba(115,135,255,0.12)] hover:shadow-[0_16px_48px_rgba(115,135,255,0.2)] hover:-translate-y-1.5' 
                    : 'border-[#E9EBEF]/60 shadow-[0_4px_24px_rgba(7,7,78,0.03)] hover:shadow-[0_12px_40px_rgba(7,7,78,0.08)] hover:-translate-y-1'
                  }
                `}
              >
                {/* Featured Top Border Accent */}
                {isFeatured && (
                  <div className="absolute top-0 inset-x-0 h-[4px] bg-gradient-to-r from-[#7387FF] to-[#3B4FE4] z-20"></div>
                )}

                {/* Top Area: Cover Image & Logos */}
                <div className="relative h-[160px] w-full shrink-0 bg-[#F3F3FF] overflow-hidden">
                  <img src={brief.cover} alt={brief.brand} className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-700 ease-out" />
                  
                  {/* Subtle Gradient Overlay for Text Readability */}
                  <div className="absolute inset-0 bg-gradient-to-t from-black/70 via-black/10 to-transparent pointer-events-none"></div>
                  
                  {/* Save Bookmark Action */}
                  <button className="absolute top-3 right-3 w-8 h-8 rounded-full bg-black/20 backdrop-blur-md flex items-center justify-center text-white hover:bg-white hover:text-[#7387FF] transition-colors z-20 shadow-sm border border-white/10">
                    <Bookmark className="w-[14px] h-[14px]" />
                  </button>

                  {/* Featured Match Tag */}
                  {isFeatured && (
                    <div className="absolute top-3 left-3 z-20">
                      <span className="bg-[#7387FF] text-white text-[10px] font-bold uppercase tracking-wider px-2.5 py-1.5 rounded-[6px] shadow-sm flex items-center gap-1">
                        <Sparkles className="w-3 h-3" /> Best Match
                      </span>
                    </div>
                  )}

                  {/* Brand Identity Overlaid */}
                  <div className="absolute bottom-3 left-4 right-4 flex items-end gap-3 z-20">
                    <img 
                      src={brief.logo} 
                      alt={brief.brand}
                      className="w-12 h-12 rounded-[12px] bg-white object-cover border-2 border-white shadow-md ring-1 ring-black/5" 
                    />
                    <div className="flex flex-col pb-0.5">
                      <div className="flex items-center gap-1.5 drop-shadow-md">
                        <span className="text-[15px] font-bold text-white font-['Readex_Pro'] tracking-wide">{brief.brand}</span>
                        {brief.verified && (
                          <div className="bg-white rounded-full flex items-center justify-center p-[1px]">
                            <CheckCircle2 className="w-[14px] h-[14px] text-[#27AE60]" />
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Middle Content Area */}
                <div className="p-5 flex flex-col flex-1">
                  
                  {/* Title & Summary */}
                  <h3 className="text-[16px] font-semibold text-[#07074E] font-['Readex_Pro'] leading-snug group-hover:text-[#7387FF] transition-colors line-clamp-2 mb-2 pr-4">
                    {brief.title}
                  </h3>
                  
                  <p className="text-[13px] text-[#9F9FD1] font-medium line-clamp-2 mb-4 leading-relaxed">
                    {brief.description}
                  </p>

                  {/* Tags Row */}
                  <div className="flex flex-wrap gap-2 mb-5">
                    {/* Match Score Chip as first tag */}
                    <span className="bg-[#27AE60]/10 text-[#27AE60] text-[11px] font-bold px-2.5 py-1 rounded-[6px] border border-[#27AE60]/20 flex items-center gap-1">
                      <Star className="w-3 h-3 fill-current" /> {brief.matchScore}%
                    </span>
                    
                    {/* Content Tags */}
                    {brief.tags.slice(0, 2).map(tag => (
                      <span key={tag} className="bg-[#F3F3FF] text-[#9F9FD1] text-[11px] font-semibold px-2.5 py-1 rounded-[6px] border border-[#E9EBEF]">
                        {tag}
                      </span>
                    ))}
                    
                    {/* Fast Pay / Trust Chips */}
                    {brief.fastPayment && (
                      <span className="bg-[#7387FF]/10 text-[#7387FF] text-[11px] font-bold px-2.5 py-1 rounded-[6px] border border-[#7387FF]/20 flex items-center gap-1">
                        <Zap className="w-3 h-3 fill-current" /> Fast
                      </span>
                    )}
                  </div>

                  {/* Push remaining content to bottom */}
                  <div className="mt-auto"></div>

                  {/* Divider */}
                  <div className="h-px w-full bg-[#E9EBEF]/60 mb-4"></div>

                  {/* Bottom Area: Payout & Action */}
                  <div className="flex justify-between items-end">
                    <div className="flex flex-col">
                      <span className="text-[20px] font-bold text-[#07074E] font-['Readex_Pro'] tracking-tight">
                        {brief.budget}
                      </span>
                      <div className="flex items-center gap-1 text-[#9F9FD1] text-[11px] font-semibold mt-1">
                        <MapPin className="w-3 h-3" /> {brief.location}
                      </div>
                    </div>
                    
                    <div className="flex flex-col items-end gap-2.5">
                      <div className="flex items-center gap-1 text-[#F39C12] text-[10px] font-bold uppercase tracking-wider bg-[#F39C12]/10 px-2 py-0.5 rounded-[4px]">
                        <Clock className="w-3 h-3" /> {brief.deadline}
                      </div>
                      <button className="bg-[#F3F3FF] text-[#07074E] group-hover:bg-[#7387FF] group-hover:text-white px-5 py-2.5 rounded-[10px] text-[13px] font-bold transition-all shadow-sm group-hover:shadow-[0_4px_16px_rgba(115,135,255,0.3)] border border-[#E9EBEF] group-hover:border-transparent flex items-center gap-1.5">
                        Pitch Now
                      </button>
                    </div>
                  </div>
                </div>
                
              </div>
            );
          })}
        </div>

      </div>
    </div>
  );
}
