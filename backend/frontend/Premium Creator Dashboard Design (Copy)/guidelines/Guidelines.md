<!-- make-kit-guidelines -->
## Design System Setup — MANDATORY

This project depends on `@figma/astraui-kit` packages. Before writing
any code:

1. Read guidelines/setup.md and guidelines/Guidelines.md by their exact
   path (e.g. node_modules/<scope>/<package>/guidelines/setup.md).
   This project uses pnpm, which symlinks packages — do NOT use
   `find`, `glob`, or `file_search` to discover files as they silently
   fail on symlinks. Instead use: reading files by exact path,
   `ls` (follows symlinks), `find -L` (`-L` follows symlinks), or `cat`.
2. Execute all setup instructions (install dependencies, config changes)
   against THIS project — not the package itself.
3. Do not skip, modify, or improvise any setup steps.
4. Read ALL other required .md files specified in guidelines/Guidelines.md.
5. Verify that all packages specified in setup.md appear in this
   project's package.json and that all required .md files have been read before proceeding.
<!-- /make-kit-guidelines -->

1. How to Read This Document
This document defines every screen in the UGCad.io product. It covers three user perspectives — Brand, Creator, and Admin — across 13 screens. Each screen entry contains:

	•	Screen ID and name (matches the interactive wireframe file)
	•	User type (Brand / Creator / Admin)
	•	Purpose — what the user is trying to accomplish on this screen
	•	Components — the UI elements present, with descriptions
	•	User Actions — what the user can do on this screen
	•	State Variations — how the screen changes depending on context
	•	Notes — design constraints, PRD rules, and edge cases to implement

Note: The interactive wireframe HTML file accompanies this document. Use both together — the wireframe shows layout and interaction, this doc adds the rules and constraints that cannot be expressed visually.

2. Brand System
2.1 Color Palette
All four colors are defined and final. Do not introduce new palette colors without brand approval.
Swatch
Name
Hex
Usage

Periwinkle Pulse
#7387FF
Primary CTA buttons, links, accents, active states, chips, progress fills

Frosted Lilac
#F3F3FF
Light page background, secondary sections, card backgrounds on dark surfaces

Velvet Mist
#9F9FD1
Secondary text, muted labels, icon accents, subtitle color

Midnight Indigo
#07074E
Primary text, headers, dark section backgrounds (stats, footer, CTAs)

Rule: Never introduce new palette colors. For functional states (success, error, warning) use: Green #27AE60, Red #E74C3C, Amber #F39C12 — these extend the brand and are not primary palette colors.

2.2 Typography
Role
Typeface
Weights
Usage
Display / Headlines
Readex Pro
Medium (500), Bold (600)
H1, H2, H3, logo wordmark, stat numbers, screen titles
Body / UI
Just Sans
ExtraLight through ExtraBold (200–800)
Body copy, labels, captions, table cells, form inputs
Fallback (web)
Inter
400, 500, 600
Only if Just Sans unavailable via CDN — use as system fallback

Type Scale
Level
Size (print pt)
Weight
Usage
Hero Title
72–84pt
500 Readex Pro
Homepage hero headline only
Page Title
36–48pt
500 Readex Pro
Screen H1, section headlines
Section Title
28–32pt
500 Readex Pro
Card titles, sub-section headers
Component Title
18–22pt
500 Readex Pro
Card H3, sidebar section labels
Body
14–16pt
400 Just Sans
Paragraph text, descriptions
UI Label
12–13pt
500 Just Sans
Form labels, table headers, nav items
Caption / Hint
11–12pt
400 Just Sans
Helper text, timestamps, mono IDs
Badge / Tag
10–11pt
500 Just Sans or mono
Chips, status badges

2.3 Logo Usage
	•	Monogram: U+G+C geometric fusion forming a paperclip shape. Uses Periwinkle Pulse (#7387FF) stroke on light backgrounds.
	•	Wordmark: "UGCad.io" — exact casing. Never "UGCAD.IO", "ugcad.io", or "UgcAd.io".
	•	Lock-up: Monogram left, wordmark right. Minimum clear space = 1x the monogram height on all sides.
	•	Dark background: Use white wordmark + Periwinkle Pulse monogram.
	•	Never place on backgrounds that compromise contrast. Minimum contrast ratio 4.5:1.

2.4 Spacing & Layout Grid
Token
Value
Usage
Base unit
4px
All spacing is multiples of 4px
Component gap
8px / 12px / 16px
Inside cards between elements
Section gap
20px / 24px
Between sibling cards
Page padding
24px (desktop) / 20px (mobile)
Container edge padding
Card radius
12px (--radius-lg)
Primary card corners
Button radius
8–14px
Context-dependent
Sidebar width
240px (fixed)
Navigation sidebar
Topbar height
52px
Sticky page-level topbar

3. Brand Screens
The Brand user (e.g. "Priya", D2C marketing manager) logs in to post briefs, review creator applications, manage active deals, review delivered content, and manage their wallet.
Screen B-01 — Brand Dashboard
[B-01] Brand Dashboard  ·  Brand  ·  Primary entry screen after login

Purpose
Give the brand a single view of everything requiring attention: active deals, pending actions, wallet balance, and recent brief status.
Layout
Note: Sticky topbar (52px). Left sidebar (240px fixed). Content area = full remaining width. Standard 24px padding.
Components
Component
Type
Description
Concierge Notice
Info Banner
Only shown during first 30 days of onboarding. Blue background. Link to book a setup call. Dismissible.
Stat Row
4-column metric cards
Active Deals · In Escrow (₹ total) · Deals Delivered · Wallet Balance. Each card shows label + large value + delta line.
Active Deals Table
Data table
Columns: Brief name + category, Creator handle, Stage chip, Due in, Escrow amount, View/Review button. Max 5 rows visible before pagination.
Pending Actions Panel
Right sidebar card
Priority action cards stacked vertically. Each shows icon, title, sub-label, and a single CTA button. Max 5 items.
Recent Briefs Table
Data table
Columns: Title, Budget, Applications count, Status chip. Shows last 3-5 briefs.
Brand Plan Card
Right sidebar card
Plan name (chip), commission rate, brief budget progress bar with amount/total + percentage.
User Actions
	•	Click "Post a Brief" → navigates to B-02
	•	Click "View" or "Review" on a deal row → navigates to B-04 Deal Room
	•	Click "Review" on pending action → navigates to B-03 or B-04 as appropriate
	•	Click "Mark Shipped" → opens shipping confirmation modal
State Variations
	•	Empty state (new brand, no deals): Replace tables with illustrated empty states. Show "Post your first brief" CTA prominently.
	•	Concierge active: Show banner for first 30 days, then auto-hide.
	•	Wallet below ₹5,000: Show warning chip on wallet stat card.
Notes
Note: Wallet balance is separate from escrow. Escrow shows the total currently locked across all active deals — this money has left the wallet but not reached the creator.
Rule: Pending Actions panel must show the "Home Decor Reel delivered — review & approve" action prominently if a deal is awaiting brand approval. This drives the most critical user action on the platform.

Screen B-02 — Post a Brief
[B-02] Post a Brief  ·  Brand  ·  5-step multi-screen form flow

Purpose
Collect all information needed to create a campaign brief that creators can apply to. The brief drives matching, deal creation, and escrow.
Step Indicator
5-step horizontal progress indicator pinned below the topbar. Each step is a numbered circle (done = green checkmark, current = blue filled, future = gray outline with dashed border).
Step
Title
Key Fields
1
Product Info
Product name, variant, retail price, product category, brief type (UGC reel / unboxing / testimonial / tutorial)
2
Content Requirements
Campaign brief / hook (free text), key message (max 120 chars), what NOT to do, tone reference
3
Deliverables
Primary video format (Reel / Short / Story / feed), aspect ratio, duration (15s / 30s / 60s), extras (B-roll count, photos), revision count (default 2 free)
4
Creator Requirements
Minimum creator level (New / Verified / L1 / L2 / Elite), quality tier (A / A+ / A++), gender preference, city filter, niche tags (freeform)
5
Budget & Review
Per-video budget (₹), commission auto-calculated and shown, creator payout shown, escrow notice, submit button
Components
	•	Step 1-4: Two-column layout (main form left, preview/guidance card right)
	•	Step 5: Single column with budget breakdown table and submit CTA
	•	Right card on Steps 1-4: Contextual help text explaining why each field matters
	•	Save Draft button: Always visible in topbar actions area
	•	Back / Next buttons: Bottom of each step form
Budget Panel (Step 5)
Line
Formula
Example
Brand pays (per video)
User-entered amount
₹18,750
Platform commission
20% (Brand Pro) · 25% (Free) · 15% (Enterprise)
₹3,750
Creator receives
Brand pays minus commission
₹15,000
Listing fee (1-3 creators)
₹500 (refunded as wallet credit if hired)
₹500
Validation Rules
Rule: Budget cannot be set below the minimum floor for the selected creator level: New ₹1,500 / Verified ₹2,500 / L1 ₹4,000 / L2 ₹7,500 / Elite ₹15,000. If quality tier is A+ (×1.25) or A++ (×1.6), minimum is multiplied accordingly.
Rule: Brief title is mandatory. Max 80 characters. No special characters.
Rule: Product category and brief type must both be selected before Step 2 unlocks.
Note: Briefs go to admin review before being shown to creators. Estimated review time: 24 hours in V0.5.

Screen B-03 — Browse Creators / Creator Matches
[B-03] Browse Creators  ·  Brand  ·  Creator discovery and selection screen

Purpose
Show the brand a filtered grid of creators who match the brief requirements. The brand can invite creators, review portfolios, and accept or decline applications.
Layout
4-column card grid (responsive: 2-column on narrower viewports). Filter bar above the grid.
Creator Card Components
Element
Description
Thumbnail
Gradient placeholder (V0.5). V1: real watermarked portfolio thumbnail with play button overlay.
Category chip
Top-left: content category (Beauty, Fitness, Tech, etc.)
Tier badge
Top-right: Elite / L2 Pro / L1 Rising / Verified / New. Color-coded.
Handle
@handle format. Monospaced font. Verified checkmark icon if applicable.
Rating + Deals
Star rating (1dp) + deal count. Monospaced font.
City
Creator city — important for shipping.
Past brands
Brand names of completed past deals shown. Real names, not handles.
Quality tier chip
A / A+ / A++
Sample thumbnails
3-cell grid of watermarked sample video thumbnails. Click to play in modal.
Action buttons
Primary: Invite (if not yet applied). Accept / Decline (if applied). Shortlist star icon.
Applied state
Border accent + "Applied X hrs ago" badge replaces Invite button.
Critical Privacy Rule
Rule: Creator real name, phone number, email, and social media handles are NEVER shown to brands at any stage. Only the anonymised platform handle is visible. This is enforced at the API level, not just the UI.
Note: Past brand names ARE shown (e.g. "Mamaearth, Dot&Key, Minimalist") — this is intentional. It signals creator quality without revealing identity.
Filter Bar
	•	Creator level (multi-select chips)
	•	Quality tier (A / A+ / A++)
	•	Category (dropdown)
	•	City (dropdown)
	•	Sort: Best match / Highest rated / Most deals / Newest
State Variations
	•	No matches: Empty state with suggestion to widen filters or reduce level requirement.
	•	Brief not yet reviewed by admin: Show notice — "Brief is under review. Matching will begin within 24 hours."
	•	Application window closed (48hr passed): Show expired badge on unreviewed applications.

Screen B-04 — Deal Room (Brand View)
[B-04] Deal Room  ·  Brand  ·  Core transaction screen — most complex

Purpose
The primary workspace for a single deal. Shows the full deal state machine, all documentation (pre-ship checklist, unboxing video, delivered content, revisions), and the approval/payout action.
Layout
Full-width content area. Two-column below the state machine: main content area (left, ~65%) and side panel (right, ~35%).
State Machine — 9 Stages
Stage
Stage Name
Trigger
Brand Actions Available
1
Brief
Brief submitted & approved by admin
None (passive)
2
Matched
Brand accepts a creator application
Chat unlocked
3
Escrow
Brand locks payment from wallet
None (auto-triggers on acceptance)
4
Shipping
Brand marks item shipped via Shiprocket
Enter tracking number, mark shipped
5
Received
Creator confirms receipt + uploads unboxing video
View unboxing video, flag damage within 48hr
6
Production
Creator working on the deliverable
Chat, request milestone update
7
In Review
Creator submits final video
Watch video, request revision (if <2 used), approve, or dispute
8
Approved
Brand approves or 5-day auto-approve triggers
None (system releases escrow)
9
Completed
Escrow released, payout initiated
Rate creator (2-way rating), download content
Main Content Area Components
	•	State machine visual: Horizontal step track with circles and connecting lines. Done = green, Active = blue, Pending = gray dashed.
	•	Stage notice: Contextual banner explaining current stage and required action. Changes per stage.
	•	Video delivery panel (Stage 7+): Video thumbnail (placeholder until delivered), download button, revision request button, revision counter ("1 of 2 free used"), approve button, dispute button.
	•	Unboxing video panel (Stage 5+): Shows unboxing video with upload timestamp. Read-only for brand.
	•	Damage report window: 48-hour window from receipt confirmation. Shows as expired after 48hr.
Side Panel Components
	•	Deal summary table: Deal ID, creator handle, tier, quality tier, brief name, dates, status chip.
	•	Payment breakdown: Brand paid / Platform commission / Creator receives (3 rows, always visible).
	•	Pre-ship checklist: 4 items shown as checked/unchecked. Read-only for brand.
	•	Shipping details: Tracking number, Shiprocket carrier, delivery date. "Masked sender" label.
	•	Revision log: Each revision as a card — request text, status (free/paid), outcome.
Approval Flow (Stage 7 → 8)
Rule: Approve button releases escrow to creator. This action is FINAL and cannot be reversed. Show confirmation dialog before proceeding: "This will release ₹X to the creator. This cannot be undone."
Rule: If brand takes no action within 5 calendar days of delivery, the system auto-approves. Show a countdown timer on the stage notice when auto-approve is within 24 hours.
Note: Dispute opens a separate flow. Dispute must be filed within the 5-day review window. After auto-approval triggers, dispute is no longer available.

Screen B-05 — Messages / Chat
[B-05] Messages  ·  Brand + Creator  ·  Shared screen — same layout for both POVs

Purpose
On-platform, deal-scoped communication between brand and creator. Enforces no direct contact exchange. Provides structured action cards for deal-relevant events.
Layout
Two-pane: conversation list (left, 260px fixed) + active conversation (right, remaining width). Active conversation has: topbar with creator info, action pills, message list, input bar.
Conversation List (Left Pane)
Element
Description
Chat item
Avatar initials, handle, last message preview (truncated), timestamp
Active state
Highlighted with Periwinkle Pulse background tint
Deal context
Deal stage chip shown under handle in active conversation topbar, not in list
Message Types
Type
Alignment
Visual Treatment
Sent (me)
Right-aligned
Periwinkle Pulse bubble, white text, bottom-right flat corner
Received (them)
Left-aligned
White bubble with border, ink text, bottom-left flat corner
Action Card
Left-aligned (full width card)
White card with border, action type label (uppercase, blue), title, meta, optional CTA button
System Message
Centered
Gray pill label, small text, no bubble
Action Cards
Action cards are structured messages tied to deal events. They are generated by the platform or by either party using the action pills.
Action Card Type
Who Can Create
When Used
Custom Offer
Either party
Creator proposes price change; brand accepts or counters. Max 3 counter-rounds.
Revision Request
Brand
When requesting a content change. Auto-decrements revision counter.
Milestone Update
Creator
When sharing production progress (text + optional media).
Damage Report
Creator
Within 48hr of receiving product. Triggers admin review.
Delivery
Creator
Auto-generated when creator uploads final video to deal room.
Escalate
Either party
Escalates issue to admin without opening full dispute.
Dispute
Either party
Opens formal dispute. Deal enters Disputed state. Admin notified.
Contact Filter
Rule: The platform filters all outgoing messages for phone numbers (10-digit patterns), email addresses (@domain patterns), and social media handles (@username, instagram.com, wa.me, etc.). Filtered content is replaced with "[contact info removed]" and the sender receives a warning.
Rule: Third violation in a single deal triggers action-cards-only mode for that deal. The text input is hidden and only action cards can be sent.
Input Bar
	•	Free-text input field (multi-line, auto-expand)
	•	Send button (primary)
	•	Action pills above input: Custom Offer · Revision Request · Milestone Update · Damage Report · Escalate · Dispute
Note: Action pills are context-aware. "Damage Report" only shown within 48hr of product receipt. "Revision Request" hidden after 2 free revisions used and no paid revisions purchased.

Screen B-06 — Wallet (Brand)
[B-06] Wallet  ·  Brand  ·  Payment management screen

Purpose
Show available wallet balance, manage recharges, view recharge bonus tiers, and review transaction history.
Components
Component
Description
Wallet Bar
Dark (Midnight Indigo) full-width card. Shows: Available Balance (large), bonus active label, two recharge CTAs (₹10K and ₹25K+).
Minimum Notice
Warning banner: ₹5,000 minimum recharge required to unlock platform chat. Wallet credits are non-refundable.
Bonus Tiers Table
4-row table: Recharge Amount / Bonus / Status. Shows active tier highlighted.
Transaction History
Date / Type / Amount. Negative amounts in red, positive in green. Shows last 10 transactions.
Recharge Bonus Tiers
Recharge
Bonus %
Bonus Value
₹10,000
+5%
₹500

+7%
₹1,750

+10%
₹5,000

+12.5%
₹12,500
Transaction Types
	•	Wallet recharge (positive)
	•	Recharge bonus credited (positive)
	•	Escrow lock — deal accepted (negative)
	•	Escrow release — deal cancelled/refunded (positive)
	•	Listing fee charged (negative)
	•	Listing fee refunded as credit — creator hired (positive)
Rule: Wallet balance is non-refundable to bank. Surplus credit carries forward. Make this explicit in the UI.

4. Creator Screens
The Creator user (e.g. "Anjali", part-time UGC creator) logs in using their permanent anonymous handle to browse briefs, manage active deals, upload content, and track payouts.
Screen C-01 — Creator Dashboard
[C-01] Creator Dashboard  ·  Creator  ·  Primary entry screen after login

Purpose
Give the creator an overview of their active deals, earnings, level progress, and badge status. Motivate quality work and level-up behaviour.
Components
Component
Description
Stat Row
Active Deals · Pending Payout (₹) · Total Earned (₹) · Rating (star). Same 4-card layout as Brand dashboard.
Level Progress Card
Shows current level, metrics required for next level (rating / dispute rate / deals in 90d), progress bar to next level, promotion eligibility status.
Active Deals Table
Brief name + quality, Brand handle (masked, e.g. "Brand #881"), Stage chip, Due date, Payout amount, Open button.
Badge Showcase
List of earned and locked badges. Earned badges show title + description. Locked badges show greyscale with unlock condition.
Rate Card
Minimum rate for their level, quality tier multiplier, custom offer limit, payout window.
Level System Display
Level
Label
Demotion Thresholds
New
New Creator
No demotion (entry level)
Verified
Verified
Rating < 4.3 OR dispute rate > 8%
L1
L1 Rising
Rating < 4.5 OR dispute rate > 6% OR < 5 deals in 90d
L2
L2 Pro
Rating < 4.6 OR dispute rate > 4% OR < 8 deals in 90d
Elite
Elite Creator
Rating < 4.8 OR dispute rate > 2% OR < 10 deals in 90d
Note: Grace period: 14-day warning before demotion. During grace period, show a warning banner on the dashboard with specific metric that triggered the warning.
9 Badges (4 shown at launch, rest in V2)
	•	Fast Deliverer — 0 late deliveries in 90 days
	•	Brief Faithful — avg < 2 revision requests per deal
	•	Unboxer Pro — 10+ unboxing videos submitted on time
	•	5-Star Streak — 5 consecutive 5-star ratings
	•	High Volume — 20+ deals completed
	•	Dispute-Free — 0 disputes in 12 months
	•	Multi-Niche — deals across 3+ content categories
	•	Repeat Favourite — hired by same brand 3+ times
	•	Elite Creator — reach Elite level

Screen C-02 — Browse Briefs
[C-02] Browse Briefs  ·  Creator  ·  Brief discovery and application screen

Purpose
Show available campaign briefs the creator can apply to. Creator sees payout, brief requirements, and applies within 48hr windows.
Layout
Single-column list of brief cards. Filter bar at top. No grid — list format allows more brief detail per card.
Brief Card Components
Element
Description
Category icon
Large emoji/icon for visual scanning (Beauty ✨, Fitness 💪, Home 🏠, etc.)
Brief title
Bold, full width
Chips row
Quality tier chip (A/A+/A++) + Status chip (New / Applied / Shortlisted / Closed)
Meta line
Category · Content type · Duration · City restriction (if any)
Brief summary
2-3 sentence description of the campaign angle. NOT the full brief — revealed post-application.
Niche tags
Small chips: Beauty, Skincare, Glow, etc.
Payout
Large ₹ amount — clearly shows what creator receives (after commission, not brand total)
Per-video label
Small label clarifying if it is per video or for a bundle
Apply button
Primary CTA. Changes to "Pending" chip after application. Shows countdown to window close.
Important Display Rules
Rule: Creator sees the payout they receive, NOT the brand total budget. This is after the platform commission is deducted. Show clearly: "₹15,000 to you (after 20% platform fee)".
Rule: Full brief details (hook, direction, do/don't list, exact product) are only revealed after the brand accepts the creator's application. Pre-application, show only the summary.
Note: Creator can apply to maximum 5 custom offer conversations per day. Standard brief applications are unlimited.
Filter & Sort
	•	Category (multi-select)
	•	Quality tier (A / A+ / A++)
	•	City match (show only briefs where product ships to creator city)
	•	Sort: Newest / Highest payout / Closes soonest
	•	"Applied" filter: Show only briefs creator has already applied to

Screen C-03 — Deal Room (Creator View)
[C-03] Deal Room  ·  Creator  ·  Mirror of Brand Deal Room — different actions available

Purpose
Same deal state machine as Brand view, but creator-facing. Creator sees full brief details, manages product receipt, uploads unboxing video and final deliverable, and tracks their payout.
Key Differences from Brand Deal Room (B-04)
Feature
Brand View
Creator View
Brief details
Hidden (already knows)
Shown in full — hook, direction, don'ts, format
Video upload
Not available
Upload panel visible in Stage 6 (Production)
Approve button
Visible (Stage 7)
Not available — creator cannot approve their own work
Shipping info
Can mark shipped
Can confirm receipt + upload unboxing video
Payout shown
Shows escrow total
Shows their net payout (after commission)
Damage report
Can view
Can file within 48hr of receipt
Late penalty tracker
Not shown
Visible: current deal + rolling 6-month count
Upload Panel (Stage 6 — Production)
	•	Drag-and-drop upload zone with dashed border
	•	Accepted: MP4, MOV. Max 500MB. 9:16 preferred.
	•	Progress bar during upload
	•	Once uploaded: "Submit Final Delivery" button locks the upload and notifies the brand
Rule: Creator cannot re-upload after submitting delivery unless brand requests a revision. If brand requests revision, upload panel reopens.
Unboxing Video Requirement
Rule: Creator must upload a 2-minute minimum unboxing video within 48 hours of confirming product receipt. The unboxing video must show: sealed packaging, product, brief-spec variant, working condition. If not uploaded within 48hr, the platform flags the deal for admin review.
Due Date Warning
Note: When fewer than 72 hours remain before the due date, show a prominent amber warning banner with the exact due date and the first late penalty (5% of payout). When fewer than 24 hours remain, escalate to red.

Screen C-04 — Payouts
[C-04] Payouts  ·  Creator  ·  Payout history and bank details

Components
Component
Description
Stat Row
Pending Release · Paid This Month · All Time · Payout Window. Same 4-card layout.
Payout History Table
Deal ID (mono) · Brief name · Approval date (or dash if pending) · Gross amount · Commission · Net Paid · Status chip (Pending / Paid / Disputed).
Add Bank Account Button
Opens modal for bank account entry. V0.5: manual entry, no API verification. V1: integrate IFSC verify.
Payout Windows by Level
Level
Payout Window After Approval
New
12 business days
Verified
7 business days
L1 Rising
5 business days
L2 Pro
3 business days
Elite
48 hours
Rule: Payout window starts from brand approval (or auto-approval at day 5). If deal is in dispute, payout is frozen until dispute resolves.

Screen C-05 — Creator Profile
[C-05] Creator Profile  ·  Creator  ·  Public profile management

Purpose
Allow creator to manage how they appear to brands. Control bio, niche, city, portfolio samples, and GST verification status.
Components
Component
Description
Handle Display
Read-only. Shown with "permanent" label. Cannot be changed after initial selection.
Bio Field
Text area, 280 char max. Shown to brands on creator card.
Niche Selector
Primary niche dropdown. Secondary niches (up to 3) as multi-select chips.
City Selector
Dropdown. Used for brief matching and shipping routing.
Portfolio Samples
Upload up to 5 video samples. All auto-watermarked before brand display. Each shows watermark badge in preview.
GST Verification
Current tier shown (Self-verified free / Tier 2 ₹2,499). Upgrade CTA if not at Tier 2.
Preview as Brand
Button to show how profile appears to brands — opens read-only view.
Privacy Rules on Profile
Rule: Profile page must never show or collect: real name, phone number, email address, social media handles. If any of these appear in the bio text (detected by filter), flag and prompt correction before saving.
Note: Past deal brand names are automatically added to the creator profile as they complete deals. Creator cannot remove or edit these — they are earned through the platform.

5. Admin Screens
The Admin user (UGCad.io team) uses the admin panel to manage the platform — review creator/brand onboarding, handle disputes, generate shipping labels, monitor platform health, and enforce penalties.
Screen A-01 — Admin Overview
[A-01] Admin Overview  ·  Admin  ·  Primary admin dashboard

Components
Component
Description
Stat Row
Total Deals · In Escrow (₹) · Active Creators · Active Brands.
Platform Health Card
Progress bars for: Deal completion rate (target ≥80%) · Dispute rate (target <15%) · Avg brief-to-delivery (target <14d) · Brand repeat rate (target ≥40%). Values in realtime from DB.
Alerts Panel
Priority action list: Open disputes (with day counter) · Late penalty events · New creator applications pending review · Manual Shiprocket labels pending · Brands pending KYB.
Financial Summary
Escrow held · Commission earned this month · Pending payouts · Active disputes.
Alert Priority Order
	•	P1 — Open disputes (dispute entered Disputed state; requires resolution within 14 days)
	•	P2 — Creator applications pending manual review (SLA: 48hr from submission)
	•	P3 — Manual shipping labels pending (V0.5 — before Shiprocket API integration)
	•	P4 — Brands pending KYB completion
	•	P5 — Late penalties triggered (informational; auto-applied by system)

Screen A-02 — All Deals
[A-02] All Deals  ·  Admin  ·  Full deal management table

Components
Component
Description
Filter Bar
Stage filter · Flagged only toggle · Date range picker · Search by deal ID or handle.
Deals Table
Deal ID · Brand (masked ID) · Creator handle · Brief title · Stage chip · Escrow · Due date · Flag indicator · Actions.
Disputed rows
Amber background tint. Flag badge shows day counter (e.g. "🚩 Day 3 of 14"). Arbitrate CTA.
Late rows
Red background tint. Shows which penalty event (1st/2nd/3rd/4th/5th). Review CTA.
Deal Table Actions
	•	View — opens full deal room in admin view (can see all data including both sides)
	•	Arbitrate — opens dispute resolution modal. Admin can rule in favour of brand (refund) or creator (release), or split 50/50. Decision is final.
	•	Override shipping — admin generates Shiprocket label manually (V0.5 flow)
Dispute Resolution Rules
Rule: Admin has 14 calendar days to resolve a dispute from the day it is opened. After 14 days without resolution, platform auto-refunds the brand from escrow and the creator receives nothing. This is the nuclear option — should be avoided.
Rule: Penalty split on dispute: 50% to brand as credit, 50% to platform. Not paid out to creator.

6. Global Components
6.1 Navigation — Sidebar
Element
Description
Brand logo
Monogram + "UGCad.io" wordmark. Links to dashboard.
Section labels
10px uppercase mono font, Velvet Mist color. Non-clickable.
Nav items
Icon (16×16) + label. Active state: Periwinkle Pulse background tint + color. Hover: light gray background.
Notification badges
Circular badges on nav items showing count. Blue for neutral, Amber for attention, Red for urgent. Max 99+.
Bottom utilities
Settings link at bottom of sidebar, always visible.
6.2 Topbar
Element
Description
Breadcrumb
Small monospace, Velvet Mist color. Shows: section / current screen. Active segment in Periwinkle Pulse.
Page title
H1 in Readex Pro, Midnight Indigo. Left side.
Actions area
Right side. Up to 3 buttons. Primary action always rightmost.
Sticky behavior
Topbar sticks to top of viewport on scroll. Background becomes opaque white with bottom border.
6.3 Status Chips
Status
Color
Usage
New / Draft
Gray (#D8D8E8 bg, #7878A0 text)
Unpublished briefs, new creators
Pending / Matching
Indigo tint (#EEF0FF bg, #07074E text)
Brief under admin review or creator matching
Shipping / In Progress
Blue (#EEF0FF bg, #7387FF text)
Active, non-critical stage
In Production
Amber (#FFF8E8 bg, #F39C12 text)
Creator working on deliverable
In Review
Green (#E8F8EE bg, #27AE60 text)
Content delivered, awaiting brand approval
Approved
Green filled (#27AE60 bg, white text)
Deal complete, payout triggered
Disputed
Red (#FCEAEA bg, #E74C3C text)
Active dispute
Late
Red
Delivery past due date
Completed
Gray/indigo
Payout received, deal closed
6.4 Empty States
Every table and list must have a designed empty state — not just a blank space. Each empty state includes:
	•	Simple illustration or icon (not photographic)
	•	Headline: what is empty (e.g. "No active deals yet")
	•	Sub-copy: what to do next (e.g. "Post your first brief to get matched with creators")
	•	Primary CTA button where relevant
6.5 Confirmation Dialogs
The following actions require an explicit confirmation modal before proceeding:
Action
Warning Level
Dialog Text
Approve deal and release escrow
Critical
This will release ₹[amount] to [handle]. Approval is final and cannot be reversed.
Open a dispute
High
Opening a dispute pauses the deal. Admin will review within 48 hours. This cannot be withdrawn.
Decline a creator application
Medium
This creator will be notified their application was declined.
Delete a brief draft
Low
This will permanently delete your draft. This cannot be undone.
6.6 Mobile Responsiveness
V0.5 is web-only (desktop browser). However, designer should flag any components that would be critical to support on mobile for V1 planning.
	•	Minimum desktop viewport: 1280px wide
	•	Sidebar collapses to icon-only at < 1100px, hidden at < 768px (hamburger menu)
	•	Stat rows collapse from 4-column to 2-column at < 900px
	•	Creator card grid collapses from 4 → 2 → 1 column
	•	Deal room aside collapses below main column on narrow viewports

7. Screen Inventory
Complete list of all screens in v0.5 scope.
Screen ID
Name
POV
Priority
Status
B-01
Brand Dashboard
Brand
P0
Wireframe done
B-02
Post a Brief (5-step wizard)
Brand
P0
Wireframe done
B-03
Browse Creators / Matches
Brand
P0
Wireframe done
B-04
Deal Room — Brand View
Brand
P0
Wireframe done
B-05
Messages / Chat
Brand + Creator
P0
Wireframe done
B-06
Wallet
Brand
P1
Wireframe done
C-01
Creator Dashboard
Creator
P0
Wireframe done
C-02
Browse Briefs
Creator
P0
Wireframe done
C-03
Deal Room — Creator View
Creator
P0
Wireframe done
C-04
Payouts
Creator
P1
Wireframe done
C-05
Creator Profile
Creator
P1
Wireframe done
A-01
Admin Overview
Admin
P0
Wireframe done
A-02
Admin All Deals
Admin
P0
Wireframe done
AUTH-01
Login / Signup (Brand)
Brand
P0
Not wireframed yet
AUTH-02
Login / Signup (Creator)
Creator
P0
Not wireframed yet
AUTH-03
Creator Onboarding (handle selection)
Creator
P0
Not wireframed yet
B-07
Brief Detail (post-submission view)
Brand
P1
Not wireframed yet
C-06
Custom Offer flow
Creator
P2
V1 scope
B-08
Campaign Analytics
Brand
P2
V2 scope

8. Handoff Notes for Designer
8.1 Files Delivered
	•	This document: ugcad-io-ui-spec.docx
	•	Interactive wireframe: ugcad-io-wireframe.html (open in Chrome)
	•	Homepage (animated): ugcad-io-homepage.html (open in Chrome)
	•	Brand kit: UGCad_io_Visual_Identity_Variations_pdf.pdf + 20 Behance posts
8.2 Design Tool Recommendation
	•	Primary: Figma (for component library, design system, and screen design)
	•	Start by building the Design System page: color styles, text styles, component library (buttons, chips, inputs, cards, table rows, nav items, badges)
	•	Then build screens in order of priority: B-01 → C-01 → B-04 → B-02 → B-03 → B-05
8.3 What Still Needs Decisions
Topic
Decision Needed
Auth screens
Login / signup flow not yet wireframed. Needs decision: social login (Google), OTP, or email/password.
Creator onboarding
Handle selection screen — only one chance to pick. Needs a specific UI that makes this feel important.
Video player
What video player to use for portfolio samples and delivered content. Native HTML5 or library?
Notification system
In-app notification dropdown not yet designed. Where does it live in the topbar?
Empty state illustrations
Do we create custom SVG illustrations or use a library (e.g. Undraw)?
Shipping label UI
V0.5 admin generates Shiprocket labels manually. What does the admin shipping workflow screen look like?
2-way rating UI
Rating screen after deal completion — not yet wireframed. Stars + optional text review for both sides.
8.4 Terminology Reference
Term
Definition
Brief
Campaign request posted by a brand
Deal
A brief + creator pairing that has been accepted and is in progress
Escrow
Brand payment held by platform until brand approves the delivered content
Handle
Creator's anonymous platform username (e.g. @creator_2847). Permanent.
Tier / Level
Creator's earned level: New → Verified → L1 Rising → L2 Pro → Elite
Quality Tier
Content quality classification: A (standard) / A+ (premium) / A++ (top-tier)
Listing Fee
Fee brand pays to publish a brief: ₹500 (1-3 creators), ₹1,500 (4-10), ₹3,000 (11+). Refunded as credit if creator is hired.
Masked shipping
Shiprocket-mediated shipping where brand's real address is hidden from creator
Action Card
Structured chat message tied to a deal event (offer, revision, dispute, etc.)
Payout window
Days after brand approval that creator receives payment. Varies by level.
Auto-approve
If brand does not review delivered content in 5 days, deal auto-approves and escrow releases
POV
Point of view — Brand, Creator, or Admin perspective in the UI

End of document.
UGCad.io UI Spec v0.5 · Built from PRD · For UI Designer Handoff
