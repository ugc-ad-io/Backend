# UGCad User Stories

The complete story catalog for the UGCad platform — shared by the **website** and the **Android app** (same backend, same flows). Every acceptance criterion reflects behavior actually implemented in production code.

> **Status legend** · ✅ **Live** = verified working · 🟡 **Test mode** = deliberately simulated during the testing phase · ⛔ **Stub** = UI/data exists, flow not wired
>
> 3 roles · 59 stories · as of 29 Sep 2026 · source: `server.py`, Frontend, ugcapp
> Full journey maps live in [USER_FLOWS.md](USER_FLOWS.md)

---

## Creator stories (23)

A creator joins, gets approved, wins work, delivers content, and gets paid — with the platform holding money in escrow the whole way.

### Onboarding & identity

**US-C01 · Sign up with email, OTP and mobile number** ✅
As a creator, I want to create an account with my email and a compulsory mobile number, so that the platform and brands can always reach me.
- Email + password signup; mobile number is required and shown to admin
- Google Sign-In offered as an alternative
- New creator accounts start as `approval_status: pending`

**US-C02 · Build my profile** ✅
As a new creator, I want to set up my profile in one guided form, so that brands see a complete, bookable card.
- Photo (required) and banner (optional), each ≤ 5 MB
- Real name replaces the auto-generated handle everywhere
- Content styles + content categories (multi-select dropdowns)
- **Instagram is the only social field** (link or @handle, required); extra custom links allowed
- Languages with per-language fluency

**US-C03 · Upload portfolio video cards** ✅
As a creator, I want to add portfolio videos with a price, delivery time and category, so that brands can book me at my own rate.
- Drag & drop or tap-to-upload, video ≤ 100 MB, stored on Cloudinary
- Card flow: upload → "✓ Added" card → Modify (change video / price / delivery / category) → Delete
- An upload that storage rejects fails **loudly** — never a silently dead link
- 3–5 portfolio items enforced on submit

**US-C04 · Wait under review — and resubmit if asked** ✅
As an applicant, I want a clear "Profile Under Review" screen, so that I know my application status without guessing.
- Pending → full-screen "Under Review" gate instead of the dashboard (24–48 h promise)
- Admin can request more info → I see the request and can edit + resubmit
- Rejected → rejection gate with reason; rejection history preserved on reapply
- An already-approved creator editing their profile stays approved (flagged for re-review, never de-listed)

**US-C05 · Get reminded if I abandon onboarding** ✅
As a signed-up creator who never finished the form, I want a reminder email after 24 h, so that I come back and complete my card.
- One reminder per user, gated by `form_reminder_sent_at`
- Applies to both creators and brands

**US-C06 · Complete KYC** ✅
As a creator, I want to submit PAN / Aadhaar / bank–UPI details once, so that I can withdraw real earnings.
- `GET /kyc/me` shows my status; `POST /kyc/submit` files documents
- Only the `kyc_verified` badge is ever visible to others — PII never leaves admin
- TDS exemption flag honored in payout math

### Finding work

**US-C07 · Browse open briefs** ✅
As an approved creator, I want to browse all active public campaigns, so that I can find work that fits my niche.
- Only admin-approved (`active`) campaigns appear
- Privately-invited briefs never leak into the public board
- Restricted categories (tobacco, weapons, adult, gambling) blocked platform-wide

**US-C08 · Save briefs for later** ✅
As a creator, I want to bookmark briefs, so that my shortlist follows my account onto any device.
- Saved list stored on my user record, synced between web and app

**US-C09 · Bid on a brief** ✅
As a creator, I want to place a bid with my price, so that the brand can pick me.
- My Bids screen shows every bid and its state
- Brand sees my real name on the bid, not my internal handle

**US-C10 · Receive a private invitation** ✅
As a creator, I want brands to invite me directly to a private brief, so that I get work without competing on the open board.
- Notification: "You've received a private brief"
- Only I can see it, and only after admin clears it

**US-C11 · Negotiate through action cards** ✅
As a creator, I want structured offer cards in chat (accept / decline / counter-price), so that money talk is explicit and recorded.
- Counter sends "Creator proposed a new price" to the brand; acceptance notifies me
- Declining a booking refunds the brand automatically

**US-C12 · Chat safely inside the deal room** ✅
As a creator, I want in-platform chat with the brand, so that all deal context lives in one place.
- Contact-info (phone/email/handles) auto-filtered from messages and images (OCR)
- Violations escalate: message cleared → warning → policy strike → suspension
- Typing indicators, unread counts, read receipts

### Doing the work

**US-C13 · Receive the brief and start** ✅
As a hired creator, I want a "📋 Brief received — you can start" moment with the full brief, so that expectations are written down before I shoot.
- Brief carries deliverables, must-include / must-avoid, style guidance, usage rights, timeline
- Raw footage is always handed over; an edited cut only when the brand asked for one

**US-C14 · Give my delivery address privately** ✅
As a creator on a shipment deal, I want to confirm my address to the platform only, so that the brand never sees where I live.
- Address stored server-side; brand-facing responses always strip it
- Deal shows "Awaiting shipment" until the brand ships; tracking updates automatically (Delhivery)
- Late shipping by the brand credits me a fee (₹200/day, cap ₹1,000)

**US-C15 · Submit my work** ✅
As a creator, I want to upload my finished video for review, so that approval and payment can begin.
- Video ≤ 100 MB and ≤ 400 s; persisted to Cloudinary or the upload fails with a clear error
- Brand sees a **watermarked preview** until approval — the clean file releases only after payment is committed

**US-C16 · Handle revision requests** ✅
As a creator, I want revision requests with timestamped comments, so that I know exactly what to change.
- Brand gets the number of included revisions set in the brief (default 2)
- Extra revisions cost the brand ₹500 — ₹300 of it comes to me
- "Creator responded to your revision request" keeps the brand informed

### Getting paid

**US-C17 · Get paid on approval — automatically** ✅
As a creator, I want escrow to release when the brand approves (or goes silent), so that finished work always converts to money.
- Approval releases escrow; if the brand does nothing for 5 days, work **auto-approves**
- Payout nets out: platform commission (20%), TDS (unless exempt), any late-delivery penalty
- Payout timing by level: New 12 d → Verified 7 → L1 5 → L2 3 → Elite 2
- Numbered payout receipt generated, naming the brand and campaign

**US-C18 · Understand late-delivery consequences** ✅
As a creator, I want the penalty ladder to be explicit, so that deadlines are fair and predictable.
- Late delivery deducts a % penalty from my payout; half is credited to the brand as goodwill
- Repeat offenses climb a ladder (rolling window) up to a 25% penalty + brief cooldown
- Admin can waive a penalty (medical, brand-caused delay, force majeure) — I'm notified

**US-C19 · Track earnings and withdraw** ✅
As a creator, I want an earnings page and withdrawal requests, so that my balance reaches my bank.
- Earnings list shows who paid, for what, with receipt breakdowns
- Withdrawals require verified KYC; schedule per account (weekly default)

**US-C20 · Level up** ✅
As a creator, I want my level to grow with delivered work, so that I unlock faster payouts and better placement.
- Levels: New → Verified → L1 → L2 → Elite; admin can promote/demote with notification
- "You've been promoted 🎉" / level-change notices

**US-C21 · Collect reviews** ✅
As a creator, I want brand ratings on my profile, so that a good track record wins me the next deal.
- Post-approval, the brand rates me; average + count shown on my directory card

**US-C22 · Stay informed** ✅
As a creator, I want in-app + email notifications with per-category mutes, so that I never miss money or deadlines but control the noise.
- ~45 notification types across payments, deals, shipping, disputes, moderation
- Category-level settings (payout alerts, deal updates, …)

**US-C23 · Raise or answer a dispute** ✅
As a creator, I want a formal dispute channel with evidence, so that a disagreement gets a ruling instead of a stalemate.
- Either side can open a dispute; admin may request more info from me
- Ruling splits money explicitly (favor creator / favor brand / no fault) and lands in the deal room

---

## Brand stories (20)

A brand funds a wallet, finds creators, briefs them precisely, reviews work behind a watermark, and releases payment only when satisfied.

### Getting started

**US-B01 · Sign up and get approved** ✅
As a brand, I want to register my business and pass a quick review, so that creators know briefs here are vetted.
- Brand profile setup; account starts `pending`; directory browsing already works while pending
- Publishing, invitations and payments unlock at approval

**US-B02 · Invite my team** ✅
As a brand owner, I want teammates in my workspace, so that campaigns and the wallet are shared, not personal.
- Email invite with expiring token; member accounts join pre-approved
- All campaigns and wallet money key off the workspace owner — members see the same wallet

**US-B03 · Verify GST (optional)** ✅
As a brand, I want to file my GSTIN for verification, so that my billing records are proper.
- Admin verifies or rejects with notification; **not required** to add funds

### Money in

**US-B04 · Recharge my wallet** 🟡 *Test mode — intentional*
As a brand, I want to add funds via Razorpay, so that I can fund campaigns instantly from a prepaid balance.
- Minimum recharge ₹2,500; bonus tiers (₹10K/₹25K +7%, ₹50K +10%) credited instantly
- Signature-verified + webhook-backed crediting; idempotent (can never double-credit)
- Numbered payment receipt emailed; wallet credits are non-refundable
- **Currently on deliberate test keys** — simulated money until live keys are swapped in

**US-B05 · See every rupee in Transaction History** ✅
As a brand, I want a complete wallet ledger, so that I can reconcile recharges, holds, fees and refunds.
- Rows: Wallet Recharge, Bonus Credit, Budget Reserved, Escrow Lock, Platform Fee, Revision Fee, Budget Refund, Goodwill Credit, Refund
- Abandoned payment popups never appear as credits
- A failed page load says so — it never fakes an empty wallet

**US-B06 · Unlock chat with a funded wallet** ✅
As a platform, we want brand chat gated on a ₹2,500 minimum balance, so that only serious brands message creators.
- Below the bar: chat locked with a clear Add-Funds prompt

### Finding creators

**US-B07 · Browse the creator directory** ✅
As a brand, I want to filter approved creators by niche, language, region, style and budget, so that I shortlist fast.
- Cards show real ratings, portfolio preview, price and delivery time
- Creators who opted out stay hidden; internal handles and emails never exposed

**US-B08 · Book a creator straight from their card** ✅
As a brand, I want to book at the creator's own per-video rate, so that hiring is one flow, not a negotiation.
- Price recomputed server-side from the creator's rate card — the browser can't set it
- Wallet short? Inline top-up sheet without losing the half-filled brief
- Booking holds budget + fee from the wallet into escrow immediately

**US-B09 · Invite a specific creator privately** ✅
As a brand, I want to send a brief to one chosen creator, so that it never becomes public.
- Brief stays private through approval and beyond; only the named creator sees it

### Posting campaigns

**US-B10 · Post a campaign through the 8-section wizard** ✅
As a brand, I want a guided brief (Basics → Deliverables → Must-Include → Must-Avoid → Style → Usage Rights → Timeline & Budget → Review), so that creators receive complete, unambiguous instructions.
- Deliverables: type, quantity 1–5, aspect ratios, duration; **raw footage always included; "Edited file required?" Yes/No**, with "Edited by: Creator / UGC.ad"
- Usage rights: platforms, duration (**minimum 1 month** … perpetual), exclusivity, modification rights
- Timeline: shipping (only for physical products), draft date; **final-delivery date only when an edited cut was requested**
- Pricing nudges (perpetual +40%, whitelisting +30%, paid ads +20%) shown before publish
- Identical field set on web and app — a phone brief carries the same detail

**US-B11 · Know the full cost before publishing** ✅
As a brand, I want the review step to itemize my wallet debit, so that there are no surprise charges.
- Creator payout + platform commission (20%) + one-time listing fee (₹500 / ₹1,500 / ₹3,000 by size) = total debit
- Budget reserved from the wallet at post time and visible as "on hold"

**US-B12 · Save drafts** ✅
As a brand, I want to save a half-finished brief, so that I can resume on any device.
- Draft tab lists drafts with completion %; same list on web and app

**US-B13 · Pass admin review before going live** ✅
As a platform, we want every published brief reviewed, so that creators only ever see legitimate campaigns.
- Publish → `pending_approval`; approve → live; reject → refund of the reservation
- **UGC.ad-scripted briefs don't go live on admin approval** — they park at `awaiting_brand_confirmation` for the brand's sign-off first (US-B21)

**US-B21 · Confirm the UGC.ad script before creators see the brief** ✅
As a brand that ordered a UGC.ad-written script, I want to read and confirm it, so that nothing goes to creators in my name that I haven't approved.
- Admin cannot approve the brief without attaching the script; approval parks it at "Script Ready — Confirm"
- I get a "📝 Your script is ready" notification; the campaign page shows the full script with **Confirm — send to creators** and **Request changes**
- Confirm → brief goes live (private invites deliver now, not earlier); admins are told I confirmed
- Request changes (with my note) → back to the admin queue; the team revises and re-approves
- Creators — including a privately invited one — can never see the brief before my confirmation

### Running the deal

**US-B14 · Review bids and hire — one creator or many** ✅
As a brand, I want to shortlist and select from bidders, so that the best fit gets the deal.
- Multi-creator briefs supported; creators 2…N fund from the original reservation
- Each hire opens its own deal room and escrow row

**US-B15 · Ship the product with a real courier** ✅
As a brand, I want a prepaid Delhivery label from inside the deal, so that shipping the sample takes one form.
- Pickup address auto-registered with the courier; serviceability checked before manifesting
- Real AWB + label PDF; status advances automatically (awaiting pickup → in transit → delivered)
- Creator's address is never revealed to me

**US-B16 · Review work behind a watermark** ✅
As a brand, I want to preview submissions watermarked with download blocked, so that neither side can be cheated.
- Timestamped video comments drive precise revision requests
- 2 included revisions; extras cost ₹500 with an explicit warning before the debit
- Approve → escrow releases to the creator and I get the clean file
- A missing file shows "file unavailable — ask the creator to resubmit", never a black box

**US-B17 · Get goodwill when a creator is late** ✅
As a brand, I want compensation for late delivery, so that slipped deadlines aren't only my problem.
- Half of the creator's late penalty lands in my wallet as a Goodwill Credit, with a notification and ledger row

**US-B18 · Dispute when things go wrong** ✅
As a brand, I want to raise a dispute with evidence, so that an admin rules on the money.
- Rulings: favor brand (refund), favor creator (release), no fault; deal state and both wallets update to match
- Escalation to senior admin when the value exceeds the handler's cap

**US-B19 · Rate the creator** ✅
As a brand, I want to leave a rating after approval, so that the directory stays honest.
- One review per completed deal; feeds the creator's average

**US-B20 · Buy gigs from a catalog** ⛔ *Stub — not built*
As a brand, I want to buy a creator's fixed-price gig directly, so that small jobs skip the brief process.
- Gig listings and admin approval exist; **checkout was never wired** — briefs + wallet are the only money path today

---

## Admin & ops stories (14)

Ops keeps the marketplace honest: vetting both sides, gating campaigns, ruling disputes, and holding the platform's money levers.

**US-A01 · Vet every applicant** ✅
As an admin, I want approve / reject / request-more-info on creator and brand applications, so that only real people and businesses trade here.
- Queues with full profiles incl. mobile numbers; decisions notify the applicant

**US-A02 · Gate campaigns before creators see them** ✅
As an admin, I want a campaign approval queue with the full structured brief, so that bad briefs never reach creators.
- Approve → live; reject → brand's reservation refunded automatically

**US-A03 · Review KYC** ✅
As an admin, I want a KYC queue with documents, so that withdrawals only reach verified identities.

**US-A04 · Run the shipping queue** ✅
As ops, I want the request-shipment queue with both addresses, label upload and mark-shipped, so that samples move even when the brand didn't self-serve a label.

**US-A05 · Rule disputes within my authority** ✅
As an admin, I want dispute rulings with explicit money splits and value caps per role, so that big-money calls escalate to seniors.
- Reserve covers any escrow gap (logged); outcome posted into the deal room
- Deadline extensions instead of a ruling when appropriate

**US-A06 · Configure payments** ✅
As an admin, I want gateway keys managed in the panel, so that switching Razorpay accounts needs no deploy.
- Key ID/secret per gateway, enable/disable, default selection; takes effect on the next payment

**US-A07 · Own the platform's money levers** ✅
As an admin, I want commission, listing fees, revision price, payout delays, bonus tiers and feature flags in Settings, so that pricing changes are policy, not code.
- Commission currently 20% platform-wide (both sides of a deal recorded as revenue)

**US-A08 · Manage creator levels & payouts** ✅
As an admin, I want to promote/demote levels, set payout schedules and convert accounts to Pro, so that creator quality maps to privileges.

**US-A09 · Enforce and forgive penalties** ✅
As an admin, I want the late-offense ladder visible and waivable, plus brand-side penalties, so that enforcement is consistent but humane.
- Brand penalties: late-ship fee ₹200/day (cap ₹1,000), poaching ₹25,000, low-rating restrictions

**US-A10 · Oversee chat** ✅
As an admin, I want visibility into chat violations with strike/suspend/lift controls, so that off-platform poaching dies quietly.
- False-positive marking; "Message from the UGCad team" for direct outreach
- Support can post into deal rooms; both parties notified

**US-A11 · Watch the money** ✅
As an admin, I want payment transactions, escrow states and platform revenue in one place, so that finance questions have answers.

**US-A12 · Fix wallets when reality demands it** ✅
As an admin, I want manual wallet adjustments and escrow refunds, so that support cases end with correct balances.
- Every adjustment notifies the user and lands in the audit log

**US-A13 · Audit everything** ✅
As an admin, I want an append-only audit log of admin actions with before/after, so that accountability survives staff turnover.

**US-A14 · Act as a brand when support needs to** ✅
As support, I want short-lived delegated access to a brand account, so that I can reproduce and fix their issue.
- 2-hour token stamped with the admin's identity; delegated actions are attributable

**US-A15 · Run the Editing Queue for "Edited by UGC.ad" deliverables** ✅
As UGC.ad's editing team, I want raw creator footage to land in a dedicated queue, so that we cut the final version before the brand ever reviews.
- Creator submission on such a deal parks at `awaiting_edit` — the brand can't approve/reject it and the 5-day auto-approval clock does NOT run
- Admin → Editing Queue lists each job with campaign, brand, creator, raw files and the creator's note
- Uploading the edited cut hands the submission to the brand (watermarked), restarts the review clock, and notifies brand + creator
- Every completion is stamped into the audit log

---

*Generated from the live codebase (backend `server.py`, web `Frontend`, Android `ugcapp`) on 29 Sep 2026.*
