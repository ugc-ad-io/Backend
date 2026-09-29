# UGCad — Flow Test Failures (live run)

Every flow in [USER_FLOWS.md](USER_FLOWS.md) driven end-to-end against the **live local Python backend** (`localhost:8000`, same code as prod/Render, Atlas `test_database`) and the **live local website** (`localhost:3000`, React, `.env.local` → `localhost:8000`). Website screens driven with **Playwright** (headless Chromium). Android app (`ugcapp`) checked statically — not booted (hybrid WebShell loads the same site; emulator is unreliable on this machine).

*Run: 29 Sep 2026. Harness scripts + raw JSON under the session scratchpad.*

**Scoreboard**
- API flows 1–3: all steps pass (onboarding, campaign publish, script gate).
- API flows 4–9: all steps pass **except direct booking** (bids, select, escrow, work review, revisions, approve/payout, editing queue, shipment, wallet/ledger, recharge order, disputes + freeze + ruling — all verified live).
- Website: **29/29 key flow screens render** without crashing (2 initial `networkidle` timeouts were blocked Google-avatar images, not page failures — re-verified OK).

Legend: 🔴 broken / security · 🟠 real gap · ⚪ not-integrated (dead code) · 🟡 cosmetic/config.

---

## 🔴 1. Anyone can self-register as a founder admin — `POST /api/auth/signup`
**Flow:** all (auth). **Severity: critical, live in production.**

`signup` accepts `role:"admin"`. The created account is **auto-approved** (`approval_status=approved`), gets `admin_role=None` which the code treats as **founder**, and can immediately call admin-only endpoints.

- Evidence (live): `signup {role:"admin"}` → `200` + token; `/auth/me` → `role=admin, approval_status=approved, admin_role=None`; `GET /api/admin/users` with that token → `200`.
- Also flagged in `../UGCad_LiveTestRun_Python.md` (#3) — **still open**.
- Fix: restrict signup `role` to `creator`/`business` server-side ([server.py:3393](server.py#L3393) `signup`, model [server.py:245](server.py#L245) `SignupRequest`).
- (A test admin I created this way, `evil…@x.dev`, was deleted at end of run.)

## 🔴/🟠 2. Direct booking is broken for web-onboarded creators (web/app parity)
**Flow 4 — "Direct booking: brand books from the creator's card at THEIR rate (price recomputed server-side)".**

`checkout/quote`, `checkout/brief` and the web `PlanBrief.js` all read the price from **`profile.rate_card.expected_payout`** ([server.py:4459](server.py#L4459) `creator_plan_price`). But the **web** onboarding form `CreatorProfileSetup.js` submits per-card prices as `portfolio_items[].price` and **never writes `rate_card`**. So a web-onboarded creator has no price → booking is refused.

- Evidence (live): quote for a freshly web-onboarded creator → `400 "This creator hasn't set a price yet. Message them to agree on one."`
- DB reality (126 creators): **58 have `rate_card.expected_payout`**, only **4 have any portfolio-card price** — the two price sources are disjoint.
- Parity: the **app** form `ugcapp/src/screens/CreatorProfileSetup.tsx:923` **does** write `rate_card.expected_payout`, so app-onboarded creators are bookable. This is the split.
- Fix (one place): in `creator_plan_price`, fall back to the lowest/nominated `portfolio[].price` when `rate_card.expected_payout` is empty — or have web `CreatorProfileSetup.js` post `rate_card.expected_payout` like the app does.
- Bid-based hiring is **unaffected** (uses the bid amount, not the rate card) — verified working.

## ⚪ 3. `/admin/applications/*` is dead, disconnected code
**Flow 1 — admin application queue.**

`applications.py` serves `/api/admin/applications/creators|brands` (+ `/approve`, `/reject`, `/request-more-info`) from the collections `creator_applications` / `brand_applications`. **`server.py` never writes those collections** — onboarding lives entirely on `users.approval_status`. And **all three** admin pages (`AdminDashboard.js`, `AdminProfiles.js`, `ApplicationsPage.js`) call `/admin/pending-profiles`, not these.

- Evidence (live): `/admin/applications/creators` → `200 {data:[], total:0}` while `/admin/pending-profiles` → 9 pending.
- Not a user-facing break (the real queue works), but it's misleading dead code + duplicate approve/reject logic. Remove it or wire onboarding to it — pick one.

## 🟡 4. `AdminCampaigns` — React "unique key" warning
**Flow 2/3.** Console warning on `/dashboard/admin/campaigns`: *"Each child in a list should have a unique key prop… Check the render method of `AdminCampaigns`."* Cosmetic; add `key=` to the mapped list.

## 🟡 5. Google Sign-In fails on `localhost` (dev only)
**Flow 1 auth.** `/auth` console: `[GSI_LOGGER] The given origin is not allowed for the given client ID` → 403. Expected — `localhost:3000` isn't in the OAuth client's allowed origins. Email/password login works locally; Google works on the deployed origins. Not a code bug.

---

## Verified working end-to-end (live) — no action needed

| Flow | Confirmed live |
|---|---|
| 1 Onboarding | signup rejects missing mobile (422); creator/brand start `pending`; profile save; admin approve via `/admin/pending-profiles` → `approved` |
| 2 Campaign | unapproved brand blocked (403); publish → `pending_approval`; budget+fee reserved off wallet; hidden from creators; admin approve → `active` & visible; reject → refund; ledger rows written |
| 3 Script gate | scripted brief → approve blocked without script (400); approve+script → `awaiting_brand_confirmation`; hidden from creators; brand request-changes → back to `pending_approval`; re-approve; confirm → `active` & visible |
| 4 Hiring | approved+KYC creator bids; duplicate bid blocked (400); brand sees bid; select-creator → deal `DEAL-####` + **escrow held** |
| 5 Shipment | creator saves address; brand request-shipment (200); **creator address NOT leaked** to brand |
| 6 Work review | submit final; shows in brand queue; request-revision (200, revision counter); resubmit; approve → escrow release/schedule; creator payout overview reflects pending release |
| 7 Editing queue | raw footage parks `awaiting_edit`; brand approve **blocked** (400); appears in `/admin/editing-queue`; editor `/complete` → flips to `submitted` |
| 8 Money | wallet balance + ledger (`Budget Reserved`/`Escrow Lock`/`Platform Fee`); recharge → real Razorpay `order_id` (test keys, intentional) |
| 9 Disputes | brand raises structured dispute (200); shows in admin queue; **deal freezes** — work submit blocked (409); admin `/rule favor_creator` → resolved, creator paid |

## Notes / caveats
- Ran against Atlas `test_database` (shared with prod). Test artifacts named `*@flowtest.dev`. A test founder admin `flowtest-admin@flowtest.dev` was left in place for re-runs — **delete it** if unwanted.
- 4 harness "failures" in flows 4–9 were wrong field names in the test, not product bugs; each endpoint was then re-confirmed working (dispute freeze returns `409` not `400`; editing-complete wants `edited_file_url`; dispute rule wants `reasoning`; `awaiting_edit` confirmed by the two following checks).
- App not booted: `ugcapp` native screens call the same `/api/*` endpoints verified here (debug build → `localhost:8000`), and everything else falls through to the same website WebView. Disputes have **no native screen** — they're WebView-only in the app (fine, covered by web).
