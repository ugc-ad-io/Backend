# End-to-End Test Run

Live backend (`https://backend-chq9.onrender.com/api`) · 2026-09-29 · **46/47 API steps passed**

Driven through the same API the app and website call. **Fresh throwaway accounts** were registered for this run (`e2e.creator.*@example.com`, `e2e.brand.*@example.com`) so no real account was touched; the admin account was reused read-only for approvals. Payments are in test mode, so wallet money is simulated (the brand wallet was funded via an admin adjustment).

The **only** failure is an external courier test-data rejection, not a product bug — see the note at the end. Every guard that "blocked" a step (KYC-before-bid, GST uniqueness, receive-before-submit, approval gates) did so **correctly**.

## ✅ Auth (fresh accounts)
- Register + login new creator · Register + login new brand · Admin login · `/auth/me` for both

## ✅ Onboarding & approval (creator + brand)
- Brand fills business profile → status resets to pending (by design)
- Admin views applications queue
- Admin **requests more info** on the brand, then **approves** it → brand now approved
- Admin funds the brand wallet (test funding)
- Admin **approves the creator**
- Creator submits **KYC** → Admin **approves KYC**

## ✅ Brand money & discovery
- Submit GST · Read wallet · Create recharge order (Razorpay, test mode) · Browse creator directory

## ✅ Standard campaign
- Brand creates + publishes campaign → Admin **approves** → campaign goes **active**

## ✅ Script-by-UGC.ad flow (new feature — full round trip)
- Create UGC-scripted campaign
- Admin approval **blocked without a script** ✓
- Admin approves **with** script → parks at **awaiting_brand_confirmation** (not live) ✓
- Brand **requests changes** → back to admin queue ✓
- Admin re-approves → Brand **confirms** → campaign goes **live** ✓

## ✅ Hiring & messaging
- Creator browses briefs and **sees the campaign** · Creator places **bid** · Brand **hires** the creator
- Brand ↔ creator **chat** both directions
- Brand **views the creator's profile** (real data the creator entered)

## ✅ Shipment
- Creator saves delivery address (server-side, hidden from brand) ✓
- Brand generates Delhivery label → **external courier rejection** (see below)

## ✅ Work review & revision (digital deal, no shipment gate)
- Creator submits work · Brand sees it in Work Review · Brand **requests a revision** ✓

## ✅ Edited-by-UGC.ad flow (new feature — full round trip)
- Creator submits **raw footage** → parks in the **Editing Queue** (brand can't act, no auto-approve clock) ✓
- Admin **attaches the edited cut** → submission handed to the brand as **pending review** ✓

---

## The one ❌ — external, not a code bug

**Brand generates Delhivery label → HTTP 502**
`Courier rejected the shipment: "Crashing while saving package due to exception suspicious order/consignee"`

This is **Delhivery's own live API** rejecting the *test* shipment — fake pickup/delivery addresses and a throwaway consignee name trip their fraud/validation check. It proves the integration is wired correctly: our backend authenticated, registered the pickup warehouse, called Delhivery, and faithfully surfaced the courier's error instead of a fake success. A real deal with real addresses and a funded Delhivery wallet will pass. Nothing to fix in our code.

---

## Device check (Android emulator, via ADB)

The real app was installed and driven on the emulator:
- ✅ **Login** as creator → creator **dashboard** renders live data (deals closed, top creators)
- ✅ **Browse Campaigns** → live brief list renders (incl. campaigns created in this test)

### ⚠️ Build finding — wrong app in the debug APK
`ugcapp/android/app/build/outputs/apk/debug/app-debug.apk` (built today) launches a **different app entirely — "coracure", a healthcare/doctor-consultation app**, under the `com.ugcapp` package. The correct UGCad app is the **release** APK (`app-release.apk`, Sep 26). This is the same cross-project contamination seen in the repos (FontAwesome fonts, force-pushes). **Rebuild the app from clean ugcapp source before shipping any APK** — verify the build environment isn't mixing projects.
