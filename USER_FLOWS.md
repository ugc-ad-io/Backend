# UGCad User Flows

End-to-end journey maps for the UGCad platform — shared by the website and the Android app. Companion to [USER_STORIES.md](USER_STORIES.md). Every step below is implemented and live unless marked otherwise.

*As of 29 Sep 2026.*

---

## Flow 1 · Creator onboarding

```
Sign up (email + compulsory mobile, or Google)
  → Profile setup: photo · name · content styles · categories
    · Instagram (only social, required) · portfolio video cards (3–5, each with
      price / delivery days / category) · languages + fluency
  → Submit application                          [status: pending]
  → "Profile Under Review" gate (24–48 h)
      ├── Admin approves        → full dashboard + visible in brand directory
      ├── Admin asks for info   → creator edits + resubmits
      └── Admin rejects         → rejection gate (history kept on reapply)
  → (abandoned mid-form? one reminder email at 24 h)
```

## Flow 2 · Brand posts a campaign (standard — no UGC.ad services)

```
Brand (approved, wallet funded) → Post a Campaign wizard (8 sections A–H)
  → Publish: budget + 20% commission + listing fee reserved from wallet
                                                [status: pending_approval]
  → Admin reviews the full structured brief
      ├── Approve → LIVE — creators see it      [status: active]
      └── Reject  → reservation refunded        [status: rejected]
```

## Flow 3 · Campaign with "Script by UGC.ad" — the brand-confirmation gate

```
Brand picks "Script written by: UGC.ad" in the wizard → Publish
                                                [status: pending_approval]
  → Admin queue flags: "needs a script from UGC.ad (required before approve)"
  → Admin WRITES THE SCRIPT into the approval form
      (approving without it is blocked by the backend)
  → Approve → parks, NOT live                   [status: awaiting_brand_confirmation]
  → Brand notified: "📝 Your script is ready — review and confirm"
  → Brand opens the campaign page → reads the full script
      ├── Confirm — send to creators → LIVE     [status: active]
      │     (private invitation delivers ONLY now; admins notified)
      └── Request changes (+note)   → back to admin queue
            → team revises the script → approve again → brand re-confirms
  ⚠ No creator — not even a privately invited one — can see the brief
    before the brand's confirmation.
```

## Flow 4 · Hiring: bids, direct booking, private invites

```
LIVE brief
  ├── Public: creators browse/save → bid → brand shortlists → selects
  │     (multi-creator briefs: each hire funds from the original reservation)
  ├── Direct booking: brand books from the creator's card at THEIR rate
  │     (price recomputed server-side; short wallet → inline top-up)
  └── Private invitation: one named creator receives it after approval
  → Selection → deal room opens (chat + action cards) → escrow holds the payout
  → Creator accepts (or declines → automatic refund; or counters price)
```

## Flow 5 · Product shipment (physical products only)

```
Creator confirms delivery address (server-side only — brand never sees it)
Brand → "Ship Product" form → Delhivery:
  pickup auto-registered → pincode serviceability check → real AWB + label PDF
  → status auto-advances: awaiting_pickup → in_transit → delivered
  → creator confirms receipt → content clock starts
(Brand ships late → ₹200/day fee, cap ₹1,000, credited to the creator)
```

## Flow 6 · Work submission & review (standard — creator edits their own video)

```
Creator uploads final video (≤100 MB / ≤400 s, Cloudinary)
                                                [work: submitted]
  → Brand reviews WATERMARKED preview (download blocked)
      ├── Approve → escrow releases; payout scheduled by creator level
      │             (New 12d … Elite 2d, minus 20% commission, TDS, penalties);
      │             clean file unlocks for the brand; brand rates the creator
      ├── Request revision (timestamped comments)
      │     · first 2 free, then ₹500 each (₹300 creator / ₹200 platform)
      │     · creator responds → resubmits → back to review
      └── Do nothing 5 days → AUTO-APPROVED, creator paid
(Creator late vs deadline → % penalty off payout; half credited to brand as "Late Fee Credit")
```

## Flow 7 · Work submission with "Edited by UGC.ad" — the editing queue

```
Creator uploads RAW footage                     [work: awaiting_edit]
  → Brand notified: "editing in progress — you'll review once it's ready"
      (brand CANNOT approve/reject yet; auto-approval clock NOT running)
  → Admin → Editing Queue: campaign, brand, creator, raw files, creator's note
  → UGC.ad editor uploads the edited cut (+optional note, audit-logged)
  → Submission flips to the brand               [work: submitted, clock restarts]
  → Brand + creator notified → normal review from Flow 6 (watermark, revisions,
    approve → payout)
```

## Flow 8 · Money (brand side)

```
Recharge (Razorpay, min ₹2,500, bonus tiers +7–10%)   [🟡 test keys — intentional]
  → wallet balance (workspace-shared; ₹2,500 unlocks chat)
  → posting reserves budget+fees ("Budget Reserved" ledger rows)
  → hire moves it to escrow → approval releases to creator
  → refunds on decline/reject/dispute; goodwill "Late Fee Credit" on late delivery
Every movement = a Transaction History row; every recharge = an emailed receipt.
```

## Flow 9 · Disputes

```
Either side raises (evidence attached) → other side notified → deal actions freeze
  → Admin reviews (may request more info; value caps escalate to senior admin)
  → Ruling: favor brand (refund) / favor creator (release) / no fault / extend deadline
  → Wallets + deal state updated; outcome posted in the deal room
```

## Status glossary

| Entity | Status | Meaning |
|---|---|---|
| Campaign | `draft` | Saved, unfinished, visible only to the brand |
| Campaign | `pending_approval` | Waiting on admin (script gets written here if UGC.ad-scripted) |
| Campaign | `awaiting_brand_confirmation` | Script attached; waiting on the brand's sign-off — invisible to creators |
| Campaign | `active` | Live for creators |
| Campaign | `in_progress` / `work_submitted` / `completed` | Deal running / content in / paid out |
| Work | `awaiting_edit` | Raw footage with UGC.ad's editors; brand actions blocked; no auto-approve clock |
| Work | `submitted` | With the brand; 5-day auto-approval clock running |
| Work | `revision_requested` / `approved` | Feedback round / escrow released |
