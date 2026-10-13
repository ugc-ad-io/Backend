# fix.md implementation audit — 13 October 2026

The numbered items and the final unnumbered editing-rate request are covered across Backend, Frontend, and ugcapp. Existing fixes on main were retained; this pass closes remaining gaps.

| Item | Implementation |
| --- | --- |
| 1 | Website and native revision composers warn before the second request; backend counters span resubmissions and charge ₹500 from request three. |
| 2 | Paid revisions accrue ₹300 on that creator's escrow and include it in the final wallet credit. Regression verifies no duplicate credit and no payment to the other creator. |
| 3 | Both product-receipt routes notify and email the brand. |
| 4 | Raw approval advances to edited submission without releasing escrow. Legacy raw records without an asset index now advance correctly too. |
| 5 | Email, Google, and Apple signup send welcome messages. Reading notifications replaces the known legacy `cdsnig` placeholder with welcome copy, without changing genuine admin announcements or other users' records. |
| 6 | Product visibility has explicit Yes and No choices in both brief forms. |
| 7 | Raw-only briefs show one content delivery date; creator-edited briefs show raw and edited dates. |
| 8 | Lead generation is included in objectives on website and app. |
| 9 | Submission, review state, escrow, approval and payout are scoped to the creator. Tests verify one creator cannot receive another creator's payment. |
| 10 | Creator activity and timeline entries are scoped to that creator's deal; shared campaign notices remain visible to all hired creators. |
| 11 | Amazon listing video is included as a deliverable on website and app. |
| 12 | Private website invitations now open the same full brief wizard, without logo placement, and submit for admin approval. Native private briefs already use the full wizard and approval flow. |
| 13 | Budget is per video; quantities, creator count, editing, 20% commission and the one-time listing fee appear in totals. ₹5,000 × 3 videos + ₹3,000 commission + ₹1,500 listing = ₹19,500. |
| 14 | Row quantities count as separate videos. ₹2,000 × 2 videos + ₹800 commission + ₹1,500 listing = ₹6,300. |
| Editing rates | Creator onboarding and profile editing on both clients collect raw and additional editing payouts separately. Briefs add editing only for assets edited by the creator; private briefs use the creator's saved rates. Backend split bids are retained. |

Backend price normalization now keeps `budget_max` at the per-video amount rather than substituting `total_budget`; per-video-only records also calculate correctly.

Verification uses an in-memory MongoDB, with outbound email disabled. App TypeScript and focused native tests pass. Website tests and production build pass; the build has an existing missing MediaPipe source-map warning. These checks do not constitute an on-device Android/iOS release or a live-production data audit. Existing production payouts are not retrospectively recalculated.
