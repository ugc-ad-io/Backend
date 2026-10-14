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

## Updated saved request list

The saved update supplied after the earlier audit is a separate set of requests. The rows below map its wording to implementation; the earlier section records the work already pushed.

| Saved request | Implementation |
| --- | --- |
| Remove em dashes across creator, brand and admin | Removed em dashes from website/native UI literals and backend-generated messages. User-authored messages and source comments are preserved. |
| Dashboard pending shipment, KYC and GST | Added authoritative pending counts and links to each review queue alongside profile/campaign approvals. Dispatched shipments are excluded from the pending count. |
| Back buttons on admin queue pages | Shared admin layout returns to the dashboard; legacy admin tabs also have a back control. KYC rejection has a Back control. |
| Horizontal scrolling on long admin pages | A fixed, keyboard-accessible range and left/right buttons control the visible overflowing table. It stays reachable when the table bottom is offscreen. |
| Same scrolling access for brand creator filters | The same control finds the overflowing category/filter rail on the creator directory. |
| KYC card alignment on laptops | Cards fill the available content width; grid columns can shrink, documents wrap, and the compact layout activates earlier. |
| Full profile and preview show all uploaded videos | Directory, profile and own-account responses share a normalized, deduplicated portfolio. Rich `portfolio_items`, legacy top-level/nested portfolios and intro-only records are supported. Video URLs are preferred over cover-image URLs, and metadata is retained. |
| Notify both parties to add delivery details after selection | Physical-product deals notify and email both creator and brand once per deal. The brand link opens that creator's deal room; the creator link opens their campaign deal. Digital deals do not request shipping addresses. |
| Auth logo top-left and responsive card | Website logo stays top-left; phone forms keep the correct grid placement and disable the desktop slide transition. Native auth has a top-left wordmark and retains its responsive scroll/keyboard layout. |
| Submission button returns to auth instead of reopening the form | Website confirmation signs out and opens auth. Native confirmation returns to sign-in when a logout callback exists; the looping fallback button is removed. The app's existing WebView completion flow continues to detect submitted profiles. |
| Signup upload automatically adds the first video, then Add More | Both forms add a described upload automatically after input settles, without an Add to Profile step. Add More exposes another upload. A submit before the website debounce finishes still includes the described draft. |
| Verified KYC should lead to profile settings when bidding | Website and native bid entry point to profile settings for incomplete profiles; KYC navigation is reserved for unverified creators. Website auth data refreshes with the update cursor so KYC status does not remain stale. |
| New-account portfolio should appear on full profile | Shared portfolio normalization fixes nested-only uploads and preserves every clip on directory and profile reads. |
| Automatic refresh throughout website | Mounted data effects subscribe to the backend mutation cursor, checked every 15 seconds and on focus. Native screens retain the existing cursor subscription. Refresh clears cached reads and does not remount the page; focused inputs and dirty forms defer it. Auth caches are isolated by token. |
| One bid for raw plus edited files | Both clients show a single combined per-video quote and explain that it includes raw and edited files. Quantities multiply that quote. Editing-inclusive budget ceilings match the server; legacy split-bid API requests remain compatible. |
| Explain work auto-approval timing | Default is five days from the current submission, configurable in admin settings. Disputes pause approval. A required raw stage advances to editing rather than prematurely paying the deal. |
| Digital product option in private brief | Private invitations use the shared full brief form. Digital/App and Service selections set shipment flags false and hide shipping requirements. |
| Supplied screenshot fixes | Collapsed rail reserves its full 76px width, creator grids shrink to their available width, quick previews are portaled above navigation and constrained to the viewport, and the full-profile compact header respects the sidebar offset. |

Validation includes backend regression tests, the native TypeScript check and test suite, website unit tests and a production build. Headless browser checks with mocked data cover laptop/phone auth, preview/full-profile portfolio counts, cursor refresh, dashboard queues and laptop KYC fit. The native Jest suite uses `--forceExit` because existing test fixtures retain asynchronous handles after assertions finish. Browser screenshots are local validation artifacts, not production captures.
