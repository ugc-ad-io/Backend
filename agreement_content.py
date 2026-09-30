"""Single source of truth for the Creator & Brand Agreement.

Served by GET /api/agreement so the website and the app render the SAME text and
version, and acceptance (POST /api/agreement/accept) is stored on the user — so
agreeing on one surface satisfies the other. Bump AGREEMENT_VERSION whenever the
text changes to re-prompt every user.
"""

AGREEMENT_VERSION = "2026-09-28"
AGREEMENT_TITLE = "UGCad.io Creator & Brand Agreement"
AGREEMENT_LAST_UPDATED = "28 September 2026"

# The opening paragraph(s) shown as the preview before "View all".
AGREEMENT_INTRO = (
    "Platform: ugcad.io (Web & App) | Last Updated: 28 September 2026\n\n"
    "Between Crawl Digitally (\"Company\"), registered office at 303 Sanrachna "
    "Avenue, Satya Sai Square, Dewas Naka Road, Indore, MP 452010, and every "
    "registered Creator and Brand (\"User(s)\"). Applies uniformly to all Users; "
    "accepted electronically on onboarding/wallet funding. Read with the Terms & "
    "Conditions and Privacy Policy, incorporated by reference."
)

# Each section: {"n": label, "heading": ..., "body": ...}. Clients show the intro
# plus the first `PREVIEW_SECTIONS` sections, then reveal the rest on "View all".
PREVIEW_SECTIONS = 2

AGREEMENT_SECTIONS = [
    {"n": "1", "heading": "Role of the Company",
     "body": "Runs the marketplace; facilitates deals, wallet/escrow, masked shipping, disputes. Not a party to the Creator–Brand relationship. No guaranteed invitations, deals, or earnings."},
    {"n": "2", "heading": "Eligibility & Onboarding",
     "body": "Creators: Application + KYC (ID, address, bank/UPI) → admin review (~3 business days; no auto-approval). Anonymous handle post-approval. Must be 18+; KYC name must match payout name. Rejected applicants may reapply after 90 days.\n\nBrands: Business details + GST self-verification. Manual review of legitimacy and category eligibility."},
    {"n": "3", "heading": "Creator Anonymity",
     "body": "Real identity (name, contact, address) kept separate from Brand-facing profile (handle, samples, portfolio only); address used only for masked shipping.\n\nSelf-disclosure by Creator forfeits protection for that relationship. Company not liable for external discovery it didn't cause."},
    {"n": "3A", "heading": "Identity Leak Protection",
     "body": "A — Platform fault (bug/error exposes identity): ₹10,000+ compensation, fix.\nB — Self-disclosure (Creator shares own identity): No protection.\nC — Brand discovery (found externally, not acted on): No penalty.\nD — Willful breach (Brand contacts off-platform using leaked info): ₹25,000 + suspension/ban + legal action.\n\nReport via in-app form; investigated within 48 hours."},
    {"n": "4", "heading": "Restricted/Prohibited Categories (Brands)",
     "body": "Prohibited: tobacco, gambling, adult content, unregulated financial products/crypto, medical weight-loss claims, political and religious content. Case-by-case: alcohol, dating services."},
    {"n": "5", "heading": "Deal Formation",
     "body": "No open bid-board. Creators get work via: private Brand invitation (72-hr response window), ops-mediated shortlist (3–5 Creators), or Creator-initiated Custom Offer (price floor, 48-hr expiry, 5/day cap). Deal = binding once Brief/Offer accepted; scope/deadline/price changes need written Platform agreement. Accepting = representation of availability."},
    {"n": "5A", "heading": "Content Production — Scripting, Filming, Editing",
     "body": "Base deliverable = raw, unedited video.\nScripting: Brand's own script, or Company writes one for a disclosed add-on fee.\nEditing (Brand's choice): by Creator (separate paid slot, own fee/deadline/revisions) or by Company (add-on fee). Neither chosen = raw video is final deliverable.\nMulti-slot deals: each slot approved/paid individually unless Brief states a combined payout."},
    {"n": "6", "heading": "Content Ownership & Usage Rights",
     "body": "Creator retains ownership; Brand gets a license only per the Brief (platforms, duration 1 month–perpetual, exclusivity 0/15/30/60/90 days, whitelisting, modification rights). Overuse = unauthorized, penalized, disputable. Ambiguity resolves toward narrower use. Drafts shown watermarked until approval. No exclusivity = Creator free to work with competitors."},
    {"n": "7", "heading": "Location, Setting & Third Parties",
     "body": "Location requirements must be in the Brief to be binding. Brief-stated violations = compliance reshoot (not a free revision); undisclosed after-the-fact objections = disputable scope creep. Creator confirms consent/availability of any third party appearing in content."},
    {"n": "8", "heading": "Fees, Commission & Revisions",
     "body": "Commission: 20% of Deal value, charged to each side — Brand pays Deal value +20%; Creator receives Deal value −20% (before TDS). Example: ₹1,000 Deal → Brand pays ₹1,200; Creator gets ₹800 (~₹720 net after ~10% TDS).\n\n2 free revisions/deliverable; extra rounds ₹500 (Creator gets ₹300). Each multi-slot deliverable gets its own revision allowance.\n\nScope creep = Brand must withdraw or pay if disputed in Creator's favor. Subjective creative dislikes aren't valid grounds to withhold approval. 5+ revisions triggers Company intervention.\n\nAdd-on fees (Company scripting/editing): disclosed upfront, payable by Brand, not shared with Creator. [Turnaround, revisions, and ownership to be finalized.]"},
    {"n": "9", "heading": "Wallet, Escrow & Payment",
     "body": "Brand Wallet: min ₹5,000, non-refundable (except admin-approved refund), never expires.\nOn acceptance: Deal value + commission + add-on fees debited to Escrow.\nBrand review window: 5 days (deemed approval if silent); final except pre-release dispute.\nCreator payout: within 12 days (~17 days total), auto UPI/bank transfer, TDS certificates issued.\nEach Deal's Escrow is independent of others.\n⚠️ Wallet/Escrow may qualify as an RBI-regulated PPI; not yet confirmed by fintech counsel."},
    {"n": "10", "heading": "Products — Shipping, Disposition, Returns, Damage",
     "body": "Brand ships via masked-shipping by agreed date; 5+ days late = disputable; late fee ₹200/day (max ₹1,000).\nBrand warrants product safety/compliance and discloses risks/allergens.\nBrief must state gift vs. loaner; Creator can't unilaterally keep a loaner (=breach).\nCreator liable for loaner damage/loss beyond reasonable wear — except courier-fault or pre-existing damage.\nDamage/wrong-item report window: 48 hrs from delivery (description + 2 photos + unboxing video); confirmed claims → Brand reships/refunds. False claims penalized.\nLost/misdelivered = courier's fault, no Creator penalty. No confirmation after 7 days of \"Delivered\" = auto \"Received.\""},
    {"n": "11", "heading": "Product Liability & Health/Safety",
     "body": "Brand solely liable for product safety/injury (except Creator's own negligence/non-disclosure); Creator discloses known allergies. Brand indemnifies Creator and Company."},
    {"n": "12", "heading": "Creator Cancellation After Product Delivery",
     "body": "Treated as failure to deliver: Creator forfeits payment; Deal value refunded to Brand (commission retained by Company, not refunded); Creator must make product available for return within 5 days."},
    {"n": "13", "heading": "Late Delivery Penalties & Brand Cancellation",
     "body": "Late = 1–24 hrs; Severely late = 24–72 hrs; Failed = 72+ hrs. Rolling 6-month escalation:\n1st late: Warning + 5% penalty.\n2nd late: 10% penalty + 60-day level-pause.\n3rd late: 15% penalty + 90-day probation.\n4th late/1st severe: 25% penalty + 14-day cooldown.\n5th late/failure: 100% forfeit + review + possible ban.\nPenalty split 50% Brand wallet / 50% Company. Non-delivery = Deal value refunded to Brand; commission retained by Company.\nBrand may cancel pre-work (subject to listing-fee rules); post-delivery cancellation = dispute process.\nBrand penalties: chronic <3.5 rating = restricted posting; confirmed product fraud = warning/probation/suspension."},
    {"n": "14", "heading": "Listing Fees (Brands)",
     "body": "1 deliverable: ₹500. 2–5 deliverables: ₹1,500. Multi-creator (2–10): ₹1,500. Large multi-creator (11+): ₹3,000.\nRefunded as wallet credit on successful completion; forfeited if Brand cancels early, no Creator accepts within 14 days, or Brand's fault confirmed in dispute. Multi-creator: each Creator = separate Deal/Escrow; one Creator's failure doesn't affect others."},
    {"n": "15", "heading": "Illness/Emergency Notification",
     "body": "No penalty for documented medical emergencies, platform outages, or Brand-caused delays, if notified before deadline. Late notification generally doesn't qualify."},
    {"n": "16", "heading": "Dispute Resolution",
     "body": "Creators can dispute: late shipping (5+ days), damaged product, scope creep, non-review, abuse. Brands can dispute: late/non-delivery, Brief mismatch, unresponsiveness, unprofessional conduct.\nCannot dispute after payment release. Raised via Deal Room with description, desired outcome, evidence; Escrow holds during review.\nSLA: Critical (leak/fraud) 4hr/24hr; High 24hr/3 business days; Medium 24hr/5 business days; Low 48hr/7 business days.\nOutcomes: full/partial refund, extension, reassignment, split, or no-fault (50/50). Appeal within 7 days with new evidence; second ruling final on-platform. Only Platform records count as evidence."},
    {"n": "17", "heading": "Anti-Poaching / Non-Circumvention",
     "body": "12-month ban on off-platform engagement after a Platform introduction. Violation = ₹25,000 + 90-day suspension + possible ban + legal action. Contact-info sharing auto-blocked; three-strike system: warning → chat pause → action-cards-only (14 days) → possible suspension."},
    {"n": "18", "heading": "Conduct Standards & Confidentiality",
     "body": "Content must be original, lawful, non-defamatory, ASCI-compliant; minors require guardian consent. Non-public Brief info confidential for 12 months. Creators may refuse unlawful/unsafe requests without penalty if promptly flagged."},
    {"n": "19", "heading": "Independent Contractor Status",
     "body": "Creators are independent contractors; no employment/partnership/agency relationship created."},
    {"n": "20", "heading": "Representations & Warranties",
     "body": "Creators warrant accurate KYC, legal capacity, lawful/non-infringing content. Brands warrant authorized signatory, accurate GSTIN/business info, lawful campaigns."},
    {"n": "21", "heading": "Disclaimers",
     "body": "Platform provided \"as is\"; no guaranteed volume/earnings; not liable for third-party (payment/courier/verification) failures."},
    {"n": "22", "heading": "Indemnification",
     "body": "Creators indemnify Company for their own breaches/content/product use/disputes. Brands indemnify Company for their breaches/campaigns/products/disputes, plus product-liability indemnity to Creators (Section 11)."},
    {"n": "23", "heading": "Account Closure/Termination",
     "body": "Creators: no closure with active Deals; pending payout released; portfolio archived 30 days; KYC retained 7 years; handle reserved 1 year. Brands: no closure with unspent wallet or open Deals; data retained 7 years. Company-initiated ban: for fraud/violations; blocklists email/phone/PAN/GSTIN; owed amounts still paid."},
    {"n": "24", "heading": "Taxes",
     "body": "Each User handles own taxes. Company deducts/certifies TDS for Creators; issues GST invoices for Brand recharges."},
    {"n": "25", "heading": "Platform Rights",
     "body": "May showcase anonymized case studies; modify/suspend features with notice; moderate/remove violating content or accounts."},
    {"n": "26", "heading": "Limitation of Liability",
     "body": "To Creators: capped at commission earned on the specific Deal. To Brands/others: capped at fees paid in preceding 6 months (except fraud/willful misconduct). No liability for indirect/consequential damages."},
    {"n": "27", "heading": "Governing Law",
     "body": "Indian law; amicable resolution → arbitration (Arbitration and Conciliation Act, 1996) seated at [Insert City], English, sole arbitrator. Courts at [Insert City] otherwise have exclusive jurisdiction."},
    {"n": "28", "heading": "Notices",
     "body": "To Company: support@ugcad.io / 9039035060. To Users: registered email/phone or in-Platform notification."},
    {"n": "29", "heading": "Miscellaneous",
     "body": "This Agreement + T&C + Privacy Policy = entire agreement. Invalid provisions severed; rest remains enforceable. Company may assign on M&A; Users may not assign without consent. Force majeure applies. IP, confidentiality, indemnification, liability-limitation, and dispute-resolution clauses survive account closure."},
]


def agreement_payload() -> dict:
    """The full agreement as served to clients."""
    return {
        "version": AGREEMENT_VERSION,
        "title": AGREEMENT_TITLE,
        "last_updated": AGREEMENT_LAST_UPDATED,
        "intro": AGREEMENT_INTRO,
        "preview_sections": PREVIEW_SECTIONS,
        "sections": AGREEMENT_SECTIONS,
    }
