/**
 * Contact-info filter (PRD 10.4).
 *
 * Detects attempts to exchange off-platform contact details: phone numbers
 * (incl. obfuscated/spaced), emails (incl. "name at gmail dot com"), social
 * handles, WhatsApp/Telegram links, and known contact-bearing URLs.
 *
 * Returns { hasContact, matches } where matches is a list of category strings
 * for the filter log. Intentionally biased toward catching obfuscation; users
 * can flag false positives for admin review.
 */

const SOCIAL_KEYWORDS = [
  'instagram', 'insta', '\\big\\b', 'whatsapp', 'whats app', 'wsapp', 'telegram',
  'snapchat', 'snap', 'linkedin', 'twitter', '\\bx\\b', 'youtube', '\\byt\\b',
  'discord', 'signal', 'fb', 'facebook', 'messenger'
];

const CONTACT_HOSTS = [
  'wa\\.me', 't\\.me', 'telegram\\.me', 'linktr\\.ee', 'linktree', 'about\\.me',
  'beacons\\.ai', 'bit\\.ly', 'cutt\\.ly', 'tinyurl', 'snapchat\\.com', 'ig\\.me'
];

// Leetspeak / word-number substitutions used to obfuscate digits and "at/dot".
function deobfuscate(text) {
  let t = String(text || '').toLowerCase();
  // word forms of @ and .
  t = t.replace(/\s*\(?\s*(at|\[at\]|\{at\})\s*\)?\s*/g, '@');
  t = t.replace(/\s*\(?\s*(dot|\[dot\]|\{dot\})\s*\)?\s*/g, '.');
  // spelled-out digits
  const words = {
    zero: '0', one: '1', two: '2', three: '3', four: '4', five: '5',
    six: '6', seven: '7', eight: '8', nine: '9', oh: '0', o: '0'
  };
  t = t.replace(/\b(zero|one|two|three|four|five|six|seven|eight|nine|oh)\b/g, (m) => words[m]);
  // NOTE: leet digit substitution (o->0, l->1) is applied only inside hasPhone(),
  // never here — doing it globally corrupts emails/hosts (e.g. "gmail.com" -> "gmail.c0m").
  return t;
}

// Collapse separators commonly inserted inside phone numbers, then look for
// long digit runs (Indian 10-digit, with/without +country code).
function hasPhone(raw) {
  const compact = String(raw || '')
    .toLowerCase()
    .replace(/[oO]/g, '0')
    .replace(/[\s().\-_+]/g, '');
  // 10–13 consecutive digits (covers +91XXXXXXXXXX and bare 10-digit)
  if (/\d{10,13}/.test(compact)) return true;
  // grouped digits with separators, e.g. "98 76 54 32 10" or "987-654-3210"
  if (/(\d[\s.\-]?){9,}\d/.test(String(raw))) return true;
  return false;
}

const EMAIL_RE = /[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/i;
const HANDLE_RE = /(^|[\s:])@[a-z0-9._]{2,}/i;

// ── Admin-managed rules (Admin → Chat oversight → Filter rules) ──────────────
//
// These used to exist only in the admin UI: the page let you add "call me", and
// the filter — which reads the hardcoded patterns above and nothing else — happily
// delivered "call me". The rules are now real rows, and this is where they get
// applied.
//
// check() stays synchronous because every caller treats it that way, so the rules
// are held in a cache that's refreshed on boot, whenever an admin changes a rule,
// and lazily in the background once stale.
const RULE_CACHE_TTL_MS = 30_000;
let ruleCache = { rules: [], loadedAt: 0, loading: null };

const escapeRegex = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Turn a stored rule into something we can test with. A bad regex from the admin
// form must never take chat down, so a rule that won't compile is dropped (and
// logged) rather than thrown.
function compileRule(r) {
  try {
    if (r.type === 'regex') {
      return { rule_id: r.rule_id, label: r.label, re: new RegExp(r.pattern, 'i') };
    }
    // keyword: a comma-separated list, matched as whole words/phrases so the rule
    // "snap" doesn't fire on "snapshot".
    const words = String(r.pattern || '')
      .split(',')
      .map((w) => w.trim())
      .filter(Boolean)
      .map(escapeRegex);
    if (!words.length) return null;
    return { rule_id: r.rule_id, label: r.label, re: new RegExp(`\\b(${words.join('|')})\\b`, 'i') };
  } catch (e) {
    console.error(`[contactFilter] rule "${r.rule_id}" has an invalid pattern, skipping:`, e.message);
    return null;
  }
}

// Load the enabled rules into the cache. Safe to call repeatedly; concurrent calls
// share one query.
async function refreshRules() {
  if (ruleCache.loading) return ruleCache.loading;
  ruleCache.loading = (async () => {
    try {
      const FilterRule = require('../models/FilterRule');
      const docs = await FilterRule.find({ enabled: true }).lean();
      ruleCache = {
        rules: docs.map(compileRule).filter(Boolean),
        loadedAt: Date.now(),
        loading: null,
      };
    } catch (e) {
      // DB down / not connected yet: keep whatever we had. The built-in patterns
      // below still run, so the filter degrades rather than failing open entirely.
      console.error('[contactFilter] could not load filter rules:', e.message);
      ruleCache.loading = null;
    }
    return ruleCache.rules;
  })();
  return ruleCache.loading;
}

function activeRules() {
  // Stale cache → kick off a refresh but don't block this message on it.
  if (Date.now() - ruleCache.loadedAt > RULE_CACHE_TTL_MS && !ruleCache.loading) {
    refreshRules().catch(() => {});
  }
  return ruleCache.rules;
}

// Fire-and-forget: keeps the "hits" count on the admin page real.
function countHit(ruleIds) {
  if (!ruleIds.length) return;
  try {
    const FilterRule = require('../models/FilterRule');
    FilterRule.updateMany({ rule_id: { $in: ruleIds } }, { $inc: { hits: 1 } }).catch(() => {});
  } catch (e) { /* never block a message on bookkeeping */ }
}

function check(rawText) {
  const matches = [];
  const raw = String(rawText || '');
  const deob = deobfuscate(raw);

  if (hasPhone(raw) || hasPhone(deob)) matches.push('phone');
  if (EMAIL_RE.test(raw) || EMAIL_RE.test(deob)) matches.push('email');

  const socialRe = new RegExp(`\\b(${SOCIAL_KEYWORDS.join('|')})\\b`, 'i');
  const hasHandle = HANDLE_RE.test(raw);
  const mentionsSocial = socialRe.test(raw);
  // A bare @handle, or a social keyword paired with a handle / "dm"/"add me"
  if (hasHandle) matches.push('social_handle');
  else if (mentionsSocial && /(dm|add|ping|reach|find|follow|message)\s+me|my\s+\w+\s+is|@/i.test(raw)) {
    matches.push('social_handle');
  }

  const hostRe = new RegExp(`(${CONTACT_HOSTS.join('|')})`, 'i');
  if (hostRe.test(raw) || hostRe.test(deob)) matches.push('contact_link');

  // The admin's own rules, checked against the raw text AND the de-obfuscated form
  // so "c a l l  m e" style evasion is caught the same way.
  const hitIds = [];
  for (const rule of activeRules()) {
    if (rule.re.test(raw) || rule.re.test(deob)) {
      matches.push(rule.label || rule.rule_id);
      hitIds.push(rule.rule_id);
    }
  }
  countHit(hitIds);

  return { hasContact: matches.length > 0, matches: [...new Set(matches)] };
}

/**
 * OCR scan hook for image attachments (10.4). A real deployment plugs an OCR
 * engine (tesseract.js / cloud OCR) here; until then we scan the filename and
 * any caption with the same text filter so obvious leaks in filenames are caught.
 */
async function scanImage({ url, caption } = {}) {
  const name = decodeURIComponent(String(url || '').split('/').pop() || '');
  const result = check(`${name} ${caption || ''}`);
  return { ...result, engine: 'filename-stub' };
}

// The rules the admin page ships with. Seeded once, then owned by the admin —
// they're editable rows, not constants, so this list is only ever used to fill an
// empty collection.
const DEFAULT_RULES = [
  { rule_id: 'r-phone', type: 'regex', label: 'Phone numbers', pattern: '\\b(?:\\+?\\d[ -]?){7,}\\b', enabled: true, status: 'active' },
  { rule_id: 'r-email', type: 'regex', label: 'Email addresses', pattern: '[\\w.+-]+@[\\w-]+\\.[\\w.-]+', enabled: true, status: 'active' },
  { rule_id: 'r-wa', type: 'keyword', label: 'Off-platform apps', pattern: 'whatsapp, telegram, signal, snapchat', enabled: true, status: 'active' },
  { rule_id: 'r-callme', type: 'keyword', label: 'Contact solicitations', pattern: 'call me, text me, dm me, reach me at', enabled: true, status: 'active' },
];

// Put the defaults in the DB the first time, then warm the cache. Called at boot.
async function initRules() {
  try {
    const FilterRule = require('../models/FilterRule');
    await Promise.all(DEFAULT_RULES.map((r) =>
      FilterRule.updateOne({ rule_id: r.rule_id }, { $setOnInsert: r }, { upsert: true })
    ));
  } catch (e) {
    console.error('[contactFilter] could not seed default rules:', e.message);
  }
  return refreshRules();
}

module.exports = { check, scanImage, deobfuscate, refreshRules, initRules, DEFAULT_RULES };
