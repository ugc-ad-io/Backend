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

module.exports = { check, scanImage, deobfuscate };
