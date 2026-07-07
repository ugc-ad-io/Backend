const { Resend } = require('resend');

/**
 * Email service (Resend).
 *
 * Generic, reusable sender — no business logic baked in. Wire it into any flow
 * (password reset, welcome, approvals, notifications) by calling sendEmail().
 *
 * Config (.env):
 *   RESEND_API_KEY   — API key from https://resend.com/api-keys (required to send)
 *   EMAIL_FROM       — default From, e.g. "UGCad.io <no-reply@ugcad.io>"
 *                      (the domain must be verified in Resend)
 *   EMAIL_REPLY_TO   — optional default Reply-To (e.g. support@ugcad.io)
 *
 * If RESEND_API_KEY is missing, sendEmail() is a safe no-op: it logs and returns
 * { skipped: true } instead of throwing, so callers never crash in dev/staging.
 */

const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const DEFAULT_FROM = process.env.EMAIL_FROM || 'UGCad.io <onboarding@resend.dev>';
const DEFAULT_REPLY_TO = process.env.EMAIL_REPLY_TO || undefined;

// Instantiate lazily/guarded so a missing key doesn't break module load.
const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;

// Strip HTML tags to a rough plain-text fallback when only `html` is provided.
function htmlToText(html = '') {
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|h[1-6]|tr)>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/**
 * Send an email through Resend.
 *
 * @param {Object}   opts
 * @param {string|string[]} opts.to        Recipient(s)
 * @param {string}   opts.subject          Subject line
 * @param {string}  [opts.html]            HTML body (wrap with baseTemplate for branding)
 * @param {string}  [opts.text]            Plain-text body (auto-derived from html if omitted)
 * @param {string}  [opts.from]            Override the default From
 * @param {string}  [opts.replyTo]         Override the default Reply-To
 * @param {string|string[]} [opts.cc]
 * @param {string|string[]} [opts.bcc]
 * @param {Array}   [opts.attachments]     Resend attachment objects [{ filename, content }]
 * @param {Array}   [opts.tags]            Resend tags [{ name, value }]
 * @returns {Promise<{ id?: string, skipped?: boolean, error?: string }>}
 */
async function sendEmail({
  to,
  subject,
  html,
  text,
  from = DEFAULT_FROM,
  replyTo = DEFAULT_REPLY_TO,
  cc,
  bcc,
  attachments,
  tags
} = {}) {
  if (!to || !subject || (!html && !text)) {
    throw new Error('sendEmail requires "to", "subject", and one of "html"/"text"');
  }

  if (!resend) {
    console.warn(`[email] RESEND_API_KEY not set — skipping send to ${Array.isArray(to) ? to.join(', ') : to} ("${subject}")`);
    return { skipped: true };
  }

  const payload = {
    from,
    to: Array.isArray(to) ? to : [to],
    subject,
    html,
    text: text || (html ? htmlToText(html) : undefined)
  };
  if (replyTo) payload.reply_to = replyTo;
  if (cc) payload.cc = cc;
  if (bcc) payload.bcc = bcc;
  if (attachments) payload.attachments = attachments;
  if (tags) payload.tags = tags;

  const { data, error } = await resend.emails.send(payload);
  if (error) {
    console.error('[email] Resend send failed:', error);
    return { error: error.message || String(error) };
  }
  return { id: data?.id };
}

/**
 * Wrap body HTML in a minimal, responsive, brand-consistent shell.
 * Pass the inner content (heading, paragraphs, buttons) as `content`.
 */
function baseTemplate({ title = 'UGCad.io', content = '', footer = '' } = {}) {
  const year = new Date().getFullYear();
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${title}</title>
  </head>
  <body style="margin:0;padding:0;background:#f4f5fb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1f2340;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f5fb;padding:32px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 8px 30px rgba(20,22,58,0.08);">
            <tr>
              <td style="background:linear-gradient(135deg,#5b6bff,#8b5cf6);padding:24px 32px;">
                <span style="color:#fff;font-size:20px;font-weight:800;letter-spacing:-0.02em;">UGCad.io</span>
              </td>
            </tr>
            <tr>
              <td style="padding:32px;">
                ${content}
              </td>
            </tr>
            <tr>
              <td style="padding:20px 32px;background:#fafbff;border-top:1px solid #eef0f6;color:#9296ba;font-size:12px;line-height:1.6;">
                ${footer || `You're receiving this email from UGCad.io.`}<br/>
                &copy; ${year} UGCad.io. All rights reserved.
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`;
}

/** Reusable primary button (inline-styled for email clients). */
function button(label, href) {
  return `<a href="${href}" style="display:inline-block;background:#5b6bff;color:#ffffff;text-decoration:none;font-weight:700;font-size:15px;padding:13px 28px;border-radius:10px;">${label}</a>`;
}

module.exports = { sendEmail, baseTemplate, button, htmlToText, isConfigured: !!resend };
