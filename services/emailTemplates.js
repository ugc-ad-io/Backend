const { baseTemplate, button } = require('./emailService');

/**
 * Email copy/templates for application (onboarding) review decisions.
 * Each returns { subject, html } ready to hand to sendEmail().
 *
 * `name`  — recipient display name
 * `role`  — 'creator' | 'business' (drives the update-profile link)
 * `frontendUrl` — base app URL (no trailing slash needed)
 */

const trimUrl = (u) => (u || 'https://www.ugcad.io').replace(/\/+$/, '');

// Nicely map reject reason codes to human sentences (extend as needed).
const REASON_TEXT = {
  incomplete_profile: 'Your profile was missing required information.',
  low_quality: 'The submitted samples did not meet our current quality bar.',
  policy_violation: 'The application conflicted with our community guidelines.',
  duplicate: 'This looks like a duplicate of an existing account.',
  other: ''
};

function applicationApproved({ name, role, frontendUrl } = {}) {
  const base = trimUrl(frontendUrl);
  const dashUrl = role === 'business' ? `${base}/dashboard/business` : `${base}/dashboard/creator`;
  return {
    subject: '🎉 Your UGCad.io application is approved',
    html: baseTemplate({
      title: 'Application approved',
      content: `
        <h2 style="margin:0 0 12px;font-size:22px;color:#15163a;">You're in${name ? `, ${name}` : ''}! 🎉</h2>
        <p style="margin:0 0 16px;font-size:15px;line-height:1.6;color:#4a4f74;">
          Great news — your ${role === 'business' ? 'brand' : 'creator'} application has been
          <strong style="color:#16a34a;">approved</strong>. Your profile is now live and you can start
          ${role === 'business' ? 'discovering creators and posting campaigns' : 'browsing campaigns and sending bids'} right away.
        </p>
        <p style="margin:0 0 24px;">${button('Go to your dashboard', dashUrl)}</p>
        <p style="margin:0;font-size:13px;color:#9296ba;">Welcome aboard — we can't wait to see what you create.</p>
      `,
      footer: 'You received this because your UGCad.io application was reviewed.'
    })
  };
}

function applicationRejected({ name, reasonCode, reasonDetails, frontendUrl } = {}) {
  const base = trimUrl(frontendUrl);
  const canned = REASON_TEXT[reasonCode] ?? '';
  const detail = reasonDetails || canned;
  return {
    subject: 'Update on your UGCad.io application',
    html: baseTemplate({
      title: 'Application update',
      content: `
        <h2 style="margin:0 0 12px;font-size:22px;color:#15163a;">Hi${name ? ` ${name}` : ''},</h2>
        <p style="margin:0 0 16px;font-size:15px;line-height:1.6;color:#4a4f74;">
          Thank you for applying to UGCad.io. After review, we're not able to approve your application at this time.
        </p>
        ${detail ? `<div style="margin:0 0 20px;padding:14px 16px;background:#fff5f8;border:1px solid #fdd8e2;border-radius:12px;font-size:14px;color:#9f1239;">
          <strong>Reason:</strong> ${detail}
        </div>` : ''}
        <p style="margin:0 0 24px;font-size:15px;line-height:1.6;color:#4a4f74;">
          You're welcome to address the above and re-apply. If you believe this was a mistake, just reply to this email.
        </p>
        <p style="margin:0;">${button('Visit UGCad.io', base)}</p>
      `,
      footer: 'You received this because your UGCad.io application was reviewed.'
    })
  };
}

function applicationRevision({ name, role, message, items, frontendUrl } = {}) {
  const base = trimUrl(frontendUrl);
  const updateUrl = role === 'business' ? `${base}/profile-setup/business` : `${base}/profile-setup/creator`;
  const list = Array.isArray(items) && items.length
    ? `<ul style="margin:0 0 20px;padding-left:20px;font-size:14px;line-height:1.7;color:#4a4f74;">
         ${items.map((i) => `<li>${typeof i === 'string' ? i : (i.label || i.text || i.field || '')}</li>`).join('')}
       </ul>`
    : '';
  return {
    subject: 'Action needed: more info for your UGCad.io application',
    html: baseTemplate({
      title: 'More info needed',
      content: `
        <h2 style="margin:0 0 12px;font-size:22px;color:#15163a;">Almost there${name ? `, ${name}` : ''}!</h2>
        <p style="margin:0 0 16px;font-size:15px;line-height:1.6;color:#4a4f74;">
          We're reviewing your application and need a little more information before we can approve it.
        </p>
        ${message ? `<div style="margin:0 0 16px;padding:14px 16px;background:#f5f7ff;border:1px solid #d9e0ff;border-radius:12px;font-size:14px;color:#3a3f74;">
          ${message}
        </div>` : ''}
        ${list}
        <p style="margin:0 0 24px;">${button('Update your profile', updateUrl)}</p>
        <p style="margin:0;font-size:13px;color:#9296ba;">Once you've updated it, our team will take another look.</p>
      `,
      footer: 'You received this because your UGCad.io application needs an update.'
    })
  };
}

module.exports = { applicationApproved, applicationRejected, applicationRevision };
