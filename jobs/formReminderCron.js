const cron = require('node-cron');
const User = require('../models/User');
const { sendEmail } = require('../services/emailService');
const { formReminderEmail } = require('../services/emailTemplates');

/**
 * Daily job: email creators/brands who signed up 24h+ ago and still haven't
 * completed their onboarding form. Sends once per user (form_reminder_sent_at
 * gates re-sends) — filling the form is the only way to get another email.
 */
async function runFormReminderSweep() {
  const cutoff = new Date(Date.now() - 24 * 3600 * 1000);
  const users = await User.find({
    role: { $in: ['creator', 'business'] },
    profile_completed: false,
    form_reminder_sent_at: null,
    createdAt: { $lte: cutoff },
  }).select('email nickname full_name role').lean();

  let sent = 0;
  for (const u of users) {
    if (!u.email) continue;
    const name = u.nickname || u.full_name || '';
    const mail = formReminderEmail({ name, role: u.role, frontendUrl: process.env.FRONTEND_URL });
    const result = await sendEmail({ to: u.email, subject: mail.subject, html: mail.html }).catch((err) => {
      console.error(`[formReminderCron] send failed for ${u.email}:`, err.message);
      return null;
    });
    if (result && !result.error) {
      await User.updateOne({ _id: u._id }, { $set: { form_reminder_sent_at: new Date() } });
      sent += 1;
    }
  }
  console.log(`[formReminderCron] swept ${users.length} pending user(s), sent ${sent} reminder(s)`);
  return { checked: users.length, sent };
}

// Runs once a day at 09:00 server time.
function startFormReminderCron() {
  cron.schedule('0 9 * * *', () => {
    runFormReminderSweep().catch((err) => console.error('[formReminderCron] sweep failed:', err.message));
  });
  console.log('[formReminderCron] scheduled daily at 09:00');
}

module.exports = { startFormReminderCron, runFormReminderSweep };
