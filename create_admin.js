/**
 * Create (or promote) an ADMIN account you can log in with directly.
 *
 *   node create_admin.js <email> <password>
 *
 * - If the email doesn't exist → creates a new admin (approved, active).
 * - If it already exists → makes it admin and resets the password.
 * The password is hashed by the User model's pre-save hook.
 * After this, just log in on the site with these credentials → admin panel.
 */
require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');

(async () => {
  const [, , email, password] = process.argv;
  if (!email || !password) {
    console.error('Usage: node create_admin.js <email> <password>');
    process.exit(1);
  }

  await mongoose.connect(process.env.MONGODB_URI);

  const FOUNDER_EMAIL = (process.env.FOUNDER_EMAIL || 'admin@gmail.com').toLowerCase();
  // First admin / the founder email is a Founder; everyone else seeds as Ops (Senior).
  const seedRole = email.toLowerCase() === FOUNDER_EMAIL ? 'founder' : 'ops_senior';

  let user = await User.findOne({ email: email.toLowerCase() }).select('+password');
  if (user) {
    user.role = 'admin';
    user.admin_role = email.toLowerCase() === FOUNDER_EMAIL ? 'founder' : (user.admin_role || seedRole);
    user.approval_status = 'approved';
    user.active = true;
    user.profile_completed = true;
    user.password = password;            // re-hashed by the pre-save hook
    await user.save();
    console.log(`✓ Existing user "${user.email}" is now an ADMIN — ${user.admin_role} (password reset).`);
  } else {
    user = await User.create({
      email,
      password,                          // hashed by the pre-save hook
      role: 'admin',
      admin_role: seedRole,
      nickname: email.split('@')[0],
      approval_status: 'approved',
      active: true,
      profile_completed: true
    });
    console.log(`✓ Created new ADMIN account "${user.email}" — ${user.admin_role}.`);
  }

  console.log('Now log in on the site with this email + password — you land in the admin panel.');
  await mongoose.disconnect();
})().catch(e => { console.error(e); process.exit(1); });
