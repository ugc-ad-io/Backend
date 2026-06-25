/**
 * Assign / check the admin role.
 *
 *   node make_admin.js                      → list all users + roles (and current admins)
 *   node make_admin.js <email>              → promote that user to admin
 *   node make_admin.js <email> creator      → set that user's role (creator|business|admin)
 *
 * After promoting, the user must LOG OUT and LOG IN again — the role is baked
 * into the JWT at login, so an existing session keeps the old role until re-login.
 */
require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');

(async () => {
  await mongoose.connect(process.env.MONGODB_URI);

  const [, , email, roleArg] = process.argv;
  const role = roleArg || 'admin';

  if (!email) {
    const users = await User.find({}, 'email role approval_status').lean();
    console.log(`\nTotal users: ${users.length}`);
    console.log('Current admins:', users.filter(u => u.role === 'admin').map(u => u.email).join(', ') || '(none)');
    console.log('\nAll users:');
    users.forEach(u => console.log(`  ${u.role.padEnd(9)} ${u.approval_status.padEnd(9)} ${u.email}`));
    await mongoose.disconnect();
    return;
  }

  if (!['creator', 'business', 'admin'].includes(role)) {
    console.error(`Invalid role "${role}". Use creator | business | admin.`);
    await mongoose.disconnect();
    process.exit(1);
  }

  const user = await User.findOneAndUpdate(
    { email: email.toLowerCase() },
    { $set: { role, approval_status: 'approved', active: true } },
    { new: true }
  );

  if (!user) console.error(`No user found with email: ${email}`);
  else console.log(`✓ ${user.email} is now role="${user.role}". Log out and log back in to refresh the token.`);

  await mongoose.disconnect();
})().catch(e => { console.error(e); process.exit(1); });
