const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema(
  {
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    type: { type: String, required: true },
    channel: { type: String, default: 'in_app' }, // in_app | email | sms | whatsapp
    title: { type: String, default: '' },
    body: { type: String, default: '' },
    critical: { type: Boolean, default: false },
    deferred_until: { type: Date, default: null }, // set when held for quiet hours
    read: { type: Boolean, default: false }
  },
  { timestamps: true }
);

module.exports = mongoose.model('Notification', notificationSchema);
