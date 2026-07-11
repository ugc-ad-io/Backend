const mongoose = require('mongoose');

// A contact-info filter rule, as managed on Admin → Chat oversight → Filter rules.
//
// These used to be hardcoded demo fixtures on the server and a fallback array in
// the React page, and the filter itself never read either. So the admin page was
// decoration: you could add "call me" and still send "call me".
const filterRuleSchema = new mongoose.Schema(
  {
    rule_id: { type: String, required: true, unique: true, index: true },
    // regex  → `pattern` is a raw regular expression.
    // keyword→ `pattern` is a comma-separated list matched as whole words.
    type: { type: String, enum: ['regex', 'keyword'], default: 'keyword' },
    label: { type: String, required: true },
    pattern: { type: String, required: true },

    // enabled is what the FILTER obeys. status is what the ADMIN UI shows.
    // A proposed rule lands disabled + pending_review so a careless pattern (an
    // admin once proposed the keyword "as") can't take the whole chat down before
    // a human has looked at it.
    enabled: { type: Boolean, default: false, index: true },
    status: { type: String, enum: ['active', 'pending_review', 'disabled'], default: 'pending_review' },

    hits: { type: Number, default: 0 },
    created_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  },
  { timestamps: true }
);

module.exports = mongoose.models.FilterRule || mongoose.model('FilterRule', filterRuleSchema);
