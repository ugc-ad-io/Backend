// UGC content categories (aligned with Billo / Trend / Insense style marketplaces).
// `GIGA_CATEGORIES` maps a stable KEY → value code; `CATEGORY_LABELS` maps the
// value code → human label shown in pickers (signup, work distribution, etc.).
const GIGA_CATEGORIES = {
  TESTIMONIAL: 'testimonial',
  PRODUCT_DEMO: 'product_demo',
  TRY_ON: 'try_on',
  GRWM: 'grwm',
  DAY_IN_LIFE: 'day_in_life',
  TRANSFORMATION: 'transformation',
  FOOD: 'food',
  VOICEOVER: 'voiceover',
  ASMR: 'asmr',
  UGC_AD: 'ugc_ad',
  COMPARISON: 'comparison',
  STREET_INTERVIEW: 'street_interview',
  CUSTOM: 'custom'
};

const GIG_STATUS = {
  PENDING: 'PENDING',
  APPROVED: 'APPROVED',
  REJECTED: 'REJECTED',
  IN_PROGRESS: 'IN_PROGRESS',
  COMPLETED: 'COMPLETED',
  CANCELLED: 'CANCELLED'
};

const CATEGORY_LABELS = {
  testimonial: 'Testimonial / Review',
  product_demo: 'Product Demo',
  try_on: 'Try-On / Haul',
  grwm: 'GRWM (Get Ready With Me)',
  day_in_life: 'Day-in-the-Life / Vlog',
  transformation: 'Before & After / Transformation',
  food: 'Recipe / Food',
  voiceover: 'Voiceover / Faceless',
  asmr: 'ASMR',
  ugc_ad: 'Problem–Solution Ad / Skit',
  comparison: 'Comparison / "This vs That"',
  street_interview: 'Street Interview / Vox Pop',
  custom: 'Custom'
};

// [{ value, label }] in display order — convenient for dropdowns / pickers.
const CATEGORY_LIST = Object.keys(CATEGORY_LABELS).map((value) => ({ value, label: CATEGORY_LABELS[value] }));

module.exports = {
  GIGA_CATEGORIES,
  GIG_STATUS,
  CATEGORY_LABELS,
  CATEGORY_LIST
};
