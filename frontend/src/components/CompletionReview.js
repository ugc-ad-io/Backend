import { useEffect, useState } from 'react';
import axios from 'axios';
import { toast } from 'sonner';
import { Star } from 'lucide-react';
import { useAuth } from '../App';
import './CompletionReview.css';

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

export default function CompletionReview({ deal }) {
  const { user } = useAuth();
  const [rating, setRating] = useState(5);
  const [text, setText] = useState('');
  const [existing, setExisting] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [saving, setSaving] = useState(false);
  const campaignId = deal?.campaign?.id;
  const ratesBrand = user?.role === 'creator';
  const target = ratesBrand ? deal?.brand : deal?.creator;
  const state = String(deal?.current_state || '').replace(/[\u2014\u2013]/g, '-').toLowerCase();
  const complete = state === 'paid - complete' || deal?.campaign?.status === 'completed';

  useEffect(() => {
    if (!complete || !campaignId || !target?.id) return;
    let active = true;
    setLoading(true);
    setError(false);
    setExisting(null);
    setRating(5);
    setText('');
    axios.get(`${API}/reviews/${ratesBrand ? 'business' : 'creator'}/${target.id}`)
      .then(({ data }) => {
        if (active) setExisting(data.find(review => review.campaign_id === campaignId && review.reviewer_id === user.id && (ratesBrand ? review.reviewee_role === 'business' : review.reviewee_role !== 'business')) || null);
      })
      .catch(() => { if (active) setError(true); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [complete, campaignId, target?.id, ratesBrand, user?.id]);

  if (!complete || !campaignId || !target?.id) return null;

  const submit = async event => {
    event.preventDefault();
    setSaving(true);
    try {
      await axios.post(`${API}/reviews`, {
        campaign_id: campaignId,
        creator_id: ratesBrand ? user.id : target.id,
        business_id: ratesBrand ? target.id : undefined,
        rating,
        review: text.trim()
      });
      setExisting({ rating, review: text.trim() });
      toast.success('Review submitted');
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Unable to submit review');
    } finally {
      setSaving(false);
    }
  };

  return <section className="deal-card completion-review">
    <h2>{existing ? 'Your Review' : `Review your ${ratesBrand ? 'brand' : 'creator'}`}</h2>
    <p>{target.name || target.handle} · Campaign complete</p>
    {loading ? <p role="status">Loading review...</p> : existing ? <div><strong>{existing.rating}/5 stars</strong><p>{existing.review}</p><small>Review submitted. Thank you.</small></div> : error ? <p role="alert">Unable to load your review. Reopen this deal to try again.</p> : <form onSubmit={submit}>
      <fieldset disabled={saving}><legend>Rating</legend>
        {[1, 2, 3, 4, 5].map(value => <label key={value}>
          <input type="radio" name={`rating-${deal.deal_id}`} value={value} checked={rating === value} onChange={() => setRating(value)} aria-label={`${value} stars`} />
          <Star size={25} fill={value <= rating ? '#f59e0b' : 'none'} color="#f59e0b" />
        </label>)}
      </fieldset>
      <label htmlFor={`review-${deal.deal_id}`}>How was the collaboration?</label>
      <textarea id={`review-${deal.deal_id}`} value={text} onChange={event => setText(event.target.value)} required maxLength={2000} rows={3} disabled={saving} />
      <small>Reviews cannot be changed after submission.</small>
      <button type="submit" className="deal-submit" disabled={saving || !text.trim()}>{saving ? 'Submitting...' : 'Submit Review'}</button>
    </form>}
  </section>;
}
