import { useLiveEffect } from "../lib/liveUpdates";
import { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import axios from 'axios';
import { ArrowLeft, MessageSquare, Star } from 'lucide-react';
import './PublicProfile.css';

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;
const assetUrl = value => /^https?:\/\//i.test(value || '') ? value : `${process.env.REACT_APP_BACKEND_URL || ''}${value}`;

export default function PublicProfile() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [person, setPerson] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [reviews, setReviews] = useState([]);
  const [reviewsError, setReviewsError] = useState('');

  useLiveEffect(() => {
    if (!person || !['creator', 'business'].includes(person.role)) return;
    let active = true;
    setReviews([]);
    setReviewsError('');
    axios.get(`${API}/reviews/${person.role}/${encodeURIComponent(person.id)}`)
      .then(({ data }) => { if (active) setReviews(Array.isArray(data) ? data : []); })
      .catch(() => { if (active) setReviewsError('Unable to load reviews.'); });
    return () => { active = false; };
  }, [person]);

  useLiveEffect(() => {
    let active = true;
    setLoading(true);
    setPerson(null);
    setError('');
    axios.get(`${API}/profile/${encodeURIComponent(id)}`)
      .then(({ data }) => { if (active) setPerson(data); })
      .catch(err => { if (active) setError(err.response?.status === 404 ? 'Profile not found.' : 'Unable to load this profile. Please try again.'); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [id]);

  const profile = person?.profile || {};
  const name = person?.full_name || person?.nickname || profile.business_name || 'Profile';
  const photo = person?.profile_photo || person?.profile_picture || profile.profile_photo;
  const portfolio = person?.portfolio || profile.portfolio || [];
  const languages = person?.languages || profile.languages || [];

  return (
    <main className="public-profile-page">
      <button type="button" className="public-profile-back" onClick={() => navigate(-1)}><ArrowLeft size={18} /> Back to messages</button>
      {loading ? <p role="status">Loading profile...</p> : error ? <p role="alert">{error}</p> : (
        <>
          <section className="public-profile-card public-profile-header">
            <div className="public-profile-avatar">{photo ? <img src={assetUrl(photo)} alt={name} /> : name.charAt(0).toUpperCase()}</div>
            <div><h1>{name}</h1><p>{person.role === 'creator' ? 'Creator' : 'Brand'}</p></div>
            <button type="button" onClick={() => navigate(`/messages?conv=${encodeURIComponent(id)}`)}><MessageSquare size={18} /> Message</button>
          </section>
          <section className="public-profile-card">
            <h2>About</h2>
            <p className="public-profile-bio">{person.bio || profile.bio || person.description || profile.description || 'No bio added yet.'}</p>
            <dl>
              {(person.city || profile.city) && <div><dt>Location</dt><dd>{person.city || profile.city}</dd></div>}
              {(person.primary_category || profile.primary_category || profile.category) && <div><dt>Category</dt><dd>{person.primary_category || profile.primary_category || profile.category}</dd></div>}
              {languages.length > 0 && <div><dt>Languages</dt><dd>{Array.isArray(languages) ? languages.join(', ') : languages}</dd></div>}
              {person.role === 'creator' && <div><dt>Completed works</dt><dd>{person.deliverables_completed || 0}</dd></div>}
            </dl>
          </section>
          <section className="public-profile-card">
            <h2>Portfolio</h2>
            <div className="public-profile-gallery">
              {portfolio.map((item, index) => {
                const url = typeof item === 'string' ? item : item.video_url || item.url || item.image_url;
                if (!url) return null;
                return /\.(mp4|webm|mov|m4v)(?:[?#]|$)/i.test(url)
                  ? <video key={index} src={assetUrl(url)} controls playsInline preload="metadata" aria-label={`Portfolio video ${index + 1}`} />
                  : <img key={index} src={assetUrl(url)} alt={`Portfolio work ${index + 1}`} loading="lazy" />;
              })}
            </div>
            {!portfolio.length && <p>No portfolio work added yet.</p>}
          </section>
          <section className="public-profile-card">
            <h2>Reviews</h2>
            <p><Star size={16} /> {person.total_reviews > 0
              ? `${Number(person.average_rating).toFixed(1)} / 5 · ${person.total_reviews} reviews`
              : 'No reviews yet.'}</p>
            {reviewsError && <p role="alert">{reviewsError}</p>}
            {reviews.map(review => (
              <article key={review.id}>
                <strong>{review.rating} / 5</strong>
                <p>{review.review || review.review_text || review.comment || ''}</p>
              </article>
            ))}
          </section>
        </>
      )}
    </main>
  );
}
