import { useEffect, useRef } from 'react';
import axios from 'axios';

const listeners = new Set();
const emit = () => listeners.forEach(listener => listener());
const editing = () => /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName) || document.activeElement?.isContentEditable;

/** Refresh existing data effects, without remounting the page or losing forms. */
export function useLiveEffect(effect, dependencies) {
  const latest = useRef(effect);
  latest.current = effect;
  useEffect(() => {
    let cleanup = latest.current();
    const refresh = () => {
      if (document.hidden || editing() || document.querySelector('.razorpay-container')) return;
      if (typeof cleanup === 'function') cleanup();
      cleanup = latest.current();
    };
    listeners.add(refresh);
    return () => {
      listeners.delete(refresh);
      if (typeof cleanup === 'function') cleanup();
    };
    // The caller supplies the same dependencies as its original data effect.
    // eslint-disable-next-line
  }, dependencies);
}

export function startLiveUpdates() {
  let stopped = false, pending = false, version, ticks = 0;
  const check = async (force = false) => {
    if (stopped || pending || document.hidden || !localStorage.getItem('token')) return;
    pending = true;
    try {
      const response = await axios.get(`${process.env.REACT_APP_BACKEND_URL}/api/live/revision`);
      if (stopped) return;
      const changed = version !== undefined && version !== response.data.version;
      version = response.data.version;
      if (changed || force || ++ticks % 4 === 0) emit();
    } catch {
      // Periodic fallback also picks up changes made by background jobs.
      if (!stopped && (force || ++ticks % 4 === 0)) emit();
    } finally { pending = false; }
  };
  const resume = () => { if (!document.hidden) check(true); };
  check();
  const timer = setInterval(check, 15000);
  window.addEventListener('focus', resume);
  document.addEventListener('visibilitychange', resume);
  return () => {
    stopped = true;
    clearInterval(timer);
    window.removeEventListener('focus', resume);
    document.removeEventListener('visibilitychange', resume);
  };
}
