import { useEffect, type RefObject } from "react";

const MAX_ACTIVE_VIDEOS = 4;
type Preview = { video: HTMLVideoElement; url: string; ratio: number; active: boolean };
const previews = new Set<Preview>();

function reconcile() {
  const selected = new Set(
    document.hidden ? [] : [...previews]
      .filter(preview => preview.ratio >= 0.2)
      .sort((a, b) => b.ratio - a.ratio)
      .slice(0, MAX_ACTIVE_VIDEOS)
  );
  for (const preview of previews) {
    const shouldPlay = selected.has(preview);
    if (preview.active === shouldPlay) continue;
    preview.active = shouldPlay;
    if (shouldPlay) preview.video.play().catch(() => {});
    else preview.video.pause();
  }
}

/** Share a four-video playback budget across both brand creator browsing views. */
export function useCreatorVideo(
  videoRef: RefObject<HTMLVideoElement | null>,
  containerRef: RefObject<HTMLDivElement | null>,
  url: string,
) {
  useEffect(() => {
    const video = videoRef.current;
    const container = containerRef.current;
    if (!video || !container) return;
    const preview: Preview = { video, url, ratio: 0, active: false };
    previews.add(preview);
    video.preload = "metadata";
    video.src = url;
    const observer = new IntersectionObserver(([entry]) => {
      preview.ratio = entry.isIntersecting ? entry.intersectionRatio : 0;
      reconcile();
    }, { threshold: [0, 0.2, 0.4, 0.6, 0.8, 1] });
    observer.observe(container);
    document.addEventListener("visibilitychange", reconcile);
    return () => {
      observer.disconnect();
      document.removeEventListener("visibilitychange", reconcile);
      previews.delete(preview);
      preview.video.pause();
      reconcile();
    };
  }, [videoRef, containerRef, url]);
}
