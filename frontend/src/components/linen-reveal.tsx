'use client';
import { useEffect } from 'react';

export function LinenReveal() {
  useEffect(() => {
    const section = document.querySelector<HTMLElement>('#linen-records');
    const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
    let observer: IntersectionObserver | undefined;
    function observe() {
      observer?.disconnect();
      section?.removeAttribute('data-reveal');
      if (!section || motion.matches || !('IntersectionObserver' in window)) return;
      if (section.getBoundingClientRect().top < window.innerHeight) return;
      section.dataset.reveal = 'pending';
      observer = new IntersectionObserver(entries => {
        if (entries.some(entry => entry.isIntersecting)) {
          section!.dataset.reveal = 'shown';
          observer?.disconnect();
        }
      }, { threshold: 0.06 });
      observer.observe(section);
    }
    observe();
    motion.addEventListener('change', observe);
    return () => {
      observer?.disconnect();
      motion.removeEventListener('change', observe);
      section?.removeAttribute('data-reveal');
    };
  }, []);

  return null;
}
