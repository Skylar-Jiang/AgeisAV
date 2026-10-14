'use client';
import { useEffect } from 'react';
import { useSearchParams } from 'next/navigation';
import { Button } from '@/components/ui/button';

export function LinenScrollControls() {
  const parameters = useSearchParams();
  const mode = parameters.get('scroll') === 'snap' ? 'snap' : 'reveal';

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.linenScroll = mode;
    const section = document.querySelector<HTMLElement>('#linen-records');
    const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
    let observer: IntersectionObserver | undefined;
    function observe() {
      observer?.disconnect();
      section?.removeAttribute('data-reveal');
      if (!section || mode !== 'reveal' || motion.matches || !('IntersectionObserver' in window)) return;
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
      delete root.dataset.linenScroll;
    };
  }, [mode]);

  function select(next: 'snap' | 'reveal') {
    if (next === mode) return;
    const url = new URL(window.location.href);
    url.searchParams.set('scroll', next);
    window.history.pushState(null, '', url);
  }

  return <div className="linen-scroll-controls" role="group" aria-label="页面滚动体验对比">
    <Button variant="ghost" aria-pressed={mode === 'reveal'} onClick={() => select('reveal')}>自然滚动</Button>
    <Button variant="ghost" aria-pressed={mode === 'snap'} onClick={() => select('snap')}>整屏吸附</Button>
  </div>;
}
