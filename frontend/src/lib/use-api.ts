'use client';
import { useEffect, useState } from 'react';
import { api, ApiError, terminal } from './api';

export function useApi<T>(path: string | null, poll: number | false = false) {
  const [data, setData] = useState<T | null>(null);
  const [status, setStatus] = useState<'loading' | 'ready' | 'error' | 'unauthorized'>('loading');
  const [error, setError] = useState('');
  const [errorStatus, setErrorStatus] = useState(0);
  const [owner, setOwner] = useState<string | null>(null);
  const [epoch, setEpoch] = useState(0);
  useEffect(() => {
    if (!path) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    setOwner(path); setData(null); setStatus('loading'); setError(''); setErrorStatus(0);
    async function load() {
      if (controller.signal.aborted) return;
      if (document.hidden && poll) { timer = setTimeout(load, 1000); return; }
      try {
        const value = await api<T>(path!, { signal: controller.signal });
        if (controller.signal.aborted) return;
        setData(value); setStatus('ready'); setError('');
        if (poll && !terminal((value as { status?: string }).status)) timer = setTimeout(load, poll);
      } catch (failure) {
        if (controller.signal.aborted) return;
        setStatus(failure instanceof ApiError && failure.status === 401 ? 'unauthorized' : 'error');
        setErrorStatus(failure instanceof ApiError ? failure.status : 0);
        setError(failure instanceof Error ? failure.message : '请求失败');
      }
    }
    void load();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [path, poll, epoch]);
  return { data: owner === path ? data : null, status: owner === path ? status : 'loading',
    error: owner === path ? error : '', errorStatus: owner === path ? errorStatus : 0,
    reload: () => setEpoch(value => value + 1) };
}
