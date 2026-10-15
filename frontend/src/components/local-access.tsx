'use client';
import { useState } from 'react';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Field, FieldLabel } from './ui/field';
import { api } from '@/lib/api';

export function LocalAccess({ onConnected }: { onConnected: () => void }) {
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  return <form className="local-access" onSubmit={async event => {
    event.preventDefault(); setBusy(true); setError('');
    try { await api('/v1/session', { method: 'POST', headers: { Authorization: `Bearer ${key.trim()}` } }); setKey(''); onConnected(); }
    catch { setError('连接失败。请核对本地访问密钥与服务状态。'); }
    finally { setBusy(false); }
  }}><h2>连接你的本地检测服务</h2><p>使用启动器生成的本地访问密钥。密钥只用于建立会话，不写入浏览器存储。</p>
    <Field><FieldLabel htmlFor="access-key">本地访问密钥</FieldLabel><Input id="access-key" name="access-key" type="password" autoComplete="current-password" value={key} required onChange={event => setKey(event.target.value)} aria-describedby="access-error"/></Field>
    <Button disabled={busy}>{busy ? '正在连接…' : '连接本地服务'}</Button><p id="access-error" role="status" aria-live="polite">{error}</p>
  </form>;
}
