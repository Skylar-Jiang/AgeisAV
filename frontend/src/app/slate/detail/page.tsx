import { Suspense } from 'react';
import type { Metadata } from 'next';
import { PrototypeShell } from '@/components/prototype-shell';
import { ReportDetail } from '@/components/report-detail';
export const metadata: Metadata = { title: 'Slate 检测详情 · AegisAV 原型' };
export default function Page() { return <PrototypeShell direction="slate" view="detail"><Suspense fallback={<p role="status">加载详情…</p>}><ReportDetail direction="slate"/></Suspense></PrototypeShell>; }
