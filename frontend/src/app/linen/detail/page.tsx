import { Suspense } from 'react';
import { CalmShell } from '@/components/calm-shell';
import { ReportDetail } from '@/components/report-detail';
export default function Page() { return <CalmShell view="detail"><Suspense fallback={<p role="status">正在加载…</p>}><ReportDetail/></Suspense></CalmShell>; }
