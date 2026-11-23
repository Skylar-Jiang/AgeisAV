import { Suspense } from 'react';
import { CalmShell } from '@/components/calm-shell';
import { DemoReportDetail } from '@/components/demo-report-detail';
export default function Page() { return <CalmShell view="detail" demo><Suspense fallback={<p role="status">正在加载演示…</p>}><DemoReportDetail/></Suspense></CalmShell>; }
