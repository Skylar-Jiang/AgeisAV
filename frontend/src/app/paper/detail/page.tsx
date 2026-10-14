import { Suspense } from 'react';
import { CalmShell } from '@/components/calm-shell';
import { ReportDetail } from '@/components/report-detail';
export default function Page() { return <CalmShell direction="paper" view="detail"><Suspense fallback={<p role="status">Loading...</p>}><ReportDetail direction="paper"/></Suspense></CalmShell>; }
