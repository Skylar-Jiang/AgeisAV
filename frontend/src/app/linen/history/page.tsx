import { Suspense } from 'react';
import { CalmShell } from '@/components/calm-shell';
import { TaskLedger } from '@/components/task-ledger';
export default function Page() { return <CalmShell view="history"><Suspense fallback={<p role="status">正在加载历史…</p>}><TaskLedger history/></Suspense></CalmShell>; }
