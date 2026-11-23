import { Suspense } from 'react';
import { CalmShell } from '@/components/calm-shell';
import { TaskLedger } from '@/components/task-ledger';
export default function Page() { return <CalmShell view="tasks"><Suspense fallback={<p role="status">正在加载任务…</p>}><TaskLedger/></Suspense></CalmShell>; }
