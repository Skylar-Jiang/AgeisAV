import { Suspense } from 'react';
import { CalmShell } from '@/components/calm-shell';
import { BehaviorWorkspace } from '@/components/behavior-workspace';

export default function Page() {
  return <CalmShell view="behavior"><Suspense fallback={<p role="status">正在准备离线行为分析…</p>}><BehaviorWorkspace/></Suspense></CalmShell>;
}
