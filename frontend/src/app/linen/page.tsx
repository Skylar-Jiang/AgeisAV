import { Suspense } from 'react';
import { CalmShell } from '@/components/calm-shell';
import { CalmWorkspace } from '@/components/calm-workspace';
import { LinenScrollControls } from '@/components/linen-scroll-controls';
export default function Page() { return <CalmShell direction="linen" view="workspace" controls={<Suspense fallback={null}><LinenScrollControls/></Suspense>}><CalmWorkspace direction="linen"/></CalmShell>; }
