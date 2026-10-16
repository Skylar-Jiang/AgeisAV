import { CalmShell } from '@/components/calm-shell';
import { AssetStatus } from '@/components/asset-status';
export default function Page() { return <CalmShell view="assets"><Suspense fallback={<p role="status">正在加载资产清单…</p>}><AssetStatus/></Suspense></CalmShell>; }
import { Suspense } from 'react';
