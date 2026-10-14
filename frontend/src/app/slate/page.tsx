import type { Metadata } from 'next';
import { PrototypeShell } from '@/components/prototype-shell';
import { Workspace } from '@/components/workspace';
export const metadata: Metadata = { title: 'Slate 扫描工作台 · AegisAV 原型' };
export default function Page() { return <PrototypeShell direction="slate" view="workspace"><Workspace direction="slate"/></PrototypeShell>; }
