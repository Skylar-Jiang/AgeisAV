import type { Metadata } from 'next';
import { PrototypeShell } from '@/components/prototype-shell';
import { Workspace } from '@/components/workspace';
export const metadata: Metadata = { title: 'Obsidian 扫描工作台 · AegisAV 原型' };
export default function Page() { return <PrototypeShell direction="obsidian" view="workspace"><Workspace direction="obsidian"/></PrototypeShell>; }
