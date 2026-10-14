import { CalmShell } from '@/components/calm-shell';
import { CalmWorkspace } from '@/components/calm-workspace';
import { LinenReveal } from '@/components/linen-reveal';
export default function Page() { return <CalmShell view="workspace"><LinenReveal/><CalmWorkspace/></CalmShell>; }
