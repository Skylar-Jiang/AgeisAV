import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = { title: 'AegisAV · Linen', description: '本地 PE 静态扫描工作台与五引擎证据详情；演示入口单独标记。', icons: { icon: '/icon.svg' } };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="zh-CN"><body>{children}</body></html>;
}
