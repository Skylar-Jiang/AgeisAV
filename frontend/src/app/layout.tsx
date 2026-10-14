import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = { title: 'AegisAV · Linen', description: 'Linen 扫描工作台与五引擎证据详情；合成演示数据。', icons: { icon: '/icon.svg' } };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="zh-CN"><body>{children}</body></html>;
}
