import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = { title: 'AegisAV · 设计原型', description: '两套深色扫描工作台与检测详情原型；演示数据。', icons: { icon: '/icon.svg' } };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="zh-CN"><body>{children}</body></html>;
}
