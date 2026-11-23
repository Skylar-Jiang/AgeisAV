import type { NextConfig } from 'next';
const config: NextConfig = {
  output: 'export',
  trailingSlash: true,
  poweredByHeader: false,
  experimental: { cpus: 2 },
};
export default config;
