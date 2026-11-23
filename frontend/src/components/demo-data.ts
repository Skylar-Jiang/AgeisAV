// Synthetic UI fixtures. Never derived from private candidates or final tests.
export const demoFiles = [
  { name: 'Quarterly_Report.exe', size: '1.42 MB', architecture: 'Win64', status: '需要复核', evidence: '2 个引擎支持', time: '3.84 s' },
  { name: 'DataConnector.dll', size: '642 KB', architecture: 'Win64', status: '未定', evidence: '未命中不代表安全', time: '1.26 s' },
  { name: 'Legacy_Client_Architecture_Compatibility_Test.exe', size: '2.81 MB', architecture: 'ARM64', status: '部分弃权', evidence: '模型不适用', time: '2.17 s' },
  { name: 'Readme.txt', size: '4 KB', architecture: '非 PE', status: '解析失败', evidence: '不计为阴性', time: '—' },
];
export const demoEngines = [
  { id: 'sha256', name: 'SHA-256', kind: '精确哈希', status: '未命中', version: 'UI fixture', time: 4, evidence: '参考哈希库中没有相同 SHA-256。未命中不能排除恶意。' },
  { id: 'fuzzy', name: 'TLSH / SSDeep', kind: '相似性匹配', status: '超时', version: 'UI fixture', time: 1200, evidence: '演示超时状态：本引擎未完成检测，不参与阴性计数。' },
  { id: 'yara', name: 'YARA-X', kind: '规则证据', status: '需要复核', version: 'UI fixture', time: 38, evidence: '演示规则 Demo_PE_Indicator，偏移 0x1200。规则命中作为可疑证据，需要结合其他引擎。' },
  { id: 'clamav', name: 'ClamAV', kind: '特征库检测', status: '未命中', version: 'UI fixture', time: 462, evidence: '演示阴性状态。生产报告将保留引擎及病毒库版本。' },
  { id: 'ml', name: 'LightGBM', kind: 'PE 静态模型', status: '需要复核', version: 'UI fixture', time: 2140, evidence: '演示分数 0.931，演示阈值 0.500。分数未经概率校准，不等于恶意概率，也不保证部署 FPR。' },
];
export const demoHash = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
