export type EngineResult = { engine_id: string; engine_version: string; artifact_version: string | null; status: string; elapsed_ms: number; evidence: unknown[]; score?: number | null; threshold?: number | null; profile?: string };
export type ScanReport = { sha256: string; size_bytes: number; verdict: string; cached: boolean; engines: Record<string, EngineResult>; fusion?: { policy_id: string; abstained_engines: string[] } };
export type TaskFile = { name: string; size_bytes: number; status: string; report: ScanReport | null; error: string | null; elapsed_ms?: number; duplicate_of?: number; verdict?: string | null };
export type ScanTask = { id: string; status: string; created_at: string; total: number; finished: number; persistent: boolean; cancel_requested: boolean; files: TaskFile[] };
export type Inventory = { service_release: string | null; engines: { id: string; status: string; artifact_version: string | null }[]; task_limits: { max_file_bytes: number; max_files: number; max_task_bytes: number; persistent: boolean } };
export const engines = [
  { id: 'sha256', name: 'SHA-256', kind: '精确哈希' }, { id: 'fuzzy', name: 'TLSH / SSDeep', kind: '相似性匹配' },
  { id: 'yara_x', name: 'YARA-X', kind: '规则证据' }, { id: 'clamav', name: 'ClamAV', kind: '特征库检测' },
  { id: 'lightgbm', name: 'LightGBM', kind: 'PE 静态模型' },
];
export const statusText: Record<string, string> = { queued: '排队中', running: '扫描中', cancelling: '正在取消', cancelled: '已取消', completed: '已完成', completed_with_errors: '部分文件失败', error: '检测失败', timeout: '超时（弃权）', unavailable: '不可用（弃权）', not_applicable: '不适用（弃权）', no_match: '未命中', matched: '命中证据', malicious: '恶意参考命中', suspicious: '需要复核', benign: '良性参考命中', undetermined: '未定' };
export const terminal = (status?: string) => ['completed', 'completed_with_errors', 'cancelled'].includes(status ?? '');
export const bytesText = (bytes: number) => bytes < 1024 ? `${bytes} B` : bytes < 1024 ** 2 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1024 ** 2).toFixed(2)} MB`;
export class ApiError extends Error { constructor(public status: number, message: string) { super(message); } }
export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  try {
    const response = await fetch(path, { ...options, credentials: 'same-origin', cache: 'no-store', signal: options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(15000)]) : AbortSignal.timeout(60000) });
    const body = await response.json();
    if (!response.ok) throw new ApiError(response.status, typeof body.detail === 'string' ? body.detail : `服务返回 ${response.status}`);
    return body as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(0, '本地服务未响应或连接超时。请检查服务并刷新；提交响应丢失时先核对历史，避免重复提交。');
  }
}
export async function encodeFiles(files: File[]) {
  const result = [];
  for (const file of files) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    let binary = '';
    for (let offset = 0; offset < bytes.length; offset += 32768) binary += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
    result.push({ name: file.name, content_base64: btoa(binary) });
  }
  return { files: result };
}
