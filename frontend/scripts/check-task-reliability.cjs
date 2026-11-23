// Real process death/restart, SQLite and browser acceptance; benign PE + inert faults only.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { spawn, execFileSync } = require('node:child_process');
const { chromium } = require(process.env.AEGISAV_PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '../..'), base = 'http://127.0.0.1:3419';
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const python = path.join(root, '.venv/Scripts/python.exe');
const output = path.join(root, 'output/playwright/task-reliability');
const record = { schema: 1, benign_functional_only: true, accuracy_evaluation: false, checks: [], failures: [] };
let server, browser, key = '', state;
const note = name => record.checks.push({ name, passed: true });
async function request(route, method = 'GET', body, idempotency) {
  return fetch(base + route, { method, headers: { Authorization: 'Bearer ' + key,
    ...(body ? { 'Content-Type': 'application/json' } : {}), ...(idempotency ? { 'Idempotency-Key': idempotency } : {}) },
    body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(10000) });
}
async function resources() { return (await request('/v1/test/resources')).json(); }
function file(name, bytes) { return { name, content_base64: bytes.toString('base64') }; }
async function submit(files, idempotency) {
  for (let attempt = 0; attempt < 8; attempt++) {
    const response = await request('/v1/tasks', 'POST', { files }, idempotency);
    if (response.status === 429) { await pause(Number(response.headers.get('retry-after') || 5)*1000); continue; }
    assert.equal(response.status, 202);
    return response.json();
  }
  throw new Error('idempotent request remained backpressured');
}
async function finish(id) {
  for (let i = 0; i < 160; i++) {
    const job = await (await request('/v1/tasks/' + id)).json();
    if (!['queued', 'running', 'cancelling'].includes(job.status)) return job;
    await pause(250);
  }
  throw new Error('owned task did not finish');
}
async function start(fileTimeout = 30, taskTimeout = 60) {
  server = spawn(python, ['-m', 'uvicorn', 'experiments.task_reliability_fixture:app', '--host', '127.0.0.1', '--port', '3419', '--no-proxy-headers', '--no-access-log'], {
    cwd: root, windowsHide: true, stdio: 'ignore', env: { ...process.env, AEGISAV_RELIABILITY_FIXTURE: '1',
      AEGISAV_ACCESS_TOKEN_FILE: path.join(state, 'access.key'), AEGISAV_TASK_DB: path.join(state, 'tasks.sqlite3'),
      AEGISAV_TEST_FILE_TIMEOUT: String(fileTimeout), AEGISAV_TEST_TASK_TIMEOUT: String(taskTimeout),
      AEGISAV_ML_PYTHON: path.join(root, '.venv-ml/Scripts/python.exe') },
  });
  for (let i = 0; i < 90; i++) {
    if (server.exitCode !== null) throw new Error('owned acceptance server startup failed');
    try {
      if ((await fetch(base, { signal: AbortSignal.timeout(500) })).ok) {
        key = (await fs.readFile(path.join(state, 'access.key'), 'utf8')).trim();
        return;
      }
    } catch {}
    await pause(250);
  }
  throw new Error('owned acceptance server unavailable');
}
function processes() {
  return JSON.parse(execFileSync('powershell.exe', ['-NoProfile', '-Command',
    'Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,WorkingSetSize,CreationDate | ConvertTo-Json -Compress'],
  { windowsHide: true, encoding: 'utf8', timeout: 15000 }));
}
function tree(rows, pid) {
  const selected = [pid];
  for (let changed = true; changed;) {
    changed = false;
    for (const row of rows) if (selected.includes(row.ParentProcessId) && !selected.includes(row.ProcessId)) {
      selected.push(row.ProcessId); changed = true;
    }
  }
  return rows.filter(row => selected.includes(row.ProcessId));
}
async function stop() {
  if (server && server.exitCode === null) {
    execFileSync('taskkill.exe', ['/PID', String(server.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
    await new Promise(resolve => server.once('exit', resolve));
  }
}
(async () => {
  await fs.mkdir(output, { recursive: true });
  try { await fs.copyFile(path.join(root, 'docs/benchmarks/task_reliability_check_20261016.json'), path.join(output, `previous-${Date.now()}.json`)); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  state = await fs.mkdtemp(path.join(os.tmpdir(), 'aegisav-reliability-'));
  await new Promise((resolve, reject) => { const probe = require('node:net').createServer(); probe.once('error', reject); probe.listen(3419, '127.0.0.1', () => probe.close(resolve)); });
  try {
    await start();
    record.resources_before = await resources();
    assert.equal((await fetch(base + '/v1/tasks')).status, 401);
    note('authenticated persistent service, isolated acceptance database');
    const benign = await fs.readFile('C:/Windows/System32/notepad.exe');
    const inert = Buffer.from('AEGISAV-INERT-HANG: never executable');
    const normalFiles = [file('vendor-notepad.exe', benign), file('invalid-inert.exe', Buffer.from('invalid inert PE'))];
    const normal = await submit(normalFiles, 'normal');
    const completed = await finish(normal.id);
    assert.equal(completed.status, 'completed_with_errors');
    assert.equal(completed.files[0].status, 'completed');
    assert.equal(completed.files[1].status, 'error');
    assert.equal(completed.files[1].report, null);
    record.engine_statuses = Object.fromEntries(Object.entries(completed.files[0].report.engines).map(([id, engine]) => [id, engine.status]));
    record.benign_file_wall_ms = completed.files[0].elapsed_ms;
    note('actual five-engine benign report and parser failure persisted');
    const duplicates = await Promise.all(Array.from({ length: 8 }, () => submit(normalFiles, 'normal')));
    assert(duplicates.every(job => job.id === normal.id));
    assert.equal((await request('/v1/tasks', 'POST', { files: [file('renamed.exe', benign)] }, 'normal')).status, 409);
    note('eight concurrent network retries replay one task; different semantics conflict');
    const cancel = await submit([file('cancel-inert.exe', inert)], 'cancel');
    while (!(await resources()).worker_pid) await pause(50);
    const cancelStarted = Date.now();
    await request('/v1/tasks/' + cancel.id + '/cancel', 'POST');
    const cancelled = await finish(cancel.id);
    assert.equal(cancelled.status, 'cancelled');
    assert.equal(cancelled.files[0].report, null);
    assert.equal((await resources()).reserved_bytes, 0);
    record.cancel_wall_ms = Date.now() - cancelStarted;
    note('running scan process cancellation and reservation release');
    const crash = await submit([file('preserved-before-crash.exe', benign), file('crash-inert.exe', inert)], 'crash');
    for (;;) {
      const job = await (await request('/v1/tasks/' + crash.id)).json();
      if (job.files[0].status === 'completed' && job.files[1].status === 'running') break;
      await pause(100);
    }
    await pause(500); // Ensure the inert fixture spawned its sleeping descendant.
    const live = await resources(), owned = tree(processes(), live.worker_pid);
    assert(owned.length >= 2, 'owned worker descendants were not observed');
    record.owned_tree_peak_observed_rss_bytes = owned.reduce((sum, row) => sum + Number(row.WorkingSetSize), 0);
    record.crash_owned_process_count = owned.length;
    execFileSync('taskkill.exe', ['/PID', String(live.pid), '/F'], { windowsHide: true, stdio: 'ignore' }); // No /T: job object must clean descendants itself.
    await pause(700);
    const survivors = processes().filter(row => owned.some(old => old.ProcessId === row.ProcessId && old.CreationDate === row.CreationDate));
    assert.equal(survivors.length, 0, 'worker survived service-only termination');
    note('service-only forced termination closes job and kills owned parser descendants');
    await start();
    assert.deepEqual(await (await request('/v1/tasks/' + normal.id)).json(), completed);
    assert.deepEqual(await (await request('/v1/tasks/' + cancel.id)).json(), cancelled);
    const interrupted = await (await request('/v1/tasks/' + crash.id)).json();
    assert.equal(interrupted.status, 'interrupted');
    assert.equal(interrupted.files[0].status, 'completed');
    assert.equal(interrupted.files[1].status, 'interrupted');
    assert.equal(interrupted.files[1].report, null);
    assert.equal((await submit(crash.files.map((_, i) => i === 0 ? file('preserved-before-crash.exe', benign) : file('crash-inert.exe', inert)), 'crash')).id, crash.id);
    assert.equal((await resources()).pending, 0);
    note('restart preserves completed/cancelled reports, interrupts lost uploads, stable replay without execution');
    browser = await chromium.launch({ channel: 'chrome', headless: true });
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: 'reduce' });
    const page = await context.newPage();
    const jsErrors = []; page.on('pageerror', error => jsErrors.push(error.message));
    await page.goto(base + '/linen/', { waitUntil: 'networkidle' });
    await page.getByLabel('本地访问密钥', { exact: true }).fill(key);
    await page.getByRole('button', { name: '连接本地服务', exact: true }).click();
    await page.getByText('任务报告已持久化', { exact: true }).waitFor();
    await page.getByRole('link', { name: '查看 crash-inert.exe 检测详情', exact: true }).click();
    await page.getByText('服务重启后上传字节已丢失。请返回工作台重新选择文件，作为新任务提交。', { exact: true }).waitFor();
    assert.equal(await page.locator('.engine-row').count(), 0);
    await page.screenshot({ path: path.join(output, 'interrupted-1440.png'), fullPage: true });
    await page.goto(base + `/linen/detail/?task=${normal.id}&file=0`, { waitUntil: 'networkidle' });
    await page.locator('.engine-row').first().waitFor();
    const download = page.waitForEvent('download'); await page.getByRole('button', { name: '导出 JSON', exact: true }).click();
    const downloaded = await download; await downloaded.saveAs(path.join(output, 'persisted-report.json'));
    const exported = JSON.parse(await fs.readFile(path.join(output, 'persisted-report.json'), 'utf8'));
    assert.equal(exported.file.report.sha256, completed.files[0].report.sha256);
    await page.setViewportSize({ width: 375, height: 812 });
    await page.screenshot({ path: path.join(output, 'persisted-detail-375.png'), fullPage: true });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    assert.equal(jsErrors.length, 0);
    note('real browser restored history, interrupted resubmit state, completed export and mobile layout');
    await browser.close(); browser = null;
    await stop(); await start(.7, 1.1);
    const timeouts = await Promise.all([submit([file('timeout-inert.exe', inert)], 'timeout'), submit([file('queued-deadline.exe', inert)], 'queue-timeout')]);
    const expired = await Promise.all(timeouts.map(job => finish(job.id)));
    assert(expired.every(job => job.files[0].status === 'timed_out' && job.files[0].report === null));
    record.timeout_statuses = expired.map(job => ({ task: job.status, file: job.files[0].status, elapsed_ms: job.files[0].elapsed_ms }));
    record.resources_after = await resources();
    assert.equal(record.resources_after.reserved_bytes, 0); assert.equal(record.resources_after.pending, 0); assert.equal(record.resources_after.worker_pid, null);
    note('per-file and queue-inclusive task deadlines, no false negative and process release');
    await stop(); await start();
    for (const expected of expired) assert.deepEqual(await (await request('/v1/tasks/' + expected.id)).json(), expected);
    note('timeout and failure records survive another actual service restart');
    const queued = [];
    for (let i = 0; i < 4; i++) queued.push(await submit([file(`budget-${i}.exe`, inert)], 'budget-' + i));
    assert.equal((await request('/v1/tasks', 'POST', { files: [file('overflow.exe', inert)] }, 'overflow')).status, 429);
    assert.equal((await submit([file('budget-0.exe', inert)], 'budget-0')).id, queued[0].id);
    for (const job of queued) await request('/v1/tasks/' + job.id + '/cancel', 'POST');
    await Promise.all(queued.map(job => finish(job.id)));
    assert.equal((await resources()).pending, 0); assert.equal((await resources()).reserved_bytes, 0);
    note('four-task backpressure, replay under full queue, cancellation of queued and running jobs');
    record.unique_vendor_pe = 1; record.malicious_samples = 0;
    record.private_state_bytes = (await Promise.all((await fs.readdir(state)).map(async name => (await fs.stat(path.join(state, name))).size))).reduce((a, b) => a + b, 0);
    record.private_evidence_retained = true;
    await fs.writeFile(path.join(output, 'private-state-location.txt'), state + '\n');
  } catch (error) { record.failures.push(error.message.replaceAll(key || '\0', '[redacted]')); }
  finally {
    if (browser) await browser.close();
    await stop();
    await fs.writeFile(path.join(root, 'docs/benchmarks/task_reliability_check_20261016.json'), JSON.stringify(record, null, 2) + '\n');
  }
  console.log(JSON.stringify({ checks: record.checks.length, failures: record.failures, engines: record.engine_statuses }));
  assert.equal(record.failures.length, 0);
})().catch(error => { console.error(error.message); process.exitCode = 1; });
