// Real local FastAPI + installed engines. Only vendor-shipped benign PE and inert bytes.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { spawn, execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { chromium } = require(process.env.AEGISAV_PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '../..');
const base = 'http://127.0.0.1:3418';
const output = path.join(root, 'output/playwright/live-api');
const keyPath = path.join(process.env.LOCALAPPDATA, 'AegisAV/local-access.key');
const python = path.join(root, '.venv/Scripts/python.exe');

(async () => {
  await fs.mkdir(output, { recursive: true });
  const privateState = await fs.mkdtemp(path.join(require('node:os').tmpdir(), 'aegisav-live-api-'));
  await new Promise((resolve, reject) => {
    const probe = require('node:net').createServer();
    probe.once('error', reject);
    probe.listen(3418, '127.0.0.1', () => probe.close(resolve));
  });
  const report = { schema: 1, functional_benign_only: true, accuracy_evaluation: false, checks: [], failures: [] };
  const server = spawn(python, ['-m', 'uvicorn', 'aegisav.main:app', '--host', '127.0.0.1', '--port', '3418', '--no-proxy-headers', '--no-access-log'], {
    cwd: root, windowsHide: true, stdio: 'ignore', env: { ...process.env, AEGISAV_ACCESS_TOKEN_FILE: keyPath, AEGISAV_TASK_DB: path.join(privateState, 'tasks.sqlite3'), AEGISAV_ML_PYTHON: path.join(root, '.venv-ml/Scripts/python.exe') },
  });
  let browser;
  let accessKey = '';
  try {
    let online = false;
    for (let attempt = 0; attempt < 90; attempt++) {
      if (server.exitCode !== null) throw new Error('Owned test service exited during startup');
      try { if ((await fetch(base, { signal: AbortSignal.timeout(1000) })).ok) { online = true; break; } } catch {}
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    assert(online, 'test service did not start');
    accessKey = (await fs.readFile(keyPath, 'utf8')).trim();
    browser = await chromium.launch({ channel: 'chrome', headless: true });
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: 'reduce' });
    const page = await context.newPage();
    page.setDefaultTimeout(10000);
    const errors = [], requests = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => requests.push(request.url()));
    await page.goto(base + '/linen/', { waitUntil: 'networkidle' });
    await page.getByRole('heading', { name: '连接你的本地检测服务' }).waitFor();
    assert.equal(await page.getByText('Quarterly_Report.exe', { exact: true }).count(), 0);
    await page.getByLabel('本地访问密钥', { exact: true }).fill('invalid-test-key');
    await page.getByRole('button', { name: '连接本地服务', exact: true }).click();
    await page.getByText('连接失败。请核对本地访问密钥与服务状态。', { exact: true }).waitFor();
    await page.getByLabel('本地访问密钥', { exact: true }).fill(accessKey);
    await page.getByRole('button', { name: '连接本地服务', exact: true }).click();
    await page.getByRole('button', { name: '选择文件', exact: true }).waitFor();
    report.checks.push({ flow: 'authentication, incorrect key, no automatic demo fallback', passed: true });
    const benign = await fs.readFile('C:/Windows/System32/notepad.exe');
    const digest = createHash('sha256').update(benign).digest('hex');
    await page.locator('input[type=file]').setInputFiles([
      { name: 'vendor-notepad.exe', mimeType: 'application/octet-stream', buffer: benign },
      { name: 'invalid-inert-fixture.exe', mimeType: 'application/octet-stream', buffer: Buffer.from('inert invalid PE; never executed') },
      { name: 'vendor-notepad-copy.exe', mimeType: 'application/octet-stream', buffer: benign },
    ]);
    const submitted = page.waitForResponse(response => response.url() === base + '/v1/tasks' && response.request().method() === 'POST');
    await page.getByRole('button', { name: '开始扫描', exact: true }).click();
    const response = await submitted;
    assert.equal(response.status(), 202);
    const identity = (await response.json()).id;
    let job;
    for (let attempt = 0; attempt < 150; attempt++) {
      job = await (await context.request.get(base + '/v1/tasks/' + identity)).json();
      if (['completed', 'completed_with_errors'].includes(job.status)) break;
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    assert.equal(job.status, 'completed_with_errors');
    assert.equal(job.finished, 3);
    assert.equal(job.files[0].report.sha256, digest);
    assert.equal(job.files[1].status, 'error');
    assert.equal(job.files[1].report, null);
    assert.equal(job.files[2].duplicate_of, 0);
    assert.equal(job.files[2].report.sha256, digest);
    assert.deepEqual(Object.keys(job.files[0].report.engines).sort(), ['sha256', 'fuzzy', 'yara_x', 'clamav', 'lightgbm'].sort());
    report.engine_statuses = Object.fromEntries(Object.entries(job.files[0].report.engines).map(([id, engine]) => [id, engine.status]));
    report.file_wall_ms = job.files[0].elapsed_ms;
    report.functional_files = { submitted: 3, unique_benign: 1, inert_invalid: 1, duplicate: 1 };
    report.checks.push({ flow: 'actual batch, SHA independently checked, parser failure, duplicate reuse, five engine results', passed: true });
    await page.getByText('已处理 3 / 3 个文件', { exact: true }).waitFor();
    await page.getByRole('link', { name: '查看 vendor-notepad.exe 检测详情', exact: true }).click();
    await page.getByRole('heading', { name: 'vendor-notepad.exe', exact: true }).waitFor();
    assert.equal(await page.locator('.engine-row').count(), 5);
    assert(await page.getByText(digest, { exact: true }).isVisible());
    assert.equal(await page.getByText('演示报告', { exact: true }).count(), 0);
    const downloaded = page.waitForEvent('download');
    await page.getByRole('button', { name: '导出 JSON', exact: true }).click();
    const download = await downloaded;
    await download.saveAs(path.join(output, 'real-benign-report.json'));
    const exported = JSON.parse(await fs.readFile(path.join(output, 'real-benign-report.json'), 'utf8'));
    assert.equal(exported.data_origin, 'local_api');
    assert.equal(exported.file.report.sha256, digest);
    await page.reload({ waitUntil: 'networkidle' });
    await page.getByRole('heading', { name: 'vendor-notepad.exe', exact: true }).waitFor();
    report.checks.push({ flow: 'real details, versions/evidence, JSON export, reload', passed: true });
    for (const [width, height] of [[1920, 1080], [1440, 900], [1024, 720], [768, 1024], [375, 812], [812, 375]]) {
      await page.setViewportSize({ width, height });
      for (const [view, route] of [['workspace', '/linen/'], ['detail', `/linen/detail/?task=${identity}&file=0`]]) {
        await page.goto(base + route, { waitUntil: 'networkidle' });
        await page.getByRole('heading', { name: view === 'detail' ? 'vendor-notepad.exe' : /从一个文件/ }).waitFor();
        if (view === 'detail') await page.locator('.engine-row').first().waitFor();
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `${view} overflow at ${width}`);
        await page.screenshot({ path: path.join(output, `${view}-${width}.png`), fullPage: true });
        report.checks.push({ view, width, height, passed: true });
      }
    }
    await page.goto(`${base}/linen/detail/?task=${identity}&file=1`, { waitUntil: 'networkidle' });
    await page.getByRole('heading', { name: 'invalid-inert-fixture.exe', exact: true }).waitFor();
    assert.equal(await page.locator('.engine-row').count(), 0);
    assert(await page.getByText('未获得检测报告，不能据此判断文件安全。', { exact: true }).isVisible());
    await page.goto(base + '/linen/detail/?task=' + 'f'.repeat(32), { waitUntil: 'networkidle' });
    await page.getByRole('heading', { name: '报告暂不可用', exact: true }).waitFor();
    assert.equal(await page.getByText('Quarterly_Report.exe', { exact: true }).count(), 0);
    report.checks.push({ flow: 'failed and missing reports never become negative or demo reports', passed: true });
    await page.goto(base + '/linen/', { waitUntil: 'networkidle' });
    await page.route('**/v1/tasks', route => route.abort('connectionrefused'));
    await page.getByRole('alert').filter({ hasText: '本地服务未响应或连接超时' }).waitFor();
    await page.unroute('**/v1/tasks');
    await page.getByRole('button', { name: '重新连接', exact: true }).click();
    await page.getByRole('link', { name: '查看 vendor-notepad.exe 检测详情', exact: true }).waitFor();
    report.checks.push({ flow: 'injected connection failure and explicit recovery', passed: true, injected: true });
    await page.locator('input[type=file]').setInputFiles([
      { name: 'cancel-benign.exe', mimeType: 'application/octet-stream', buffer: benign },
      { name: 'cancel-inert.exe', mimeType: 'application/octet-stream', buffer: Buffer.from('never scanned after cancellation') },
      { name: 'cancel-copy.exe', mimeType: 'application/octet-stream', buffer: benign },
    ]);
    const cancelSubmission = page.waitForResponse(response => response.url() === base + '/v1/tasks' && response.request().method() === 'POST');
    await page.getByRole('button', { name: '开始扫描', exact: true }).click();
    const cancelId = (await (await cancelSubmission).json()).id;
    await page.getByRole('button', { name: '取消任务', exact: true }).click();
    let cancelled;
    for (let attempt = 0; attempt < 150; attempt++) {
      cancelled = await (await context.request.get(base + '/v1/tasks/' + cancelId)).json();
      if (cancelled.status === 'cancelled') break;
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    assert.equal(cancelled.status, 'cancelled');
    assert(cancelled.files.some(file => file.status === 'cancelled' && file.report === null));
    await page.getByRole('button', { name: '取消任务', exact: true }).waitFor({ state: 'hidden' });
    report.checks.push({ flow: 'actual UI cancellation preserves partial results and skips unstarted files', passed: true });
    report.cancellation_files = cancelled.files.map(file => file.status);
    await page.route('**/v1/tasks/*', route => route.request().method() === 'GET' ? route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ detail: 'Injected lost task' }) }) : route.continue());
    await page.locator('input[type=file]').setInputFiles({ name: 'lost-task-inert.exe', mimeType: 'application/octet-stream', buffer: Buffer.from('inert recovery fixture') });
    await page.getByRole('button', { name: '开始扫描', exact: true }).click();
    await page.getByRole('button', { name: '清除失效任务', exact: true }).waitFor();
    await page.getByRole('button', { name: '清除失效任务', exact: true }).click();
    await page.unroute('**/v1/tasks/*');
    await page.locator('input[type=file]').setInputFiles({ name: 'session-resume-inert.exe', mimeType: 'application/octet-stream', buffer: Buffer.from('another inert recovery fixture') });
    assert(await page.getByRole('button', { name: '开始扫描', exact: true }).isEnabled());
    report.checks.push({ flow: 'injected active-task 404 clears stale lock and permits new submission', passed: true, injected: true });
    let expired = true;
    const expiryRoute = url => url.origin === base && (url.pathname === '/v1/tasks' || /^\/v1\/tasks\/[a-f0-9]{32}$/.test(url.pathname));
    await page.route(expiryRoute, route => expired && route.request().method() === 'GET' ? route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ detail: 'Injected session expiry' }) }) : route.continue());
    await page.getByRole('button', { name: '开始扫描', exact: true }).click();
    await page.getByRole('heading', { name: '连接你的本地检测服务' }).waitFor();
    await page.getByRole('alert').filter({ hasText: '会话已过期，请重新认证后读取任务。' }).waitFor();
    await page.getByLabel('本地访问密钥', { exact: true }).fill(accessKey);
    expired = false;
    await page.getByRole('button', { name: '连接本地服务', exact: true }).click();
    await page.getByText('已处理 1 / 1 个文件', { exact: true }).waitFor();
    await page.unroute(expiryRoute);
    report.checks.push({ flow: 'reauthentication resumes previously unauthorized active-task polling', passed: true, injected: true });
    report.additional_inert_recovery_files = 2;
    await page.keyboard.press('Control+Home');
    await page.reload({ waitUntil: 'networkidle' });
    await page.keyboard.press('Tab');
    assert.equal(await page.evaluate(() => document.activeElement.textContent), '跳到主要内容');
    await page.keyboard.press('Enter');
    assert.equal(await page.evaluate(() => document.activeElement.id), 'main-content');
    const listing = await (await context.request.get(base + '/v1/tasks')).json();
    const allFiles = listing.tasks.flatMap(task => task.files);
    report.file_accounting = { total: allFiles.length, completed_report_rows: allFiles.filter(file => file.status === 'completed').length, error_rows: allFiles.filter(file => file.status === 'error').length, cancelled_rows: allFiles.filter(file => file.status === 'cancelled').length };
    assert.equal(report.file_accounting.total, 8);
    await page.getByRole('button', { name: '断开会话', exact: true }).click();
    await page.getByRole('heading', { name: '连接你的本地检测服务' }).waitFor();
    report.checks.push({ flow: 'keyboard skip and logout', passed: true });
    assert.equal(errors.length, 0, errors.join('\n'));
    assert(requests.every(url => url.startsWith(base + '/') || url.startsWith('blob:')), 'non-local network request');
    report.javascript_errors = errors;
  } catch (error) { report.failures.push(error.message.replaceAll(accessKey || '\0', '[redacted]')); }
  finally {
    if (browser) await browser.close();
    if (server.exitCode === null) execFileSync('taskkill.exe', ['/PID', String(server.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
    await fs.writeFile(path.join(root, 'docs/benchmarks/live_api_check_20261016.json'), JSON.stringify(report, null, 2) + '\n');
  }
  console.log(JSON.stringify({ checks: report.checks.length, failures: report.failures, engines: report.engine_statuses }));
  assert.equal(report.failures.length, 0);
})().catch(error => { console.error(error.message); process.exitCode = 1; });
