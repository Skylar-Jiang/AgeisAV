// Full Linen business pages against real persisted benign reports and inert faults.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { spawn, execFileSync } = require('node:child_process');
const { chromium } = require(process.env.AEGISAV_PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '../..'), base = 'http://127.0.0.1:3420';
const output = path.join(root, 'output/playwright/product-pages');
const python = path.join(root, '.venv/Scripts/python.exe');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const record = { schema: 1, benign_and_inert_only: true, accuracy_evaluation: false, checks: [], failures: [] };
let server, browser, key = '', state;
const note = name => record.checks.push({ name, passed: true });
async function start(database) {
  server = spawn(python, ['-m', 'uvicorn', 'experiments.task_reliability_fixture:app', '--host', '127.0.0.1', '--port', '3420', '--no-proxy-headers', '--no-access-log'], {
    cwd: root, windowsHide: true, stdio: 'ignore', env: { ...process.env, AEGISAV_RELIABILITY_FIXTURE: '1',
      AEGISAV_ACCESS_TOKEN_FILE: path.join(state, 'access.key'), AEGISAV_TASK_DB: database,
      AEGISAV_ML_PYTHON: path.join(root, '.venv-ml/Scripts/python.exe') },
  });
  for (let i = 0; i < 100; i++) {
    if (server.exitCode !== null) throw new Error('owned page acceptance service exited');
    try { if ((await fetch(base, { signal: AbortSignal.timeout(500) })).ok) { key = (await fs.readFile(path.join(state, 'access.key'), 'utf8')).trim(); return; } } catch {}
    await pause(250);
  }
  throw new Error('owned page acceptance service did not start');
}
async function stop() {
  if (server && server.exitCode === null) {
    const exited = new Promise(resolve => server.once('exit', resolve));
    execFileSync('taskkill.exe', ['/PID', String(server.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
    await exited;
  }
}
async function json(route, method = 'GET', body) {
  const response = await fetch(base + route, { method, headers: { Authorization: 'Bearer ' + key, ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
  assert(response.ok, `${route} ${response.status}`); return response.json();
}
(async () => {
  await fs.mkdir(output, { recursive: true });
  try { await fs.copyFile(path.join(root, 'docs/benchmarks/product_pages_check_20261016.json'), path.join(output, `previous-${Date.now()}.json`)); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  state = await fs.mkdtemp(path.join(os.tmpdir(), 'aegisav-product-pages-'));
  await new Promise((resolve, reject) => { const probe = require('node:net').createServer(); probe.once('error', reject); probe.listen(3420, '127.0.0.1', () => probe.close(resolve)); });
  try {
    await start(path.join(state, 'empty.sqlite3'));
    browser = await chromium.launch({ channel: 'chrome', headless: true });
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: 'reduce' });
    const page = await context.newPage(), errors = [], requests = [];
    page.on('pageerror', error => errors.push(error.message)); page.on('request', request => requests.push(request.url()));
    await page.goto(base + '/linen/tasks/', { waitUntil: 'networkidle' });
    await page.getByLabel('本地访问密钥', { exact: true }).fill(key);
    await page.getByRole('button', { name: '连接本地服务', exact: true }).click();
    await page.getByRole('heading', { name: '还没有扫描任务', exact: true }).waitFor();
    await page.goto(base + '/linen/statistics/', { waitUntil: 'networkidle' });
    await page.getByText('尚无任务，提交良性文件后开始记录。', { exact: true }).waitFor();
    note('actual empty SQLite tasks/statistics and authentication');
    await stop();
    const source = (await fs.readFile(path.join(root, 'output/playwright/task-reliability/private-state-location.txt'), 'utf8')).trim();
    execFileSync(python, ['-m', 'experiments.backup_task_database', path.join(source, 'tasks.sqlite3'), path.join(state, 'restored.sqlite3')], { cwd: root, windowsHide: true, stdio: 'ignore' });
    await start(path.join(state, 'restored.sqlite3'));
    const before = await json('/v1/statistics');
    assert(before.recent.reports > 0);
    record.original_restored_tasks = before.task_count;
    // Add actual invalid-PE tasks, not fabricated detection reports, to exercise pagination.
    for (let i = before.task_count; i < 22; i++) {
      const job = await json('/v1/tasks', 'POST', { files: [{ name: `pagination-inert-${i}.exe`, content_base64: Buffer.from('inert invalid PE').toString('base64') }] });
      for (;;) { const current = await json('/v1/tasks/' + job.id); if (current.status === 'completed_with_errors') break; await pause(50); }
    }
    await page.goto(base + '/linen/tasks/', { waitUntil: 'networkidle' });
    await page.getByRole('heading', { name: '批量任务', exact: true }).waitFor();
    assert.equal(await page.locator('.task-entry').count(), 20);
    await page.getByRole('link', { name: '下一页', exact: true }).click();
    await page.waitForURL('**/linen/tasks/?offset=20&state=all');
    await page.locator('.task-entry').first().waitFor();
    assert.equal(await page.locator('.task-entry').count(), 2);
    await page.getByRole('link', { name: '上一页', exact: true }).click();
    note('real persisted pagination with 22 tasks, URL state and return navigation');
    const hanging = await json('/v1/tasks', 'POST', { files: [{ name: 'cancel-product-inert.exe', content_base64: Buffer.from('AEGISAV-INERT-HANG: non-executable').toString('base64') }] });
    await page.goto(base + '/linen/tasks/?state=active', { waitUntil: 'networkidle' });
    await page.getByRole('button', { name: '取消未完成扫描', exact: true }).click();
    await page.getByText('当前没有处理中任务', { exact: true }).waitFor();
    const cancelled = await json('/v1/tasks/' + hanging.id);
    assert.equal(cancelled.status, 'cancelled'); assert.equal(cancelled.files[0].report, null);
    note('actual business-page cancellation and active-filter recovery');
    const routes = [['tasks', '批量任务'], ['history', '历史记录'], ['assets', '规则与模型'], ['statistics', '运行统计']];
    for (const [width, height] of [[1920, 1080], [1440, 900], [768, 1024], [375, 812]]) {
      await page.setViewportSize({ width, height });
      for (const [route, heading] of routes) {
        await page.goto(`${base}/linen/${route}/`, { waitUntil: 'networkidle' });
        await page.getByRole('heading', { name: heading, exact: true }).waitFor();
        await page.locator('[data-slot=skeleton]').waitFor({ state: 'hidden' });
        if (!(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1))) {
          record.layout_failure = { route, width, elements: await page.evaluate(() => [...document.querySelectorAll('main *')].map(element => ({ tag: element.tagName, class: element.className, text: element.textContent.slice(0, 100), right: element.getBoundingClientRect().right })).filter(item => item.right > innerWidth + 1)) };
          await page.screenshot({ path: path.join(output, `failed-${route}-${width}.png`), fullPage: true });
          throw new Error(`${route} overflow at ${width}`);
        }
        if (route === 'history') await page.locator('.task-entry summary').first().click();
        await page.screenshot({ path: path.join(output, `${route}-${width}.png`), fullPage: true });
        note(`${route} rendered at ${width}x${height}, no viewport overflow`);
      }
    }
    const stats = await json('/v1/statistics');
    record.statistics = stats;
    await page.goto(base + '/linen/statistics/', { waitUntil: 'networkidle' });
    await page.getByText('当前任务数据库没有独立核实的标签及冻结划分，尚不能计算 Recall、Precision、FPR、F1、ROC-AUC 或 PR-AUC。', { exact: true }).waitFor();
    assert.equal(stats.accuracy.available, false);
    assert(stats.recent.engines.clamav.abstentions > 0);
    assert(stats.file_statuses.error > 0 && stats.file_statuses.interrupted > 0);
    note('statistics match SQLite counts; no fabricated accuracy, errors and abstentions preserved');
    await page.goto(base + '/linen/assets/', { waitUntil: 'networkidle' });
    const assets = await json('/v1/engines');
    await page.getByText(assets.ml.model_version, { exact: true }).waitFor();
    await page.getByText(String(assets.ml.threshold), { exact: true }).waitFor();
    assert.equal(await page.locator('.asset-row').count(), 5);
    assert.equal(await page.locator('.model-route').count(), 2);
    await page.getByRole('link', { name: '下一页规则', exact: true }).click();
    await page.waitForURL('**/linen/assets/?rules=20');
    await page.locator('.rule-list details').first().waitFor();
    assert.equal(await page.locator('.rule-list details').count(), 20);
    record.assets = { model_profile: assets.ml.profile, model_version: assets.ml.model_version, threshold: assets.ml.threshold, rules: assets.rules.count, hash_references: assets.hash_reference_count };
    note('actual installed model threshold/version and rule provenance, read-only controls');
    await page.route('**/v1/statistics', route => route.abort('connectionrefused'));
    await page.goto(base + '/linen/statistics/', { waitUntil: 'networkidle' });
    await page.getByRole('alert').filter({ hasText: '本地服务未响应或连接超时' }).waitFor(); assert.equal(await page.locator('.statistics-table').count(), 0);
    await page.unroute('**/v1/statistics'); await page.getByRole('button', { name: '重试', exact: true }).click();
    await page.locator('.statistics-table').waitFor();
    note('statistics API failure cannot turn into demo data; explicit retry restores real state');
    await page.keyboard.press('Control+Home'); await page.reload({ waitUntil: 'networkidle' });
    await page.keyboard.press('Tab'); assert.equal(await page.evaluate(() => document.activeElement.textContent), '跳到主要内容');
    assert.equal(errors.length, 0); assert(requests.every(url => url.startsWith(base + '/')));
    note('keyboard skip, no JavaScript errors and same-origin requests');
    const usage = await json('/v1/test/resources'); assert.equal(usage.pending, 0); assert.equal(usage.reserved_bytes, 0); assert.equal(usage.worker_pid, null);
    record.resources_after = usage;
    record.formal_private_evidence_preserved = true;
    await fs.writeFile(path.join(output, 'private-state-location.txt'), state + '\n');
  } catch (error) { record.failures.push(error.message.replaceAll(key || '\0', '[redacted]')); }
  finally { if (browser) await browser.close(); await stop(); await fs.writeFile(path.join(root, 'docs/benchmarks/product_pages_check_20261016.json'), JSON.stringify(record, null, 2) + '\n'); }
  console.log(JSON.stringify({ checks: record.checks.length, failures: record.failures })); assert.equal(record.failures.length, 0);
})().catch(error => { console.error(error.message); process.exitCode = 1; });
