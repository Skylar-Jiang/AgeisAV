// Browser plugin not available. Real Playwright + local API, harmless log descriptions only.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { spawn, execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { chromium } = require(process.env.AEGISAV_PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '../..'), base = 'http://127.0.0.1:3422';
const python = path.join(root, '.venv/Scripts/python.exe');
const output = path.join(root, 'output/playwright/behavior');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
let server, browser, state, key = '';
const evidence = { schema: 1, harmless_only: true, program_execution: false, accuracy_evaluation: false, checks: [], failures: [] };
const note = name => evidence.checks.push({ name, passed: true });
async function start() {
  server = spawn(python, ['-m', 'uvicorn', 'aegisav.main:app', '--host', '127.0.0.1', '--port', '3422', '--no-proxy-headers', '--no-access-log'], {
    cwd: root, windowsHide: true, stdio: 'ignore', env: { ...process.env, AEGISAV_ACCESS_TOKEN_FILE: path.join(state, 'access.key'), AEGISAV_TASK_DB: path.join(state, 'tasks.sqlite3'), AEGISAV_ML_PYTHON: path.join(root, '.venv-ml/Scripts/python.exe') },
  });
  for (let i = 0; i < 100; i++) {
    if (server.exitCode !== null) throw new Error('Owned acceptance service exited');
    try { if ((await fetch(base, { signal: AbortSignal.timeout(500) })).ok) { key = (await fs.readFile(path.join(state, 'access.key'), 'utf8')).trim(); return; } } catch {}
    await pause(250);
  }
  throw new Error('Acceptance service startup timeout');
}
async function stop() {
  if (server && server.exitCode === null) {
    const exited = new Promise(resolve => server.once('exit', resolve));
    execFileSync('taskkill.exe', ['/PID', String(server.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
    await exited;
  }
}
async function request(route, options = {}) {
  const response = await fetch(base + route, { ...options, headers: { Authorization: 'Bearer ' + key, ...options.headers } });
  assert(response.ok, `API ${route} returned ${response.status}`); return response.json();
}
function event(id, second, fields) { return { event_id: id, computer: 'harmless-fixture.local', provider: 'Microsoft-Windows-Sysmon', timestamp: `2026-10-19T00:00:0${second}Z`, record_id: String(second), fields }; }
(async () => {
  await fs.mkdir(output, { recursive: true });
  state = await fs.mkdtemp(path.join(os.tmpdir(), 'aegisav-behavior-'));
  try {
    await new Promise((resolve, reject) => { const probe = require('node:net').createServer(); probe.once('error', reject); probe.listen(3422, '127.0.0.1', () => probe.close(resolve)); });
    await start();
    browser = await chromium.launch({ channel: 'chrome', headless: true });
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
    const page = await context.newPage(), errors = [], requests = [];
    page.on('pageerror', error => errors.push(error.message)); page.on('request', request => requests.push(request.url()));
    await page.goto(base + '/linen/behavior/', { waitUntil: 'networkidle' });
    await page.getByLabel('本地访问密钥', { exact: true }).fill(key);
    await page.getByRole('button', { name: '连接本地服务', exact: true }).click();
    await page.getByRole('heading', { name: '把行为，留在证据里。', exact: true }).waitFor();
    assert(await page.getByText(/当前没有打开行为日志/).isVisible()); note('authenticated empty not_observed; no demo fallback');
    // Real existing static pipeline on an OS-supplied benign file; never execute it.
    const pe = await fs.readFile('C:/Windows/System32/notepad.exe');
    const sha = createHash('sha256').update(pe).digest('hex');
    let task = await request('/v1/tasks', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ files: [{ name: 'vendor-notepad.exe', content_base64: pe.toString('base64') }] }) });
    for (let i = 0; i < 180; i++) { task = await request('/v1/tasks/' + task.id); if (task.files[0].report) break; if (['failed', 'completed_with_errors', 'timed_out'].includes(task.status)) break; await pause(500); }
    assert.equal(task.files[0].report.sha256, sha); evidence.static_engine_statuses = Object.fromEntries(Object.entries(task.files[0].report.engines).map(([id, value]) => [id, value.status]));
    await page.goto(`${base}/linen/detail/?task=${task.id}&file=0`, { waitUntil: 'networkidle' });
    await page.getByText(/没有与此 SHA-256 关联的行为日志/).waitFor();
    await page.getByRole('link', { name: '导入日志并尝试精确关联', exact: true }).click();
    const rows = [event(1, 1, { ProcessGuid: '{parent}', ProcessId: '20', Image: 'C:\\Windows\\notepad.exe', CommandLine: 'notepad.exe', Hashes: 'SHA256=' + sha }),
      event(1, 2, { ProcessGuid: '{child}', ParentProcessGuid: '{parent}', ProcessId: '21', Image: 'C:\\Windows\\System32\\certutil.exe', CommandLine: 'certutil -urlcache https://example.invalid/inert.txt <img src=x onerror=alert(1)>' }),
      event(3, 3, { ProcessGuid: '{child}', ProcessId: '21', DestinationIp: '192.0.2.1', DestinationPort: '443' }),
      event(11, 4, { ProcessGuid: '{child}', TargetFilename: 'C:\\Lab\\inert.txt' }),
      event(13, 5, { ProcessGuid: '{child}', TargetObject: 'HKCU\\Software\\AegisAV\\Fixture', Details: 'inert' }),
      event(5, 6, { ProcessGuid: '{child}', ProcessId: '21' })];
    await page.getByLabel('Sysmon 日志文件', { exact: true }).setInputFiles({ name: 'harmless-sysmon.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify({ events: rows })) });
    const imported = page.waitForResponse(r => r.url().startsWith(base + '/v1/behavior?task=') && r.request().method() === 'POST');
    await page.getByRole('button', { name: '分析日志', exact: true }).click();
    const response = await imported; assert.equal(response.status(), 201); const result = await response.json();
    assert.equal(result.status, 'matched'); assert.equal(result.events.length, 6); assert.equal(result.processes.length, 2); assert.equal(result.matches.length, 1);
    assert.equal(result.static_link.status, 'log_claimed_sha256'); assert.equal(result.static_link.authenticity_verified, false);
    await page.getByRole('heading', { name: '行为证据', exact: true }).waitFor();
    await page.getByRole('button', { name: '查看证据 e1', exact: true }).click();
    await page.locator('pre[aria-label="事件 e1 原始字段"]').waitFor();
    assert.equal(await page.locator('pre img').count(), 0); assert(await page.locator('pre').innerText().then(t => t.includes('<img')));
    note('real bounded import, Sigma match, parent-child/network/file/registry evidence, inert command XSS escaped, exact static hash link');
    const downloadEvent = page.waitForEvent('download'); await page.getByRole('button', { name: '导出行为 JSON', exact: true }).click();
    const download = await downloadEvent; await download.saveAs(path.join(output, 'harmless-report.json'));
    assert.equal(JSON.parse(await fs.readFile(path.join(output, 'harmless-report.json'), 'utf8')).behavior.id, result.id);
    await page.getByRole('button', { name: '显示全部事件', exact: true }).click();
    for (const [width, height] of [[1440, 1000], [1024, 768], [768, 1024], [375, 812], [812, 375]]) {
      await page.setViewportSize({ width, height });
      const fits = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1);
      if (!fits) evidence.overflow = await page.evaluate(() => [...document.querySelectorAll('body *')].filter(e => e.getBoundingClientRect().right > innerWidth + 1).slice(0, 16).map(e => ({ tag: e.tagName, class: e.className, width: e.getBoundingClientRect().width, text: e.textContent.slice(0, 80) })));
      await page.screenshot({ path: path.join(output, `behavior-${width}.png`), fullPage: true });
      assert(fits, `overflow at ${width}`);
      note(`real browser screenshot and no horizontal overflow ${width}x${height}`);
    }
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.getByLabel('Sysmon 日志文件', { exact: true }).setInputFiles({ name: 'bad.xml', mimeType: 'text/xml', buffer: Buffer.from('<!DOCTYPE x [<!ENTITY e "x">]><Events>&e;</Events>') });
    await page.getByRole('button', { name: '分析日志', exact: true }).click();
    await page.getByText(/XML DTD\/entities/).waitFor();
    assert.equal(await page.locator('#behavior-error').evaluate(e => e === document.activeElement), true); note('malformed entity input rejected and error receives keyboard focus');
    await page.getByLabel('Sysmon 日志文件', { exact: true }).setInputFiles({ name: 'oversize.json', mimeType: 'application/json', buffer: Buffer.alloc(4 * 1024 ** 2 + 1, 32) });
    await page.getByRole('button', { name: '分析日志', exact: true }).click(); await page.getByText(/文件不能超过 4 MB/).waitFor(); note('client-side byte cap explicit');
    await stop(); await start();
    const restored = await request('/v1/behavior/' + result.id); assert.deepEqual(restored, result);
    await page.goto(base + '/linen/behavior/?report=' + result.id, { waitUntil: 'networkidle' });
    await page.getByRole('heading', { name: '行为证据', exact: true }).waitFor();
    await page.goto(`${base}/linen/detail/?task=${task.id}&file=0`, { waitUntil: 'networkidle' });
    await page.getByRole('link', { name: /命中行为信号/ }).waitFor(); assert.equal(await page.locator('.engine-row').count(), 5);
    note('actual forced service stop/restart; SQLite report byte-equivalent and static detail cross-link, five engines intact');
    assert.equal(errors.length, 0); assert(requests.every(url => url.startsWith(base))); note('no page errors or external browser requests');
    evidence.report = { id: result.id, status: result.status, events: result.events.length, processes: result.processes.length, matches: result.matches.length, elapsed_ms: result.elapsed_ms };
    evidence.private_db_bytes = (await fs.stat(path.join(state, 'tasks.behavior.sqlite3'))).size;
  } catch (error) { evidence.failures.push(error.message); process.exitCode = 1; }
  finally {
    if (browser) await browser.close(); await stop();
    await fs.writeFile(path.join(output, 'check.json'), JSON.stringify(evidence, null, 2));
    if (state && path.dirname(state) === os.tmpdir() && path.basename(state).startsWith('aegisav-behavior-')) await fs.rm(state, { recursive: true, force: false });
    key = ''; console.log(JSON.stringify(evidence));
  }
})();
