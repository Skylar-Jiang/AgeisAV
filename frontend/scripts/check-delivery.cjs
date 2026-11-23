// Browser plugin unavailable; real Chrome + actual ZIP/runtime/service, no mocked detections.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');
const { createHash } = require('node:crypto');
const { chromium } = require(process.env.AEGISAV_PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '../..');
const bundle = process.env.AEGISAV_DELIVERY_ZIP;
assert(bundle, 'Set AEGISAV_DELIVERY_ZIP to the reviewed portable ZIP');
const output = process.env.AEGISAV_DELIVERY_OUTPUT || path.join(root, 'output/playwright/delivery');
const base = 'http://127.0.0.1:3426';
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const evidence = { schema: 1, real_service: true, harmless_only: true, accuracy_evaluation: false, checks: [], failures: [] };
const note = name => evidence.checks.push({ name, passed: true });
let temp, app, profile, env, browser, key = '', running = false;
async function command(exe, args, extra = {}) {
  const start = performance.now();
  return new Promise((resolve, reject) => {
    const p = spawn(exe, args, { cwd: app || root, env: env || process.env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], ...extra });
    const timer = setTimeout(() => { p.kill(); reject(new Error('Owned acceptance command exceeded 60 seconds')); }, 60000);
    let stdout = '', stderr = '';
    p.stdout.on('data', data => { stdout += data; }); p.stderr.on('data', data => { stderr += data; });
    p.on('error', error => { clearTimeout(timer); reject(error); });
    p.on('close', code => { clearTimeout(timer); resolve({ code, stdout, stderr, elapsed_ms: performance.now() - start }); });
  });
}
function runtime(args) { return command(path.join(app, 'runtime/python.exe'), ['-I', '-B', ...args]); }
function controller(action, args = []) { return runtime(['-m', 'aegisav.desktop', action, '--port', '3426', '--data-dir', profile, '--no-browser', ...args]); }
async function wrapper(name, args = []) {
  // Fixed script name/arguments; no string-built filesystem commands.
  return command(process.env.ComSpec || 'C:/Windows/System32/cmd.exe', ['/d', '/c', name, ...args]);
}
async function start() {
  const result = await wrapper('Start-AegisAV.cmd', ['--no-browser', '--port', '3426']);
  assert.equal(result.code, 0, result.stderr); running = true;
  key = (await fs.readFile(path.join(profile, 'local-access.key'), 'utf8')).trim();
  return result;
}
async function stop() {
  if (!running) return;
  const result = await wrapper('Stop-AegisAV.cmd');
  assert.equal(result.code, 0, result.stderr); running = false;
  assert.match(result.stdout, /stopped/);
  for (let i = 0; i < 20; i++) {
    try { await fetch(base, { signal: AbortSignal.timeout(300) }); } catch { return result; }
    await pause(100);
  }
  throw new Error('Listener survived confirmed Stop');
}
async function request(route, options = {}) {
  const response = await fetch(base + route, { ...options, headers: { Authorization: 'Bearer ' + key, ...options.headers } });
  assert(response.ok, `API ${route} ${response.status}`); return response.json();
}
async function terminal(id) {
  for (let i = 0; i < 240; i++) {
    const task = await request('/v1/tasks/' + id);
    if (!['queued', 'running', 'cancelling'].includes(task.status)) return task;
    await pause(250);
  }
  throw new Error('Task did not reach terminal state');
}
async function submit(files, headers = {}) {
  return request('/v1/tasks', { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify({ files }) });
}
async function serviceMemory() {
  const status = await request('/v1/desktop/status'); assert(Number.isInteger(status.pid));
  const measured = await command('C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe', ['-NoProfile', '-Command',
    `Get-Process -Id ${status.pid} | Select-Object WorkingSet64,PeakWorkingSet64,CPU | ConvertTo-Json -Compress`]);
  assert.equal(measured.code, 0, measured.stderr);
  return { ...JSON.parse(measured.stdout), scope: 'service only; excludes scan/model children; not a total tree peak' };
}
(async () => {
  await fs.mkdir(output, { recursive: true });
  temp = await fs.mkdtemp(path.join(os.tmpdir(), 'aegisav-delivery-'));
  app = path.join(temp, '软件 测试'); profile = path.join(temp, 'Private Settings/AegisAVDesktop');
  try {
    const bytes = await fs.readFile(bundle), digest = createHash('sha256').update(bytes).digest('hex');
    assert.equal((await fs.readFile(bundle + '.sha256', 'utf8')).split(/\s/)[0], digest);
    evidence.bundle = { sha256: digest, bytes: bytes.length };
    // Trusted own ZIP only. Host Python performs bounded path-checked extraction, never runs its contents.
    const extract = `import os,zipfile,pathlib\nr=pathlib.Path(os.environ['AEGISAV_TEST_EXTRACT']).resolve()\nr.mkdir()\nwith zipfile.ZipFile(os.environ['AEGISAV_TEST_ZIP']) as z:\n assert sum(x.file_size for x in z.infolist())<300*1024**2\n for x in z.infolist():\n  p=(r/x.filename).resolve()\n  assert p.is_relative_to(r) and ':' not in x.filename and '\\\\' not in x.filename\n  p.parent.mkdir(parents=True,exist_ok=True)\n  p.write_bytes(z.read(x))\n`;
    const installed = await command(path.join(root, '.venv/Scripts/python.exe'), ['-c', extract], { cwd: root, env: { ...process.env, AEGISAV_TEST_ZIP: bundle, AEGISAV_TEST_EXTRACT: app } });
    assert.equal(installed.code, 0, installed.stderr); evidence.extraction_ms = installed.elapsed_ms;
    const packageManifest = JSON.parse(await fs.readFile(path.join(app, 'PACKAGE_MANIFEST.json'), 'utf8'));
    profile = path.join(temp, 'Private Settings', packageManifest.ssdeep_backend === 'native' ? 'AegisAVDesktop-Candidate' : 'AegisAVDesktop');
    evidence.package_version = packageManifest.version;
    env = { ...process.env, LOCALAPPDATA: path.join(temp, 'Private Settings'), PATH: 'C:/Windows/System32', PYTHONHOME: path.join(temp, 'nonexistent'), PYTHONPATH: path.join(temp, 'nonexistent'), PYTHONNOUSERSITE: '1' };
    for (const name of Object.keys(env)) if (name.startsWith('AEGISAV_')) delete env[name];
    const isolated = await runtime(['-c', 'import sys,json,site;print(json.dumps(dict(version=sys.version,paths=sys.path,user_site=site.ENABLE_USER_SITE)))']);
    assert.equal(isolated.code, 0, isolated.stderr); const identity = JSON.parse(isolated.stdout);
    assert(identity.version.startsWith('3.12.15')); assert(identity.paths.every(p => p.startsWith(app)));
    evidence.runtime = identity; note('actual ZIP extracted to Unicode/space path; bundled Python ignores host environment and PATH');
    assert.equal((await wrapper('Verify-Package.cmd')).code, 0); note('full extracted package integrity verified');
    const started = await start(); evidence.startup_ms = started.elapsed_ms;
    const first = await request('/v1/desktop/status');
    evidence.core_service_memory = await serviceMemory();
    assert.equal((await controller('start')).code, 0); assert.equal((await request('/v1/desktop/status')).pid, first.pid);
    assert.equal((await fetch(base + '/v1/tasks')).status, 401); note('real Start script, single-instance reuse and unauthenticated denial');
    browser = await chromium.launch({ channel: 'chrome', headless: true });
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: 'reduce' });
    const page = await context.newPage(), errors = [], requests = []; page.setDefaultTimeout(15000);
    page.on('pageerror', e => errors.push(e.message)); page.on('request', r => requests.push(r.url()));
    await page.goto(base + '/linen/', { waitUntil: 'networkidle' });
    await page.getByLabel('本地访问密钥', { exact: true }).fill('inert-wrong-key');
    await page.getByRole('button', { name: '连接本地服务', exact: true }).click();
    await page.getByText('连接失败。请核对本地访问密钥与服务状态。', { exact: true }).waitFor();
    await page.getByLabel('本地访问密钥', { exact: true }).fill(key);
    await page.getByRole('button', { name: '连接本地服务', exact: true }).click();
    await page.getByRole('button', { name: '选择文件', exact: true }).waitFor(); note('real browser first login and wrong-key feedback');
    const pe = await fs.readFile('C:/Windows/System32/notepad.exe'), sha = createHash('sha256').update(pe).digest('hex');
    await page.locator('input[type=file]').setInputFiles([
      { name: 'vendor-notepad.exe', mimeType: 'application/octet-stream', buffer: pe },
      { name: 'invalid-inert.exe', mimeType: 'application/octet-stream', buffer: Buffer.from('inert invalid PE') },
      { name: 'vendor-copy.exe', mimeType: 'application/octet-stream', buffer: pe },
    ]);
    const submitted = page.waitForResponse(r => r.url() === base + '/v1/tasks' && r.request().method() === 'POST');
    await page.getByRole('button', { name: '开始扫描', exact: true }).click();
    const task = await terminal((await (await submitted).json()).id);
    assert.equal(task.status, 'completed_with_errors'); assert.equal(task.files[1].report, null);
    assert.equal(task.files[2].duplicate_of, 0); assert.equal(task.files[0].report.sha256, sha);
    evidence.core_engine_statuses = Object.fromEntries(Object.entries(task.files[0].report.engines).map(([id, e]) => [id, e.status]));
    assert.equal(evidence.core_engine_statuses.clamav, process.env.AEGISAV_TEST_CLAM_STATE === 'healthy' ? 'no_match' : 'unavailable');
    assert.equal(evidence.core_engine_statuses.lightgbm, 'unavailable');
    if (packageManifest.ssdeep_backend === 'native') assert.match(task.files[0].report.engines.fuzzy.engine_version, /native-ssdeep\/abi1\+[a-f0-9]{16}$/);
    assert.equal(Object.keys(evidence.core_engine_statuses).length, 5); evidence.core_file_wall_ms = task.files[0].elapsed_ms;
    note('real batch: benign PE, invalid parser input, duplicate reuse; five statuses with honest missing ML/ClamAV');
    await page.goto(`${base}/linen/detail/?task=${task.id}&file=0`, { waitUntil: 'networkidle' });
    await page.getByRole('heading', { name: 'vendor-notepad.exe', exact: true }).waitFor();
    assert.equal(await page.locator('.engine-row').count(), 5);
    const exported = page.waitForEvent('download'); await page.getByRole('button', { name: '导出 JSON', exact: true }).click();
    await (await exported).saveAs(path.join(output, 'benign-static-report.json'));
    assert.equal(JSON.parse(await fs.readFile(path.join(output, 'benign-static-report.json'), 'utf8')).file.report.sha256, sha);
    note('real evidence/detail and JSON export');
    const routes = [['workspace', '/linen/', /从一个文件/], ['detail', `/linen/detail/?task=${task.id}&file=0`, 'vendor-notepad.exe'],
      ['tasks', '/linen/tasks/', '批量任务'], ['history', '/linen/history/', '历史记录'], ['assets', '/linen/assets/', '规则与模型'], ['statistics', '/linen/statistics/', '运行统计']];
    for (const width of [1440, 375]) {
      await page.setViewportSize({ width, height: 900 });
      for (const [name, route, heading] of routes) {
        await page.goto(base + route, { waitUntil: 'networkidle' }); await page.getByRole('heading', { name: heading, exact: typeof heading === 'string' }).waitFor();
        await page.locator('[data-slot=skeleton]').waitFor({ state: 'hidden' });
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `${name} overflow ${width}`);
        await page.screenshot({ path: path.join(output, `${name}-${width}.png`), fullPage: true });
        note(`${name} actual browser and no overflow at ${width}`);
      }
    }
    const stats = await request('/v1/statistics'); assert.equal(stats.accuracy.available, false);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto(`${base}/linen/detail/?task=${task.id}&file=0`, { waitUntil: 'networkidle' });
    await page.getByRole('link', { name: '导入日志并尝试精确关联', exact: true }).click();
    const rows = JSON.parse(await fs.readFile(path.join(app, 'examples/sysmon_harmless.json'), 'utf8'));
    rows.events[0].fields.Hashes = 'SHA256=' + sha; // Explicit synthetic log claim; never program execution.
    await page.getByLabel('Sysmon 日志文件', { exact: true }).setInputFiles({ name: 'synthetic-claim.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(rows)) });
    const importing = page.waitForResponse(r => r.url().startsWith(base + '/v1/behavior?task=') && r.request().method() === 'POST');
    await page.getByRole('button', { name: '分析日志', exact: true }).click();
    const behavior = await (await importing).json(); assert.equal(behavior.matches.length, 1); assert.equal(behavior.processes.length, 2);
    assert.equal(behavior.static_link.status, 'log_claimed_sha256'); assert.equal(behavior.static_link.authenticity_verified, false);
    await page.getByRole('heading', { name: '行为证据', exact: true }).waitFor();
    await page.getByRole('button', { name: '查看证据 e1', exact: true }).click();
    await page.locator('pre[aria-label="事件 e1 原始字段"]').waitFor();
    const behaviorDownload = page.waitForEvent('download'); await page.getByRole('button', { name: '导出行为 JSON', exact: true }).click();
    await (await behaviorDownload).saveAs(path.join(output, 'synthetic-behavior-report.json'));
    for (const width of [1440, 375]) { await page.setViewportSize({ width, height: 900 }); assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)); await page.screenshot({ path: path.join(output, `behavior-${width}.png`), fullPage: true }); }
    note('real bounded behavior child, Sigma match, process chain, explicit synthetic static hash claim and export');
    const bad = await fetch(base + '/v1/behavior', { method: 'POST', headers: { Authorization: 'Bearer ' + key }, body: '<!DOCTYPE x [<!ENTITY e "x">]><Events>&e;</Events>' });
    assert.equal(bad.status, 422);
    const large = await fetch(base + '/v1/scan', { method: 'POST', headers: { Authorization: 'Bearer ' + key }, body: Buffer.alloc(16 * 1024 ** 2 + 1) }); assert.equal(large.status, 413);
    const peFile = { name: 'cancel-benign.exe', content_base64: pe.toString('base64') };
    const cancelling = await submit([peFile]); await request('/v1/tasks/' + cancelling.id + '/cancel', { method: 'POST' });
    const cancelled = await terminal(cancelling.id); assert.equal(cancelled.status, 'cancelled'); assert.equal(cancelled.files[0].report, null);
    note('actual malformed log/oversize input rejection and real benign-task cancellation with no negative report');
    const stopResult = await stop(); evidence.stop_ms = stopResult.elapsed_ms;
    const restarted = await start(); evidence.restart_ms = restarted.elapsed_ms;
    assert.deepEqual(await request('/v1/tasks/' + task.id), task); assert.deepEqual(await request('/v1/behavior/' + behavior.id), behavior);
    await page.goto(`${base}/linen/detail/?task=${task.id}&file=0`, { waitUntil: 'networkidle' });
    await page.getByRole('link', { name: /命中行为信号/ }).waitFor();
    note('actual Stop/Start; persisted static/behavior reports identical, cross-link restored');
    await page.keyboard.press('Control+Home'); await page.reload({ waitUntil: 'networkidle' }); await page.keyboard.press('Tab');
    assert.equal(await page.evaluate(() => document.activeElement.textContent), '跳到主要内容');
    assert.equal(errors.length, 0, errors.join('\n')); assert(requests.every(u => u.startsWith(base) || u.startsWith('blob:')));
    note('keyboard navigation, zero page errors and no external browser requests');
    // Optional existing private assets are configured by path; never copied into ZIP.
    if (process.env.AEGISAV_TEST_EXISTING_ML === '1') {
      await stop();
      const configured = await controller('configure', ['--model-dir', path.join(root, 'models/ember2024'), '--ml-python', path.join(root, '.venv-ml/Scripts/python.exe')]);
      assert.equal(configured.code, 0, configured.stderr); await start();
      const modelTask = await terminal((await submit([peFile])).id);
      evidence.external_model_engine_statuses = Object.fromEntries(Object.entries(modelTask.files[0].report.engines).map(([id, e]) => [id, e.status]));
      assert.equal(evidence.external_model_engine_statuses.lightgbm, 'no_match');
      evidence.external_model_file_wall_ms = modelTask.files[0].elapsed_ms;
      evidence.external_model_service_memory = await serviceMemory();
      note('actual optional external frozen ML asset integration; ClamAV availability is reported separately');
    }
    await stop();
    // Authentication failure must never claim that a live owned service stopped.
    await start(); const originalKey = key;
    try {
      await fs.writeFile(path.join(profile, 'local-access.key'), 'x'.repeat(43));
      const deniedStop = await controller('stop'); assert.equal(deniedStop.code, 1);
    } finally { key = originalKey; await fs.writeFile(path.join(profile, 'local-access.key'), originalKey); }
    await request('/v1/desktop/status'); await stop();
    note('changed private key causes explicit stop failure; live service untouched, original key restored');
    const occupied = require('node:net').createServer(socket => socket.destroy());
    await new Promise((resolve, reject) => { occupied.once('error', reject); occupied.listen(3426, '127.0.0.1', resolve); });
    try { assert.equal((await controller('start')).code, 1); assert(occupied.listening); }
    finally { await new Promise(resolve => occupied.close(resolve)); }
    note('occupied loopback port rejected; unrelated listener retained');
    const readme = path.join(app, 'Read-Me-First.txt'), original = await fs.readFile(readme);
    await fs.appendFile(readme, '\ntamper-fixture'); assert.equal((await controller('verify')).code, 1); await fs.writeFile(readme, original);
    assert.equal((await controller('verify')).code, 0); note('package tampering rejected and exact restoration passes');
    const db = await fs.stat(path.join(profile, 'tasks.sqlite3')); evidence.private_db_bytes = db.size;
    assert.equal((await controller('verify')).code, 0); note('scanning created no package cache/config/private files');
    assert.equal(path.dirname(app), temp); assert.equal(path.dirname(temp), os.tmpdir());
    await fs.rm(app, { recursive: true }); assert((await fs.stat(path.join(profile, 'tasks.sqlite3'))).isFile());
    note('controlled portable uninstall removes only extracted application; private reports retained');
  } catch (error) { evidence.failures.push(error.message.replaceAll(key || '\0', '[redacted]')); process.exitCode = 1; }
  finally {
    if (browser) await browser.close();
    if (running) { try { await stop(); } catch (error) { evidence.failures.push('Cleanup: ' + error.message); } }
    await fs.writeFile(path.join(output, 'check.json'), JSON.stringify(evidence, null, 2));
    if (!running && temp && path.dirname(temp) === os.tmpdir() && path.basename(temp).startsWith('aegisav-delivery-')) await fs.rm(temp, { recursive: true });
    key = ''; console.log(JSON.stringify({ checks: evidence.checks.length, failures: evidence.failures, core_engines: evidence.core_engine_statuses, external_model_engines: evidence.external_model_engine_statuses }));
  }
})();
