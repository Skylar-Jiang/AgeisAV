// Real Chromium checks on synthetic UI fixtures only; no PE content or API credentials.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { chromium } = require(process.env.AEGISAV_PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '../..');
const output = path.join(root, 'output/playwright');
const base = process.env.AEGISAV_PREVIEW_URL || 'http://127.0.0.1:3417';

function contrast(a, b) {
  const luminance = color => {
    const values = color.trim().slice(1).match(/../g).map(value => parseInt(value, 16) / 255)
      .map(value => value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4);
    return values[0] * .2126 + values[1] * .7152 + values[2] * .0722;
  };
  const x = luminance(a), y = luminance(b);
  return (Math.max(x, y) + .05) / (Math.min(x, y) + .05);
}

(async () => {
  await fs.mkdir(output, { recursive: true });
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const context = await browser.newContext({ deviceScaleFactor: 1, reducedMotion: 'reduce' });
  const page = await context.newPage();
  const report = { schema: 1, synthetic_ui_only: true, real_detector_metrics: false, checks: [], failures: [] };
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  const requests = [];
  page.on('request', request => requests.push({ url: request.url(), method: request.method() }));
  try {
    await page.goto(base + '/', { waitUntil: 'networkidle' });
    assert(await page.getByRole('heading', { name: /从一个文件，\s*看清每一条证据。/ }).isVisible());
    assert.equal(await page.getByRole('link', { name: /切换方案/ }).count(), 0);
    assert.equal(await page.getByRole('group', { name: '页面滚动体验对比' }).count(), 0);
    for (const route of ['paper', 'slate', 'obsidian']) {
      assert.equal((await context.request.get(`${base}/${route}/`)).status(), 404);
      assert.equal((await context.request.get(`${base}/${route}/detail/`)).status(), 404);
    }
    report.checks.push({ interaction: 'root opens Linen; rejected routes return 404; no design/mode switchers', passed: true });
    for (const direction of ['linen']) {
      for (const view of ['workspace', 'detail']) {
        const route = `/${direction}/${view === 'detail' ? 'detail/' : ''}`;
        for (const [width, height] of [[1440, 1000], [768, 1024], [375, 812], [812, 375]]) {
          try {
            await page.setViewportSize({ width, height });
            await page.goto(base + route, { waitUntil: 'networkidle' });
            await page.locator('h1').waitFor();
            assert.equal(await page.locator('h1').count(), 1);
            assert(await page.getByText('演示数据', { exact: true }).isVisible());
            const dimensions = await page.evaluate(() => ({ width: innerWidth, scroll: document.documentElement.scrollWidth }));
            assert(dimensions.scroll <= dimensions.width + 1, `page overflow ${JSON.stringify(dimensions)}`);
            const colors = await page.locator('.calm-shell').evaluate(element => {
              const style = getComputedStyle(element);
              return Object.fromEntries(['foreground', 'background', 'muted-foreground', 'card', 'primary', 'primary-foreground', 'warning'].map(key => [key, style.getPropertyValue('--' + key)]));
            });
            const ratios = [['foreground', 'background'], ['muted-foreground', 'card'], ['primary', 'primary-foreground'], ['warning', 'card']]
              .map(([a, b]) => ({ pair: `${a}/${b}`, ratio: contrast(colors[a], colors[b]) }));
            assert(ratios.every(item => item.ratio >= 4.5), 'text contrast below 4.5');
            const filename = `${direction}-${view}-${width}.png`;
            await page.screenshot({ path: path.join(output, filename), fullPage: true });
            report.checks.push({ direction, view, width, height, page_overflow: false, contrast: ratios, screenshot: `output/playwright/${filename}` });
          } catch (error) { report.failures.push({ direction, view, width, reason: error.message }); }
        }
      }
      await page.setViewportSize({ width: 1440, height: 1000 });
      await page.goto(`${base}/${direction}/`, { waitUntil: 'networkidle' });
      await page.getByRole('textbox', { name: '搜索文件名' }).fill('no-such-file');
      assert(await page.getByText('没有匹配的分析记录').isVisible());
      await page.getByRole('button', { name: '显示演示记录' }).click();
      await page.getByRole('combobox', { name: '原型状态预览' }).selectOption('error');
      assert(await page.getByRole('alert').filter({ hasText: '记录加载失败' }).isVisible());
      await page.getByRole('button', { name: '重试', exact: true }).click();
      await page.getByRole('combobox', { name: '原型状态预览' }).selectOption('loading');
      assert(await page.getByLabel('记录加载中').isVisible());
      await page.getByRole('combobox', { name: '原型状态预览' }).selectOption('normal');
      await page.locator('input[type=file]').setInputFiles({ name: 'harmless-ui-fixture.exe', mimeType: 'application/octet-stream', buffer: Buffer.from('not an executable; UI test only') });
      assert(await page.getByText('已选择：harmless-ui-fixture.exe').isVisible());
      await page.getByRole('button', { name: '演示扫描', exact: true }).click();
      assert(await page.getByRole('button', { name: '演示扫描中…' }).isDisabled());
      await page.getByRole('status').filter({ hasText: '演示完成' }).waitFor();
      await page.getByRole('link', { name: '查看 Legacy_Client_Architecture_Compatibility_Test.exe 检测详情' }).click();
      await page.getByText('General PE（架构不适用）', { exact: true }).waitFor();
      assert(await page.getByText('ARM64', { exact: true }).isVisible());
      await page.getByRole('link', { name: '返回扫描工作台' }).click();
      await page.getByRole('link', { name: '查看 Readme.txt 检测详情' }).click();
      await page.getByRole('heading', { name: 'Readme.txt', exact: true }).waitFor();
      assert(await page.getByRole('heading', { name: '解析失败', exact: true }).isVisible());
      await page.goto(`${base}/${direction}/detail/`, { waitUntil: 'networkidle' });
      await page.evaluate(() => { navigator.clipboard.writeText = async () => { throw new Error('synthetic clipboard denial'); }; });
      await page.getByRole('button', { name: '复制 SHA-256' }).click();
      const copyFailure = page.getByText('剪贴板不可用，请从下方选择并复制 SHA-256。', { exact: true });
      await copyFailure.waitFor();
      assert(await copyFailure.evaluate(element => getComputedStyle(element).clipPath === 'none' && element.getBoundingClientRect().width > 150));
      await page.locator('summary').filter({ hasText: 'YARA-X' }).click();
      assert(await page.getByText(/演示规则 Demo_PE_Indicator/).isVisible());
      const downloaded = page.waitForEvent('download');
      await page.getByRole('button', { name: '导出 JSON' }).click();
      const download = await downloaded;
      const target = path.join(output, `${direction}-demo-report.json`);
      await download.saveAs(target);
      assert.equal(JSON.parse(await fs.readFile(target, 'utf8')).demo, true);
      await page.goto(`${base}/${direction}/`, { waitUntil: 'networkidle' });
      await page.keyboard.press('Tab');
      assert.equal(await page.evaluate(() => document.activeElement.textContent), '跳到主要内容');
      await page.keyboard.press('Enter');
      assert.equal(await page.evaluate(() => document.activeElement.id), 'main-content');
      report.checks.push({ direction, interactions: ['search-empty-reset', 'error-retry', 'loading', 'file-name-only-selection', 'demo-progress', 'unsupported-architecture', 'non-PE-detail', 'visible-clipboard-failure', 'evidence-expand', 'demo-JSON-export', 'keyboard-skip'], passed: true });
    }
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await page.goto(`${base}/linen/`, { waitUntil: 'networkidle' });
    assert.equal(await page.locator('.calm-intro-copy').evaluate(element => getComputedStyle(element).animationName), 'calm-enter');
    await page.getByRole('button', { name: '演示扫描', exact: true }).click();
    await page.locator('.calm-engine-steps li[data-phase=active]').first().waitFor();
    await page.screenshot({ path: path.join(output, 'linen-motion-scanning.png'), fullPage: true });
    await page.getByRole('status').filter({ hasText: '演示完成' }).waitFor();
    assert.equal(await page.locator('.calm-engine-steps li[data-phase=done]').count(), 5);
    await page.emulateMedia({ reducedMotion: 'reduce' });
    assert.equal(await page.locator('.calm-intro-copy').evaluate(element => getComputedStyle(element).animationName), 'none');
    report.checks.push({ motion: 'entry and five-step scanning, reduced-motion fallback', passed: true });
    assert.equal(errors.length, 0, errors.join('\n'));
    assert(requests.every(request => request.url.startsWith(base + '/') && request.method === 'GET'), 'unexpected network or upload');
    report.console_errors = errors;
    report.unexpected_uploads = 0;
  } catch (error) { report.failures.push({ reason: error.message }); }
  finally {
    await browser.close();
    await fs.writeFile(path.join(root, 'docs/benchmarks/frontend_linen_check_20261015.json'), JSON.stringify(report, null, 2) + '\n');
  }
  console.log(JSON.stringify({ checks: report.checks.length, failures: report.failures }));
  assert.equal(report.failures.length, 0);
})().catch(error => { console.error(error.message); process.exitCode = 1; });
