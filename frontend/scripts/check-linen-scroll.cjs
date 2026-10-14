// Synthetic UI only: exercise real native wheel/keyboard scrolling and viewport geometry.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { chromium } = require(process.env.AEGISAV_PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '../..');
const base = process.env.AEGISAV_PREVIEW_URL || 'http://127.0.0.1:3417';
const output = path.join(root, 'output/playwright/linen-scroll');

(async () => {
  await fs.mkdir(output, { recursive: true });
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const page = await browser.newPage({ reducedMotion: 'no-preference', deviceScaleFactor: 1 });
  page.setDefaultTimeout(4000);
  const report = { schema: 1, synthetic_ui_only: true, checks: [], failures: [] };
  const errors = [], requests = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('request', r => requests.push({ url: r.url(), method: r.method() }));
  const geometry = () => page.evaluate(() => {
    const box = selector => { const r = document.querySelector(selector).getBoundingClientRect(); return { top: r.top, bottom: r.bottom, height: r.height, left: r.left, width: r.width }; };
    return { width: innerWidth, height: innerHeight, scrollWidth: document.documentElement.scrollWidth,
      snap: getComputedStyle(document.documentElement).scrollSnapType,
      header: box('.calm-header'), start: box('#linen-start'), records: box('#linen-records'),
      composer: box('.file-composer'), actions: box('.composer-actions'),
      title: box('.calm-intro h1'), titleFont: getComputedStyle(document.querySelector('.calm-intro h1')).fontSize };
  });
  try {
      for (const [width, height] of [[1440,900],[1366,768],[1920,1080],[2560,1440],[2984,1606],[1024,720],[768,1024],[375,812],[812,375]]) {
        await page.setViewportSize({ width, height });
        await page.goto(`${base}/linen/`, { waitUntil: 'networkidle' });
        const before = await geometry();
        assert(before.scrollWidth <= width + 1, 'horizontal overflow');
        const desktop = width >= 1024 && height >= 720;
        assert.equal(before.snap, 'none');
        if (desktop) {
          assert(before.composer.top >= before.header.bottom, 'composer hidden under header');
          assert(before.composer.bottom <= height, 'first state clipped');
          assert(before.actions.bottom <= height, 'primary actions below first screen');
          assert(before.start.bottom <= height + 2, 'complete first state exceeds viewport');
          await page.screenshot({ path: path.join(output, `natural-start-${width}.png`) });
        }
        await page.getByRole('link', { name: '查看最近分析' }).click();
        await page.waitForFunction(desktop => {
          const r = document.querySelector('#linen-records').getBoundingClientRect();
          const h = document.querySelector('.calm-header').getBoundingClientRect();
          return desktop ? Math.abs(r.top - h.bottom) < 3 : r.top >= -2 && r.top < innerHeight;
        }, desktop);
        await page.waitForFunction(() => getComputedStyle(document.querySelector('.calm-history')).opacity === '1');
        const last = await page.getByRole('link', { name: '查看 Readme.txt 检测详情' }).boundingBox();
        if (desktop) assert(last.y + last.height <= height, 'last file clipped in records state');
        if (desktop) {
          const footer = await page.locator('.linen-state-footer').boundingBox();
          assert(footer.y + footer.height <= height, 'records footer clipped');
        }
        await page.screenshot({ path: path.join(output, `natural-records-${width}.png`), fullPage: !desktop });
        await page.getByRole('textbox', { name: '搜索文件名' }).fill('not-present');
        assert(await page.getByText('没有匹配的分析记录').isVisible());
        await page.getByRole('button', { name: '显示演示记录' }).click();
        report.checks.push({ mode: 'natural', width, height, desktop_full_states: desktop, snap: before.snap, first_state: before, passed: true });
      }
    await page.setViewportSize({ width:1440, height:900 });
    await page.goto(`${base}/linen/`, { waitUntil:'networkidle' });
    await page.mouse.move(700,450); await page.mouse.wheel(0,370);
    await page.waitForFunction(() => scrollY >= 350);
    assert.equal((await geometry()).snap, 'none');
    report.checks.push({ interaction:'natural wheel has no snap', passed:true });

    await page.goto(`${base}/linen/`, { waitUntil:'networkidle' });
    await page.keyboard.press('Tab');
    assert.equal(await page.evaluate(() => document.activeElement.textContent), '跳到主要内容');
    await page.keyboard.press('Enter');
    await page.getByRole('link', { name:'查看最近分析' }).focus();
    await page.keyboard.press('Enter');
    await page.waitForFunction(() => Math.abs(document.querySelector('#linen-records').getBoundingClientRect().top - 80) < 3);
    await page.getByRole('textbox', { name:'搜索文件名' }).focus();
    const focused = await page.getByRole('textbox', { name:'搜索文件名' }).boundingBox();
    assert(focused.y >= 80 && focused.y + focused.height <= 900, 'focused input covered');
    report.checks.push({ interaction:'keyboard navigation and unobscured focus', passed:true });

    await page.emulateMedia({ reducedMotion:'reduce' });
    await page.goto(`${base}/linen/`, { waitUntil:'networkidle' });
    assert.equal((await geometry()).snap, 'none');
    assert.equal(await page.locator('.calm-history').evaluate(e => getComputedStyle(e).opacity), '1');
    report.checks.push({ interaction:'reduced motion exposes content and disables snap', passed:true });
    await page.emulateMedia({ reducedMotion:'no-preference' });
    const fallback = await browser.newContext({ javaScriptEnabled:false, viewport:{ width:1440, height:900 } });
    const fallbackPage = await fallback.newPage();
    await fallbackPage.goto(`${base}/linen/`, { waitUntil:'networkidle' });
    assert.equal(await fallbackPage.locator('.calm-history').evaluate(e => getComputedStyle(e).opacity), '1');
    await fallbackPage.getByRole('link', {name:'查看最近分析'}).click();
    // Poll from Node: requestAnimationFrame callbacks do not run with page JS disabled.
    let fallbackBox;
    for (let attempt=0; attempt<40; attempt++) {
      fallbackBox = await fallbackPage.locator('#linen-records').boundingBox();
      if (Math.abs(fallbackBox.y-80) < 2) break;
      await new Promise(resolve => setTimeout(resolve,50));
    }
    assert(Math.abs(fallbackBox.y-80)<2, 'no-JavaScript anchor obscured by header');
    await fallback.close();
    report.checks.push({ interaction:'no-JavaScript records remain readable', passed:true });

    await page.goto(`${base}/linen/`, { waitUntil:'networkidle' });
    await page.locator('input[type=file]').setInputFiles(Array.from({length:20}, (_,index) => ({ name:`${index}-${'long-filename-'.repeat(8)}.exe`, mimeType:'application/octet-stream', buffer:Buffer.from('UI only') })));
    assert((await geometry()).scrollWidth <= 1441, 'long filenames overflow');
    await page.getByRole('button', { name:'演示扫描', exact:true }).scrollIntoViewIfNeeded();
    const actions = await page.getByRole('button', { name:'演示扫描', exact:true }).boundingBox();
    assert(actions.y >= 80 && actions.y + actions.height <= 900, 'oversized first state traps scan action');
    report.checks.push({ interaction:'oversized file selection stays scrollable', passed:true });
    assert.equal(errors.length, 0, errors.join('\n'));
    assert(requests.every(r => r.url.startsWith(base + '/') && r.method === 'GET'), 'unexpected upload/network');
    report.console_errors = errors;
    report.unexpected_uploads = 0;
  } catch (error) { report.failures.push(error.message); }
  finally {
    await browser.close();
    await fs.writeFile(path.join(root,'docs/benchmarks/linen_natural_check_20261015_r2.json'), JSON.stringify(report,null,2)+'\n');
  }
  console.log(JSON.stringify({ checks:report.checks.length, failures:report.failures }));
  assert.equal(report.failures.length,0);
})().catch(error => { console.error(error.message); process.exitCode=1; });
