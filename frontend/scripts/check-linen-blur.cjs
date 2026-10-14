// Harmless UI fixtures only. Inspect real browser filters, not just compiled CSS text.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { chromium } = require(process.env.AEGISAV_PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '../..');
const base = process.env.AEGISAV_PREVIEW_URL || 'http://127.0.0.1:3417';
const clear = value => value === 'none' || value === 'blur(0px)';

(async () => {
  const browser = await chromium.launch({ channel:'chrome', headless:true });
  const page = await browser.newPage({ viewport:{ width:1440,height:900 }, reducedMotion:'no-preference' });
  page.setDefaultTimeout(4000);
  const output = path.join(root,'output/playwright/linen-blur');
  await fs.mkdir(output,{recursive:true});
  const report={schema:1,synthetic_ui_only:true,checks:[],failures:[]};
  const errors=[],requests=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
  page.on('request',r=>requests.push({url:r.url(),method:r.method()}));
  try {
    await page.goto(`${base}/linen/?scroll=reveal`,{waitUntil:'networkidle'});
    const content=page.locator('.linen-records-content');
    await content.waitFor({state:'attached'});
    await page.waitForFunction(()=>getComputedStyle(document.querySelector('.linen-records-content')).filter==='blur(3px)');
    assert.equal(await content.evaluate(e=>getComputedStyle(e).filter),'blur(3px)');
    await page.getByRole('link',{name:'查看最近分析'}).click();
    await page.waitForFunction(()=>document.querySelector('#linen-records').dataset.reveal==='shown');
    await page.waitForFunction(()=>['none','blur(0px)'].includes(getComputedStyle(document.querySelector('.linen-records-content')).filter));
    report.checks.push({interaction:'scroll entry resolves 3px blur to clear',passed:true});

    const preview=page.getByRole('combobox',{name:'原型状态预览'});
    await preview.selectOption('slow');
    const loading=page.getByRole('status').filter({hasText:'正在加载演示记录…'});
    await loading.waitFor();
    assert(clear(await loading.evaluate(e=>getComputedStyle(e).filter)), 'loading label blurred');
    assert.equal(await content.getAttribute('aria-busy'),'true');
    assert.equal(await page.locator('.skeleton-list').evaluate(e=>getComputedStyle(e).filter),'blur(2px)');
    assert.equal(await page.locator('.calm-file-list').count(),0,'stale records shown during loading');
    await page.screenshot({path:path.join(output,'slow-loading.png')});
    report.checks.push({interaction:'slow placeholder blurred, label clear, no stale results',passed:true});

    await page.waitForFunction(()=>{
      const list=document.querySelector('.calm-file-list');
      const animation=list?.getAnimations().find(a=>a.animationName==='linen-resolve');
      if(!animation)return false;
      animation.pause();animation.currentTime=90;
      return true;
    });
    const list=page.locator('.calm-file-list');
    const middle=await list.evaluate(e=>getComputedStyle(e).filter);
    assert(!clear(middle),'completion has no blur transition');
    await page.screenshot({path:path.join(output,'resolving.png')});
    await list.evaluate(e=>e.getAnimations().forEach(a=>a.finish()));
    assert(clear(await list.evaluate(e=>getComputedStyle(e).filter)));
    assert.equal(await content.getAttribute('aria-busy'),'false');
    await page.screenshot({path:path.join(output,'ready.png')});
    report.checks.push({interaction:'resolved records animate to clear with no retained filter',mid_filter:middle,passed:true});

    await preview.selectOption('slow');
    await loading.waitFor();
    await preview.selectOption('error');
    await page.getByRole('alert').filter({hasText:'记录加载失败'}).waitFor();
    await new Promise(resolve=>setTimeout(resolve,1900));
    assert.equal(await preview.inputValue(),'error','canceled load replaced failure state');
    assert(await page.getByRole('alert').filter({hasText:'记录加载失败'}).isVisible());
    report.checks.push({interaction:'slow loading cancellation preserves newer error state',passed:true});

    await preview.selectOption('normal');
    await page.getByRole('link',{name:'查看 Quarterly_Report.exe 检测详情'}).focus();
    assert(clear(await list.evaluate(e=>getComputedStyle(e).filter)),'keyboard focus remains blurred');
    report.checks.push({interaction:'keyboard focus immediately clears result blur',passed:true});

    await page.emulateMedia({reducedMotion:'reduce'});
    await preview.selectOption('slow');
    await loading.waitFor();
    assert(clear(await page.locator('.skeleton-list').evaluate(e=>getComputedStyle(e).filter)));
    await page.waitForFunction(()=>document.querySelector('.linen-records-content')?.getAttribute('aria-busy')==='false');
    assert(clear(await list.evaluate(e=>getComputedStyle(e).filter)));
    assert.equal(await list.evaluate(e=>getComputedStyle(e).animationName),'none');
    report.checks.push({interaction:'reduced motion disables loading and result blur',passed:true});
    assert.equal(errors.length,0,errors.join('\n'));
    assert(requests.every(r=>r.method==='GET'&&r.url.startsWith(base+'/')),'unexpected network/upload');
    report.console_errors=errors;report.unexpected_uploads=0;
  } catch(error){report.failures.push(error.message);}
  finally {
    await browser.close();
    await fs.writeFile(path.join(root,'docs/benchmarks/linen_blur_check_20261014.json'),JSON.stringify(report,null,2)+'\n');
  }
  console.log(JSON.stringify({checks:report.checks.length,failures:report.failures}));
  assert.equal(report.failures.length,0);
})().catch(e=>{console.error(e.message);process.exitCode=1;});
