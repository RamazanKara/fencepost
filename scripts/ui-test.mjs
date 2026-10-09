import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';

const root = path.resolve('.ui-fixture');
const executable = path.join(root, process.platform === 'win32' ? 'fencepost.exe' : 'fencepost');
const child = spawn(executable, ['ui', '--config', path.join(root, 'mcp.json'), '--policy', path.join(root, 'policy.yaml'), '--lock', path.join(root, 'fencepost.lock')], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
let browser;
try {
  const url = await new Promise((resolve, reject) => {
    let output = '';
    const timeout = setTimeout(() => reject(new Error('Console startup timed out')), 15000);
    child.on('error', reject);
    child.on('exit', code => reject(new Error(`Console exited: ${code}`)));
    child.stderr.on('data', data => process.stderr.write(data));
    child.stdout.on('data', data => { output += data; if (output.includes('\n')) { clearTimeout(timeout); resolve(output.trim()); } });
  });
  const edge = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
  browser = await chromium.launch({headless: true, ...(process.platform === 'win32' && existsSync(edge) ? {executablePath: edge} : {})});
  await mkdir(path.join(root, 'screens'), {recursive: true});
  const restricted = await browser.newContext({colorScheme: 'light'});
  await restricted.addInitScript(() => {
    Object.defineProperty(window, 'localStorage', {get() { throw new DOMException('Storage disabled', 'SecurityError'); }});
  });
  const restrictedPage = await restricted.newPage();
  const restrictedErrors = [];
  restrictedPage.on('pageerror', error => restrictedErrors.push(error.message));
  await restrictedPage.goto(url);
  await restrictedPage.waitForSelector('#server-list .name', {timeout: 5000});
  await restrictedPage.getByRole('button', {name: 'Dark theme', exact: true}).click();
  assert.equal(await restrictedPage.locator('html').getAttribute('data-theme'), 'dark');
  assert.deepEqual(restrictedErrors, [], 'Console failed with browser storage disabled');
  await restricted.close();
  let count = 0;
  const viewports = ['en-US', 'de-DE'].flatMap(locale => [1280, 360, 393].map(width => ({locale, width})));
  for (const {locale, width} of viewports) {
    for (const theme of ['light', 'dark']) {
      const context = await browser.newContext({viewport: {width, height: width === 1280 ? 900 : 852}, colorScheme: theme, timezoneId: 'UTC', locale});
      const page = await context.newPage();
      const errors = [];
      page.on('pageerror', error => errors.push(error.message));
      page.on('console', message => { if (message.type() === 'error' && !message.text().includes('status of 400')) errors.push(message.text()); });
      await page.goto(url);
      await page.waitForSelector('#server-list .name');
      assert.match(await page.title(), /Fencepost/);
      const localeState = await page.evaluate(() => ({language: navigator.language, dateLocale: Intl.DateTimeFormat().resolvedOptions().locale}));
      assert.equal(localeState.language, locale);
      if (width === 1280 && theme === 'light') console.log(`Locale check: ${JSON.stringify(localeState)}`);
      assert.ok(!page.url().includes('token='));
      const capture = async name => {
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `Overflow: ${name}`);
        await page.screenshot({path: path.join(root, 'screens', `${name}-${width}-${locale}-${theme}.png`), fullPage: true});
        count++;
      };
      assert.match(await page.locator('#drift-list').innerText(), /browser_navigate/);
      await capture('servers');
      await page.getByRole('button', {name: 'Recent calls', exact: true}).click();
      assert.match(await page.locator('#call-list').innerText(), /redacted/);
      await capture('calls');
      await page.getByRole('button', {name: 'Policy', exact: true}).click();
      await page.waitForFunction(() => document.querySelector('#policy-text').value.includes('version: 1'));
      await page.getByRole('button', {name: 'Validate', exact: true}).click();
      await page.waitForFunction(() => document.querySelector('#policy-result').textContent.includes('Policy is valid'));
      await capture('policy');
      if (width !== 1280 && theme === 'light') {
        const original = await page.locator('#policy-text').inputValue();
        await page.locator('#policy-text').fill(original.replaceAll('action: allow', 'action: deny'));
        await page.getByRole('button', {name: 'Test against recent calls', exact: true}).click();
        await page.waitForFunction(() => document.querySelector('#policy-result').textContent.includes('changed or unknown'));
        assert.match(await page.locator('#test-results').innerText(), /"after":\s*"deny"/);
        await page.locator('#policy-text').evaluate(editor => { editor.scrollTop = 0; });
        await capture('policy-replay');
        await page.locator('#policy-text').fill('version: 1\nservers: {s: {default: allow, typo: true}}');
        await page.getByRole('button', {name: 'Validate', exact: true}).click();
        await page.waitForSelector('#policy-result.danger');
        await capture('policy-invalid');
        await page.locator('#policy-text').fill(original + '\n# Console save verified\n');
        await page.getByRole('button', {name: 'Save policy', exact: true}).click();
        await page.waitForFunction(() => document.querySelector('#policy-result').textContent.includes('Policy saved'));
        await page.getByRole('button', {name: 'Recent calls', exact: true}).click();
        await page.locator('#decision').selectOption('deny');
        assert.ok((await page.locator('#call-list .event').count()) >= 2);
        await capture('denies');
        await page.locator('#decision').selectOption('redacted');
        assert.equal(await page.locator('#call-list .event').count(), 1);
        await page.locator('#call-list summary').click();
        await capture('redactions');
        await page.locator('#search').fill('no-such-tool');
        assert.match(await page.locator('#call-list').innerText(), /No matching calls/);
        await capture('calls-empty');
        await page.getByRole('button', {name: 'Dark theme', exact: true}).click();
        assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
      }
      assert.deepEqual(errors, [], `Browser errors at ${width} ${theme}`);
      await context.close();
    }
  }
  console.log(`UI checks passed; ${count} screenshots at 1280/360/393 CSS pixels, EN/DE browser locales, light and dark. Console labels are English.`);
} finally {
  if (browser) await browser.close();
  child.kill();
}
