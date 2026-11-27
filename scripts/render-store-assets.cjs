// Compose store graphics from real Chromium captures of authorized synthetic fixtures.
const assert = require('node:assert/strict');
const { mkdirSync, readFileSync } = require('node:fs');
const { join } = require('node:path');
const { chromium } = require('playwright');

const png = filename => 'data:image/png;base64,' + readFileSync(filename).toString('base64');
const items = [
  ['popup', 'extension-popup.png', 'Browser protection status', 'Check available protection and review the evidence from the extension.'],
  ['block', 'warning-confirmed.png', 'Known threats interrupted', 'Current reputation evidence triggers a dedicated warning.'],
  ['advisory', 'warning-advisory.png', 'Financial sign-in cautions', 'Review the reason for caution alongside the browser’s checks.'],
  ['dashboard', 'overview.png', 'Optional operator reporting', 'Authorized administrators review classified reports in a separate console.']
];
const css = `
  @font-face { font-family: Inter; src: url(FONT) format("woff2"); font-weight: 100 900; }
  * { box-sizing: border-box; }
  body { margin: 0; background: radial-gradient(ellipse at right, #34204e, #100d18 54%, #0a090d 80%); color: #f6f1ff; font: 16px Inter, sans-serif; }
  .screen { width: 1280px; height: 800px; padding: 58px 62px 0; overflow: hidden; }
  .brand { display: flex; align-items: center; gap: 12px; color: #e0cff8; font-size: 19px; font-weight: 700; }
  .brand img { width: 35px; height: 35px; }
  h1 { margin: 24px 0 0; line-height: 1.04; letter-spacing: -.045em; font-size: 54px; }
  p { margin: 14px 0 24px; color: #c7bad7; font-size: 19px; }
  .image { display: block; width: 100%; max-height: 590px; object-fit: cover; object-position: top;
    border: 1px solid #6a4e90; border-radius: 16px; box-shadow: 0 14px 65px #0009; }
  .popup { display: grid; grid-template-columns: 1fr 360px; align-items: center; gap: 65px; padding-bottom: 58px; }
  .popup .image { max-height: none; width: 360px; }
  .sample { display: inline-block; border-radius: 5px; padding: 4px 8px; background: #332448; color: #e7d5ff; font-size: 14px; }
  .tile { width: 440px; height: 280px; display: grid; place-content: center; justify-items: center; }
  .tile img { width: 86px; height: 86px; }
  .tile h1 { margin: 15px 0 0; font-size: 38px; }
  .tile p { margin: 7px 0 0; font-size: 16px; }
`;

async function main() {
  const [captures, output] = process.argv.slice(2);
  if (!captures || !output) throw new Error('Provide the Chromium smoke capture directory and an output directory');
  mkdirSync(output, { recursive: true });
  const iconPath = join(__dirname, '../extension/icons/icon128.png');
  const icon = png(iconPath);
  const font = readFileSync(join(__dirname, '../extension/fonts/inter-latin.woff2')).toString('base64');
  const style = css.replace('FONT', 'data:font/woff2;base64,' + font);
  const browser = await chromium.launch({ channel: 'chromium' });
  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
    for (const [name, filename, title, text] of items) {
      await page.setContent(`<!doctype html><html lang="en"><style>${style}</style>
        <main class="screen ${name}"><div><div class="brand"><img src="${icon}" alt="">ThreatDetection</div>
        <h1>${title}</h1><p>${text}</p><span class="sample">Synthetic fixture</span></div>
        <img class="image" src="${png(join(captures, filename))}" alt=""></main></html>`);
      await page.locator('.image').evaluate(image => image.decode());
      await page.evaluate(() => document.fonts.ready);
      const bounds = await page.locator('main').boundingBox();
      assert.deepEqual([bounds.width, bounds.height], [1280, 800]);
      await page.screenshot({ path: join(output, name + '-1280x800.png') });
    }
    await page.setViewportSize({ width: 440, height: 280 });
    await page.setContent(`<!doctype html><html lang="en"><style>${style}</style><main class="tile">
      <img src="${icon}" alt=""><h1>ThreatDetection</h1><p>Evidence for safer browsing</p></main></html>`);
    await page.locator('img').evaluate(image => image.decode());
    await page.evaluate(() => document.fonts.ready);
    await page.screenshot({ path: join(output, 'promo-440x280.png') });
    for (const [name, width, height] of [
      ...items.map(([key]) => [key + '-1280x800.png', 1280, 800]), ['promo-440x280.png', 440, 280]
    ]) {
      const asset = readFileSync(join(output, name));
      assert.deepEqual([asset.readUInt32BE(16), asset.readUInt32BE(20), asset[25]], [width, height, 2]);
    }
    console.log('Verified four 1280x800 RGB screenshots and one 440x280 RGB promo tile.');
  } finally {
    await browser.close();
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
