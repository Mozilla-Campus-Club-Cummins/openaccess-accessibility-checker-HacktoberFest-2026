
const { chromium } = require('playwright');
const path = require('node:path');
const { pathToFileURL, fileURLToPath } = require('node:url');
const fs = require('node:fs');

const FIXTURES_DIR = path.resolve(__dirname, '../tests/fixtures');

async function inspectKeyboardAccessibility(url) {
  const parsed = new URL(url);

  // Only allow controlled local fixture files.
  if (parsed.protocol !== 'file:') {
    throw new Error(
      'For safety, browser checks currently support local test fixtures only.'
    );
  }

  const fixturePath = path.resolve(fileURLToPath(parsed));

  if (
    !fixturePath.startsWith(FIXTURES_DIR + path.sep) ||
    !fs.existsSync(fixturePath)
  ) {
    throw new Error('Only existing HTML files in tests/fixtures are allowed.');
  }

  const browser = await chromium.launch({ headless: true });

  try {
    const page = await browser.newPage();

    // Prevent fixture scripts from making network requests.
    await page.route('**/*', async route => {
      const requestUrl = route.request().url();

      if (requestUrl.startsWith('file:')) {
        await route.continue();
      } else {
        await route.abort();
      }
    });

    await page.goto(parsed.href, {
      waitUntil: 'domcontentloaded',
      timeout: 10000
    });

    const findings = await page.evaluate(() => {
      const results = [];
      const selector = '[onclick], [role="button"], [role="link"]';

      for (const element of document.querySelectorAll(selector)) {
        const tag = element.tagName.toLowerCase();
        const tabIndex = element.getAttribute('tabindex');

        const nativeFocus =
          (tag === 'button' && !element.disabled) ||
          (tag === 'a' && element.hasAttribute('href')) ||
          (['input', 'select', 'textarea'].includes(tag) &&
            !element.disabled);

        const sequentialFocus =
          tabIndex !== '-1' &&
          (nativeFocus || (tabIndex !== null && Number(tabIndex) >= 0));

        if (!sequentialFocus) {
          results.push({
            type: 'automated',
            rule: 'Clickable element not keyboard-focusable',
            element: tag,
            message:
              'An element appears clickable but may not be reachable by sequential keyboard focus.',
            fix:
              'Prefer a native button or link, or implement and test keyboard interaction.'
          });
        }
      }

      return results;
    });

    const tabStops = [];
    const seenStops = new Set();

    for (let i = 0; i < 30; i++) {
      await page.keyboard.press('Tab');

      const active = await page.evaluate(() => {
        const element = document.activeElement;

        if (
          !element ||
          element === document.body ||
          element === document.documentElement
        ) {
          return null;
        }

        return {
          tag: element.tagName.toLowerCase(),
          id: element.id || null,
          text: (
            element.innerText ||
            element.getAttribute('aria-label') ||
            ''
          ).trim().slice(0, 80)
        };
      });

      if (!active) break;

      const key = `${active.tag}|${active.id || ''}|${active.text}`;

      if (seenStops.has(key)) break;

      seenStops.add(key);
      tabStops.push(active);
    }

    return {
      url: page.url(),
      method: 'Browser-based keyboard checks on a local fixture',
      findings,
      tabStops,
      manualReviewRequired: true,
      limitations: [
        'Only controlled local test fixtures are supported.',
        'Tab stops reflect the tested page state and browser.',
        'Automation cannot reliably determine whether focus order is meaningful.',
        'Keyboard activation, visible focus, dialogs, and dynamic interactions need human testing.',
        'These checks do not establish WCAG conformance.'
      ]
    };
  } finally {
    await browser.close();
  }
}

async function main() {
  const filename = process.argv[2];

  if (!filename) {
    console.error(
      'Usage: node browser/keyboard-check.js tests/fixtures/keyboard-fail.html'
    );
    process.exitCode = 2;
    return;
  }

  try {
    const fixturePath = path.resolve(filename);
    const report = await inspectKeyboardAccessibility(
      pathToFileURL(fixturePath).href
    );

    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } catch (error) {
    console.error(`Keyboard check failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main();
}

module.exports = { inspectKeyboardAccessibility };
