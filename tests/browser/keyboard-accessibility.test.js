
const { test, expect } = require('@playwright/test');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { inspectKeyboardAccessibility } = require('../../browser/keyboard-check');

const fixturesDir = path.resolve(__dirname, '../fixtures');

function fixtureUrl(filename) {
  return pathToFileURL(path.join(fixturesDir, filename)).href;
}

test('detects a clickable element that is not keyboard-focusable', async () => {
  const report = await inspectKeyboardAccessibility(
    fixtureUrl('keyboard-fail.html')
  );

  expect(report.findings).toContainEqual(
    expect.objectContaining({
      type: 'automated',
      rule: 'Clickable element not keyboard-focusable',
      element: 'div'
    })
  );

  expect(report.manualReviewRequired).toBe(true);
});

test('passes for native keyboard-accessible controls', async () => {
  const report = await inspectKeyboardAccessibility(
    fixtureUrl('keyboard-pass.html')
  );

  expect(report.findings).toEqual([]);
});

test('reports observed Tab stops for the passing fixture', async () => {
  const report = await inspectKeyboardAccessibility(
    fixtureUrl('keyboard-pass.html')
  );

  expect(report.tabStops.some(stop => stop.tag === 'button')).toBe(true);
  expect(report.tabStops.some(stop => stop.tag === 'a')).toBe(true);
});

test('documents limitations and requires manual review', async () => {
  const report = await inspectKeyboardAccessibility(
    fixtureUrl('keyboard-pass.html')
  );

  expect(report.manualReviewRequired).toBe(true);
  expect(report.limitations).toContain(
    'These checks do not establish WCAG conformance.'
  );
});

test('rejects non-local URLs', async () => {
  await expect(
    inspectKeyboardAccessibility('https://example.com')
  ).rejects.toThrow(
    'For safety, browser checks currently support local test fixtures only.'
  );
});
