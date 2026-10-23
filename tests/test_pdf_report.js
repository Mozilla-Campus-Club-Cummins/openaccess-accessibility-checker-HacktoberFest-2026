
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const assert = require('assert');

// Load the report generator from index.html.
const html = fs.readFileSync(
  path.join(__dirname, '..', 'index.html'),
  'utf8'
);

const start = html.indexOf('function escapeReportHtml');
const handlerStart = html.indexOf('/* DOWNLOAD PDF */', start);
const end = handlerStart;

assert.notStrictEqual(start, -1, 'Report generator was not found');
assert.notStrictEqual(end, -1, 'End of report generator was not found');

const source = html.slice(start, end);

const context = {};
vm.createContext(context);
vm.runInContext(
  `${source}
  globalThis.buildPrintableReport = buildPrintableReport;`,
  context
);

const buildPrintableReport = context.buildPrintableReport;

function makeReport(findings) {
  return {
    url: 'https://example.com',
    scanTimestamp: '2026-10-24 10:00',
    method: 'Automated test',
    score: {
      value: 80,
      passed: 4,
      applicable: 5,
      note: 'Basic automated indicator only.'
    },
    findings
  };
}

function makeFinding(index) {
  return {
    impact: 'moderate',
    rule: `Test finding ${index}`,
    element: `div#element-${index}`,
    message: `Test issue ${index}`,
    fix: `Suggested fix ${index}`
  };
}

// Empty-report test.
const emptyHtml = buildPrintableReport(makeReport([]));

assert(emptyHtml.includes('Findings (0)'));
assert(emptyHtml.includes('No issues were reported'));
assert(emptyHtml.includes('URL safety'));
assert(emptyHtml.includes('https://example.com'));
// HTML escaping test: report data must not inject HTML.
const unsafeReport = makeReport([
  {
    impact: 'moderate',
    rule: '<script>alert("x")</script>',
    element: '<img src=x onerror=alert(1)>',
    message: 'Unsafe <b>message</b>',
    fix: 'Use & and < characters safely.'
  }
]);

const safeHtml = buildPrintableReport(unsafeReport);

assert(!safeHtml.includes('<script>alert("x")</script>'));
assert(!safeHtml.includes('<img src=x onerror=alert(1)>'));
assert(safeHtml.includes('&lt;script&gt;'));
assert(safeHtml.includes('&lt;img'));
// Multi-page report test.
const manyFindings = Array.from(
  { length: 100 },
  (_, index) => makeFinding(index + 1)
);

const longHtml = buildPrintableReport(makeReport(manyFindings));

assert(longHtml.includes('Findings (100)'));
assert(longHtml.includes('Test finding 1'));
assert(longHtml.includes('Test finding 100'));
assert(longHtml.includes('Suggested fix 100'));
assert(longHtml.includes('break-inside: avoid'));
assert(longHtml.includes('@page'));
assert(longHtml.includes('overflow-wrap: anywhere'));

console.log('PDF report tests passed: empty and long reports.');
