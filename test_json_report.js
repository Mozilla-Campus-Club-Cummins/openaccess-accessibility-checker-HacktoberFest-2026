
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const html = fs.readFileSync('index.html', 'utf8');
const match = html.match(
  /function buildVersionedReport\(data\) \{[\s\S]*?\n\}/
);

assert.ok(match, 'Report builder must exist in index.html');

const buildVersionedReport = vm.runInNewContext(
  `(${match[0]})`
);

const input = {
  url: 'https://example.com/',
  method: 'Static HTML checks',
  score: { value: 80, passed: 4, applicable: 5, note: 'Test score' },
  findings: [
    {
      rule: 'Image alternative text',
      impact: 'serious',
      element: '<img src="photo.jpg">',
      message: 'Image is missing alternative text.',
      fix: 'Add an appropriate alt attribute.'
    },
    {
      rule: 'Button name',
      impact: 'moderate',
      element: '<button></button>',
      message: 'Button has no accessible name.',
      fix: 'Add descriptive button text.'
    }
  ]
};

const report = buildVersionedReport(input);
const parsed = JSON.parse(JSON.stringify(report));

assert.equal(parsed.schemaVersion, '1.0.0');
assert.ok(!Number.isNaN(Date.parse(parsed.exportedAt)));
assert.equal(parsed.scan.url, input.url);
assert.equal(parsed.issueCounts.serious, 1);
assert.equal(parsed.issueCounts.moderate, 1);
assert.deepEqual(parsed.rules, ['Image alternative text', 'Button name']);
assert.equal(parsed.findings.length, 2);
assert.equal(parsed.fixes.length, 2);
assert.equal(parsed.url, input.url);
assert.equal(parsed.findings[0].rule, 'Image alternative text');
assert.equal(parsed.score.value, 80);
assert.equal(parsed.method, input.method);
assert.ok(Array.isArray(parsed.limitations));
assert.ok(parsed.safety);

console.log('Versioned JSON report tests passed.');
