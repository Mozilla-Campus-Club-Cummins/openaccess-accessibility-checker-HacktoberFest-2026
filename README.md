OpenAccess — Campus Accessibility Checker
An accessibility-first adaptation of a phishing URL detector prototype. Windows step-by-step instructions. Enter a public webpage URL to receive static HTML findings with affected elements and suggested fixes. A separate panel shows limited URL safety signals. Saved reports and JSON export are available in the browser.

Quick start
Requires Python 3.10+; no packages or API keys.
## Versioned JSON Report Export

The browser's JSON export uses schema version `1.0.0`. Each exported report includes:

- Export timestamp and scan metadata, including the URL, engine, method, and score.
- Issue counts grouped by impact.
- Unique rule names and detailed findings, including affected elements and suggested fixes.
- Safety signals, when available, and known limitations of automated checks.
- Legacy-compatible top-level fields (`url`, `findings`, `score`, and `method`).

The schema is documented in [`JSON_REPORT_SCHEMA.md`](JSON_REPORT_SCHEMA.md). Existing browser history entries retain their original format and can still be opened.

### Run tests

Run the Python test suite from the project root:

```powershell
python -m unittest discover -s tests -v
```

The versioned JSON report test uses Node.js. If Node.js is unavailable, that test is skipped. The automated accessibility score is only a basic indicator and does not establish WCAG compliance.