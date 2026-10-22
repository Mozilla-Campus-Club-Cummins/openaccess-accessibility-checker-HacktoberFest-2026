"""Dependency-free starter scanner: static HTML checks and limited URL risk signals."""
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit, urljoin
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler, HTTPSHandler
from urllib.error import HTTPError, URLError
import certifi
import ipaddress
import socket
import re
import ssl

MAX_BYTES = 1_500_000

class ScanError(Exception):
    pass


def validate_url(raw):
    if not isinstance(raw, str) or len(raw) > 2048:
        raise ScanError('Enter a URL shorter than 2048 characters.')
    raw = raw.strip()
    if not raw:
        raise ScanError('Enter a URL to scan.')
    if '://' not in raw:
        raw = 'https://' + raw
    try:
        parts = urlsplit(raw)
        port = parts.port
        hostname = parts.hostname
    except ValueError:
        raise ScanError('Invalid URL or port.')
    if parts.scheme not in ('http', 'https') or not hostname or parts.username or parts.password:
        raise ScanError('Use a public HTTP or HTTPS URL without embedded credentials.')
    if port not in (None, 80, 443, 8000, 8080):
        raise ScanError('Only standard web ports are supported.')
    if any(c.isspace() for c in raw):
        raise ScanError('Remove spaces from the URL.')
    return urlunsplit((parts.scheme, parts.netloc, parts.path or '/', parts.query, ''))


def public_addresses(hostname):
    if hostname.lower() == 'localhost' or hostname.lower().endswith(('.localhost', '.local', '.internal')):
        raise ScanError('Private and local addresses cannot be scanned.')
    try:
        addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)}
    except (socket.gaierror, ValueError):
        raise ScanError('The domain could not be resolved.')
    if not addresses or any(not ip.is_global for ip in addresses):
        raise ScanError('Private and local addresses cannot be scanned.')
    return addresses


class NoRedirect(HTTPRedirectHandler, ProxyHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def fetch_page(url):
    """Revalidate each redirect; DNS rebinding still requires network sandboxing for public deployments."""
    tls_context = ssl.create_default_context(cafile=certifi.where())
    opener = build_opener(NoRedirect, ProxyHandler({}), HTTPSHandler(context=tls_context))
    current = url
    for _ in range(5):
        current = validate_url(current)
        parts = urlsplit(current)
        public_addresses(parts.hostname)
        try:
            response = opener.open(Request(current, headers={'User-Agent': 'CampusA11yChecker/0.1'}), timeout=8)
        except HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                location = exc.headers.get('Location')
                if not location:
                    raise ScanError('The website redirected without a destination.')
                current = urljoin(current, location)
                continue
            raise ScanError(f'The website returned HTTP {exc.code}.')
        except (URLError, TimeoutError, OSError) as exc:
            raise ScanError(f'Could not load the webpage: {exc.reason if hasattr(exc, "reason") else exc}')
        with response:
            kind = response.headers.get_content_type()
            if kind not in ('text/html', 'application/xhtml+xml'):
                raise ScanError('This URL does not return an HTML webpage.')
            raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ScanError('The webpage exceeds the 1.5 MB scan limit.')
            charset = response.headers.get_content_charset() or 'utf-8'
            try:
                return current, raw.decode(charset, errors='replace')
            except LookupError:
                return current, raw.decode('utf-8', errors='replace')
    raise ScanError('Too many redirects.')


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.nodes = []
        self.stack = []
        self.title = ''
        self.labels = set()
        self.ids = set()
        self.html_lang = ''
        self._title_depth = 0

    def handle_starttag(self, tag, attrs):
        props = dict(attrs)
        node = {'tag': tag, 'attrs': props, 'text': '', 'path': self._path(tag, props), 'parent': self.stack[-1] if self.stack else None}
        self.nodes.append(node)
        if props.get('id'):
            self.ids.add(props['id'])
        if tag == 'label' and props.get('for'):
            self.labels.add(props['for'])
        if tag == 'html':
            self.html_lang = props.get('lang', '')
        if tag not in ('area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr'):
            self.stack.append(node)
        if tag == 'title':
            self._title_depth += 1

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == 'title':
            self._title_depth = max(0, self._title_depth - 1)
        for i in range(len(self.stack)-1, -1, -1):
            if self.stack[i]['tag'] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        if self._title_depth:
            self.title += data
        for node in self.stack:
            node['text'] += data

    def _path(self, tag, props):
        if props.get('id'):
            return tag + '#' + props['id'][:80]
        return tag + '[' + str(sum(n['tag'] == tag for n in self.nodes) + 1) + ']'


def accessibility_findings(html):
    page = PageParser()
    page.feed(html)
    findings = []
    def add(rule, impact, element, message, fix):
        findings.append({'rule':rule,'impact':impact,'element':element,'message':message,'fix':fix})
    if not page.title.strip():
        add('Page title', 'serious', 'head > title', 'The page has no meaningful title.', 'Add a descriptive <title> in <head>.')
    if not page.html_lang.strip():
        add('Page language', 'serious', 'html', 'The page does not declare its language.', 'Set a valid lang attribute on <html>, such as lang="en".')
    headings = []
    for node in page.nodes:
        tag, a, value, path = node['tag'], node['attrs'], node['text'].strip(), node['path']
        if tag == 'img' and not any(k in a for k in ('alt',)) and a.get('role') != 'presentation' and a.get('aria-hidden') != 'true':
            add('Image alternative text','serious',path,'Image has no alt attribute.','Add meaningful alt text, or alt="" if decorative.')
        if tag in ('input','select','textarea') and a.get('type') not in ('hidden','submit','button','reset','image'):
            if not (a.get('aria-label') or a.get('aria-labelledby') or (a.get('id') in page.labels) or a.get('title') or (node['parent'] and node['parent']['tag'] == 'label')):
                add('Form control label','critical',path,'Form field has no associated label.','Associate a <label for="..."> with its id or use an accessible name.')
        if tag == 'button' and not (value or a.get('aria-label') or a.get('aria-labelledby') or a.get('title')):
            add('Button name','critical',path,'Button has no accessible name.','Add visible text or an accessible label.')
        if tag == 'a' and 'href' in a and not (value or a.get('aria-label') or a.get('aria-labelledby') or a.get('title')):
            add('Link name','serious',path,'Link has no accessible name.','Add meaningful link text or an accessible label.')
        if tag in ('h1','h2','h3','h4','h5','h6'):
            if not value:
                add('Empty heading','moderate',path,'Heading contains no text.','Add a meaningful heading or remove the element.')
            headings.append((int(tag[1]), path, value))
        if tag == 'html' and a.get('lang') and not re.match(r'^[a-zA-Z]{2,3}(?:-[a-zA-Z0-9]+)*$', a['lang']):
            add('Page language','moderate',path,'Language code may be invalid.','Use a valid BCP 47 language tag.')
    levels = [heading[0] for heading in headings]

    if 1 not in levels:
        add(
            'Main heading',
            'moderate',
            'page',
            'No h1 heading was found.',
            'Give the page a descriptive main heading.'
        )

    h1_headings = [heading for heading in headings if heading[0] == 1]
    if len(h1_headings) > 1:
        for heading in h1_headings[1:]:
            add(
                'Multiple main headings',
                'moderate',
                heading[1],
                f'Multiple h1 headings found; this heading is "{heading[2]}".',
                'Use a single main h1 heading and organize other sections with lower-level headings.'
            )

    for previous, current in zip(headings, headings[1:]):
        if current[0] > previous[0] + 1:
            add(
                'Skipped heading level',
                'moderate',
                current[1],
                f'Heading "{current[2]}" skips from h{previous[0]} to h{current[0]}.',
                f'Use h{previous[0] + 1} instead, or restructure the heading hierarchy.'
            )

    return findings



def accessibility_score(html, findings):
    """Small teaching metric: passed applicable categories, not WCAG conformance."""
    page = PageParser()
    page.feed(html)
    tags = {node['tag'] for node in page.nodes}
    categories = [
        ('Page title', True, {'Page title'}),
        ('Page language', True, {'Page language'}),
        ('Heading structure', True, {
            'Main heading',
            'Empty heading',
            'Skipped heading level',
            'Multiple main headings'
        }),

        ('Image alternatives', 'img' in tags, {'Image alternative text'}),
        ('Form labels', bool(tags & {'input','select','textarea'}), {'Form control label'}),
        ('Links and buttons', bool(tags & {'a','button'}), {'Link name','Button name'}),
    ]
    failed = {finding['rule'] for finding in findings}
    checks = [{'name':name, 'status':('not applicable' if not applies else 'fail' if failed & rules else 'pass')}
              for name, applies, rules in categories]
    applicable = [check for check in checks if check['status'] != 'not applicable']
    passed = sum(check['status'] == 'pass' for check in applicable)
    return {'value':round(100 * passed / len(applicable)) if applicable else None,
            'passed':passed, 'applicable':len(applicable), 'checks':checks,
            'note':'Basic indicator from the listed static checks only. This is not a WCAG compliance score.'}


def scan(url):
    normalized = validate_url(url)
    # Validate before any request. These signals do not authorize navigation.
    public_addresses(urlsplit(normalized).hostname)
    final_url, html = fetch_page(normalized)
    findings = accessibility_findings(html)
    return {'url':final_url,'findings':findings,'score':accessibility_score(html, findings),'method':'Static HTML checks; dynamic content and manual accessibility checks are not covered.'}
