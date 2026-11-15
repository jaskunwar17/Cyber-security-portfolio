import { isIP } from 'node:net';

export const MAX_TEXT_LENGTH = 24000;
export const MODES = ['message', 'url', 'logs'];

const unique = (items) => [...new Set(items)];
const urlsIn = (text) => unique((text.match(/https?:\/\/[^\s<>"'`]+/gi) || [])
  .map((url) => url.replace(/[.,;!?)\]]+$/, '')));
const ipsIn = (text) => unique((text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter((ip) => isIP(ip)));

export function analyze(text, mode = 'message') {
  if (typeof text !== 'string' || !text.trim()) throw new Error('Enter some text to analyze.');
  if (text.length > MAX_TEXT_LENGTH) throw new Error(`Use ${MAX_TEXT_LENGTH.toLocaleString('en-US')} characters or fewer.`);
  if (!MODES.includes(mode)) throw new Error('Choose message, URL, or logs.');

  text = text.trim();
  let urls = urlsIn(text);
  if (mode === 'url') {
    urls = unique(text.split(/\s+/).filter(Boolean).map((value) => {
      const candidate = /^https?:\/\//i.test(value) ? value : `https://${value}`;
      let parsed;
      try { parsed = new URL(candidate); } catch { throw new Error('Enter valid HTTP or HTTPS URLs, one per line.'); }
      if (!parsed.hostname.includes('.') && !isIP(parsed.hostname.replace(/^\[|\]$/g, '')) && parsed.hostname !== 'localhost') {
        throw new Error('Enter a complete domain or IP address.');
      }
      if (/^[a-z][a-z\d+.-]*:/i.test(value) && !/^https?:\/\//i.test(value) && !/^[^/?#]+:\d+(?:[/?#]|$)/.test(value)) {
        throw new Error('Only HTTP or HTTPS URLs are supported.');
      }
      return candidate;
    }));
  }

  const findings = [];
  const add = (id, title, severity, evidence, explanation, action, weight) => {
    const existing = findings.find((finding) => finding.id === id);
    if (existing) {
      existing.evidence = unique([...existing.evidence, ...evidence]).slice(0, 8);
      return;
    }
    findings.push({ id, title, severity, evidence: evidence.slice(0, 8), explanation, action, weight });
  };

  for (const value of urls) {
    let url;
    try { url = new URL(value); } catch { continue; }
    const host = url.hostname.toLowerCase();
    if (url.protocol === 'http:') add('http', 'Unencrypted link', 'low', [value], 'HTTP does not encrypt traffic. This alone does not establish maliciousness.', 'Use the known official HTTPS address before entering information.', 10);
    if (url.username || url.password) add('userinfo', 'Link hides its actual destination', 'high', [value], `Text before @ is user information. The actual destination is ${host}.`, 'Check the hostname after @; do not enter credentials through this link.', 30);
    if (isIP(host.replace(/^\[|\]$/g, ''))) add('ip-url', 'IP address used as a website', 'medium', [value], 'An IP-based destination provides fewer identity cues than a recognizable domain.', 'Verify the destination with the service owner.', 15);
    if (host.includes('xn--')) add('punycode', 'Internationalized domain', 'medium', [host], 'Encoded international characters can resemble other domain names, although many such domains are legitimate.', 'Compare the exact domain with a trusted source.', 20);
    const brands = ['microsoft', 'paypal', 'google', 'apple', 'amazon'];
    for (const brand of brands) {
      if (host.includes(brand) && host !== `${brand}.com` && !host.endsWith(`.${brand}.com`)) {
        add('brand', 'Brand name on a different domain', 'high', [host], `The hostname contains “${brand}” but is outside ${brand}.com. Other legitimate domains may exist.`, 'Open the service through your bookmark or independently verify the domain.', 25);
      }
    }
    if (/\.(?:exe|scr|msi|bat|cmd|ps1|vbs|js|iso)(?:$|\/)/i.test(url.pathname)) add('download', 'Executable or script download', 'medium', [value], 'The link points to a file type that can execute code.', 'Confirm the source and inspect the file before opening it.', 20);
    if (value.length > 180 || host.split('.').length > 5) add('complex-url', 'Unusually complex link', 'low', [value.slice(0, 220)], 'Long URLs and many subdomains can make the real destination difficult to spot.', 'Inspect the exact hostname; length alone is not evidence of a threat.', 5);
  }

  if (mode === 'message') {
    const urgent = text.match(/\b(?:urgent|immediately|within \d+ hours?|account (?:will be |is )?(?:suspended|locked)|final warning|act now)\b/gi);
    if (urgent) add('urgency', 'Pressure to act quickly', 'medium', unique(urgent), 'Urgency can be used to discourage careful checks.', 'Verify the request through a separate, trusted channel.', 15);
    const requests = [...text.matchAll(/\b(?:verify|confirm|enter|send|share|update|provide)\b.{0,45}\b(?:password|credentials|bank details|credit card|otp|verification code)\b/gi)]
      .filter((match) => !/(?:never|do not|don't|avoid)\s*$/i.test(text.slice(Math.max(0, match.index - 12), match.index)));
    if (requests.length) add('credentials', 'Request for sensitive information', 'high', requests.map((match) => match[0]), 'The message asks for authentication or financial information.', 'Do not reply with secrets. Contact the organization using a known address.', 25);
    if (/\b(?:gift cards?|wire transfer|cryptocurrency payment|bitcoin payment)\b/i.test(text)) add('payment', 'Unusual payment request', 'medium', [text.match(/\b(?:gift cards?|wire transfer|cryptocurrency payment|bitcoin payment)\b/i)[0]], 'Some scams request payment methods that are difficult to reverse.', 'Confirm the payee and request independently before paying.', 15);
    if (/\b(?:enable macros|disable (?:your )?(?:antivirus|security)|turn off (?:your )?(?:antivirus|security))\b/i.test(text)) add('disable-security', 'Request to weaken protections', 'high', [text.match(/\b(?:enable macros|disable (?:your )?(?:antivirus|security)|turn off (?:your )?(?:antivirus|security))\b/i)[0]], 'The message asks you to change a protection that may block unsafe content.', 'Keep protections enabled and verify with your security team.', 30);
  }

  if (mode === 'logs') {
    const lines = text.split(/\r?\n/);
    const failures = new Map();
    for (const line of lines) {
      if (/failed password|authentication fail(?:ed|ure)|invalid user|login failed/i.test(line)) {
        const sources = ipsIn(line);
        for (const ip of sources) {
          const entry = failures.get(ip) || { count: 0, evidence: [] };
          entry.count++;
          if (entry.evidence.length < 3) entry.evidence.push(line.slice(0, 260));
          failures.set(ip, entry);
        }
      }
      if (/powershell(?:\.exe)?\b.{0,60}-(?:enc(?:odedcommand)?|e)\b/i.test(line)) add('encoded-command', 'Encoded PowerShell command', 'high', [line.slice(0, 300)], 'Encoded commands obscure their contents; legitimate automation may also use them.', 'Inspect the decoded content in a safe environment and verify its origin.', 30);
      if (/\b(?:curl|wget)\b[^\r\n]*\|\s*(?:bash|sh)\b/i.test(line)) add('pipe-shell', 'Download piped into a shell', 'high', [line.slice(0, 300)], 'This command pattern runs downloaded content directly.', 'Review the downloaded script and the initiating process before execution.', 30);
    }
    for (const [ip, entry] of failures) {
      if (entry.count >= 5) add(`failed-${ip}`, 'Repeated authentication failures', 'high', entry.evidence, `${entry.count} failure lines reference ${ip}. Multiple IPs in one line can make source attribution ambiguous.`, 'Check the account and source, then review access controls and rate limits.', 25);
      else add(`failed-${ip}`, 'Authentication failures', 'low', entry.evidence, `${entry.count} failure line(s) reference ${ip}; this alone may be normal user error.`, 'Review for repeated attempts or unexpected account activity.', 5);
      const success = lines.find((line) => ipsIn(line).includes(ip) && /accepted (?:password|publickey)|login success|authentication success/i.test(line));
      if (success && entry.count >= 5) add(`success-${ip}`, 'Successful login from a source with repeated failures', 'high', [success.slice(0, 300)], 'The same input contains successful access and repeated failures from this address. Timing and authorization need review.', 'Confirm the session with the account owner and inspect activity after login.', 30);
    }
  }

  const score = Math.min(100, findings.reduce((sum, finding) => sum + finding.weight, 0));
  const risk = score >= 60 ? 'high' : score >= 25 ? 'medium' : score > 0 ? 'low' : 'none';
  const severityOrder = { high: 0, medium: 1, low: 2 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  const indicators = {
    urls: urls.slice(0, 40),
    ips: unique([...ipsIn(text), ...urls.flatMap((value) => {
      try { const host = new URL(value).hostname.replace(/^\[|\]$/g, ''); return isIP(host) ? [host] : []; } catch { return []; }
    })]).slice(0, 40),
    emails: unique(text.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi) || []).slice(0, 40),
  };
  return {
    mode, engine: 'local-rules', analyzedAt: new Date().toISOString(), score, risk,
    summary: findings.length ? `${findings.length} signal${findings.length === 1 ? '' : 's'} found. Review the evidence and suggested next steps.` : 'No signals matched the local rules. This does not establish that the content is safe.',
    findings: findings.map(({ weight, ...finding }) => finding),
    indicators,
    recommendations: unique(findings.map((finding) => finding.action)).slice(0, 6),
    ai: null,
  };
}
