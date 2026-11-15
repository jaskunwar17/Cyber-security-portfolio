const $ = (id) => document.getElementById(id);
const form = $('analysis-form');
const content = $('content');
let currentReport = null;
let busy = false;
let availableAI = false;
let connected = false;
const samples = {
  message: 'Subject: Urgent — your account will be suspended\n\nYour Microsoft account is locked. Verify your password immediately at:\nhttp://microsoft-login.example.test/verify\n\nComplete this within 2 hours to avoid losing access.\n\nFrom: support@example.test',
  url: 'http://paypal.com@account-review.example.test/login',
  logs: [
    '2026-01-15T10:20:01Z sshd: Failed password for admin from 203.0.113.42 port 50201 ssh2',
    '2026-01-15T10:20:04Z sshd: Failed password for admin from 203.0.113.42 port 50203 ssh2',
    '2026-01-15T10:20:07Z sshd: Failed password for admin from 203.0.113.42 port 50206 ssh2',
    '2026-01-15T10:20:10Z sshd: Failed password for admin from 203.0.113.42 port 50209 ssh2',
    '2026-01-15T10:20:13Z sshd: Failed password for admin from 203.0.113.42 port 50211 ssh2',
    '2026-01-15T10:20:16Z sshd: Accepted password for admin from 203.0.113.42 port 50215 ssh2',
  ].join('\n'),
};
const modeNames = { message: 'Message', url: 'URL', logs: 'Logs' };
const mode = () => form.elements.mode.value;
const placeholders = { message: 'Paste a suspicious email or message here…', url: 'Paste a URL or domain, one per line…', logs: 'Paste plain-text authentication or process logs here…' };
const colors = { none: '#9cceb9', low: '#9cceb9', medium: '#f3bd83', high: '#f6a5a8' };

function countCharacters() {
  $('character-count').textContent = `${content.value.length.toLocaleString('en-US')} / 24,000`;
}
function clearReport() {
  currentReport = null;
  $('report').hidden = true;
  $('empty-state').hidden = false;
  $('export').disabled = true;
  $('error').hidden = true;
}
function announce(message) { $('status-announcement').textContent = message; }
function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}
function render(report) {
  currentReport = report;
  const color = colors[report.risk];
  $('risk-label').textContent = report.risk === 'none' ? 'No matched signals' : `${report.risk[0].toUpperCase() + report.risk.slice(1)} signal level`;
  $('risk-label').style.color = color;
  $('score').textContent = report.score;
  $('score').style.color = color;
  $('risk-fill').style.width = `${report.score}%`;
  $('risk-fill').style.backgroundColor = color;
  $('summary').textContent = report.summary;
  $('finding-count').textContent = report.findings.length;
  $('indicator-count').textContent = Object.values(report.indicators).reduce((sum, items) => sum + items.length, 0);
  $('report-mode').textContent = modeNames[report.mode];
  $('findings').replaceChildren();
  for (const finding of report.findings) {
    const card = node('article', 'finding');
    const heading = node('div', 'finding-top');
    heading.append(node('h5', '', finding.title), node('span', `severity ${finding.severity}`, finding.severity));
    card.append(heading, node('p', '', finding.explanation));
    for (const evidence of finding.evidence) card.append(node('code', '', evidence));
    $('findings').append(card);
  }
  if (!report.findings.length) $('findings').append(node('p', 'no-signals', 'No patterns matched. Independently verify the source and context.'));
  $('indicators').replaceChildren();
  for (const [kind, items] of Object.entries(report.indicators)) {
    if (!items.length) continue;
    const group = node('div', 'indicator-group');
    group.append(node('span', '', { urls: 'URLS', ips: 'IP ADDRESSES', emails: 'EMAIL ADDRESSES' }[kind]));
    for (const value of items) group.append(node('code', 'indicator', value));
    $('indicators').append(group);
  }
  $('indicators-section').hidden = !$('indicators').children.length;
  $('actions').replaceChildren(...report.recommendations.map((action) => node('li', '', action)));
  $('actions-section').hidden = !report.recommendations.length;
  $('ai-section').hidden = !report.ai;
  $('ai-text').textContent = report.ai?.text || report.ai?.error || '';
  $('report-time').textContent = new Date(report.analyzedAt).toLocaleString();
  $('report-time').dateTime = report.analyzedAt;
  $('report').hidden = false;
  $('empty-state').hidden = true;
  $('export').disabled = false;
  announce(`${report.findings.length} signals found. ${$('risk-label').textContent}.`);
}

content.addEventListener('input', () => { countCharacters(); clearReport(); });
form.querySelectorAll('input[name="mode"]').forEach((input) => input.addEventListener('change', () => {
  content.value = '';
  content.placeholder = placeholders[mode()];
  $('content-label').textContent = { message: 'MESSAGE CONTENT', url: 'URLS TO INSPECT', logs: 'LOG CONTENT' }[mode()];
  clearReport(); countCharacters(); content.focus();
}));
$('sample').addEventListener('click', () => { if (busy) return; content.value = samples[mode()]; clearReport(); countCharacters(); content.focus(); });
$('clear').addEventListener('click', () => { if (busy) return; content.value = ''; clearReport(); countCharacters(); content.focus(); });
$('use-ai').addEventListener('change', clearReport);

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (busy) return;
  if (!content.value.trim()) { $('error').textContent = 'Enter some text or load a sample.'; $('error').hidden = false; return; }
  busy = true;
  clearReport();
  $('analyze-label').textContent = 'Analyzing…';
  $('result-heading').closest('section').setAttribute('aria-busy', 'true');
  const controls = [content, ...form.querySelectorAll('button, input')];
  for (const control of controls) control.disabled = true;
  announce('Analysis in progress.');
  try {
    const response = await fetch('/api/analyze', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(35000),
      body: JSON.stringify({ text: content.value, mode: mode(), useAI: $('use-ai').checked }),
    });
    const report = await response.json();
    if (!response.ok) throw new Error(report.error || 'Analysis could not be completed.');
    render(report);
  } catch (error) {
    $('error').textContent = error.name === 'TimeoutError' ? 'The request timed out. Please retry.' : error instanceof TypeError ? 'Cannot reach the local server. Start it and try again.' : error.message;
    $('error').hidden = false;
    announce('Analysis failed. Check the message below the form.');
  } finally {
    busy = false;
    for (const control of controls) control.disabled = false;
    $('use-ai').disabled = !availableAI;
    $('analyze').disabled = !connected;
    $('analyze-label').textContent = 'Analyze content';
    $('result-heading').closest('section').setAttribute('aria-busy', 'false');
  }
});

$('export').addEventListener('click', () => {
  if (!currentReport) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(currentReport, null, 2)], { type: 'application/json' }));
  const link = node('a');
  link.href = url;
  link.download = `cyber-ai-report-${currentReport.mode}-${Date.now()}.json`;
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

async function connect() {
  try {
    const response = await fetch('/api/status');
    if (!response.ok) throw new Error('Server unavailable');
    const status = await response.json();
    availableAI = status.aiAvailable;
    connected = true;
    $('use-ai').disabled = !availableAI;
    $('ai-help').textContent = availableAI ? 'Optional · sends your text to OpenAI for a summary.' : 'Optional · set a server API key to enable.';
    $('connection').replaceChildren(node('i'), document.createTextNode('Local engine ready'));
    $('analyze').disabled = false;
  } catch {
    $('connection').classList.add('offline');
    $('connection').replaceChildren(node('i'), document.createTextNode('Server unavailable'));
    $('ai-help').textContent = 'Start the local server to analyze content.';
    $('analyze').disabled = true;
  }
}
connect();
