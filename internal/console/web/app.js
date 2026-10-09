'use strict';
const $ = id => document.getElementById(id);
let state = {servers: [], events: []};
let policyHash = '';
let policyLoaded = false;
const element = (tag, text, cls) => {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (cls) node.className = cls;
  return node;
};
async function api(path, data) {
  const response = await fetch(path, data === undefined ? {} : {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)});
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}
function problem(error) { $('error').textContent = error.message; $('error').hidden = false; }
function badge(text, kind) { return element('span', text, `badge ${kind || ''}`); }
function theme(value) {
  document.documentElement.dataset.theme = value;
  $('theme').textContent = value === 'dark' ? 'Light theme' : 'Dark theme';
  try { localStorage.setItem('fencepost-theme', value); } catch { /* Theme persistence is optional. */ }
}
let initialTheme = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
try { initialTheme = localStorage.getItem('fencepost-theme') || initialTheme; } catch { /* Use the system theme when storage is unavailable. */ }
theme(initialTheme);
$('theme').addEventListener('click', () => theme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', async () => {
  document.querySelectorAll('[data-view]').forEach(item => item.removeAttribute('aria-current'));
  button.setAttribute('aria-current', 'page');
  ['servers', 'calls', 'policy'].forEach(view => $(view).hidden = view !== button.dataset.view);
  if (button.dataset.view === 'policy' && !policyLoaded) { try { await loadPolicy(); } catch (error) { problem(error); } }
}));
function renderServers() {
  const list = $('server-list'); list.replaceChildren();
  const head = element('div', undefined, 'row table-head');
  ['Server', 'Transport', 'Pin status'].forEach(text => head.append(element('div', text))); list.append(head);
  state.servers.forEach(server => {
    const row = element('div', undefined, 'row');
    const name = element('div'); name.append(element('span', server.name, 'name'), element('span', server.wrapped ? 'Wrapped by Fencepost' : 'Not wrapped', 'secondary'));
    const transport = element('div'); transport.append(element('span', 'Transport', 'mobile-label'), element('span', server.transport === 'stdio' ? 'Stdio' : 'HTTP'));
    const pins = element('div'); pins.append(element('span', 'Pin status', 'mobile-label'), badge(server.pin, /drift/i.test(server.pin) ? 'warn' : ''));
    row.append(name, transport, pins); list.append(row);
  });
  if (!state.servers.length) list.append(element('p', 'No servers found. Start the console with --config pointing to your MCP client config.', 'empty'));
  const drift = $('drift-list'); drift.replaceChildren();
  state.servers.filter(server => /drift/i.test(server.pin)).forEach(server => {
    const block = element('div', undefined, 'drift-item'); block.append(element('strong', server.name));
    const events = state.events.filter(event => event.server === server.name && event.rule === 'pin');
    block.append(element('p', server.pin === 'Launch drift' ? 'The configured launch differs from its baseline. Review the original server configuration.' : 'An untrusted or changed tool was recorded. Review the server before updating its pin.'));
    if (events.length) block.append(element('pre', events.map(event => `${event.tool || 'server'} · ${event.decision} · ${event.time}`).join('\n')));
    drift.append(block);
  });
  if (!drift.children.length) drift.append(element('p', 'No drift in the available records. Tool definitions have not been checked live.', 'caption'));
}
function renderCalls() {
  const query = $('search').value.trim().toLowerCase(); const filter = $('decision').value;
  const events = state.events.filter(event => (event.kind === 'decision' || Object.keys(event.redactions || {}).length) &&
    `${event.server || ''} ${event.tool || ''}`.toLowerCase().includes(query) &&
    (filter === 'all' || (filter === 'redacted' ? Object.keys(event.redactions || {}).length : event.decision === filter))).slice().reverse();
  $('call-count').textContent = `${events.length} matching event${events.length === 1 ? '' : 's'}`;
  const list = $('call-list'); list.replaceChildren();
  events.forEach(event => {
    const row = element('details', undefined, 'event'); const summary = element('summary');
    const title = element('div'); title.append(element('span', event.tool || event.method || event.kind, 'name'), element('span', event.server || 'Console', 'secondary'));
    const redactions = Object.values(event.redactions || {}).reduce((a, b) => a + b, 0);
    const decision = element('div'); decision.append(badge(event.decision || event.kind, event.decision === 'allow' ? 'ok' : event.decision === 'deny' || event.decision === 'hide' ? 'bad' : ''));
    if (redactions) decision.append(element('span', `${redactions} redacted`, 'secondary'));
    const time = element('time', new Date(event.time).toLocaleString()); time.dateTime = event.time;
    summary.append(title, decision, time); row.append(summary, element('pre', JSON.stringify(event, null, 2))); list.append(row);
  });
  if (!events.length) list.append(element('p', 'No matching calls in the recent audit history.', 'empty'));
}
async function refresh() {
  $('refresh').disabled = true;
  try { state = await api('/api/state'); renderServers(); renderCalls(); $('error').hidden = true; }
  catch (error) { problem(error); } finally { $('refresh').disabled = false; }
}
$('refresh').addEventListener('click', refresh);
$('search').addEventListener('input', renderCalls);
$('decision').addEventListener('change', renderCalls);
async function loadPolicy() {
  const data = await api('/api/policy'); $('policy-text').value = data.text; policyHash = data.hash; policyLoaded = true;
}
$('reload-policy').addEventListener('click', async () => {
  if (policyLoaded && !confirm('Discard editor changes and reload the policy from disk?')) return;
  try { await loadPolicy(); $('policy-result').hidden = true; $('test-results').hidden = true; } catch (error) { problem(error); }
});
async function policyAction(action) {
  const buttons = document.querySelectorAll('.actions button'); buttons.forEach(button => button.disabled = true);
  const result = $('policy-result'); result.hidden = false; result.classList.remove('danger'); result.textContent = 'Checking policy…'; $('test-results').hidden = true;
  try {
    const data = await api(`/api/policy/${action}`, {text: $('policy-text').value, hash: policyHash});
    result.textContent = data.message;
    if (data.hash) policyHash = data.hash;
    if (data.results) { $('test-results').textContent = data.results.trim().split('\n').map(line => JSON.stringify(JSON.parse(line), null, 2)).join('\n\n'); $('test-results').hidden = false; }
  } catch (error) { result.textContent = error.message; result.classList.add('danger'); }
  finally { buttons.forEach(button => button.disabled = false); }
}
$('validate').addEventListener('click', () => policyAction('validate'));
$('test-policy').addEventListener('click', () => policyAction('test'));
$('save-policy').addEventListener('click', () => policyAction('save'));
refresh();
