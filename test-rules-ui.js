'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');

async function main() {
  const browser = process.env.RULES_UI_CDP_URL || 'http://127.0.0.1:9333';
  const target = await fetch(`${browser}/json/new?about:blank`, { method: 'PUT' }).then(r => r.json());
  const socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', reject, { once: true });
  });
  let id = 0;
  const pending = new Map();
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    const handler = pending.get(message.id);
    if (!handler) return;
    pending.delete(message.id);
    if (message.error) handler.reject(new Error(message.error.message));
    else handler.resolve(message.result);
  });
  const send = (method, params) => new Promise((resolve, reject) => {
    pending.set(++id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
  const evaluate = async expression => {
    const result = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    assert.equal(result.exceptionDetails, undefined, JSON.stringify(result.exceptionDetails));
    return result.result.value;
  };
  try {
    await evaluate('window.fetch = async () => ({ json: async () => ({}) });');
    await evaluate(fs.readFileSync('extension/popup/popup-sections.js', 'utf8'));
    const results = await evaluate(`(async () => {
      const results = [];
      const check = (condition, name) => { if (!condition) throw new Error(name); results.push(name); };
      const host = document.createElement('div');
      document.body.appendChild(host);
      const component = PopupSections.buildRulesList(host);
      const rules = [
        { id: 0, name: 'Alpha', action: 'allow', type: 'internet', order: 1 },
        { id: 2, name: 'Beta', action: 'block', type: 'private', order: 2 },
        { id: 3, name: 'Gamma', action: 'allow', type: 'private', order: 3 }
      ];
      const update = data => component.update(data, [], {}, {}, {}, {});
      const cards = () => [...host.querySelectorAll('details')];
      const card = id => cards().find(c => c.dataset.ruleId === String(id));
      const input = host.querySelector('input');
      const pills = [...host.querySelectorAll('[data-filter]')];
      const pill = id => pills.find(p => p.dataset.filter === id);
      const status = host.querySelector('[role=status]');
      const empty = [...host.querySelectorAll('div')].find(e => e.firstChild?.textContent === 'No matching rules');
      const type = text => { input.value = text; input.dispatchEvent(new Event('input')); };
      const count = text => check(status.textContent === text, 'count: ' + text);
      const pressed = id => check(pills.every(p => p.getAttribute('aria-pressed') === String(p.dataset.filter === id)), 'pressed: ' + id);
      await update(rules);
      count('3 matching / 3 total rules');
      pressed('all');
      check(status.getAttribute('aria-live') === 'polite' && status.getAttribute('aria-atomic') === 'true', 'polite atomic status');
      card(0).open = true;
      card(3).open = true;
      card(0).querySelector('summary').focus();
      await update([rules[2], { ...rules[0], name: 'Alpha renamed' }, rules[1]]);
      check(card(0).open && card(3).open && !card(2).open, 'open IDs survive reorder and rename, including ID zero');
      check(document.activeElement === card(0).querySelector('summary'), 'summary focus restored by rule ID');
      input.focus();
      await update(rules);
      check(document.activeElement === input, 'search focus remains');
      pill('allow').focus();
      pill('allow').click();
      await update(rules);
      check(document.activeElement === pill('allow'), 'filter focus remains');
      pressed('allow');
      count('2 matching / 3 total rules');
      type('Gamma');
      count('1 matching / 3 total rules');
      check(card(0).style.display === 'none' && card(3).style.display === '', 'search and filter intersect');
      check(host.querySelector('#psc-audit-summary-container').textContent.includes('Total Rules:3'), 'loaded audit total independent of filtering');
      type('absent');
      count('0 matching / 3 total rules');
      check(!empty.hidden, 'No matching rules visible');
      const observer = new MutationObserver(() => {});
      observer.observe(status, { childList: true, subtree: true, characterData: true });
      type('absent');
      check(observer.takeRecords().length === 0, 'unchanged count does not reannounce');
      await update(rules);
      check(host.querySelector('[role=status]') === status, 'status node stable across update');
      empty.querySelector('button').click();
      count('3 matching / 3 total rules');
      pressed('all');
      check(input.value === '' && empty.hidden && document.activeElement === input, 'reset clears query/filter and returns search focus');
      for (const [filter, expected] of [['block', 1], ['private', 2], ['internet', 1], ['all', 3]]) {
        pill(filter).click();
        pressed(filter);
        count(expected + ' matching / 3 total rules');
      }
      card(2).querySelector('summary').focus();
      await update([rules[0], rules[2]]);
      check(!host.contains(document.activeElement), 'removed focused rule does not focus unrelated rule');
      check(card(0).open && card(3).open, 'surviving disclosures remain open after removal');
      await update([]);
      count('0 matching / 0 total rules');
      check(empty.hidden && host.textContent.includes('No rules loaded'), 'unloaded state distinct from no matches');
      await update(rules);
      check(cards().every(c => !c.open), 'removed IDs do not retain stale open state');
      await update(null);
      count('0 matching / 0 total rules');
      return results;
    })()`);
    for (const result of results) console.log(`PASS ${result}`);
    console.log(`Rules UI: ${results.length} assertions passed`);
  } finally {
    socket.close();
    await fetch(`${browser}/json/close/${target.id}`);
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
