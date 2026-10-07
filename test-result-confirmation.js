'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('extension/popup/traffic-path-panel.js', 'utf8');
const start = source.indexOf('  function createConfirmation(');
const end = source.indexOf('\n  function create(container', start);
let now = 0;
let id = 0;
const timers = new Map();
const classes = new Set();
const toast = { dataset: {}, textContent: '', attrs: {}, setAttribute(k, v) { this.attrs[k] = v; }, classList: { add(k) { classes.add(k); }, remove(k) { classes.delete(k); } } };
const ctx = vm.createContext({ node: () => toast, setTimeout(fn, delay) { timers.set(++id, { fn, at: now + delay }); return id; }, clearTimeout(key) { timers.delete(key); } });
vm.runInContext(source.slice(start, end), ctx);
const helper = ctx.createConfirmation({ append(element) { assert.equal(element, toast); } });
function advance(ms) {
  const target = now + ms;
  while (true) {
    const next = [...timers].sort((a, b) => a[1].at - b[1].at)[0];
    if (!next || next[1].at > target) break;
    now = next[1].at;
    timers.delete(next[0]);
    next[1].fn();
  }
  now = target;
}
assert.equal(toast.attrs['aria-live'], 'polite');
assert.equal(toast.attrs.role, 'status');
const result = {};
helper.show('allow', result);
assert.equal(toast.textContent, 'ALLOWED');
advance(1000);
helper.show('allow', result);
advance(999);
assert.ok(classes.has('is-visible'));
advance(1);
assert.ok(!classes.has('is-visible'), 'duplicate must not restart timeout');
advance(180);
assert.equal(toast.textContent, '');
helper.show('allow', result);
assert.equal(timers.size, 0, 'expired result must not replay');
for (const status of ['pending', 'unknown', 'warn', 'isolate', 'unsupported']) {
  helper.show(status, {});
  assert.equal(toast.textContent, '');
  assert.equal(timers.size, 0);
}
helper.show('block', {});
assert.equal(toast.textContent, 'BLOCKED');
helper.clear();
assert.equal(toast.textContent, '');
assert.equal(timers.size, 0);
helper.show('allow', result);
advance(2000);
helper.clear();
helper.show('block', {});
advance(180);
assert.equal(toast.textContent, 'BLOCKED', 'cancelled fade cleanup cannot erase a new result');
helper.clear();
helper.show('allow', result);
assert.ok(classes.has('is-visible'), 'new run may repeat the same verdict');
helper.clear();
const describe = fs.readFileSync('extension/popup/describe-panel.js', 'utf8');
const verdictStart = describe.indexOf('    function renderVerdict(');
const verdictEnd = describe.indexOf('\n    }', verdictStart) + 6;
let shown;
const element = () => ({ append() {}, setAttribute() {}, addEventListener() {} });
const describeCtx = vm.createContext({ OUTCOME: { allow: { status: 'allow', icon: '' }, block: { status: 'block', icon: '' }, unknown: { status: 'unknown', icon: '' } }, node: element, priorityText: () => '', host: { showResult(...args) { shown = args; } } });
vm.runInContext(describe.slice(verdictStart, verdictEnd), describeCtx);
for (const action of ['allow', 'block', 'unknown']) {
  const decision = { action, verdictTitle: 'Detail remains', assumptions: [] };
  describeCtx.renderVerdict(decision, null);
  assert.equal(shown[1], action);
  assert.equal(shown[2], decision);
}
console.log('Result confirmation tests passed');
