'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
class Element {
  constructor(tag, document) {
    this.tagName = tag.toUpperCase();
    this.ownerDocument = document;
    this.children = [];
    this.parentElement = null;
    this.attributes = new Map();
    this.listeners = new Map();
    this.value = '';
    this.hidden = false;
    this._text = '';
    this.scrolls = [];
    this.classList = {
      contains: name => this.className.split(/\s+/).includes(name),
      add: name => { if (!this.classList.contains(name)) this.className = `${this.className} ${name}`.trim(); },
    };
  }
  get id() { return this.getAttribute('id') || ''; }
  set id(value) { this.setAttribute('id', value); }
  get className() { return this.getAttribute('class') || ''; }
  set className(value) { this.setAttribute('class', value); }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  set textContent(value) { this.replaceChildren(); this._text = String(value); }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.has(name) ? this.attributes.get(name) : null; }
  removeAttribute(name) { this.attributes.delete(name); }
  append(...nodes) {
    for (const child of nodes) {
      if (child.parentElement) child.parentElement.children.splice(child.parentElement.children.indexOf(child), 1);
      child.parentElement = this;
      this.children.push(child);
    }
  }
  replaceChildren(...nodes) {
    for (const child of this.children) child.parentElement = null;
    this.children = [];
    this._text = '';
    this.append(...nodes);
  }
  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(listener);
  }
  dispatchEvent(event) {
    event.target = this;
    event.currentTarget = this;
    for (const listener of this.listeners.get(event.type) || []) listener.call(this, event);
    return !event.defaultPrevented;
  }
  querySelectorAll(selector) {
    const matches = element => selector.startsWith('.') ? element.classList.contains(selector.slice(1)) :
      selector.startsWith('#') ? element.id === selector.slice(1) : element.tagName.toLowerCase() === selector;
    const found = [];
    const walk = element => { for (const child of element.children) { if (matches(child)) found.push(child); walk(child); } };
    walk(this);
    return found;
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  focus() {
    if (this.ownerDocument.activeElement === this) return;
    const previous = this.ownerDocument.activeElement;
    this.ownerDocument.activeElement = null;
    if (previous) fire(previous, 'blur');
    this.ownerDocument.activeElement = this;
    fire(this, 'focus');
  }
  blur() {
    if (this.ownerDocument.activeElement !== this) return;
    this.ownerDocument.activeElement = null;
    fire(this, 'blur');
  }
  scrollIntoView(options) { this.scrolls.push(options); }
}
function fire(element, type, data = {}) {
  const event = { type, cancelable: true, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, ...data };
  element.dispatchEvent(event);
  return event;
}
const filename = 'extension/popup/traffic-path-panel.js';
const source = fs.readFileSync(filename, 'utf8');
const exportText = 'root.TrafficPathPanel = { create };';
assert.equal(source.split(exportText).length, 2, 'private-picker export anchor must be unique');
const document = { activeElement: null, createElement(tag) { return new Element(tag, this); } };
const context = vm.createContext({ document, window: {} });
vm.runInContext(source.replace(exportText, 'root.TrafficPathPanel = { create, createPicker };'), context, { filename });
const createPicker = context.window.TrafficPathPanel.createPicker;
const sample = () => [
  { value: 'sourceUsers:1', label: 'Alice Freeman (alice@example.test)', badge: 'User' },
  { value: 'sourceUsers:2', label: 'Bob Brown (bob@example.test)', badge: 'User' },
  { value: 'sourceGroups:3', label: 'Engineering', badge: 'Group' },
];
function fixture(options = sample(), state = 'ready', id = 'tp-src-identity', noun = 'users or groups') {
  document.activeElement = null;
  const data = { options, state, noun };
  const changes = [];
  const picker = createPicker({ id, placeholder: 'Search sources', getOptions: () => data.options,
    getStatus: () => ({ state: data.state, noun: data.noun }), onChange: value => changes.push(value) });
  const list = picker.element.querySelector('.tp-picker-list');
  const clear = picker.element.querySelector('.tp-picker-clear');
  return { picker, input: picker.input, list, clear, data, changes,
    rows: () => list.querySelectorAll('.tp-picker-option'),
    type(text) { picker.input.value = text; fire(picker.input, 'input'); },
    key(key) { return fire(picker.input, 'keydown', { key }); },
  };
}
function closed(f) {
  assert.equal(f.list.hidden, true);
  assert.equal(f.input.getAttribute('aria-expanded'), 'false');
  assert.equal(f.input.getAttribute('aria-activedescendant'), null);
}
const tests = [];
const test = (name, run) => tests.push({ name, run });
test('01 combobox/listbox relationships and contextual accessible names', () => {
  const f = fixture();
  assert.equal(f.input.getAttribute('role'), 'combobox');
  assert.equal(f.input.getAttribute('aria-autocomplete'), 'list');
  assert.equal(f.input.getAttribute('aria-controls'), f.list.id);
  assert.equal(f.list.getAttribute('role'), 'listbox');
  assert.equal(f.list.getAttribute('aria-label'), 'users or groups options');
  assert.equal(f.clear.getAttribute('aria-label'), 'Clear users or groups selection');
  assert.equal(f.clear.type, 'button');
  assert.equal(f.clear.hidden, true);
  assert.equal(f.picker.value, '');
  closed(f);
  const fallback = fixture([], 'ready', 'tp-custom', 'widgets');
  assert.equal(fallback.list.getAttribute('aria-label'), 'widgets options');
  assert.equal(fallback.clear.getAttribute('aria-label'), 'Clear widgets selection');
});
test('02 focus opens all options with no phantom active descendant', () => {
  const f = fixture(); f.input.focus();
  assert.equal(f.list.hidden, false);
  assert.equal(f.input.getAttribute('aria-expanded'), 'true');
  assert.equal(f.rows().length, 3);
  assert.equal(f.input.getAttribute('aria-activedescendant'), null);
  assert.ok(f.rows().every(row => row.getAttribute('aria-selected') === 'false'));
});
test('03 case-insensitive substring search, split label, badge and safe text', () => {
  const f = fixture(); f.input.focus(); f.type('  ALICE@EXAMPLE  ');
  assert.equal(f.rows().length, 1);
  assert.equal(f.rows()[0].querySelector('.tp-picker-label').textContent, 'Alice Freeman');
  assert.equal(f.rows()[0].querySelector('.tp-picker-detail').textContent, 'alice@example.test');
  assert.equal(f.rows()[0].querySelector('.tp-picker-badge').textContent, 'User');
  f.data.options = [{ value: 'literal', label: '<img src=x> (literal@test)', badge: '<b>Group</b>' }];
  f.type('literal');
  assert.equal(f.rows()[0].querySelector('.tp-picker-label').textContent, '<img src=x>');
  assert.equal(f.rows()[0].querySelector('.tp-picker-badge').textContent, '<b>Group</b>');
  assert.equal(f.rows()[0].querySelector('img'), null);
});
test('04 loading, empty organization and no-match messages', () => {
  const f = fixture([], 'loading'); f.input.focus();
  assert.equal(f.list.querySelector('.tp-picker-loading').getAttribute('role'), 'status');
  assert.equal(f.list.querySelectorAll('.tp-picker-skeleton').length, 3);
  assert.match(f.list.textContent, /Loading users or groups/);
  f.data.state = 'ready'; f.picker.refresh();
  assert.equal(f.list.textContent, 'No users or groups in this organization.');
  f.data.options = sample(); f.type('zzzz');
  assert.equal(f.list.textContent, 'No users or groups match “zzzz”.');
  assert.equal(f.rows().length, 0);
  f.key('ArrowDown'); f.key('Enter');
  assert.equal(f.picker.value, ''); assert.deepEqual(f.changes, []);
});
test('05 60-row cap and search reaches options beyond the cap', () => {
  const options = Array.from({ length: 65 }, (_, i) => ({ value: `v${i}`, label: `Person ${String(i).padStart(2, '0')}` }));
  const f = fixture(options); f.input.focus();
  assert.equal(f.rows().length, 60);
  assert.match(f.list.textContent, /5 more — keep typing to narrow/);
  f.type('Person 64'); assert.equal(f.rows().length, 1);
  f.key('Enter'); assert.equal(f.picker.value, 'v64');
});
test('06 mouse selection prevents blur and notifies once', () => {
  const f = fixture(); f.input.focus();
  assert.equal(fire(f.rows()[1], 'mousedown').defaultPrevented, true);
  assert.equal(f.picker.value, 'sourceUsers:2');
  assert.equal(f.input.value, sample()[1].label);
  assert.equal(f.clear.hidden, false);
  closed(f); f.input.blur(); assert.deepEqual(f.changes, ['sourceUsers:2']);
  f.input.focus(); assert.equal(f.rows()[1].getAttribute('aria-selected'), 'true');
});
test('07 arrows clamp to rows and scroll the active item', () => {
  const f = fixture();
  assert.equal(f.key('ArrowDown').defaultPrevented, true);
  assert.equal(f.input.getAttribute('aria-activedescendant'), 'tp-src-identity-opt-0');
  f.key('ArrowDown'); f.key('ArrowDown'); f.key('ArrowDown');
  assert.equal(f.input.getAttribute('aria-activedescendant'), 'tp-src-identity-opt-2');
  assert.equal(f.rows()[2].scrolls.length, 1);
  assert.equal(f.rows()[2].scrolls[0].block, 'nearest');
  f.key('ArrowUp'); f.key('ArrowUp'); f.key('ArrowUp');
  assert.equal(f.input.getAttribute('aria-activedescendant'), 'tp-src-identity-opt-0');
});
test('08 Enter chooses the active row even with a prior selection', () => {
  const f = fixture(); f.picker.set('sourceUsers:2'); f.input.focus();
  f.key('ArrowDown'); assert.equal(f.key('Enter').defaultPrevented, true);
  assert.equal(f.picker.value, 'sourceUsers:1');
  assert.deepEqual(f.changes, ['sourceUsers:1']); closed(f);
});
test('09 Enter with unchanged selection does not choose the first row', () => {
  const f = fixture(); f.picker.set('sourceUsers:2'); f.input.focus();
  assert.equal(f.rows().length, 3);
  f.key('Enter');
  assert.equal(f.picker.value, 'sourceUsers:2'); assert.deepEqual(f.changes, []); closed(f);
  assert.equal(f.key('Enter').defaultPrevented, false);
});
test('10 Enter chooses the first filtered row without arrow navigation', () => {
  const f = fixture(); f.input.focus(); f.type('brown'); f.key('Enter');
  assert.equal(f.picker.value, 'sourceUsers:2'); assert.deepEqual(f.changes, ['sourceUsers:2']); closed(f);
});
test('11 Escape closes, clears active ARIA and preserves committed selection', () => {
  const f = fixture(); f.picker.set('sourceUsers:2'); f.input.focus(); f.key('ArrowDown');
  assert.equal(f.key('Escape').defaultPrevented, true);
  assert.equal(f.picker.value, 'sourceUsers:2'); assert.deepEqual(f.changes, []); closed(f);
  assert.equal(f.key('Escape').defaultPrevented, false);
  f.input.blur(); f.input.focus();
  assert.equal(f.input.getAttribute('aria-activedescendant'), null);
});
test('12 deleting typed text clears selection on blur only', () => {
  const f = fixture(); f.picker.set('sourceUsers:2'); f.input.focus(); f.type('  ');
  assert.equal(f.picker.value, 'sourceUsers:2'); assert.deepEqual(f.changes, []);
  f.input.blur(); assert.equal(f.picker.value, ''); assert.equal(f.input.value, '');
  assert.equal(f.clear.hidden, true); assert.deepEqual(f.changes, ['']); closed(f);
});
test('13 unique exact label on blur commits with trim and case folding', () => {
  const f = fixture(); f.input.focus(); f.type('  bOB bROWN (BOB@EXAMPLE.TEST)  '); f.input.blur();
  assert.equal(f.picker.value, 'sourceUsers:2'); assert.equal(f.input.value, sample()[1].label);
  assert.deepEqual(f.changes, ['sourceUsers:2']); closed(f);
});
test('14 Tab commits exact label without trapping focus or double blur commit', () => {
  const f = fixture(); f.input.focus(); f.type(' engineering ');
  assert.equal(f.key('Tab').defaultPrevented, false);
  assert.equal(f.picker.value, 'sourceGroups:3'); closed(f);
  f.input.blur(); assert.deepEqual(f.changes, ['sourceGroups:3']);
});
test('15 unknown or partial labels revert on blur and Tab', () => {
  for (const prior of ['', 'sourceUsers:2']) for (const action of ['blur', 'Tab']) {
    const f = fixture(); f.picker.set(prior); f.input.focus(); f.type('alice');
    if (action === 'blur') f.input.blur(); else { f.key('Tab'); f.input.blur(); }
    assert.equal(f.picker.value, prior);
    assert.equal(f.input.value, prior ? sample()[1].label : '');
    assert.deepEqual(f.changes, []); closed(f);
  }
});
test('16 duplicate exact labels are not arbitrarily committed on blur or Tab', () => {
  const options = [...sample(), { value: 'sourceGroups:4', label: 'engineering' }];
  for (const prior of ['', 'sourceUsers:2']) for (const action of ['blur', 'Tab']) {
    const f = fixture(options); f.picker.set(prior); f.input.focus(); f.type('ENGINEERING');
    if (action === 'blur') f.input.blur(); else f.key('Tab');
    assert.equal(f.picker.value, prior); assert.equal(f.input.value, prior ? sample()[1].label : '');
    assert.deepEqual(f.changes, []); closed(f);
  }
});
test('17 clear button clears, notifies once, refocuses and opens full list', () => {
  const f = fixture(); f.picker.set('sourceUsers:2'); f.input.focus(); f.key('ArrowDown'); f.input.blur();
  fire(f.clear, 'click');
  assert.equal(f.picker.value, ''); assert.equal(f.input.value, ''); assert.equal(f.clear.hidden, true);
  assert.deepEqual(f.changes, ['']); assert.equal(document.activeElement, f.input);
  assert.equal(f.list.hidden, false); assert.equal(f.rows().length, 3);
  assert.equal(f.input.getAttribute('aria-activedescendant'), null);
});
test('18 set restores known values and clears missing values silently', () => {
  const f = fixture(); f.input.focus(); f.key('ArrowDown'); f.picker.set('sourceGroups:3');
  assert.equal(f.picker.value, 'sourceGroups:3'); assert.equal(f.input.value, 'Engineering'); closed(f);
  f.picker.set('missing'); assert.equal(f.picker.value, ''); assert.equal(f.input.value, '');
  assert.equal(f.clear.hidden, true); f.picker.set(''); assert.deepEqual(f.changes, []);
});
test('19 refresh updates idle labels and preserves in-progress focused typing', () => {
  const f = fixture(); f.picker.set('sourceUsers:2');
  f.data.options = sample().map(option => option.value === 'sourceUsers:2' ? { ...option, label: 'Robert Brown' } : option);
  f.picker.refresh(); assert.equal(f.input.value, 'Robert Brown'); closed(f);
  f.input.focus(); f.type('eng'); f.data.options = [...f.data.options, { value: 'new', label: 'Engineering Team' }];
  f.picker.refresh(); assert.equal(f.input.value, 'eng'); assert.equal(f.rows().length, 2);
  assert.equal(f.picker.value, 'sourceUsers:2'); assert.deepEqual(f.changes, []);
  f.input.blur(); assert.equal(f.input.value, 'Robert Brown');
});
test('20 refresh shrink and input filtering cannot leave dangling active ARIA', () => {
  const f = fixture(); f.input.focus(); f.key('ArrowDown'); f.key('ArrowDown'); f.key('ArrowDown');
  f.data.options = [sample()[0]]; f.picker.refresh();
  assert.equal(f.input.getAttribute('aria-activedescendant'), null);
  f.key('ArrowDown'); assert.equal(f.input.getAttribute('aria-activedescendant'), f.rows()[0].id);
  f.type('absent'); assert.equal(f.input.getAttribute('aria-activedescendant'), null);
  f.data.options = []; f.data.state = 'loading'; f.picker.refresh();
  assert.equal(f.input.getAttribute('aria-activedescendant'), null);
  assert.deepEqual(f.changes, []);
});
test('21 focused selected label rename keeps the same selected ID after blur', () => {
  const f = fixture(); f.picker.set('sourceUsers:2'); f.input.focus();
  const oldLabel = f.input.value;
  f.data.options = sample().map(option => option.value === 'sourceUsers:2' ? { ...option, label: 'Robert Brown' } : option);
  f.data.options.push({ value: 'sourceUsers:4', label: oldLabel, badge: 'User' });
  f.picker.refresh();
  assert.equal(document.activeElement, f.input);
  assert.equal(f.input.value, 'Robert Brown');
  assert.equal(f.picker.value, 'sourceUsers:2'); assert.deepEqual(f.changes, []);
  f.input.blur();
  assert.equal(f.picker.value, 'sourceUsers:2'); assert.equal(f.input.value, 'Robert Brown');
  assert.deepEqual(f.changes, []); closed(f);
});
test('22 prevented clear mousedown avoids a transient typed-label commit', () => {
  const f = fixture(); f.picker.set('sourceUsers:2'); f.input.focus(); f.type(sample()[0].label);
  const event = fire(f.clear, 'mousedown');
  if (!event.defaultPrevented) f.clear.focus();
  assert.equal(event.defaultPrevented, true);
  assert.equal(document.activeElement, f.input);
  assert.equal(f.picker.value, 'sourceUsers:2'); assert.deepEqual(f.changes, []);
  fire(f.clear, 'click');
  assert.equal(f.picker.value, ''); assert.equal(f.input.value, ''); assert.equal(f.clear.hidden, true);
  assert.equal(document.activeElement, f.input); assert.deepEqual(f.changes, ['']);
  f.input.blur(); assert.deepEqual(f.changes, ['']); closed(f);
});
test('23 removed selected catalog entry clears on ready but not loading', () => {
  for (const focused of [false, true]) {
    const f = fixture(); f.picker.set('sourceUsers:2');
    if (focused) { f.input.focus(); f.key('ArrowDown'); }
    f.data.options = []; f.data.state = 'loading'; f.picker.refresh(); f.picker.refresh();
    assert.equal(f.picker.value, 'sourceUsers:2'); assert.equal(f.input.value, sample()[1].label);
    assert.equal(f.clear.hidden, false); assert.deepEqual(f.changes, []);
    assert.equal(f.input.getAttribute('aria-activedescendant'), null);
    if (focused) assert.match(f.list.textContent, /Loading users or groups/);
    f.data.state = 'ready'; f.picker.refresh();
    assert.equal(f.picker.value, ''); assert.equal(f.input.value, ''); assert.equal(f.clear.hidden, true);
    assert.deepEqual(f.changes, ['']); closed(f);
    f.picker.refresh(); f.input.blur(); assert.deepEqual(f.changes, ['']);
  }
});
assert.equal(tests.length, 23);
let failed = 0;
for (const { name, run } of tests) {
  try { run(); console.log(`PASS ${name}`); }
  catch (error) { failed++; console.log(`FAIL ${name}\n${error.stack}`); }
}
console.log(`RESULT ${tests.length - failed}/${tests.length} passed; ${failed} failed`);
process.exitCode = failed ? 1 : 0;
