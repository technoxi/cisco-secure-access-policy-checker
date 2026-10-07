'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const model = require('./extension/popup/traffic-path.js');
const panelSource = fs.readFileSync('extension/popup/traffic-path-panel.js', 'utf8');
function functionSource(name) {
  const start = panelSource.indexOf(`    ${name === 'check' ? 'async ' : ''}function ${name}(`);
  assert.ok(start >= 0, name);
  const end = panelSource.indexOf('\n    }', start) + 6;
  return panelSource.slice(start, end);
}
function fixture() {
  const input = { removeAttribute() {} };
  const ctx = vm.createContext({
    confirmation: { clears: 0, clear() { this.clears++; } },
    runSeq: 0, busy: false, error: { textContent: '' }, radios: {}, pickers: {},
    destination: input, port: input, protocol: input,
    results: { count: 1, replaceChildren() { this.count = 0; } },
    lastEvaluation: { stale: true }, facts: {}, factsFor: '', manualFor: '',
    activeCatalogs: {}, catalogRevision: '{}', dataState: { rulesCount: 1, revision: 1 },
    sessionStorage: { getItem() { return null; } }, DRAFT_KEY: 'draft',
    syncRunButton() {}, renderDataStatus() {},
    currentForm() { return { destination: 'example.com', port: '', protocol: 'TCP' }; },
    model: { buildRequest(draft) { return { request: draft }; } },
    showValidation(message) { ctx.error.textContent = message; },
    renderResult(request, evaluation) { ctx.results.count++; },
    onRun() { return new Promise((resolve, reject) => ctx.pending.push({ resolve, reject })); },
    pending: [],
  });
  vm.runInContext(['invalidate', 'check', 'setData', 'updateCatalogs'].map(functionSource).join('\n'), ctx);
  return ctx;
}
async function main() {
  const f = fixture();
  const first = f.check();
  assert.equal(f.busy, true);
  assert.equal(f.confirmation.clears, 1, 'new run clears confirmation');
  assert.equal(f.lastEvaluation, null);
  assert.equal(f.results.count, 0);
  f.error.textContent = 'old error';
  f.invalidate();
  assert.equal(f.confirmation.clears, 2, 'input invalidation clears confirmation');
  assert.equal(f.busy, false);
  assert.equal(f.error.textContent, '');
  const second = f.check();
  f.pending[0].resolve({ title: 'stale' });
  await first;
  assert.equal(f.busy, true, 'old finally must not release a newer run');
  assert.equal(f.lastEvaluation, null);
  assert.equal(f.results.count, 0);
  const seq = f.runSeq;
  f.setData({ rulesCount: 1, revision: 1, catalogs: {} });
  assert.equal(f.runSeq, seq, 'unchanged data must preserve generation');
  assert.equal(f.busy, true);
  f.pending[1].resolve({ title: 'current' });
  await second;
  assert.equal(f.busy, false);
  assert.equal(f.lastEvaluation.evaluation.title, 'current');
  f.setData({ revision: 2 });
  assert.equal(f.lastEvaluation, null);
  assert.equal(f.results.count, 0);
  const third = f.check();
  f.updateCatalogs({ sourceUsers: { 1: 'Alice' } });
  assert.equal(f.busy, false);
  f.pending[2].reject(new Error('stale failure'));
  await third;
  assert.equal(f.error.textContent, '');
  f.lastEvaluation = { stale: true }; f.results.count = 1;
  f.model.buildRequest = () => ({ error: 'Invalid destination' });
  await f.check();
  assert.equal(f.lastEvaluation, null);
  assert.equal(f.results.count, 0);
  assert.equal(f.error.textContent, 'Invalid destination');

  const question = { groups: [
    { field: 'applicationId', options: [{ id: 7 }] },
    { field: 'contentCategoryId', options: [{ id: 7 }] },
  ] };
  const original = { applicationId: { yes: [], no: ['7', '8'], all: true } };
  const scoped = model.answer(original, question, [{ field: 'applicationId', id: 7 }]);
  assert.deepEqual(scoped.applicationId, { yes: ['7'], no: ['8'] });
  assert.deepEqual(scoped.contentCategoryId, { yes: [], no: ['7'] });
  assert.equal(original.applicationId.all, true);
  const reversed = model.answer(scoped, question, [{ field: 'contentCategoryId', id: 7 }]);
  assert.deepEqual(reversed.applicationId, { yes: [], no: ['8', '7'] });
  assert.deepEqual(reversed.contentCategoryId, { yes: ['7'], no: [] });
  assert.deepEqual(model.answer({}, question, [7]).applicationId.yes, []);
  assert.deepEqual(model.answer({}, { groups: [question.groups[0]] }, [7]).applicationId.yes, ['7']);
  console.log('PASS UI generation, validation, data revision, stale failure, and scoped answer regressions');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
