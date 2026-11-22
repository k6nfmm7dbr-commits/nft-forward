'use strict';

// CI: install jsdom@26.1.0 outside the repo, then run
// NODE_PATH=/path/to/node_modules node tests/nff_panel_ui_test.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { JSDOM } = require('jsdom');

const root = path.join(__dirname, '../internal/webui/static');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
const entry = '/example-entry/';
const GiB = 2 ** 30;
const alpha = {
  id: 1, name: 'IPv4 <demo>', protocol: 'tcp+udp', enabled: true, status: 'normal',
  listen_port: 10443, target_address: '192.0.2.10', target_port: 443,
  quota_enabled: true, quota_limit_bytes: GiB, ip_limit_enabled: true, ip_limit_max: 2,
  quota: { quota_enabled: true, quota_used_bytes: GiB / 2, quota_limit_bytes: GiB },
  ips: { limited: true, max_ips: 2, granted_count: 1, ips: [{ ip: '198.51.100.1', tcp: 2 }] },
};
const beta = {
  id: 2, name: '域名规则', protocol: 'udp', enabled: true, status: 'dns_stale',
  listen_port: 12000, target_address: 'forward.example.test', target_port: 53,
  resolve_status: 'stale', resolved_ipv4: '192.0.2.20', resolved_ipv6: '2001:db8::20',
  quota_enabled: false, quota_limit_bytes: 0, ip_limit_enabled: false, ip_limit_max: 0,
  ips: { granted_count: 1, ips: [{ ip: '2001:db8::2', udp: 7 }] },
};
const snap = (rules = [alpha, beta]) => ({ now: 123, today_up: 1024, total_up: GiB, rules });
const live = { now: 123, rate_up: 1024, rate_down: 2048, conn_tcp: 2, conn_udp: 7, rules: [
  { id: 1, status: 'normal', rate_up: 1024, conn_tcp: 2, ip_limited: true, max_ips: 2, active_ip_count: 1 },
  { id: 2, status: 'dns_stale', rate_down: 2048, conn_udp: 7, active_ip_count: 1 },
] };
const day = (day, up = 123) => ({ days: [{ day, up, down: 42 }] });
const settle = () => new Promise(resolve => setImmediate(resolve));

function harness(t, hash = '', host = '203.0.113.4') {
  const dom = new JSDOM(html, { url: `http://${host}:8100${entry}${hash}`, runScripts: 'outside-only' });
  const { window: w } = dom;
  t.after(() => w.close());
  const calls = [], copied = [], intervals = {}, confirmations = [];
  let events;
  w.matchMedia = () => ({ matches: true });
  w.requestAnimationFrame = () => 0;
  w.setInterval = (fn, ms) => { intervals[ms] = fn; };
  Object.defineProperty(w.document, 'hidden', { value: false });
  Object.defineProperty(w.navigator, 'clipboard', { configurable: true, value: {
    writeText: text => { copied.push(text); return Promise.resolve(); },
  } });
  w.confirm = text => { confirmations.push(text); return true; };
  w.EventSource = class {
    constructor(url, options) {
      assert.equal(url, entry + 'api/events');
      assert.equal(options.withCredentials, true);
      events = this;
    }
    addEventListener(name, fn) { this[name] = fn; }
  };
  w.fetch = (input, opts) => {
    const url = new URL(input, w.location.origin);
    assert.ok(url.pathname.startsWith(entry + 'api/'), url.pathname);
    assert.equal(opts.credentials, 'same-origin');
    assert.equal(opts.cache, 'no-store');
    return new Promise(resolve => calls.push({
      route: url.pathname.slice(entry.length), method: opts.method || 'GET',
      params: Object.fromEntries(url.searchParams),
      body: opts.body && JSON.parse(opts.body),
      send(data, status = 200) {
        resolve({ ok: status >= 200 && status < 300, status, json: () => Promise.resolve(data) });
      },
    }));
  };
  w.eval(app);
  const el = sel => {
    const result = w.document.querySelector(sel);
    assert.ok(result, sel);
    return result;
  };
  const take = (route, method = 'GET') => {
    const i = calls.findIndex(call => call.route === route && call.method === method);
    assert.notEqual(i, -1, `${method} ${route} not found in ${calls.map(c => c.route)}`);
    return calls.splice(i, 1)[0];
  };
  return {
    w, calls, copied, intervals, confirmations, el, take, text: sel => el(sel).textContent,
    click: sel => el(sel).click(),
    key: (key, target = w.document, shiftKey = false) => target.dispatchEvent(new w.KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, shiftKey })),
    sse: data => events.snapshot({ data: JSON.stringify(data) }),
    async start() {
      take('api/summary').send(snap()); await settle();
      take('api/live').send(live); await settle();
    },
    value(sel, value) {
      el(sel).value = value;
      el(sel).dispatchEvent(new w.Event('change', { bubbles: true }));
    },
  };
}

test('renders overview, updates cards in place, and copies IPv6 host, port and whole address', async t => {
  const h = harness(t, '', '[2001:db8::5]');
  await h.start();
  assert.equal(h.text('#hero-rate'), '3.00 KiB/s');
  assert.equal(h.text('#status-txt'), '实时监控中');
  assert.equal(h.text('#kpi-rules'), '2 / 2');
  assert.equal(h.text('.node-name'), 'IPv4 <demo>');
  assert.equal(h.text('.addr-text'), '2001:db8::5 10443');
  assert.equal(h.text('[data-rule-ips="1"]'), '1 / 2');
  const card = h.el('.node-card');
  h.sse(snap([{ ...alpha, today_up: 2048, status: 'quota_exceeded' }, beta]));
  assert.equal(h.el('.node-card'), card);
  assert.equal(h.text('[data-rule-today]'), '2.00 KiB');
  assert.equal(h.text('[data-status="1"]'), '流量已达限');
  h.click('[data-copy-val="2001:db8::5"]');
  h.click('[data-copy-val="10443"]');
  h.click('[data-copy-val="2001:db8::5 10443"]');
  await settle();
  assert.deepEqual(h.copied, ['2001:db8::5', '10443', '2001:db8::5 10443']);
  // Plain-HTTP clipboard fallback and focus restoration inside the IP-target drawer.
  Object.defineProperty(h.w.navigator, 'clipboard', { value: undefined });
  h.w.document.execCommand = command => {
    assert.equal(command, 'copy'); h.copied.push(h.w.document.activeElement.value); return true;
  };
  h.click('[data-manage="1"]');
  assert.ok(h.el('#pol-dns-sect').classList.contains('hidden'));
  const copy = h.el('#pol-address [data-copy-val="2001:db8::5 10443"]');
  copy.focus(); copy.click();
  assert.equal(h.copied.at(-1), '2001:db8::5 10443');
  assert.equal(h.w.document.activeElement, copy);
  assert.equal(h.el('.logout-form').getAttribute('method'), 'post');
  assert.equal(h.el('.logout-form').getAttribute('action'), 'logout');
});

test('creates one rule with random-port sentinel, validates, and restores drawer focus', async t => {
  const h = harness(t); await h.start();
  h.click('#btn-new-rule');
  assert.equal(h.w.document.activeElement.id, 'new-close');
  h.key('Tab', h.w.document, true);
  assert.equal(h.w.document.activeElement.id, 'new-submit');
  assert.ok(h.el('main').hasAttribute('inert'));
  h.click('#new-submit');
  assert.match(h.text('#new-error'), /规则名称/);
  h.value('#new-name', 'Demo v6'); h.value('#new-target', 'https://example.test');
  h.value('#new-target-port', 8443); h.click('#new-submit');
  assert.match(h.text('#new-error'), /IP 或域名/);
  h.value('#new-target', '2001:db8::42');
  h.key('Enter', h.el('#new-target'));
  const create = h.take('api/rules', 'POST');
  assert.deepEqual(create.body, { name: 'Demo v6', protocol: 'tcp+udp', listen_port: 0, target_address: '2001:db8::42', target_port: 8443 });
  h.key('Enter', h.el('#new-target'));
  assert.equal(h.calls.length, 0);
  create.send({ id: 3, listen_port: 18000 }); await settle();
  assert.equal(h.w.document.activeElement.id, 'btn-new-rule');
  assert.equal(h.el('#new-drawer').getAttribute('aria-hidden'), 'true');
  assert.ok(!h.el('main').hasAttribute('inert'));
  const serverRule = { ...create.body, id: 3, listen_port: 18000, enabled: true };
  h.take('api/summary').send(snap([alpha, beta, serverRule])); await settle();
  assert.ok(h.el('[data-manage="3"]'));
});

test('edits forwarding and policy, preserves read-only DNS, and separates resets and deletion', async t => {
  const h = harness(t); await h.start();
  h.click('[data-manage="2"]');
  assert.equal(h.text('#pol-dns-host'), beta.target_address);
  assert.equal(h.text('#pol-dns-v6'), beta.resolved_ipv6);
  assert.equal(h.el('#pol-dns-sect').querySelectorAll('input, select, button').length, 0);
  assert.match(h.text('#pol-dns-status'), /沿用/);
  h.value('#pol-name', 'New name');
  h.sse(snap([alpha, { ...beta, resolve_status: 'failed' }]));
  assert.equal(h.el('#pol-name').value, 'New name');
  assert.match(h.text('#pol-dns-status'), /不可用/);
  h.click('#pol-enable'); h.click('#pol-quota-enable'); h.click('#pol-ip-enable');
  assert.ok(!h.el('#pol-quota-box').classList.contains('hidden'));
  assert.ok(!h.el('#pol-ip-box').classList.contains('hidden'));
  h.value('#pol-quota-val', '1.5'); h.value('#pol-quota-unit', 'TiB'); h.value('#pol-ip-max', '6');
  h.click('#pol-save');
  assert.ok(h.el('#pol-quota-reset').disabled);
  const edit = h.take('api/rules/2', 'PUT');
  assert.deepEqual(edit.body, { name: 'New name', protocol: 'udp', listen_port: 12000,
    target_address: beta.target_address, target_port: 53, enabled: false });
  edit.send(edit.body); await settle();
  const policy = h.take('api/rules/2/policy', 'PUT');
  assert.deepEqual(policy.body, { quota_enabled: true, quota_limit_bytes: 1.5 * 1024 * GiB, ip_limit_enabled: true, ip_limit_max: 6 });
  policy.send({ error: 'policy failed' }, 409); await settle();
  assert.match(h.text('#pol-error'), /转发设置已保存.*policy failed/);
  const edited = { ...beta, ...edit.body, status: 'disabled' };
  h.take('api/summary').send(snap([alpha, edited])); await settle();
  assert.equal(h.text('[data-status="2"]'), '已停用');
  h.click('#pol-save'); h.take('api/rules/2', 'PUT').send(edit.body); await settle();
  h.take('api/rules/2/policy', 'PUT').send(policy.body); await settle();
  assert.equal(h.el('#policy-drawer').getAttribute('aria-hidden'), 'true');
  h.take('api/summary').send(snap([alpha, { ...edited, ...policy.body }])); await settle();
  h.click('[data-manage="1"]');
  h.w.confirm = () => false;
  h.click('#pol-delete'); assert.ok(!h.calls.some(c => c.method === 'DELETE'));
  h.w.confirm = () => true;
  h.click('#pol-quota-reset'); h.take('api/rules/1/quota/reset', 'POST').send({ quota_used_bytes: 0 }); await settle();
  assert.equal(h.text('#pol-quota-used'), '0 B');
  h.take('api/summary').send(snap([{ ...alpha, quota: { ...alpha.quota, quota_used_bytes: 0 } }, edited])); await settle();
  h.click('#pol-delete'); h.take('api/rules/1', 'DELETE').send({}); await settle();
  h.take('api/summary').send(snap([edited])); await settle();
  assert.equal(h.w.document.querySelector('[data-manage="1"]'), null);
});

test('ignores old summary/live after SSE and old IP reads across drawer sessions and snapshots', async t => {
  const h = harness(t); await h.start();
  h.intervals[8000](); h.intervals[2000]();
  const slowSummary = h.take('api/summary'), slowLive = h.take('api/live');
  const newer = { ...alpha, status: 'ip_limited', ips: { ...alpha.ips, granted_count: 2 } };
  h.sse(snap([newer, beta]));
  slowSummary.send(snap()); slowLive.send(live); await settle();
  assert.equal(h.text('[data-status="1"]'), 'IP 已达上限');
  assert.equal(h.text('[data-rule-ips="1"]'), '2 / 2');
  h.click('[data-view-ips="1"]');
  const oldA = h.take('api/rules/1/ips');
  h.click('#drawer-mask'); h.click('[data-view-ips="2"]');
  const oldB = h.take('api/rules/2/ips');
  oldA.send({ ips: [{ ip: '198.51.100.17' }] }); await settle();
  assert.match(h.text('#ips-list'), /2001:db8::2/);
  assert.doesNotMatch(h.text('#ips-list'), /198.51.100.17/);
  h.sse(snap([newer, { ...beta, ips: { ips: [{ ip: '2001:db8::88' }], rejected: [{ ip: '192.0.2.77' }] } }]));
  oldB.send(beta.ips); await settle();
  assert.match(h.text('#ips-list'), /2001:db8::88.*192\.0\.2\.77.*已拒绝/);
  h.key('Escape');
  assert.equal(h.w.document.activeElement.dataset.viewIps, '2');
});

test('keeps late write results out of a different drawer', async t => {
  const h = harness(t); await h.start();
  h.click('[data-manage="1"]'); h.click('#pol-quota-reset');
  const reset = h.take('api/rules/1/quota/reset', 'POST');
  h.key('Escape'); h.click('[data-manage="2"]');
  h.value('#pol-name', 'Draft');
  reset.send({ quota_used_bytes: 0 }); await settle();
  assert.equal(h.text('#drawer-rule-name'), beta.name);
  assert.equal(h.text('#pol-quota-used'), '—');
  h.take('api/summary').send(snap()); await settle();
  h.click('#pol-delete'); const del = h.take('api/rules/2', 'DELETE');
  h.key('Escape'); h.click('[data-manage="1"]');
  del.send({ error: 'previous drawer error' }, 409); await settle();
  assert.ok(h.el('#pol-error').classList.contains('hidden'));
  assert.equal(h.text('#drawer-rule-name'), alpha.name);
});

test('uses current trend selection, clears it on removal, and falls back to the first rule', async t => {
  const h = harness(t, '#rules');
  assert.equal(h.el('[aria-current="page"]').dataset.view, 'rules');
  h.take('api/summary').send(snap()); await settle();
  const first = h.take('api/rules/1/daily');
  assert.deepEqual(first.params, { days: '60' });
  h.value('#rule-select', '2');
  h.take('api/rules/2/daily').send(day('2026-09-02')); await settle();
  first.send(day('2026-09-01')); await settle();
  assert.match(h.text('#rule-daily-table'), /2026-09-02/);
  h.sse(snap([alpha])); await settle();
  assert.match(h.text('#rule-daily-table'), /2026-09-01/);
  h.sse(snap([]));
  assert.ok(h.el('#rule-select').disabled);
  assert.match(h.text('#rule-daily-table'), /暂无可选规则/);
  h.click('[data-view="daily"]');
  assert.equal(h.w.location.hash, '#daily');
  const all = h.take('api/daily'); assert.deepEqual(all.params, { days: '60' });
  all.send(day('2026-09-03')); await settle();
  assert.match(h.text('#daily-table'), /2026-09-03/);
  const count = h.calls.length;
  h.intervals[2000](); h.intervals[8000](); assert.equal(h.calls.length, count);
});

test('does not coalesce trend reads across writes or apply prior-generation results', async t => {
  const h = harness(t); await h.start();
  h.click('[data-manage="1"]'); h.click('#pol-quota-reset');
  const reset = h.take('api/rules/1/quota/reset', 'POST');
  h.key('Escape'); h.click('[data-view="rules"]');
  const before = h.take('api/rules/1/daily');
  reset.send({ quota_used_bytes: 0 }); await settle();
  h.take('api/summary').send(snap()); await settle();
  const after = h.take('api/rules/1/daily');
  after.send(day('2026-10-02')); await settle();
  before.send(day('2026-10-01')); await settle();
  assert.match(h.text('#rule-daily-table'), /2026-10-02/);
  assert.doesNotMatch(h.text('#rule-daily-table'), /2026-10-01/);
});
