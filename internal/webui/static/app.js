/* NFT Forward 面板 —— 前端逻辑（原生 JS，无外部依赖、无构建链）
 *
 * 数据流与 SBX 一致：
 *   · /api/summary  低频（8s）：规则结构、累计/今日流量、配额、解析状态
 *   · /api/live     高频（2s）：速率、连接数、在线 IP 数
 *   · /api/events   SSE：变更后立即推送完整快照（规则增删改、配额翻转、IP 上下线）
 *
 * 所有写操作都用服务端返回的正式对象更新 UI，绝不做乐观假成功。
 */
'use strict';

var state = { ruleId: null, summary: null, live: null };
var dataEpoch = 0, summaryRevision = 0;
// activeView 记录当前页签：轮询按它节流，隐藏视图不做无谓重画。
var activeView = 'home';

/* ---------- API ---------- */

/* BASE 是面板的随机入口前缀（形如 "/3e4f65a8c24d2bd5b9e80147/"）。
 *
 * 面板不再挂在站点根下，所有请求都必须相对入口拼接。取 location.pathname
 * 到最后一个斜杠为止即可 —— 服务端已保证入口目录带尾斜杠（无尾斜杠会 302 到
 * 带斜杠版本），因此这里恒等于入口前缀。
 *
 * 刻意不把入口路径写进 JS 常量：它是每台机器不同的随机值，硬编码就意味着
 * 前端资源要按机器生成。
 */
var BASE = location.pathname.replace(/[^/]*$/, '');

// url 把入口内的相对路径拼成绝对路径（'api/summary' → '/<entry>/api/summary'）。
function url(path) { return BASE + String(path).replace(/^\/+/, ''); }

var inflight = Object.create(null);

// 面板可达性：连续失败达到阈值就把状态条切成「连接异常」，恢复后自动切回。
// 目的：网络/服务抖动时用户看到的是一句明确的「正在重试」，而不是页面像坏掉
// 一样静止不动（EventSource 会自动重连，HTTP 轮询也会继续，无需手动刷新）。
var connFailStreak = 0;
var connDown = false;
function noteAPIResult(ok) {
  if (ok) {
    connFailStreak = 0;
    if (connDown) { connDown = false; setConnState('实时监控中', false); }
    return;
  }
  connFailStreak++;
  if (!connDown && connFailStreak >= 3) {
    connDown = true;
    setConnState('连接异常 · 正在重试', true);
  }
}
function setConnState(text, stale) {
  setText('status-txt', text);
  var p = document.getElementById('pulse');
  if (p) p.className = 'pulse' + (stale ? ' stale' : '');
}

function api(path, params, freshness) {
  // 请求只在同一数据代次内合并；写入后不能复用尚未返回的旧读取。
  var epoch = dataEpoch;
  var key = JSON.stringify([epoch, freshness, path, params]);
  if (inflight[key]) return inflight[key];
  var u = new URL(url(path), location.origin);
  if (params) Object.keys(params).forEach(function (k) { u.searchParams.set(k, params[k]); });
  var req = fetch(u, { cache: 'no-store', credentials: 'same-origin' }).then(function (r) {
    if (r.status === 401) { location.href = url('login'); throw new Error('未登录'); }
    if (!r.ok) { if (epoch === dataEpoch) noteAPIResult(false); throw new Error('请求失败 ' + r.status); }
    if (epoch === dataEpoch) noteAPIResult(true);
    return r.json();
  }, function (e) { if (epoch === dataEpoch) noteAPIResult(false); throw e; })
    .finally(function () { delete inflight[key]; });
  inflight[key] = req;
  return req;
}

// mutate 统一处理写请求：业务错误抛出服务端文案。
function mutate(method, path, body) {
  var opts = { method: method, cache: 'no-store', credentials: 'same-origin', headers: {} };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  return fetch(url(path), opts).then(function (r) {
    if (r.status === 401) { location.href = url('login'); throw new Error('未登录'); }
    return r.json().then(function (d) {
      if (!r.ok) throw new Error((d && d.error) || ('请求失败 ' + r.status));
      return d;
    }, function () {
      if (!r.ok) throw new Error('请求失败 ' + r.status);
      return {};
    });
  });
}

/* ---------- 格式化 ---------- */
var UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
function fmtBytes(n) {
  n = Number(n) || 0;
  var i = 0, v = n;
  while (v >= 1024 && i < UNITS.length - 1) { v /= 1024; i++; }
  var d = v < 10 && i > 0 ? 2 : (v < 100 && i > 0 ? 1 : 0);
  return v.toFixed(d) + ' ' + UNITS[i];
}
function fmtRate(n) { return fmtBytes(n) + '/s'; }
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}
// 地址显示：IPv6 加方括号，域名/IPv4 直接拼端口。
function hostPort(addr, port) {
  var a = String(addr == null ? '' : addr);
  if (a.indexOf(':') >= 0) return '[' + a + ']:' + port;
  return a + ':' + port;
}
function toast(msg) {
  var el = document.getElementById('toast');
  el.textContent = msg; el.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(function () { el.classList.remove('show'); }, 4000);
}
function setText(id, txt) {
  var el = document.getElementById(id);
  if (el && el.textContent !== txt) el.textContent = txt;
}

/* ---------- 数值缓动（按需 rAF，尊重 prefers-reduced-motion） ---------- */
var reducedMotion = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
var eased = {};
function easeTo(id, target, fmt) {
  if (reducedMotion) { setText(id, fmt(target)); return; }
  var e = eased[id];
  if (!e) { e = eased[id] = { cur: target, target: target, fmt: fmt }; setText(id, fmt(target)); return; }
  e.target = target; e.fmt = fmt;
  kickEase();
}
function tickEase() {
  var any = false;
  for (var id in eased) {
    var e = eased[id];
    var diff = e.target - e.cur;
    if (Math.abs(diff) < Math.max(1, Math.abs(e.target) * 0.005)) e.cur = e.target;
    else { e.cur += diff * 0.22; any = true; }
    setText(id, e.fmt(e.cur));
  }
  return any;
}
var easeRunning = false;
function easeLoop() {
  if (document.hidden) { easeRunning = false; return; }
  if (!tickEase()) { easeRunning = false; return; }
  requestAnimationFrame(easeLoop);
}
function kickEase() {
  if (easeRunning || reducedMotion) return;
  easeRunning = true;
  requestAnimationFrame(easeLoop);
}

/* ---------- 状态徽标 ---------- */
var STATUS = {
  normal:         ['运行中', 'ok'],
  disabled:       ['已停用', 'off'],
  quota_exceeded: ['流量已达限', 'danger'],
  ip_limited:     ['IP 已达上限', 'warn'],
  dns_stale:      ['DNS 暂时失败', 'warn'],
  dns_failed:     ['域名无法解析', 'danger']
};
function statusOf(st) { return STATUS[st] || STATUS.normal; }

var PROTO_LABEL = { tcp: 'TCP', udp: 'UDP', 'tcp+udp': 'TCP + UDP' };

// 用访问面板的主机作为转发地址示例。
function addrHost() { return location.hostname.replace(/^\[|\]$/g, ''); }

// copyText 复制到剪贴板。面板通常是纯 HTTP（非安全上下文），此时
// navigator.clipboard 不可用，必须回退到 textarea + execCommand。
function copyText(text, okMsg) {
  function fallback() {
    var previous = document.activeElement;
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '-1000px';
    document.body.appendChild(ta);
    ta.focus({ preventScroll: true });
    ta.select();
    ta.setSelectionRange(0, text.length);
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    ta.remove();
    if (previous && previous.isConnected) previous.focus({ preventScroll: true });
    toast(ok ? (okMsg || '已复制') : '复制失败，请手动选择文本');
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function () { toast(okMsg || '已复制'); }, fallback);
    return;
  }
  fallback();
}
function protoLabel(p) { return PROTO_LABEL[p] || String(p || '—'); }

/* ---------- 概览 ---------- */
function renderSummary(s) {
  summaryRevision++;
  state.summary = s;
  updatePolicyReadouts();
  easeTo('kpi-today-total', (s.today_up || 0) + (s.today_down || 0), fmtBytes);
  easeTo('kpi-all-total', (s.total_up || 0) + (s.total_down || 0), fmtBytes);
  var enabled = 0;
  (s.rules || []).forEach(function (r) { if (r.enabled) enabled++; });
  setText('kpi-rules', enabled + ' / ' + (s.rules || []).length);
  // 卡片与 KPI 只存在于总览视图：不在总览时跳过 DOM 更新（切回时会补一次）。
  if (activeView === 'home') renderRuleCards(s);
  renderRuleSelect(s);
}

/* ---------- 规则卡片（视觉沿用 SBX node-card） ---------- */
// quotaText 返回配额的纯文本（不带标签），供定点更新使用。
function quotaText(r) {
  var q = r.quota;
  if (!r.quota_enabled && !(q && q.quota_enabled)) return '不限';
  var used = q ? fmtBytes(q.quota_used_bytes) : '—';
  return used + ' / ' + fmtBytes((q && q.quota_limit_bytes) || r.quota_limit_bytes);
}
function ipCountText(count, limited, max) {
  return limited ? ((count || 0) + ' / ' + max) : String(count || 0);
}
function ruleIPCount(r) {
  var ips = r.ips || {};
  return ipCountText(ips.granted_count ?? r.active_ip_count, ips.limited ?? r.ip_limit_enabled, ips.max_ips ?? r.ip_limit_max);
}
function addressButtons(port, label) {
  var host = esc(addrHost());
  return '<div class="addr-group">' + (label ? '<span class="addr-label">转发地址</span>' : '') +
    '<div class="addr-text">' +
    '<button type="button" class="addr-token" data-copy-val="' + host + '" title="复制 IP" aria-label="复制 IP ' + host + '">' + host + '</button> ' +
    '<button type="button" class="addr-token" data-copy-val="' + esc(port) + '" title="复制端口" aria-label="复制端口 ' + esc(port) + '">' + esc(port) + '</button>' +
    '</div></div><button type="button" class="mini-btn" data-copy-val="' + host + '" aria-label="复制 IP ' + host + '">复制 IP</button>';
}
function ruleCard(r) {
  var st = statusOf(r.status), id = esc(r.id);
  var target = r.target_text || hostPort(r.target_address, r.target_port);
  return '<article class="node-card' + (r.enabled ? '' : ' is-disabled') + '">' +
    '<div class="node-top">' +
      '<div class="node-title">' +
        '<h3 class="node-name" title="' + esc(r.name) + '">' + esc(r.name) + '</h3>' +
        '<div class="node-meta-line">' +
          '<span class="chip">' + esc(protoLabel(r.protocol)) + '</span>' +
          '<span class="status-pill ' + st[1] + '" data-status="' + id + '">' + st[0] + '</span>' +
        '</div>' +
      '</div>' +
      '<div class="node-rate">' +
        '<b class="up" data-live="' + id + '" data-kind="rate-up">—</b>' +
        '<b class="down" data-live="' + id + '" data-kind="rate-down">—</b>' +
      '</div>' +
    '</div>' +
    '<div class="rule-addr">' + addressButtons(r.listen_port, true) + '</div>' +
    '<div class="rule-target"><span>转发目标</span><b data-rule-target>' + esc(target) + '</b></div>' +
    '<div class="node-stats">' +
      '<div class="node-stat"><span>今日流量</span><b data-rule-today>' + fmtBytes((r.today_up || 0) + (r.today_down || 0)) + '</b></div>' +
      '<div class="node-stat"><span>累计流量</span><b data-rule-total>' + fmtBytes((r.total_up || 0) + (r.total_down || 0)) + '</b></div>' +
      '<div class="node-stat"><span>TCP 连接</span><b data-live="' + id + '" data-kind="conns">—</b></div>' +
      '<div class="node-stat"><span>UDP 会话</span><b data-live="' + id + '" data-kind="conns-udp">—</b></div>' +
      '<div class="node-stat"><span>流量配额</span><b data-rule-quota>' + quotaText(r) + '</b></div>' +
    '</div>' +
    '<div class="node-foot">' +
      '<button type="button" class="ip-strip" data-view-ips="' + id + '" aria-haspopup="dialog">' +
        '<span class="ip-strip-label">在线 IP</span>' +
        '<span class="ip-strip-val" data-rule-ips="' + id + '">' + esc(ruleIPCount(r)) + '</span>' +
        '<span class="ip-strip-arrow" aria-hidden="true">›</span>' +
      '</button>' +
      '<div class="node-actions"><button type="button" class="mini-btn primary" data-manage="' + id + '" aria-haspopup="dialog">管理</button></div>' +
    '</div>' +
  '</article>';
}

// renderRuleCards 只在**结构**变化时重建卡片 DOM，其余情况定点更新字段。
//
// 为什么必须这样做：/api/summary 每 8 秒一次，旧实现每次都 `innerHTML = ...`
// 把整组卡片销毁重建 —— 滚动位置丢失、正在看的详情被打断、重排开销随规则数
// 线性增长（真机上表现为明显卡顿）。结构签名只包含「决定 DOM 形状」的字段
// （id / 名称 / 协议 / 端口 / 启停），流量数字、状态与在线 IP
// 都走定点更新。
function ruleStructureSignature(rules) {
  return JSON.stringify(rules.map(function (r) {
    return [r.id, r.name, r.protocol, r.listen_port, r.enabled];
  }));
}

function renderRuleCards(s) {
  var host = document.getElementById('rule-cards');
  if (!host) return;
  var rules = s.rules || [];
  var signature = ruleStructureSignature(rules);
  if (host._structure !== signature) {
    host._structure = signature;
    if (!rules.length) {
      host.innerHTML = '<div class="empty">还没有转发规则，点右上角「添加规则」创建</div>';
      return;
    }
    host.innerHTML = rules.map(ruleCard).join('');
  }
  for (var i = 0; i < rules.length; i++) {
    var r = rules[i], card = host.children[i];
    if (!card) continue;
    setNodeText(card, '[data-rule-target]', r.target_text || hostPort(r.target_address, r.target_port));
    setNodeText(card, '[data-rule-today]', fmtBytes((r.today_up || 0) + (r.today_down || 0)));
    setNodeText(card, '[data-rule-total]', fmtBytes((r.total_up || 0) + (r.total_down || 0)));
    setNodeText(card, '[data-rule-quota]', quotaText(r));
    setNodeText(card, '[data-rule-ips]', ruleIPCount(r));
    var st = statusOf(r.status);
    var pill = card.querySelector('[data-status]');
    if (pill && pill.textContent !== st[0]) {
      pill.className = 'status-pill ' + st[1];
      pill.textContent = st[0];
    }
  }
  if (state.live) renderLiveCards(state.live, false);
}

// setNodeText 定点写文本（值未变时不触碰 DOM，避免无谓的重排/重绘）。
function setNodeText(root, sel, text) {
  var el = root.querySelector(sel);
  if (el && el.textContent !== text) el.textContent = text;
}

function renderRuleSelect(s) {
  var sel = document.getElementById('rule-select');
  var rules = s.rules || [];
  var sig = JSON.stringify(rules.map(function (r) { return [r.id, r.name]; }));
  if (sel._sig !== sig) {
    sel._sig = sig;
    sel.innerHTML = rules.map(function (r) {
      return '<option value="' + esc(r.id) + '">' + esc(r.name) + '</option>';
    }).join('');
  }
  // 选中的规则被删除时回落到第一条，避免下拉停留在已不存在的 id 上。
  var prev = state.ruleId == null ? '' : String(state.ruleId);
  var exists = rules.some(function (r) { return String(r.id) === prev; });
  var want = exists ? prev : (rules.length ? String(rules[0].id) : '');
  sel.disabled = !rules.length;
  if (want && sel.value !== want) sel.value = want;
  var changed = prev !== want;
  state.ruleId = want || null;
  if (activeView === 'rules' && (changed || !want)) loadRuleDaily();
}

/* ---------- 实时 ---------- */
function renderLive(v, updatePolicy) {
  state.live = v;
  var known = (v.now || 0) > 0;
  if (!connDown) setConnState(known ? '实时监控中' : '等待采集', !known);

  easeTo('hero-rate', (v.rate_up || 0) + (v.rate_down || 0), fmtRate);
  easeTo('hero-up', v.rate_up || 0, fmtRate);
  easeTo('hero-down', v.rate_down || 0, fmtRate);
  setText('kpi-conns', String(v.conn_tcp || 0));
  setText('kpi-conns-udp', String(v.conn_udp || 0));

  if (activeView === 'home') renderLiveCards(v, updatePolicy);
  if (updatePolicy && policyState.rule) {
    var liveRule = (v.rules || []).find(function (r) { return String(r.id) === String(policyState.rule.id); });
    if (liveRule) setText('pol-ip-active', ipCountText(liveRule.active_ip_count, liveRule.ip_limited, liveRule.max_ips));
  }
}
function renderLiveCards(v, updatePolicy) {
  var byId = Object.create(null);
  (v.rules || []).forEach(function (r) { byId[r.id] = r; });
  document.querySelectorAll('[data-live]').forEach(function (el) {
    var r = byId[el.getAttribute('data-live')];
    if (!r) return;
    var kind = el.getAttribute('data-kind');
    if (kind === 'rate-up') el.textContent = '↑ ' + fmtRate(r.rate_up || 0);
    else if (kind === 'rate-down') el.textContent = '↓ ' + fmtRate(r.rate_down || 0);
    else if (kind === 'conns') el.textContent = String(r.conn_tcp || 0);
    else if (kind === 'conns-udp') el.textContent = String(r.conn_udp || 0);
  });
  if (!updatePolicy) return;
  document.querySelectorAll('[data-rule-ips]').forEach(function (el) {
    var r = byId[el.getAttribute('data-rule-ips')];
    if (!r) return;
    var val = ipCountText(r.active_ip_count, r.ip_limited, r.max_ips);
    if (el.textContent !== val) el.textContent = val;
  });
  document.querySelectorAll('[data-status]').forEach(function (el) {
    var r = byId[el.getAttribute('data-status')];
    if (!r) return;
    var st = statusOf(r.status);
    if (el.textContent !== st[0]) {
      el.className = 'status-pill ' + st[1];
      el.textContent = st[0];
    }
  });
}

/* ---------- 明细表格 ---------- */
// 趋势数据按「全量 / 每条规则」分别缓存，带 60 秒新鲜度：
//   · 切回已加载的规则立即出图，不必重新请求；
//   · 快速切换时用请求序号丢弃过期响应，绝不让旧规则的曲线覆盖当前选择；
//   · 规则增删改后整体失效（refreshAfterRuleChange）。
var cache = { daily: null, dailyAt: 0, ruleDaily: Object.create(null) };
var dailyReq = 0, dailyEpoch = 0, ruleDailyReq = 0, ruleDailyEpoch = 0;
var DAILY_TTL_MS = 60000;

function renderTable(hostId, rows) {
  var host = document.getElementById(hostId);
  if (!host) return;
  if (!rows || !rows.length) { host.innerHTML = '<div class="empty">暂无数据</div>'; return; }
  var html = '<div class="table-scroll" tabindex="0" role="region" aria-label="每日流量明细"><table><thead><tr>' +
    '<th>日期</th><th class="up">上传</th><th class="down">下载</th><th>合计</th>' +
    '</tr></thead><tbody>';
  rows.forEach(function (r) {
    html += '<tr><td class="date">' + esc(r.day) + '</td>' +
      '<td class="up">' + fmtBytes(r.up) + '</td>' +
      '<td class="down">' + fmtBytes(r.down) + '</td>' +
      '<td><b>' + fmtBytes((r.up || 0) + (r.down || 0)) + '</b></td></tr>';
  });
  html += '</tbody></table></div>';
  host.innerHTML = html;
}
function drawDaily() { if (cache.daily) renderTable('daily-table', cache.daily); }
function drawRuleDaily() {
  if (state.ruleId == null) return;
  var entry = cache.ruleDaily[String(state.ruleId)];
  if (entry) renderTable('rule-daily-table', entry.days);
}
function trendMessage(id, msg) {
  document.getElementById(id).innerHTML = '<div class="empty" role="status">' + esc(msg) + '</div>';
}
function loadDaily(force) {
  var req = ++dailyReq, epoch = dailyEpoch;
  if (!force && cache.daily && Date.now() - cache.dailyAt < DAILY_TTL_MS) {
    if (activeView === 'daily') drawDaily();
    return Promise.resolve();
  }
  if (!cache.daily) trendMessage('daily-table', '正在加载每日流量…');
  return api('/api/daily', { days: 60 }).then(function (d) {
    if (epoch !== dailyEpoch || req !== dailyReq) return;
    cache.daily = d.days || []; cache.dailyAt = Date.now();
    if (activeView === 'daily') drawDaily();
  }).catch(function (e) {
    if (epoch !== dailyEpoch || req !== dailyReq || activeView !== 'daily' || e.message === '未登录') return;
    if (!cache.daily) trendMessage('daily-table', '每日流量加载失败 · ' + e.message);
    else toast(e.message);
  });
}
function loadRuleDaily(force) {
  var req = ++ruleDailyReq, epoch = ruleDailyEpoch;
  if (state.ruleId == null) {
    trendMessage('rule-daily-table', state.summary ? '暂无可选规则' : '正在加载规则…');
    return Promise.resolve();
  }
  var id = String(state.ruleId), cached = cache.ruleDaily[id];
  if (cached) drawRuleDaily();
  if (!force && cached && Date.now() - cached.at < DAILY_TTL_MS) return Promise.resolve();
  if (!cached) trendMessage('rule-daily-table', '正在加载规则流量…');
  function isCurrent() {
    return activeView === 'rules' && state.ruleId === id && req === ruleDailyReq && epoch === ruleDailyEpoch;
  }
  return api('/api/rules/' + id + '/daily', { days: 60 }).then(function (d) {
    if (epoch !== ruleDailyEpoch) return;
    cache.ruleDaily[id] = { days: d.days || [], at: Date.now() };
    if (isCurrent()) drawRuleDaily();
  }).catch(function (e) {
    if (!isCurrent() || e.message === '未登录') return;
    if (!cached) trendMessage('rule-daily-table', '规则流量加载失败 · ' + e.message);
    else toast(e.message);
  });
}

// refreshAfterRuleChange 在规则增删改后统一刷新：趋势缓存整体失效，
// 概览重新拉取，当前所在页签立刻补一次自己的数据。
function refreshAfterRuleChange() {
  dataEpoch++;
  state.live = null;
  cache.daily = null; cache.dailyAt = 0;
  cache.ruleDaily = Object.create(null);
  dailyReq++; dailyEpoch++; ruleDailyReq++; ruleDailyEpoch++;
  return loadSummary().then(function () {
    if (activeView === 'home') loadLive();
    else if (activeView === 'daily') return loadDaily(true);
    else if (activeView === 'rules') return loadRuleDaily(true);
  });
}

/* ---------- 底部导航 ---------- */
function initNav() {
  var valid = ['home', 'daily', 'rules'], positions = { home: 0, daily: 0, rules: 0 };
  var current = (location.hash || '#home').slice(1);
  if (valid.indexOf(current) < 0) current = 'home';
  function show(name, push) {
    if (valid.indexOf(name) < 0) name = 'home';
    closeAllDrawers();
    positions[current] = window.scrollY || 0; current = name; activeView = name;
    document.querySelectorAll('.view').forEach(function (v) { v.classList.toggle('on', v.id === 'view-' + name); });
    document.querySelectorAll('.tab[data-view]').forEach(function (b) {
      var selected = b.dataset.view === name;
      b.classList.toggle('on', selected);
      if (selected) b.setAttribute('aria-current', 'page');
      else b.removeAttribute('aria-current');
    });
    if (push && location.hash !== '#' + name) history.pushState(null, '', '#' + name);
    requestAnimationFrame(function () { window.scrollTo(0, positions[name] || 0); });
    // 切回总览立刻补一次实时数据（离开总览时高频轮询是停的）。
    if (name === 'home') {
      if (state.summary) renderRuleCards(state.summary);
      if (push || state.summary) { loadSummary(); loadLive(); }
    }
    if (name === 'daily') loadDaily();
    if (name === 'rules') loadRuleDaily();
  }
  document.querySelectorAll('.tab[data-view]').forEach(function (b) {
    b.addEventListener('click', function () { show(b.dataset.view, true); });
  });
  window.addEventListener('popstate', function () { show((location.hash || '#home').slice(1), false); });
  show(current, false);
}

/* ---------- 抽屉 ---------- */
var drawer = null, drawerSession = 0, drawerOpener = null;
function openDrawer(id, opener) {
  if (drawer) closeDrawer(drawer.id);
  drawer = document.getElementById(id);
  drawerSession++;
  drawerOpener = opener || document.activeElement;
  drawer.querySelector('.drawer-body').scrollTop = 0;
  drawer.removeAttribute('inert');
  drawer.setAttribute('aria-hidden', 'false');
  drawer.classList.add('on');
  drawer.querySelector('.icon-btn').focus({ preventScroll: true });
  document.getElementById('drawer-mask').classList.add('on');
  document.body.classList.add('drawer-open');
  document.querySelector('main').setAttribute('inert', '');
  document.querySelector('.dock').setAttribute('inert', '');
}
function isDrawer(id, session) {
  return drawer && drawer.id === id && (session == null || session === drawerSession);
}
function closeDrawer(id) {
  if (!isDrawer(id)) return;
  if (deleteConfirmation) closeDeleteConfirmation(false);
  drawer.classList.remove('on');
  drawer.setAttribute('inert', '');
  var closed = drawer;
  drawer = null;
  drawerSession++;
  if (id === 'ips-drawer') ipsDrawerRuleId = null;
  if (id === 'policy-drawer') policyState.rule = null;
  document.getElementById('drawer-mask').classList.remove('on');
  document.body.classList.remove('drawer-open');
  document.querySelector('main').removeAttribute('inert');
  document.querySelector('.dock').removeAttribute('inert');
  var focus = drawerOpener && drawerOpener.isConnected ? drawerOpener : document.querySelector('.tab.on');
  if (focus) focus.focus({ preventScroll: true });
  closed.setAttribute('aria-hidden', 'true');
  drawerOpener = null;
}
function closeAllDrawers() { if (drawer) closeDrawer(drawer.id); }
function showErr(id, msg) {
  var el = document.getElementById(id);
  el.textContent = msg; el.classList.remove('hidden');
}
function hideErr(id) {
  var el = document.getElementById(id);
  el.textContent = ''; el.classList.add('hidden');
}

// setSwitch 设置 toggle 状态。
//
// 为什么不能只写 input.checked：WebKit 在 JS 赋值 checked 后不会重新计算
// `.sw-input:checked + .sw` 这类兄弟选择器，开关会停留在旧外观（真机 iOS
// Safari 上可复现）。这里在赋值后对相邻的 .sw 强制一次重排，逼浏览器重算样式。
function setSwitch(id, on) {
  var inp = document.getElementById(id);
  if (!inp) return;
  inp.checked = !!on;
  var sw = inp.nextElementSibling;
  if (sw && sw.classList.contains('sw')) {
    var prev = sw.style.display;
    sw.style.display = 'none';
    void sw.offsetHeight; // 触发同步重排
    sw.style.display = prev;
  }
}

/* ---------- 添加规则 ---------- */
function openNewRule(e) {
  document.getElementById('new-name').value = '';
  document.getElementById('new-proto').value = 'tcp+udp';
  document.getElementById('new-listen-port').value = '';
  document.getElementById('new-target').value = '';
  document.getElementById('new-target-port').value = '';
  hideErr('new-error');
  openDrawer('new-drawer', e.currentTarget);
}

function submitNewRule() {
  var btn = document.getElementById('new-submit');
  if (!isDrawer('new-drawer') || btn.disabled) return;
  var session = drawerSession;
  var name = document.getElementById('new-name').value.trim();
  var proto = document.getElementById('new-proto').value;
  var lpRaw = document.getElementById('new-listen-port').value.trim();
  var target = document.getElementById('new-target').value.trim();
  var tpRaw = document.getElementById('new-target-port').value.trim();

  if (!name) { showErr('new-error', '请输入规则名称'); return; }
  if (!target) { showErr('new-error', '请输入目标地址（IP 或域名）'); return; }
  if (!validTarget(target)) {
    showErr('new-error', /^https?:|\/|:\d|\[/i.test(target)
      ? '目标地址只填写 IP 或域名，不要包含 http://、https://、端口或路径'
      : '请输入有效的 IPv4、IPv6 或域名');
    return;
  }
  var tp = Number(tpRaw);
  if (!Number.isInteger(tp) || tp < 1 || tp > 65535) { showErr('new-error', '请输入 1-65535 的目标端口'); return; }
  // 监听端口留空 → 传 0，由后端安全随机分配（前端绝不自己生成端口）。
  var lp = 0;
  if (lpRaw !== '') {
    lp = Number(lpRaw);
    if (!Number.isInteger(lp) || lp < 1 || lp > 65535) { showErr('new-error', '监听端口需在 1-65535，或留空由系统随机分配'); return; }
  }

  btn.disabled = true; btn.textContent = '添加中…';
  hideErr('new-error');
  mutate('POST', '/api/rules', {
    name: name, protocol: proto, listen_port: lp,
    target_address: target, target_port: tp
  }).then(function (rule) {
    btn.disabled = false; btn.textContent = '添加';
    if (isDrawer('new-drawer', session)) closeDrawer('new-drawer');
    // 用服务端返回的正式规则刷新，不做乐观假成功。
    toast('规则已添加 · 监听端口 ' + rule.listen_port);
    refreshAfterRuleChange();
  }).catch(function (e) {
    btn.disabled = false; btn.textContent = '添加';
    if (isDrawer('new-drawer', session) && e.message !== '未登录') showErr('new-error', e.message);
  });
}

// validTarget 是前端第一道校验（后端 net/netip + 严格 hostname 才是权威）。
function validTarget(v) {
  if (!v || /\s/.test(v)) return false;
  if (/^https?:/i.test(v) || v.indexOf('://') >= 0) return false;
  if (v.indexOf('/') >= 0 || v.indexOf('[') >= 0 || v.indexOf(']') >= 0 || v.indexOf('@') >= 0) return false;
  // IPv4
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) {
    return v.split('.').every(function (p) { return Number(p) <= 255; }) && v !== '0.0.0.0';
  }
  // IPv6（宽松判断：含冒号且只有合法字符；权威校验在后端）
  if (v.indexOf(':') >= 0) return /^[0-9a-fA-F:.]+$/.test(v) && v !== '::';
  // 域名
  return /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i.test(v);
}

/* ---------- 规则管理 ---------- */
var policyState = { rule: null };
var policyBusy = Object.create(null);

function ruleById(id) {
  var rules = (state.summary && state.summary.rules) || [];
  for (var i = 0; i < rules.length; i++) {
    if (String(rules[i].id) === String(id)) return rules[i];
  }
  return null;
}

function showPolicy(id, opener) {
  if (policyBusy[id]) { toast('该规则正在更新…'); return; }
  var r = ruleById(id);
  if (!r) return;
  closeAllDrawers();
  policyState.rule = r;
  document.getElementById('drawer-rule-name').textContent = r.name;
  document.getElementById('pol-address').innerHTML = addressButtons(r.listen_port, false);
  document.getElementById('pol-name').value = r.name || '';
  document.getElementById('pol-proto').value = r.protocol || 'tcp+udp';
  document.getElementById('pol-listen-port').value = r.listen_port || '';
  document.getElementById('pol-target').value = r.target_address || '';
  document.getElementById('pol-target-port').value = r.target_port || '';
  setSwitch('pol-enable', r.enabled);

  var q = r.quota || {};
  var quotaEnabled = r.quota_enabled ?? q.quota_enabled;
  var quotaLimit = r.quota_limit_bytes ?? q.quota_limit_bytes;
  setSwitch('pol-quota-enable', quotaEnabled);
  document.getElementById('pol-quota-box').classList.toggle('hidden', !quotaEnabled);
  var g = quotaLimit > 0 ? quotaLimit / (1024 * 1024 * 1024) : '', unit = 'GiB';
  if (g >= 1024 && g % 1024 === 0) { g = g / 1024; unit = 'TiB'; }
  document.getElementById('pol-quota-val').value = g;
  document.getElementById('pol-quota-unit').value = unit;

  setSwitch('pol-ip-enable', r.ip_limit_enabled);
  document.getElementById('pol-ip-box').classList.toggle('hidden', !r.ip_limit_enabled);
  document.getElementById('pol-ip-max').value = r.ip_limit_max > 0 ? r.ip_limit_max : '';

  hideErr('pol-error');
  updatePolicyReadouts();
  openDrawer('policy-drawer', opener);
}
function syncPolicyButtons() {
  var r = policyState.rule;
  if (!r) return;
  var busy = policyBusy[r.id];
  var onServer = ruleById(r.id);
  [['pol-save', '保存', '保存中…'], ['pol-delete', '删除规则', '删除中…'],
    ['pol-quota-reset', '重置用量（保留历史）', '重置中…']].forEach(function (b) {
    var el = document.getElementById(b[0]);
    el.disabled = !!busy || !onServer;
    if (el.textContent !== (busy === b[0] ? b[2] : b[1])) el.textContent = busy === b[0] ? b[2] : b[1];
  });
}
function updatePolicyReadouts() {
  var original = policyState.rule;
  if (!original) return;
  var r = ruleById(original.id);
  syncPolicyButtons();
  if (!r) { showErr('pol-error', '该规则已删除'); return; }

  // 只更新只读数据，不覆盖正在编辑的表单。DNS 始终显示当前已保存的目标。
  var isDomain = !!r.resolve_status || isHostname(r.target_address);
  document.getElementById('pol-dns-sect').classList.toggle('hidden', !isDomain);
  if (isDomain) {
    setText('pol-dns-host', r.target_address || '—');
    setKV('pol-dns-v4', r.resolved_ipv4, '无 A 记录');
    setKV('pol-dns-v6', r.resolved_ipv6, '无 AAAA 记录');
    var stEl = document.getElementById('pol-dns-status');
    stEl.className = ['stale', 'failed'].indexOf(r.resolve_status) >= 0 ? 'warn' : '';
    setText('pol-dns-status', r.resolve_status === 'stale' ? '解析失败，沿用上次地址' :
      r.resolve_status === 'failed' ? '无法解析，转发不可用' : (r.resolve_status ? '正常' : '等待解析'));
  }
  setText('pol-quota-used', r.quota ? fmtBytes(r.quota.quota_used_bytes) : '—');
  setText('pol-ip-active', ruleIPCount(r));
}

function setKV(id, val, emptyTxt) {
  var el = document.getElementById(id);
  el.classList.toggle('muted', !val);
  setText(id, val || emptyTxt);
}

function isHostname(v) {
  if (!v) return false;
  if (v.indexOf(':') >= 0) return false;
  return !/^\d{1,3}(\.\d{1,3}){3}$/.test(v);
}

function unitToBytes(val, unit) {
  var n = Number(val);
  if (!Number.isFinite(n) || n <= 0) return 0;
  var mult = unit === 'TiB' ? 1024 * 1024 * 1024 * 1024 : 1024 * 1024 * 1024;
  var bytes = Math.round(n * mult);
  return Number.isSafeInteger(bytes) ? bytes : 0;
}

// savePolicy 分两步：先保存转发设置（如有变化），再保存配额 / IP 限制。
// 两步都走各自的统一变更接口，任一失败即停止并展示服务端文案。
function savePolicy() {
  var r = policyState.rule;
  if (!isDrawer('policy-drawer') || !r || policyBusy[r.id] || !ruleById(r.id)) return;
  var name = document.getElementById('pol-name').value.trim();
  var proto = document.getElementById('pol-proto').value;
  var lpRaw = document.getElementById('pol-listen-port').value.trim();
  var target = document.getElementById('pol-target').value.trim();
  var tpRaw = document.getElementById('pol-target-port').value.trim();
  var enabled = document.getElementById('pol-enable').checked;

  if (!name) { showErr('pol-error', '请输入规则名称'); return; }
  // 编辑时端口必须明确填写，绝不静默换成随机端口。
  if (lpRaw === '') { showErr('pol-error', '请输入监听端口'); return; }
  var lp = Number(lpRaw);
  if (!Number.isInteger(lp) || lp < 1 || lp > 65535) { showErr('pol-error', '监听端口需在 1-65535'); return; }
  if (!validTarget(target)) {
    showErr('pol-error', /^https?:|\/|\[/i.test(target)
      ? '目标地址只填写 IP 或域名，不要包含 http://、https://、端口或路径'
      : '请输入有效的 IPv4、IPv6 或域名');
    return;
  }
  var tp = Number(tpRaw);
  if (!Number.isInteger(tp) || tp < 1 || tp > 65535) { showErr('pol-error', '请输入 1-65535 的目标端口'); return; }

  var quotaOn = document.getElementById('pol-quota-enable').checked;
  var ipOn = document.getElementById('pol-ip-enable').checked;
  var quotaBytes = quotaOn
    ? unitToBytes(document.getElementById('pol-quota-val').value, document.getElementById('pol-quota-unit').value)
    : 0;
  var ipMax = ipOn ? Number(document.getElementById('pol-ip-max').value) : 0;
  if (quotaOn && !(quotaBytes > 0)) { showErr('pol-error', '请输入有效的流量额度'); return; }
  if (ipOn && (!Number.isSafeInteger(ipMax) || ipMax < 1)) { showErr('pol-error', '最大同时在线数必须 ≥ 1'); return; }

  var updatedForward = false;
  policyAction('pol-save', function (id) {
    return mutate('PUT', '/api/rules/' + id, {
      name: name, protocol: proto, listen_port: lp,
      target_address: target, target_port: tp, enabled: enabled
    }).then(function () {
      updatedForward = true;
      return mutate('PUT', '/api/rules/' + id + '/policy', {
        quota_enabled: quotaOn,
        quota_limit_bytes: quotaBytes,
        ip_limit_enabled: ipOn,
        ip_limit_max: ipMax
      });
    });
  }, '已保存', function () { closeDrawer('policy-drawer'); }, function () { return updatedForward; });
}
function policyAction(action, request, okMessage, onCurrent, partialWrite) {
  var r = policyState.rule;
  if (!isDrawer('policy-drawer') || !r || policyBusy[r.id] || !ruleById(r.id)) return;
  var id = r.id, session = drawerSession;
  policyBusy[id] = action;
  syncPolicyButtons();
  hideErr('pol-error');
  request(id).then(function (d) {
    if (isDrawer('policy-drawer', session)) onCurrent(d);
    toast(okMessage);
    return refreshAfterRuleChange();
  }, function (e) {
    var partial = partialWrite && partialWrite();
    if (isDrawer('policy-drawer', session) && e.message !== '未登录') {
      showErr('pol-error', partial ? '转发设置已保存；配额或 IP 限制保存失败：' + e.message : e.message);
    }
    if (partial) return refreshAfterRuleChange();
  }).finally(function () {
    delete policyBusy[id];
    syncPolicyButtons();
  });
}
function resetQuota() {
  var r = policyState.rule;
  if (!r || policyBusy[r.id] || !window.confirm('确认重置该规则当前额度使用量？\n历史累计流量不会删除。')) return;
  policyAction('pol-quota-reset', function (id) {
    return mutate('POST', '/api/rules/' + id + '/quota/reset');
  }, '已重置用量', function (d) {
    setText('pol-quota-used', fmtBytes(d.quota_used_bytes || 0));
  });
}
var deleteConfirmation = null;
var deletePhrase = '我已确定';

function updateDeleteConfirmation() {
  var input = document.getElementById('typed-confirm-input');
  document.getElementById('typed-confirm-ok').disabled = !deleteConfirmation || input.value.trim() !== deletePhrase;
}
function closeDeleteConfirmation(restoreFocus) {
  var pending = deleteConfirmation;
  if (!pending) return;
  deleteConfirmation = null;
  document.getElementById('typed-confirm-mask').classList.add('hidden');
  document.getElementById('typed-confirm-input').value = '';
  updateDeleteConfirmation();
  if (isDrawer('policy-drawer', pending.session)) {
    drawer.removeAttribute('inert');
    drawer.setAttribute('aria-hidden', 'false');
    if (restoreFocus) {
      var button = document.getElementById('pol-delete');
      (button.disabled ? document.getElementById('drawer-close') : button).focus({ preventScroll: true });
    }
  }
}
function deleteRule() {
  var r = policyState.rule;
  var saved = r && ruleById(r.id);
  if (deleteConfirmation || !isDrawer('policy-drawer') || !saved || policyBusy[r.id]) return;
  deleteConfirmation = { id: r.id, session: drawerSession };
  setText('typed-confirm-body', '删除「' + saved.name + '」后将停止转发，历史流量统计仍保留。');
  document.getElementById('typed-confirm-input').value = '';
  updateDeleteConfirmation();
  document.getElementById('typed-confirm-mask').classList.remove('hidden');
  document.getElementById('typed-confirm').focus({ preventScroll: true });
  drawer.setAttribute('inert', '');
  drawer.setAttribute('aria-hidden', 'true');
}
function confirmDeleteRule() {
  var pending = deleteConfirmation;
  if (!pending || document.getElementById('typed-confirm-input').value.trim() !== deletePhrase) return;
  closeDeleteConfirmation(true);
  if (!isDrawer('policy-drawer', pending.session) || !policyState.rule || policyState.rule.id !== pending.id) return;
  policyAction('pol-delete', function (id) {
    return mutate('DELETE', '/api/rules/' + id);
  }, '规则已删除', function () { closeDrawer('policy-drawer'); });
}

/* ---------- 在线 IP ---------- */
var ipsDrawerRuleId = null, ipsRevision = 0;

function ipEntryHTML(e) {
  var v6 = String(e.ip || '').indexOf(':') >= 0;
  return '<div class="ip-item">' +
    '<div class="ip-line"><span class="ip-addr">' + esc(e.ip) + '</span>' +
    '<span class="ip-tag">' + (v6 ? 'IPv6' : 'IPv4') + '</span></div>' +
    '<span class="ip-meta">在线 · ' + (Number(e.tcp) || 0) + ' TCP · ' + (Number(e.udp) || 0) + ' UDP</span></div>';
}
function rejectedEntryHTML(e) {
  return '<div class="ip-item rejected">' +
    '<div class="ip-line"><span class="ip-addr">' + esc(e.ip) + '</span>' +
    '<span class="ip-tag danger">已拒绝</span></div>' +
    '<span class="ip-meta">原因：在线 IP 已达上限</span></div>';
}
function renderIPList(snap) {
  var list = document.getElementById('ips-list');
  if (!list) return;
  var ips = (snap && snap.ips) || [], rejected = (snap && snap.rejected) || [];
  if (!ips.length && !rejected.length) {
    list.innerHTML = '<div class="empty">暂无在线 IP</div>';
    return;
  }
  list.innerHTML = ips.map(ipEntryHTML).join('') + rejected.map(rejectedEntryHTML).join('');
}
function showIPs(id, opener) {
  var r = ruleById(id);
  if (!r) return;
  openDrawer('ips-drawer', opener);
  ipsDrawerRuleId = String(id);
  var session = drawerSession, revision = ipsRevision;
  setText('ips-rule-name', r.name);
  if (r.ips) renderIPList(r.ips);
  else trendMessage('ips-list', '正在读取在线 IP…');
  function isCurrent() { return isDrawer('ips-drawer', session) && revision === ipsRevision; }
  api('/api/rules/' + id + '/ips', null, revision).then(function (snap) {
    if (isCurrent()) renderIPList(snap);
  }).catch(function (e) {
    if (!isCurrent() || e.message === '未登录') return;
    if (!r.ips) trendMessage('ips-list', '在线 IP 加载失败 · ' + e.message);
    else toast(e.message);
  });
}

/* ---------- SSE ---------- */
function startEvents() {
  // EventSource 原生自动重连；服务重启后重连即收到完整 snapshot。
  if (!window.EventSource) return;
  var es = new EventSource(url('api/events'), { withCredentials: true });
  es.addEventListener('snapshot', function (e) {
    try {
      var snap = JSON.parse(e.data);
      if (!snap || !Array.isArray(snap.rules)) return;
      noteAPIResult(true);
      renderSummary(snap);
      if (ipsDrawerRuleId) {
        var r = ruleById(ipsDrawerRuleId);
        if (!r || r.ips) {
          ipsRevision++;
          if (r) renderIPList(r.ips);
          else trendMessage('ips-list', '该规则已删除');
        }
      }
    } catch (err) { /* 忽略坏包，下一次快照会覆盖 */ }
  });
  es.onerror = function () {
    // EventSource 自身会重连；但会话过期（401）时它只会无限重试，
    // 页面表现为「一直连接中」。用一次轻量探测确认是否已登出，是则回登录页。
    fetch(url('api/healthz'), { cache: 'no-store', credentials: 'same-origin' })
      .then(function (r) { if (r.status === 401) { es.close(); location.href = url('login'); } })
      .catch(function () { /* 网络抖动：交给 EventSource 自动重连 */ });
  };
}

/* ---------- 事件绑定 ---------- */
document.getElementById('rule-select').addEventListener('change', function (e) {
  state.ruleId = e.target.value || null;
  loadRuleDaily();
});
document.getElementById('btn-new-rule').addEventListener('click', openNewRule);
document.getElementById('new-close').addEventListener('click', function () { closeDrawer('new-drawer'); });
document.getElementById('new-cancel').addEventListener('click', function () { closeDrawer('new-drawer'); });
document.getElementById('new-submit').addEventListener('click', submitNewRule);
document.getElementById('new-drawer').addEventListener('keydown', function (e) {
  if (e.key === 'Enter' && e.target.tagName === 'INPUT') { e.preventDefault(); submitNewRule(); }
});
function copyAddressToken(e) {
  var token = e.target.closest('[data-copy-val]');
  if (!token) return false;
  copyText(token.dataset.copyVal);
  return true;
}
document.getElementById('pol-address').addEventListener('click', copyAddressToken);
document.getElementById('rule-cards').addEventListener('click', function (e) {
  if (copyAddressToken(e)) return;
  var ips = e.target.closest('[data-view-ips]');
  if (ips) { showIPs(ips.dataset.viewIps, ips); return; }
  var mg = e.target.closest('[data-manage]');
  if (mg) showPolicy(mg.dataset.manage, mg);
});
document.getElementById('drawer-close').addEventListener('click', function () { closeDrawer('policy-drawer'); });
document.getElementById('pol-cancel').addEventListener('click', function () { closeDrawer('policy-drawer'); });
document.getElementById('pol-save').addEventListener('click', savePolicy);
document.getElementById('pol-quota-reset').addEventListener('click', resetQuota);
document.getElementById('pol-delete').addEventListener('click', deleteRule);
document.getElementById('typed-confirm-input').addEventListener('input', updateDeleteConfirmation);
document.getElementById('typed-confirm-ok').addEventListener('click', confirmDeleteRule);
document.getElementById('typed-confirm-cancel').addEventListener('click', function () { closeDeleteConfirmation(true); });
document.getElementById('typed-confirm-mask').addEventListener('click', function (e) {
  if (e.target === this) closeDeleteConfirmation(true);
});
document.getElementById('ips-close').addEventListener('click', function () { closeDrawer('ips-drawer'); });
document.getElementById('drawer-mask').addEventListener('click', closeAllDrawers);
document.addEventListener('keydown', function (e) {
  if (!drawer) return;
  if (e.isComposing || e.keyCode === 229) return;
  if (deleteConfirmation && e.key === 'Escape') { e.preventDefault(); closeDeleteConfirmation(true); return; }
  if (deleteConfirmation && e.key === 'Enter' && e.target.id === 'typed-confirm-input') {
    e.preventDefault(); confirmDeleteRule(); return;
  }
  if (e.key === 'Escape') { e.preventDefault(); closeAllDrawers(); return; }
  if (e.key !== 'Tab') return;
  var focusScope = deleteConfirmation ? document.getElementById('typed-confirm') : drawer;
  var stops = Array.from(focusScope.querySelectorAll('button:not(:disabled), input:not(:disabled), select:not(:disabled)'))
    .filter(function (el) { return !el.closest('.hidden'); });
  var first = stops[0], last = stops[stops.length - 1], current = document.activeElement;
  if (!stops.includes(current) || (e.shiftKey ? current === first : current === last)) {
    e.preventDefault();
    (e.shiftKey ? last : first).focus();
  }
});
document.getElementById('pol-quota-enable').addEventListener('change', function (e) {
  document.getElementById('pol-quota-box').classList.toggle('hidden', !e.target.checked);
});
document.getElementById('pol-ip-enable').addEventListener('change', function (e) {
  document.getElementById('pol-ip-box').classList.toggle('hidden', !e.target.checked);
});

/* ---------- 启动与轮询 ---------- */
function loadSummary() {
  var epoch = dataEpoch, rev = summaryRevision;
  function isCurrent() { return epoch === dataEpoch && rev === summaryRevision; }
  return api('/api/summary', null, rev).then(function (s) {
    if (isCurrent()) renderSummary(s);
  }).catch(function (e) {
    if (!isCurrent() || e.message === '未登录') return;
    if (!state.summary) trendMessage('rule-cards', '转发规则加载失败 · ' + e.message);
    if (activeView === 'rules' && state.ruleId == null) trendMessage('rule-daily-table', '规则列表加载失败');
  });
}
function loadLive() {
  var epoch = dataEpoch, rev = summaryRevision;
  return api('/api/live', null, rev).then(function (v) {
    if (epoch !== dataEpoch || rev !== summaryRevision) return;
    renderLive(v, true);
  }).catch(function () {});
}

initNav();
loadSummary().then(function () { if (activeView === 'home') loadLive(); });
startEvents();
// 轮询按当前页签节流：趋势/规则页不需要每 2 秒的实时速率，总览页也不需要
// 后台重画隐藏的趋势表。离开总览即停止 live/summary 轮询，切回时立即补一次。
setInterval(function () { if (!document.hidden && activeView === 'home') loadLive(); }, 2000);
setInterval(function () { if (!document.hidden && activeView === 'home') loadSummary(); }, 8000);
setInterval(function () {
  if (document.hidden) return;
  if (activeView === 'daily') loadDaily(true);
  else if (activeView === 'rules') loadRuleDaily(true);
}, 60000);
document.addEventListener('visibilitychange', function () {
  if (!document.hidden && activeView === 'home') { loadSummary(); loadLive(); }
});
