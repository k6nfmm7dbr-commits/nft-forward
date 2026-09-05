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

var inflight = {};
function api(path, params) {
  var key = path + JSON.stringify(params || {});
  if (inflight[key]) return inflight[key];
  var u = new URL(url(path), location.origin);
  if (params) Object.keys(params).forEach(function (k) { u.searchParams.set(k, params[k]); });
  var req = fetch(u, { cache: 'no-store', credentials: 'same-origin' }).then(function (r) {
    if (r.status === 401) { location.href = url('login'); throw new Error('未登录'); }
    if (!r.ok) throw new Error('请求失败 ' + r.status);
    return r.json();
  }).finally(function () { delete inflight[key]; });
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
function protoLabel(p) { return PROTO_LABEL[p] || String(p || '—'); }

/* ---------- 概览 ---------- */
function renderSummary(s) {
  state.summary = s;
  easeTo('kpi-today-total', (s.today_up || 0) + (s.today_down || 0), fmtBytes);
  easeTo('kpi-all-total', (s.total_up || 0) + (s.total_down || 0), fmtBytes);
  var enabled = 0;
  (s.rules || []).forEach(function (r) { if (r.enabled) enabled++; });
  setText('kpi-rules', enabled + ' / ' + (s.rules || []).length);
  renderRuleCards(s);
  renderRuleSelect(s);
}

/* ---------- 规则卡片（视觉沿用 SBX node-card） ---------- */
function quotaLine(r) {
  var q = r.quota || {};
  var used = fmtBytes(q.quota_used_bytes || 0);
  if (!q.quota_enabled) {
    return '<div class="node-stat wide"><span>流量配额</span><b>' + used + ' / 不限</b></div>';
  }
  return '<div class="node-stat wide"><span>流量配额</span><b>' + used + ' / ' +
    fmtBytes(q.quota_limit_bytes || 0) + '</b></div>';
}

function ruleCard(r) {
  var st = statusOf(r.status);
  var ips = r.ips || {};
  var ipVal = ips.limited ? ((ips.granted_count || 0) + ' / ' + ips.max_ips) : String(ips.granted_count || 0);
  var target = r.target_text || hostPort(r.target_address, r.target_port);
  // 只显示监听端口。转发规则没有这个属性：规则自动作用于本机
  // 所有本地地址（nft 侧 fib daddr type local），显示某一个 IP 只会误导。
  return '<div class="node-card">' +
    '<div class="node-top">' +
      '<div class="node-title">' +
        '<div class="node-name">' + esc(r.name) + '</div>' +
        '<div class="node-meta-line">' +
          '<span class="chip">' + esc(protoLabel(r.protocol)) + '</span>' +
          '<span class="port">监听端口 ' + esc(r.listen_port) + '</span>' +
        '</div>' +
      '</div>' +
      '<div class="node-rate">' +
        '<b class="up" data-live="' + r.id + '" data-kind="rate-up">—</b>' +
        '<b class="down" data-live="' + r.id + '" data-kind="rate-down">—</b>' +
      '</div>' +
    '</div>' +
    '<div class="rule-target"><span>目标</span><b>' + esc(target) + '</b></div>' +
    '<div class="node-stats">' +
      '<div class="node-stat"><span>今日流量</span><b>' + fmtBytes((r.today_up || 0) + (r.today_down || 0)) + '</b></div>' +
      '<div class="node-stat"><span>累计流量</span><b>' + fmtBytes((r.total_up || 0) + (r.total_down || 0)) + '</b></div>' +
      '<div class="node-stat"><span>TCP 连接</span><b data-live="' + r.id + '" data-kind="conns">—</b></div>' +
      '<div class="node-stat"><span>UDP 会话</span><b data-live="' + r.id + '" data-kind="conns-udp">—</b></div>' +
      quotaLine(r) +
    '</div>' +
    '<button class="ip-strip" data-view-ips="' + r.id + '">' +
      '<span class="ip-strip-label">在线 IP</span>' +
      '<span class="ip-strip-val" data-rule-ips="' + r.id + '">' + esc(ipVal) + '</span>' +
      '<span class="ip-strip-arrow">›</span>' +
    '</button>' +
    '<div class="node-foot">' +
      '<span class="status-pill ' + st[1] + '" data-status="' + r.id + '">' + st[0] + '</span>' +
      '<div class="node-actions"><button class="mini-btn primary" data-manage="' + r.id + '">管理</button></div>' +
    '</div>' +
  '</div>';
}

function renderRuleCards(s) {
  var host = document.getElementById('rule-cards');
  var rules = s.rules || [];
  if (!rules.length) {
    host.innerHTML = '<div class="empty">还没有转发规则，点右上角「添加规则」创建</div>';
    return;
  }
  host.innerHTML = rules.map(ruleCard).join('');
  if (state.live) renderLive(state.live);
}

function renderRuleSelect(s) {
  var sel = document.getElementById('rule-select');
  var rules = s.rules || [];
  var sig = rules.map(function (r) { return r.id + ':' + r.name; }).join('|');
  if (sel._sig !== sig) {
    sel._sig = sig;
    sel.innerHTML = rules.map(function (r) {
      return '<option value="' + esc(r.id) + '">' + esc(r.name) + '</option>';
    }).join('');
  }
  var want = state.ruleId != null ? String(state.ruleId) : (rules.length ? String(rules[0].id) : '');
  if (want && sel.value !== want) sel.value = want;
  if (state.ruleId == null && want) { state.ruleId = want; loadRuleDaily(); }
}

/* ---------- 实时 ---------- */
function renderLive(v) {
  state.live = v;
  var known = (v.now || 0) > 0;
  setText('status-txt', known ? '实时监控中' : '等待采集');
  document.getElementById('pulse').className = 'pulse' + (known ? '' : ' stale');

  easeTo('hero-rate', (v.rate_up || 0) + (v.rate_down || 0), fmtRate);
  easeTo('hero-up', v.rate_up || 0, fmtRate);
  easeTo('hero-down', v.rate_down || 0, fmtRate);
  setText('kpi-conns', String(v.conn_tcp || 0));
  setText('kpi-conns-udp', String(v.conn_udp || 0));

  var byId = {};
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
  document.querySelectorAll('[data-rule-ips]').forEach(function (el) {
    var r = byId[el.getAttribute('data-rule-ips')];
    if (!r) return;
    var val = r.active_ip_count || 0;
    el.textContent = r.ip_limited ? (val + ' / ' + r.max_ips) : String(val);
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
var cache = { daily: null, ruleDaily: null };

function renderTable(hostId, rows) {
  var host = document.getElementById(hostId);
  if (!host) return;
  if (!rows || !rows.length) { host.innerHTML = '<div class="empty">暂无数据</div>'; return; }
  var html = '<div class="table-scroll"><table><thead><tr>' +
    '<th>日期</th><th class="up">上传</th><th class="down">下载</th><th>合计</th>' +
    '</tr></thead><tbody>';
  rows.slice().forEach(function (r) {
    html += '<tr><td class="date">' + esc(r.day) + '</td>' +
      '<td class="up">' + fmtBytes(r.up) + '</td>' +
      '<td class="down">' + fmtBytes(r.down) + '</td>' +
      '<td><b>' + fmtBytes((r.up || 0) + (r.down || 0)) + '</b></td></tr>';
  });
  html += '</tbody></table></div>';
  host.innerHTML = html;
}
function loadDaily() {
  return api('/api/daily', { days: 60 }).then(function (d) {
    cache.daily = d.days; renderTable('daily-table', cache.daily);
  }).catch(function (e) { if (e.message !== '未登录') toast(e.message); });
}
function loadRuleDaily() {
  if (state.ruleId == null) return Promise.resolve();
  return api('/api/rules/' + state.ruleId + '/daily', { days: 60 }).then(function (d) {
    cache.ruleDaily = d.days; renderTable('rule-daily-table', cache.ruleDaily);
  }).catch(function (e) { if (e.message !== '未登录') toast(e.message); });
}

/* ---------- 底部导航 ---------- */
(function initNav() {
  var valid = { home: 1, daily: 1, rules: 1 }, positions = { home: 0, daily: 0, rules: 0 };
  var current = (location.hash || '#home').slice(1);
  if (!valid[current]) current = 'home';
  function show(name, push) {
    if (!valid[name]) name = 'home';
    positions[current] = window.scrollY || 0; current = name;
    document.querySelectorAll('.view').forEach(function (v) { v.classList.toggle('on', v.id === 'view-' + name); });
    document.querySelectorAll('.tab').forEach(function (b) { b.classList.toggle('on', b.dataset.view === name); });
    if (push && location.hash !== '#' + name) history.pushState(null, '', '#' + name);
    requestAnimationFrame(function () { window.scrollTo(0, positions[name] || 0); });
    if (name === 'daily' && !cache.daily) loadDaily();
    if (name === 'rules' && !cache.ruleDaily) loadRuleDaily();
  }
  document.querySelectorAll('.tab').forEach(function (b) {
    b.addEventListener('click', function () { show(b.dataset.view, true); });
  });
  window.addEventListener('popstate', function () { show((location.hash || '#home').slice(1), false); });
  show(current, false);
})();

/* ---------- 抽屉 ---------- */
function openDrawer(id) {
  document.getElementById('drawer-mask').classList.add('on');
  document.getElementById(id).classList.add('on');
}
function closeDrawer(id) {
  document.getElementById(id).classList.remove('on');
  var anyOpen = document.querySelector('.drawer.on');
  if (!anyOpen) document.getElementById('drawer-mask').classList.remove('on');
}
function closeAllDrawers() {
  document.querySelectorAll('.drawer.on').forEach(function (d) { d.classList.remove('on'); });
  document.getElementById('drawer-mask').classList.remove('on');
}
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
function openNewRule() {
  document.getElementById('new-name').value = '';
  document.getElementById('new-proto').value = 'tcp+udp';
  document.getElementById('new-listen-port').value = '';
  document.getElementById('new-target').value = '';
  document.getElementById('new-target-port').value = '';
  hideErr('new-error');
  openDrawer('new-drawer');
  setTimeout(function () { document.getElementById('new-name').focus(); }, 60);
}

function submitNewRule() {
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
  if (!(tp >= 1 && tp <= 65535)) { showErr('new-error', '请输入 1-65535 的目标端口'); return; }
  // 监听端口留空 → 传 0，由后端安全随机分配（前端绝不自己生成端口）。
  var lp = 0;
  if (lpRaw !== '') {
    lp = Number(lpRaw);
    if (!(lp >= 1 && lp <= 65535)) { showErr('new-error', '监听端口需在 1-65535，或留空由系统随机分配'); return; }
  }

  var btn = document.getElementById('new-submit');
  btn.disabled = true; btn.textContent = '添加中…';
  hideErr('new-error');
  mutate('POST', '/api/rules', {
    name: name, protocol: proto, listen_port: lp,
    target_address: target, target_port: tp
  }).then(function (rule) {
    btn.disabled = false; btn.textContent = '添加';
    closeDrawer('new-drawer');
    // 用服务端返回的正式规则刷新，不做乐观假成功。
    toast('规则已添加 · 监听端口 ' + rule.listen_port);
    loadSummary();
  }).catch(function (e) {
    btn.disabled = false; btn.textContent = '添加';
    if (e.message !== '未登录') showErr('new-error', e.message);
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
var policyState = { ruleId: null, rule: null };

function ruleById(id) {
  var rules = (state.summary && state.summary.rules) || [];
  for (var i = 0; i < rules.length; i++) {
    if (String(rules[i].id) === String(id)) return rules[i];
  }
  return null;
}

function showPolicy(id) {
  var r = ruleById(id);
  if (!r) return;
  policyState.ruleId = String(id);
  policyState.rule = r;
  document.getElementById('drawer-rule-name').textContent = r.name;
  document.getElementById('pol-name').value = r.name || '';
  document.getElementById('pol-proto').value = r.protocol || 'tcp+udp';
  document.getElementById('pol-listen-port').value = r.listen_port || '';
  document.getElementById('pol-target').value = r.target_address || '';
  document.getElementById('pol-target-port').value = r.target_port || '';
  setSwitch('pol-enable', r.enabled);

  // 域名解析信息（只读）。
  var isDomain = !!r.resolve_status || isHostname(r.target_address);
  var sect = document.getElementById('pol-dns-sect');
  sect.classList.toggle('hidden', !isDomain);
  if (isDomain) {
    document.getElementById('pol-dns-host').textContent = r.target_address || '—';
    setKV('pol-dns-v4', r.resolved_ipv4, '（无 A 记录）');
    setKV('pol-dns-v6', r.resolved_ipv6 ? '[' + r.resolved_ipv6 + ']' : '', '（无 AAAA 记录）');
    var stEl = document.getElementById('pol-dns-status');
    if (r.resolve_status === 'stale') {
      stEl.className = 'warn';
      stEl.textContent = 'DNS 解析暂时失败，继续使用上次有效地址';
    } else if (r.resolve_status === 'failed') {
      stEl.className = 'warn';
      stEl.textContent = '无法解析目标域名，转发当前不可用';
    } else {
      stEl.className = '';
      stEl.textContent = '正常';
    }
  }

  var q = r.quota || {};
  setSwitch('pol-quota-enable', q.quota_enabled);
  document.getElementById('pol-quota-box').classList.toggle('hidden', !q.quota_enabled);
  document.getElementById('pol-quota-used').textContent = fmtBytes(q.quota_used_bytes || 0);
  if (q.quota_enabled && q.quota_limit_bytes > 0) {
    var g = q.quota_limit_bytes / (1024 * 1024 * 1024), unit = 'GiB';
    if (g >= 1024 && g % 1024 === 0) { g = g / 1024; unit = 'TiB'; }
    document.getElementById('pol-quota-val').value = g;
    document.getElementById('pol-quota-unit').value = unit;
  } else {
    document.getElementById('pol-quota-val').value = '';
  }

  var ips = r.ips || {};
  setSwitch('pol-ip-enable', r.ip_limit_enabled);
  document.getElementById('pol-ip-box').classList.toggle('hidden', !r.ip_limit_enabled);
  document.getElementById('pol-ip-active').textContent = ips.limited
    ? ((ips.granted_count || 0) + ' / ' + ips.max_ips) : String(ips.granted_count || 0);
  document.getElementById('pol-ip-max').value = r.ip_limit_max > 0 ? r.ip_limit_max : '';

  hideErr('pol-error');
  openDrawer('policy-drawer');
}

function setKV(id, val, emptyTxt) {
  var el = document.getElementById(id);
  if (val) { el.className = ''; el.textContent = val; }
  else { el.className = 'muted'; el.textContent = emptyTxt; }
}

function isHostname(v) {
  if (!v) return false;
  if (v.indexOf(':') >= 0) return false;
  return !/^\d{1,3}(\.\d{1,3}){3}$/.test(v);
}

function unitToBytes(val, unit) {
  var n = Number(val);
  if (!(n > 0)) return 0;
  var mult = unit === 'TiB' ? 1024 * 1024 * 1024 * 1024 : 1024 * 1024 * 1024;
  return Math.round(n * mult);
}

// savePolicy 分两步：先保存转发设置（如有变化），再保存配额 / IP 限制。
// 两步都走各自的统一变更接口，任一失败即停止并展示服务端文案。
function savePolicy() {
  var r = policyState.rule;
  if (!r) return;
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
  if (!(lp >= 1 && lp <= 65535)) { showErr('pol-error', '监听端口需在 1-65535'); return; }
  if (!validTarget(target)) {
    showErr('pol-error', /^https?:|\/|\[/i.test(target)
      ? '目标地址只填写 IP 或域名，不要包含 http://、https://、端口或路径'
      : '请输入有效的 IPv4、IPv6 或域名');
    return;
  }
  var tp = Number(tpRaw);
  if (!(tp >= 1 && tp <= 65535)) { showErr('pol-error', '请输入 1-65535 的目标端口'); return; }

  var quotaOn = document.getElementById('pol-quota-enable').checked;
  var ipOn = document.getElementById('pol-ip-enable').checked;
  var quotaBytes = quotaOn
    ? unitToBytes(document.getElementById('pol-quota-val').value, document.getElementById('pol-quota-unit').value)
    : 0;
  var ipMax = ipOn ? Number(document.getElementById('pol-ip-max').value) : 0;
  if (quotaOn && !(quotaBytes > 0)) { showErr('pol-error', '流量额度必须大于 0'); return; }
  if (ipOn && !(ipMax >= 1)) { showErr('pol-error', '最大同时在线数必须 ≥ 1'); return; }

  var btn = document.getElementById('pol-save');
  btn.disabled = true; btn.textContent = '保存中…';
  hideErr('pol-error');

  var id = policyState.ruleId;
  mutate('PUT', '/api/rules/' + id, {
    name: name, protocol: proto, listen_port: lp,
    target_address: target, target_port: tp, enabled: enabled
  }).then(function () {
    return mutate('PUT', '/api/rules/' + id + '/policy', {
      quota_enabled: quotaOn,
      quota_limit_bytes: quotaBytes,
      ip_limit_enabled: ipOn,
      ip_limit_max: ipMax
    });
  }).then(function () {
    btn.disabled = false; btn.textContent = '保存';
    closeDrawer('policy-drawer');
    toast('已保存');
    loadSummary();
  }).catch(function (e) {
    btn.disabled = false; btn.textContent = '保存';
    if (e.message !== '未登录') showErr('pol-error', e.message);
  });
}

function resetQuota() {
  if (!window.confirm('确认重置该规则当前额度使用量？\n历史累计流量不会删除。')) return;
  var btn = document.getElementById('pol-quota-reset');
  btn.disabled = true;
  mutate('POST', '/api/rules/' + policyState.ruleId + '/quota/reset')
    .then(function (d) {
      btn.disabled = false;
      document.getElementById('pol-quota-used').textContent = fmtBytes(d.quota_used_bytes || 0);
      toast('已重置'); loadSummary();
    })
    .catch(function (e) {
      btn.disabled = false;
      if (e.message !== '未登录') showErr('pol-error', e.message);
    });
}

function deleteRule() {
  var r = policyState.rule;
  if (!r) return;
  if (!window.confirm('确认删除规则「' + r.name + '」？\n转发会立即停止；历史流量统计仍保留。')) return;
  var btn = document.getElementById('pol-delete');
  btn.disabled = true; btn.textContent = '删除中…';
  mutate('DELETE', '/api/rules/' + policyState.ruleId)
    .then(function () {
      btn.disabled = false; btn.textContent = '删除规则';
      closeDrawer('policy-drawer');
      toast('规则已删除'); loadSummary();
    })
    .catch(function (e) {
      btn.disabled = false; btn.textContent = '删除规则';
      if (e.message !== '未登录') showErr('pol-error', e.message);
    });
}

/* ---------- 在线 IP ---------- */
var ipsDrawerRuleId = null;

function ipEntryHTML(e) {
  var v6 = String(e.ip || '').indexOf(':') >= 0;
  return '<div class="ip-item">' +
    '<div class="ip-line"><span class="ip-addr">' + esc(e.ip) + '</span>' +
    '<span class="ip-tag">' + (v6 ? 'IPv6' : 'IPv4') + '</span></div>' +
    '<span class="ip-meta">在线 · ' + (e.tcp || 0) + ' TCP · ' + (e.udp || 0) + ' UDP</span></div>';
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
function showIPs(id) {
  ipsDrawerRuleId = String(id);
  var r = ruleById(id);
  document.getElementById('ips-rule-name').textContent = r ? r.name : '';
  renderIPList(r && r.ips);
  openDrawer('ips-drawer');
  api('/api/rules/' + id + '/ips').then(renderIPList).catch(function (e) {
    if (e.message !== '未登录') toast(e.message);
  });
}

/* ---------- SSE ---------- */
function startEvents() {
  // EventSource 原生自动重连；服务重启后重连即收到完整 snapshot。
  var es = new EventSource(url('api/events'), { withCredentials: true });
  es.addEventListener('snapshot', function (e) {
    try {
      var snap = JSON.parse(e.data);
      renderSummary(snap);
      if (ipsDrawerRuleId) {
        var r = ruleById(ipsDrawerRuleId);
        if (r) renderIPList(r.ips);
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
  state.ruleId = e.target.value; loadRuleDaily();
});
document.getElementById('btn-new-rule').addEventListener('click', openNewRule);
document.getElementById('new-close').addEventListener('click', function () { closeDrawer('new-drawer'); });
document.getElementById('new-cancel').addEventListener('click', function () { closeDrawer('new-drawer'); });
document.getElementById('new-submit').addEventListener('click', submitNewRule);
document.getElementById('new-drawer').addEventListener('keydown', function (e) {
  if (e.key === 'Enter' && e.target.tagName === 'INPUT') { e.preventDefault(); submitNewRule(); }
});
document.getElementById('rule-cards').addEventListener('click', function (e) {
  var ips = e.target.closest('[data-view-ips]');
  if (ips) { showIPs(ips.getAttribute('data-view-ips')); return; }
  var mg = e.target.closest('[data-manage]');
  if (mg) { showPolicy(mg.getAttribute('data-manage')); return; }
});
document.getElementById('drawer-close').addEventListener('click', function () { closeDrawer('policy-drawer'); });
document.getElementById('pol-cancel').addEventListener('click', function () { closeDrawer('policy-drawer'); });
document.getElementById('pol-save').addEventListener('click', savePolicy);
document.getElementById('pol-quota-reset').addEventListener('click', resetQuota);
document.getElementById('pol-delete').addEventListener('click', deleteRule);
document.getElementById('ips-close').addEventListener('click', function () {
  ipsDrawerRuleId = null; closeDrawer('ips-drawer');
});
document.getElementById('drawer-mask').addEventListener('click', function () {
  ipsDrawerRuleId = null; closeAllDrawers();
});
document.addEventListener('keydown', function (e) {
  if (e.key === 'Escape') { ipsDrawerRuleId = null; closeAllDrawers(); }
});
document.getElementById('pol-quota-enable').addEventListener('change', function (e) {
  document.getElementById('pol-quota-box').classList.toggle('hidden', !e.target.checked);
});
document.getElementById('pol-ip-enable').addEventListener('change', function (e) {
  document.getElementById('pol-ip-box').classList.toggle('hidden', !e.target.checked);
});

/* ---------- 启动与轮询 ---------- */
function loadSummary() {
  return api('/api/summary').then(renderSummary)
    .catch(function (e) { if (e.message !== '未登录') toast(e.message); });
}
function loadLive() {
  return api('/api/live').then(renderLive).catch(function () {});
}

loadSummary().then(function () { loadLive(); loadDaily(); });
startEvents();
setInterval(function () { if (!document.hidden) loadLive(); }, 2000);
setInterval(function () { if (!document.hidden) loadSummary(); }, 8000);
setInterval(function () { if (!document.hidden) { loadDaily(); loadRuleDaily(); } }, 60000);
document.addEventListener('visibilitychange', function () {
  if (!document.hidden) { loadLive(); loadSummary(); }
});
