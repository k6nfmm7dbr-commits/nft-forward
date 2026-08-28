/* NFT Forward 前端逻辑（原生，无框架）。实时刷新走 SSE，速率走 /api/live 轮询。 */
'use strict';

var state = { rules: [], ruleId: null, snapshot: null };

/* ---------- 工具 ---------- */
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
function setText(id, txt) {
  var el = document.getElementById(id);
  if (el && el.textContent !== txt) el.textContent = txt;
}
function toast(msg) {
  var el = document.getElementById('toast');
  el.textContent = msg; el.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(function () { el.classList.remove('show'); }, 3500);
}

/* ---------- API ---------- */
function api(method, path, body) {
  var opts = { method: method, cache: 'no-store', headers: {} };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  return fetch(path, opts).then(function (r) {
    if (r.status === 401) { location.replace('/login'); throw new Error('未登录'); }
    return r.json().then(function (d) {
      if (!r.ok) throw new Error((d && d.error) || ('请求失败 ' + r.status));
      return d;
    });
  });
}

/* ---------- 状态徽标 ---------- */
var STATUS_LABEL = {
  normal: ['正常', 'ok'],
  disabled: ['已停用', 'off'],
  quota_exceeded: ['流量已达限', 'danger'],
  ip_limited: ['IP 限制中', 'warn'],
  error: ['规则异常', 'danger']
};

/* ---------- 首页规则卡 ---------- */
function ruleCard(r) {
  var st = STATUS_LABEL[r.status] || STATUS_LABEL.normal;
  var quota = r.quota || {};
  var quotaTxt = quota.quota_enabled
    ? fmtBytes(quota.quota_used_bytes) + ' / ' + fmtBytes(quota.quota_limit_bytes)
    : fmtBytes((r.total_up || 0) + (r.total_down || 0));
  var ips = r.ips || {};
  var ipTxt = ips.limited ? (ips.granted_count + ' / ' + ips.max_ips) : String(ips.granted_count || 0);
  var proto = String(r.protocol || '').toUpperCase().replace('+', '+');
  return '<div class="node-card" data-rule-card="' + r.id + '">' +
    '<div class="node-top">' +
      '<div><div class="node-name">' + esc(r.name) + '</div>' +
        '<div class="node-meta-line"><span class="chip">' + esc(proto) + '</span>' +
        '<span class="port">' + esc(r.listen_port) + ' → ' + esc(r.target_address) + ':' + esc(r.target_port) + '</span></div></div>' +
      '<div class="node-rate">' +
        '<b class="up" data-rr="' + r.id + '" data-k="up">—</b>' +
        '<b class="down" data-rr="' + r.id + '" data-k="down">—</b></div>' +
    '</div>' +
    '<div class="node-stats">' +
      '<div class="node-stat"><span>累计流量</span><b>' + fmtBytes((r.total_up || 0) + (r.total_down || 0)) + '</b></div>' +
      '<div class="node-stat"><span>流量配额</span><b>' + quotaTxt + '</b></div>' +
      '<div class="node-stat"><span>TCP 连接</span><b data-rc="' + r.id + '" data-k="tcp">—</b></div>' +
      '<div class="node-stat"><span>UDP 会话</span><b data-rc="' + r.id + '" data-k="udp">—</b></div>' +
    '</div>' +
    '<button class="ip-strip" data-ips="' + r.id + '">' +
      '<span class="ip-strip-label">在线 IP</span>' +
      '<span class="ip-strip-val" data-ipcount="' + r.id + '">' + esc(ipTxt) + '</span>' +
      '<span class="ip-strip-arrow">›</span></button>' +
    '<div class="node-foot">' +
      '<span class="status-pill ' + st[1] + '" data-status="' + r.id + '">' + st[0] + '</span>' +
      '<div><button class="mini-btn" data-manage="' + r.id + '">管理</button></div>' +
    '</div>' +
  '</div>';
}

function renderRules() {
  var host = document.getElementById('rule-cards');
  var rules = state.snapshot ? state.snapshot.rules : state.rules;
  if (!rules || !rules.length) { host.innerHTML = '<div class="empty">暂无规则，点「新增」创建</div>'; return; }
  host.innerHTML = rules.map(ruleCard).join('');
}

function renderSummary() {
  var s = state.snapshot;
  if (!s) return;
  setText('hero-rate', fmtRate((s.rate && s.rate.rx || 0) + (s.rate && s.rate.tx || 0)));
  setText('hero-up', fmtRate(s.rate && s.rate.rx || 0));
  setText('hero-down', fmtRate(s.rate && s.rate.tx || 0));
  setText('kpi-today', fmtBytes((s.today_up || 0) + (s.today_down || 0)));
  setText('kpi-total', fmtBytes((s.total_up || 0) + (s.total_down || 0)));
}

/* ---------- 实时（速率轮询 + SSE 结构更新） ---------- */
function renderLiveRate(v) {
  var statusTxt = document.getElementById('status-txt');
  var pulse = document.getElementById('pulse');
  setText('status-txt', '实时监控中');
  pulse.className = 'pulse';
  setText('kpi-tcp', '—'); // live 不含全局连接数，保留占位
  setText('kpi-udp', '—');
  setText('hero-rate', fmtRate((v.rate_up || 0) + (v.rate_down || 0)));
  setText('hero-up', fmtRate(v.rate_up || 0));
  setText('hero-down', fmtRate(v.rate_down || 0));
  (v.rules || []).forEach(function (r) {
    var up = document.querySelector('[data-rr="' + r.id + '"][data-k="up"]');
    var down = document.querySelector('[data-rr="' + r.id + '"][data-k="down"]');
    if (up) up.textContent = fmtRate(r.rate_up || 0);
    if (down) down.textContent = fmtRate(r.rate_down || 0);
    var st = document.querySelector('[data-status="' + r.id + '"]');
    if (st && STATUS_LABEL[r.status]) {
      var m = STATUS_LABEL[r.status];
      st.className = 'status-pill ' + m[1];
      st.textContent = m[0];
    }
    var ipc = document.querySelector('[data-ipcount="' + r.id + '"]');
    if (ipc && r.active_ip_count != null) {
      // active_ip_count 不带 max，仅在结构快照里有 max；这里仅更新数字部分
      var cur = ipc.textContent;
      if (cur.indexOf('/') >= 0) {
        var max = cur.split('/')[1];
        ipc.textContent = r.active_ip_count + ' /' + max;
      } else {
        ipc.textContent = String(r.active_ip_count);
      }
    }
  });
}

function applySnapshot(snap) {
  state.snapshot = snap;
  state.rules = snap.rules || [];
  renderSummary();
  renderRules();
  renderRuleSelect();
  renderRuleDetail();
  // 若在线 IP 抽屉打开，刷新
  if (ipsDrawerId != null) renderIPsDrawer(ipsDrawerId);
}

function startSSE() {
  var es = new EventSource('/api/events');
  es.addEventListener('snapshot', function (e) {
    try { applySnapshot(JSON.parse(e.data)); } catch (err) {}
  });
  es.addEventListener('node', function (e) {
    try {
      var ev = JSON.parse(e.data);
      if (ev && ev.rule_id != null) refreshRule(ev.rule_id);
    } catch (err) {}
  });
  es.onerror = function () { /* EventSource 自动重连；重连后服务端会重发 snapshot */ };
}

function refreshRule(id) {
  api('GET', '/api/rules/' + id).then(function (rv) {
    var rules = state.rules;
    for (var i = 0; i < rules.length; i++) {
      if (rules[i].id === id) { rules[i] = rv; break; }
    }
    renderRules();
    if (String(state.ruleId) === String(id)) renderRuleDetail();
    if (ipsDrawerId === id) renderIPsDrawer(id);
  }).catch(function () {});
}

/* ---------- 每日表格 ---------- */
function renderTable(hostId, rows) {
  var host = document.getElementById(hostId);
  if (!host) return;
  if (!rows || !rows.length) { host.innerHTML = '<div class="empty">暂无数据</div>'; return; }
  var html = '<div class="table-scroll"><table><thead><tr><th>日期</th><th>上传</th><th>下载</th><th>合计</th></tr></thead><tbody>';
  rows.forEach(function (r) {
    html += '<tr><td>' + esc(r.day) + '</td><td class="up">' + fmtBytes(r.up) + '</td>' +
      '<td class="down">' + fmtBytes(r.down) + '</td><td><b>' + fmtBytes(r.up + r.down) + '</b></td></tr>';
  });
  html += '</tbody></table></div>';
  host.innerHTML = html;
}

function loadDaily() {
  return api('GET', '/api/daily?days=60').then(function (d) { renderTable('daily-table', d.days); }).catch(function () {});
}
function loadRuleDaily() {
  if (state.ruleId == null) return;
  return api('GET', '/api/rules/' + state.ruleId + '/daily?days=60').then(function (d) {
    renderTable('rule-daily-table', d.days);
  }).catch(function () {});
}

/* ---------- 规则页 ---------- */
function renderRuleSelect() {
  var sel = document.getElementById('rule-select');
  var rules = state.rules;
  var sig = rules.map(function (r) { return r.id + ':' + r.name; }).join('|');
  if (sel._sig !== sig) {
    sel._sig = sig;
    sel.innerHTML = rules.map(function (r) { return '<option value="' + r.id + '">' + esc(r.name) + '</option>'; }).join('');
  }
  if (state.ruleId == null && rules.length) state.ruleId = rules[0].id;
  if (state.ruleId != null && sel.value !== String(state.ruleId)) sel.value = String(state.ruleId);
}

function findRule(id) {
  for (var i = 0; i < state.rules.length; i++) {
    if (String(state.rules[i].id) === String(id)) return state.rules[i];
  }
  return null;
}

function renderRuleDetail() {
  var host = document.getElementById('rule-detail');
  if (!host) return;
  var r = findRule(state.ruleId);
  if (!r) { host.innerHTML = '<div class="empty">请选择规则</div>'; return; }
  var st = STATUS_LABEL[r.status] || STATUS_LABEL.normal;
  var ips = r.ips || {};
  var ipTxt = ips.limited ? (ips.granted_count + ' / ' + ips.max_ips) : String(ips.granted_count || 0);
  var quota = r.quota || {};
  host.innerHTML =
    '<div class="node-stats">' +
      '<div class="node-stat"><span>状态</span><b><span class="status-pill ' + st[1] + '">' + st[0] + '</span></b></div>' +
      '<div class="node-stat"><span>协议</span><b>' + esc(String(r.protocol || '').toUpperCase()) + '</b></div>' +
      '<div class="node-stat"><span>监听</span><b>' + esc(r.listen_address) + ':' + esc(r.listen_port) + '</b></div>' +
      '<div class="node-stat"><span>目标</span><b>' + esc(r.target_address) + ':' + esc(r.target_port) + '</b></div>' +
      '<div class="node-stat"><span>在线 IP</span><b>' + esc(ipTxt) + '</b></div>' +
      '<div class="node-stat"><span>今日流量</span><b>' + fmtBytes((r.today_up || 0) + (r.today_down || 0)) + '</b></div>' +
      '<div class="node-stat"><span>累计流量</span><b>' + fmtBytes((r.total_up || 0) + (r.total_down || 0)) + '</b></div>' +
      '<div class="node-stat"><span>流量配额</span><b>' + (quota.quota_enabled ? fmtBytes(quota.quota_used_bytes) + '/' + fmtBytes(quota.quota_limit_bytes) : '不限') + '</b></div>' +
    '</div>';
}

/* ---------- 管理抽屉 ---------- */
var manageRuleId = null;

function showManage(id) {
  var r = findRule(id);
  manageRuleId = id;
  document.getElementById('drawer-rule-name').textContent = r ? r.name : '新增规则';
  document.getElementById('pol-name').value = r ? r.name : '';
  document.getElementById('pol-listen-addr').value = r ? r.listen_address : '0.0.0.0';
  document.getElementById('pol-listen-port').value = r ? r.listen_port : '';
  document.getElementById('pol-target-addr').value = r ? r.target_address : '';
  document.getElementById('pol-target-port').value = r ? r.target_port : '';
  document.getElementById('pol-proto').value = r ? r.protocol : 'tcp';
  document.getElementById('pol-enable').checked = r ? r.enabled : true;
  var quota = r && r.quota ? r.quota : {};
  document.getElementById('pol-quota-enable').checked = !!quota.quota_enabled;
  document.getElementById('pol-quota-used').textContent = fmtBytes(quota.quota_used_bytes || 0);
  document.getElementById('pol-quota-box').classList.toggle('hidden', !quota.quota_enabled);
  if (quota.quota_limit_bytes > 0) {
    var g = quota.quota_limit_bytes / (1024 * 1024 * 1024);
    var unit = 'GiB';
    if (g >= 1024 && g % 1024 === 0) { g = g / 1024; unit = 'TiB'; }
    document.getElementById('pol-quota-val').value = g;
    document.getElementById('pol-quota-unit').value = unit;
  } else {
    document.getElementById('pol-quota-val').value = '';
  }
  var ips = r && r.ips ? r.ips : {};
  document.getElementById('pol-ip-enable').checked = !!ips.limited;
  document.getElementById('pol-ip-active').textContent = String(ips.granted_count || 0);
  document.getElementById('pol-ip-box').classList.toggle('hidden', !ips.limited);
  document.getElementById('pol-ip-max').value = ips.max_ips || '';
  hidePolError();
  openDrawer('policy-drawer');
}

function showNewRule() {
  manageRuleId = null;
  document.getElementById('drawer-rule-name').textContent = '新增规则';
  ['pol-name', 'pol-listen-port', 'pol-target-addr', 'pol-target-port'].forEach(function (id) {
    document.getElementById(id).value = '';
  });
  document.getElementById('pol-listen-addr').value = '0.0.0.0';
  document.getElementById('pol-proto').value = 'tcp';
  document.getElementById('pol-enable').checked = true;
  document.getElementById('pol-quota-enable').checked = false;
  document.getElementById('pol-quota-box').classList.add('hidden');
  document.getElementById('pol-ip-enable').checked = false;
  document.getElementById('pol-ip-box').classList.add('hidden');
  hidePolError();
  openDrawer('policy-drawer');
}

function hidePolError() { document.getElementById('pol-error').classList.add('hidden'); }
function showPolError(msg) {
  var el = document.getElementById('pol-error');
  el.textContent = msg; el.classList.remove('hidden');
}

function saveRule() {
  var body = {
    name: document.getElementById('pol-name').value,
    enabled: document.getElementById('pol-enable').checked,
    protocol: document.getElementById('pol-proto').value,
    listen_address: document.getElementById('pol-listen-addr').value || '0.0.0.0',
    listen_port: Number(document.getElementById('pol-listen-port').value),
    target_address: document.getElementById('pol-target-addr').value,
    target_port: Number(document.getElementById('pol-target-port').value)
  };
  if (!body.name) { showPolError('请输入规则名称'); return; }
  if (!body.listen_port || !body.target_port) { showPolError('请填写监听/目标端口'); return; }
  if (!body.target_address) { showPolError('请填写目标地址'); return; }
  var btn = document.getElementById('pol-save');
  btn.disabled = true; btn.textContent = '保存中…';
  var p = manageRuleId == null
    ? api('POST', '/api/rules', body)
    : api('PUT', '/api/rules/' + manageRuleId, body);
  p.then(function () {
    btn.disabled = false; btn.textContent = '保存';
    // 保存配额 / IP 限制
    return savePolicyExtras();
  }).then(function () {
    closeDrawer('policy-drawer');
    toast('已保存');
    return loadAll();
  }).catch(function (e) {
    btn.disabled = false; btn.textContent = '保存';
    if (e.message !== '未登录') showPolError(e.message);
  });
}

function savePolicyExtras() {
  if (manageRuleId == null) return Promise.resolve();
  var quotaOn = document.getElementById('pol-quota-enable').checked;
  var quotaVal = Number(document.getElementById('pol-quota-val').value);
  var unit = document.getElementById('pol-quota-unit').value;
  var mult = unit === 'TiB' ? 1024 * 1024 * 1024 * 1024 : 1024 * 1024 * 1024;
  var ipOn = document.getElementById('pol-ip-enable').checked;
  var ipMax = Number(document.getElementById('pol-ip-max').value);
  var body = {
    quota_enabled: quotaOn,
    quota_limit_bytes: quotaOn ? Math.round(quotaVal * mult) : 0,
    ip_limit_enabled: ipOn,
    ip_limit_max: ipOn ? ipMax : 0
  };
  if (quotaOn && body.quota_limit_bytes <= 0) { throw new Error('流量额度必须 > 0'); }
  if (ipOn && body.ip_limit_max < 1) { throw new Error('最大同时在线数必须 >= 1'); }
  return api('PUT', '/api/rules/' + manageRuleId + '/policy', body);
}

function deleteRule() {
  if (manageRuleId == null) return;
  if (!confirm('确认删除该转发规则？历史流量将保留，但不再转发。')) return;
  api('DELETE', '/api/rules/' + manageRuleId).then(function () {
    closeDrawer('policy-drawer');
    toast('已删除');
    return loadAll();
  }).catch(function (e) { if (e.message !== '未登录') showPolError(e.message); });
}

function resetQuota() {
  if (manageRuleId == null) return;
  if (!confirm('确认重置当前已用流量？历史累计与每日流量保留。')) return;
  api('POST', '/api/rules/' + manageRuleId + '/quota/reset').then(function () {
    toast('已重置');
    return loadAll();
  }).catch(function (e) { if (e.message !== '未登录') showPolError(e.message); });
}

/* ---------- 在线 IP 抽屉 ---------- */
var ipsDrawerId = null;
function renderIPsDrawer(id) {
  ipsDrawerId = id;
  var r = findRule(id);
  document.getElementById('ips-rule-name').textContent = r ? r.name : ('规则 ' + id);
  openDrawer('ips-drawer');
  api('GET', '/api/rules/' + id + '/ips').then(function (d) {
    var list = document.getElementById('ips-list');
    var items = (d.ips || []).map(function (e) {
      var v6 = e.ip.indexOf(':') >= 0;
      return '<div class="ip-item"><div class="ip-line"><span class="ip-addr">' + esc(e.ip) + '</span>' +
        '<span class="ip-tag">' + (v6 ? 'IPv6' : 'IPv4') + '</span></div>' +
        '<span class="ip-meta">在线 · ' + (e.tcp || 0) + ' TCP · ' + (e.udp || 0) + ' UDP</span></div>';
    });
    (d.rejected || []).forEach(function (e) {
      items.push('<div class="ip-item rejected"><div class="ip-line"><span class="ip-addr">' + esc(e.ip) + '</span>' +
        '<span class="ip-tag danger">已拒绝</span></div>' +
        '<span class="ip-meta">原因：在线 IP 已达上限</span></div>');
    });
    list.innerHTML = items.length ? items.join('') : '<div class="empty">暂无在线 IP</div>';
  }).catch(function () {
    document.getElementById('ips-list').innerHTML = '<div class="empty">加载失败</div>';
  });
}

/* ---------- 抽屉开关 ---------- */
function openDrawer(id) {
  document.getElementById('drawer-mask').classList.add('on');
  document.getElementById(id).classList.add('on');
}
function closeDrawer(id) {
  document.getElementById('drawer-mask').classList.remove('on');
  document.getElementById(id).classList.remove('on');
  if (id === 'ips-drawer') ipsDrawerId = null;
  if (id === 'policy-drawer') manageRuleId = null;
}

/* ---------- 导航 ---------- */
(function initNav() {
  var valid = { home: 1, daily: 1, rules: 1 };
  var current = (location.hash || '#home').slice(1);
  if (!valid[current]) current = 'home';
  function show(name, push) {
    if (!valid[name]) name = 'home';
    current = name;
    document.querySelectorAll('.view').forEach(function (v) { v.classList.toggle('on', v.id === 'view-' + name); });
    document.querySelectorAll('.tab').forEach(function (b) { b.classList.toggle('on', b.dataset.view === name); });
    if (push && location.hash !== '#' + name) history.pushState(null, '', '#' + name);
    if (name === 'daily') loadDaily();
    if (name === 'rules') { renderRuleDetail(); loadRuleDaily(); }
  }
  document.querySelectorAll('.tab').forEach(function (b) {
    b.addEventListener('click', function () { show(b.dataset.view, true); });
  });
  window.addEventListener('popstate', function () { show((location.hash || '#home').slice(1), false); });
  window._show = show;
})();

/* ---------- 加载 ---------- */
function loadAll() {
  return api('GET', '/api/summary').then(applySnapshot).catch(function () {});
}

/* ---------- 事件绑定 ---------- */
document.getElementById('rule-cards').addEventListener('click', function (e) {
  var m = e.target.closest('[data-manage]');
  if (m) { showManage(m.getAttribute('data-manage')); return; }
  var ip = e.target.closest('[data-ips]');
  if (ip) { renderIPsDrawer(ip.getAttribute('data-ips')); return; }
});
document.getElementById('btn-new-rule').addEventListener('click', showNewRule);
document.getElementById('drawer-close').addEventListener('click', function () { closeDrawer('policy-drawer'); });
document.getElementById('drawer-mask').addEventListener('click', function () {
  closeDrawer('policy-drawer'); closeDrawer('ips-drawer');
});
document.getElementById('pol-cancel').addEventListener('click', function () { closeDrawer('policy-drawer'); });
document.getElementById('pol-save').addEventListener('click', saveRule);
document.getElementById('pol-delete-rule').addEventListener('click', deleteRule);
document.getElementById('pol-quota-reset').addEventListener('click', resetQuota);
document.getElementById('ips-close').addEventListener('click', function () { closeDrawer('ips-drawer'); });
document.getElementById('pol-quota-enable').addEventListener('change', function (e) {
  document.getElementById('pol-quota-box').classList.toggle('hidden', !e.target.checked);
});
document.getElementById('pol-ip-enable').addEventListener('change', function (e) {
  document.getElementById('pol-ip-box').classList.toggle('hidden', !e.target.checked);
});
document.getElementById('rule-select').addEventListener('change', function (e) {
  state.ruleId = Number(e.target.value);
  renderRuleDetail();
  loadRuleDaily();
});

/* ---------- 启动 ---------- */
loadAll();
startSSE();
setInterval(function () { if (!document.hidden) api('GET', '/api/live').then(renderLiveRate).catch(function () {}); }, 2000);
setInterval(function () {
  if (document.hidden) return;
  var v = document.querySelector('.view.on');
  if (v && v.id === 'view-daily') loadDaily();
  if (v && v.id === 'view-rules') loadRuleDaily();
}, 60000);
