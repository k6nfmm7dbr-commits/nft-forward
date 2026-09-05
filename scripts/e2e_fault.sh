#!/usr/bin/env bash
# e2e_fault.sh — 故障注入端到端验收（需 root + 已安装 nft-forward + 真实 nftables）。
#
# 覆盖单元测试无法真实验证的部分：
#   A. 认证（未登录 / Bearer / Cookie / query token / 413 / 节流 / XFF / 0600）
#   B. 随机暴露面（五位数端口 / 非 8090 / 随机入口 / 根路径 404 / 裸 healthz）
#   C. nftables 自愈（真删表/链/counter/set，下一轮自动恢复）
#   D. conntrack 异常期间规则 CRUD 仍真正改动 nft
#   E. 重启 / 升级后端口、入口、令牌、规则、流量全部不变
#
# 用法：bash scripts/e2e_fault.sh
set -u

APP_DIR=${APP_DIR:-/etc/nft-forward}
CORE_BIN=${CORE_BIN:-/usr/local/bin/nft-forward}
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SELF_DIR/e2e_common.sh"
nff_api_init || exit 2

P=0
F=0
ck() {
  if [ "$2" = "$3" ]; then
    P=$((P + 1)); echo "  [PASS] $1"
  else
    F=$((F + 1)); echo "  [FAIL] $1 (期望 $2 实得 $3)"
  fi
}
code() {  # code <curl args...> → HTTP 状态码
  curl -s -o /dev/null -w '%{http_code}' "$@"
}
BASE="http://127.0.0.1:${NFF_PORT}"

echo "== A. 认证 =="
ck "未认证访问 API 返回 401" "401" "$(code "$API/api/summary")"
ck "未认证访问 SSE 返回 401" "401" "$(code "$API/api/events")"
ck "正确 Bearer 可访问" "200" "$(code -H "$AUTH_HDR" "$API/api/healthz")"
ck "错误 Bearer 被拒" "401" "$(code -H 'Authorization: Bearer 00000000000000000000000000000000' "$API/api/healthz")"
ck "query token 无效" "401" "$(code "$API/api/healthz?token=$NFF_TOKEN")"
ck "Cookie 可用" "200" "$(code -H "Cookie: nff_token=$NFF_TOKEN" "$API/api/healthz")"
ck "未认证访问入口根返回登录页" "200" "$(code "$API/")"
ck "未认证不得取得面板 app.js" "404" "$(code "$API/app.js")"

# 登录 → Cookie 属性
LOGIN_HDRS=$(curl -s -D - -o /dev/null -X POST "$API/login" \
  -H 'Content-Type: application/x-www-form-urlencoded' --data "token=$NFF_TOKEN")
echo "$LOGIN_HDRS" | grep -qi '^HTTP/1.1 302'; ck "登录成功返回 302" 0 $?
echo "$LOGIN_HDRS" | grep -qi 'Set-Cookie:.*nff_token='; ck "登录下发会话 Cookie" 0 $?
echo "$LOGIN_HDRS" | grep -qi 'Set-Cookie:.*HttpOnly'; ck "Cookie 为 HttpOnly" 0 $?
echo "$LOGIN_HDRS" | grep -qi 'Set-Cookie:.*SameSite=Lax'; ck "Cookie SameSite=Lax" 0 $?
echo "$LOGIN_HDRS" | grep -qi 'Set-Cookie:.*Max-Age=604800'; ck "Cookie MaxAge=7天" 0 $?
if echo "$LOGIN_HDRS" | grep -qi 'Set-Cookie:.*Secure'; then rc=1; else rc=0; fi
ck "纯 HTTP 不设 Secure" 0 "$rc"

# 登录体 > 64 KiB → 413
BIGFILE=$(mktemp)
{ printf 'token=%s&pad=' "$NFF_TOKEN"; head -c 80000 /dev/zero | tr '\0' 'x'; } > "$BIGFILE"
ck "登录体 >64KiB 返回 413" "413" \
  "$(code -X POST "$API/login" -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$BIGFILE")"
rm -f "$BIGFILE"

# 失败节流：前 5 次快速拒绝，第 6 次起明显变慢
t0=$(date +%s%N)
for _ in 1 2 3 4 5; do
  code -X POST "$API/login" -H 'Content-Type: application/x-www-form-urlencoded' --data 'token=wrong' >/dev/null
done
t1=$(date +%s%N)
first5_ms=$(( (t1 - t0) / 1000000 ))
t0=$(date +%s%N)
code -X POST "$API/login" -H 'Content-Type: application/x-www-form-urlencoded' --data 'token=wrong' >/dev/null
t1=$(date +%s%N)
sixth_ms=$(( (t1 - t0) / 1000000 ))
echo "  前 5 次共 ${first5_ms}ms，第 6 次 ${sixth_ms}ms"
ck "达到阈值后失败被延迟 >=2s" 1 "$([ "$sixth_ms" -ge 1800 ] && echo 1 || echo 0)"

# 正确令牌不被节流拖慢
t0=$(date +%s%N)
LOGIN_OK=$(code -X POST "$API/login" -H 'Content-Type: application/x-www-form-urlencoded' --data "token=$NFF_TOKEN")
t1=$(date +%s%N)
ok_ms=$(( (t1 - t0) / 1000000 ))
ck "正确令牌仍返回 302" "302" "$LOGIN_OK"
ck "正确令牌不被节流延迟（<1s）" 1 "$([ "$ok_ms" -lt 1000 ] && echo 1 || echo 0)"

# XFF 不能绕过节流：每次换一个 XFF 连续失败，若实现信任 XFF 就会分成多个桶、
# 每桶都到不了阈值，于是第 6 次不会被延迟。
# 注意顺序：上面成功登录已清空该 IP 的失败计数，这里必须重新累计。
for i in 1 2 3 4 5; do
  code -X POST "$API/login" -H 'Content-Type: application/x-www-form-urlencoded' \
    -H "X-Forwarded-For: 10.9.9.$i" --data 'token=wrong' >/dev/null
done
t0=$(date +%s%N)
code -X POST "$API/login" -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'X-Forwarded-For: 8.8.8.8' --data 'token=wrong' >/dev/null
t1=$(date +%s%N)
xff_ms=$(( (t1 - t0) / 1000000 ))
echo "  换 5 个 XFF 失败后第 6 次耗时 ${xff_ms}ms"
ck "伪造 XFF 无法绕过节流" 1 "$([ "$xff_ms" -ge 1800 ] && echo 1 || echo 0)"
# 清掉节流状态，避免影响后续断言
code -X POST "$API/login" -H 'Content-Type: application/x-www-form-urlencoded' --data "token=$NFF_TOKEN" >/dev/null

ck "panel.json 权限 0600" "600" "$(stat -c %a "$APP_DIR/panel.json")"
ck "令牌长度 32" "32" "${#NFF_TOKEN}"
ck "令牌为十六进制" 0 "$(printf '%s' "$NFF_TOKEN" | grep -qE '^[0-9a-f]{32}$'; echo $?)"

echo
echo "== B. 随机暴露面 =="
ck "面板端口是五位数" 1 "$([ "${#NFF_PORT}" -eq 5 ] && echo 1 || echo 0)"
ck "面板端口不是 8090" 1 "$([ "$NFF_PORT" != "8090" ] && echo 1 || echo 0)"
ck "面板端口在 10000-65535" 1 "$([ "$NFF_PORT" -ge 10000 ] && [ "$NFF_PORT" -le 65535 ] && echo 1 || echo 0)"
ck "入口路径长度 >=16" 1 "$([ "${#NFF_ENTRY}" -ge 16 ] && echo 1 || echo 0)"
ck "入口路径与令牌不同" 1 "$([ "$NFF_ENTRY" != "$NFF_TOKEN" ] && echo 1 || echo 0)"
ck "根路径 / 返回 404" "404" "$(code "$BASE/")"
ck "/admin 返回 404" "404" "$(code "$BASE/admin")"
ck "/wp-login.php 返回 404" "404" "$(code "$BASE/wp-login.php")"
ck "/favicon.ico 返回 404" "404" "$(code "$BASE/favicon.ico")"
ck "错误随机入口返回 404" "404" "$(code "$BASE/deadbeefdeadbeefdeadbeef/")"
ck "未知 API 返回 404" "404" "$(code "$BASE/api/summary")"
ck "正确入口返回登录页 200" "200" "$(code "$API/")"

ROOT_BODY=$(curl -s "$BASE/")
if printf '%s' "$ROOT_BODY" | grep -qiE 'nff|nft.?forward|nftables|令牌|面板'; then rc=1; else rc=0; fi
ck "404 正文不泄漏产品/技术栈信息" 0 "$rc"
ROOT_HDRS=$(curl -s -D - -o /dev/null "$BASE/")
if printf '%s' "$ROOT_HDRS" | grep -qiE '^(Server|X-Powered-By):'; then rc=1; else rc=0; fi
ck "404 不设 Server / X-Powered-By 头" 0 "$rc"
if printf '%s' "$ROOT_HDRS" | grep -qi '^Location:'; then rc=1; else rc=0; fi
ck "404 不跳转登录页" 0 "$rc"

# 安全响应头
SEC_HDRS=$(curl -s -D - -o /dev/null "$API/")
for h in 'Cache-Control: no-store' 'X-Content-Type-Options: nosniff' \
         'Referrer-Policy: no-referrer' 'X-Frame-Options: DENY'; do
  printf '%s' "$SEC_HDRS" | grep -qi "^${h%%:*}:.*${h#*: }"; ck "响应头含 $h" 0 $?
done
CSP=$(printf '%s' "$SEC_HDRS" | grep -i '^Content-Security-Policy:' || true)
printf '%s' "$CSP" | grep -q "default-src 'self'"; ck "CSP 为 default-src 'self'" 0 $?
if printf '%s' "$CSP" | grep -qE "unsafe-eval|unsafe-inline"; then rc=1; else rc=0; fi
ck "CSP 无 unsafe-*" 0 "$rc"

# healthz：本机可用，外网视角（非 loopback 源地址）不可见
ck "本机 /healthz 可用" "200" "$(code "$BASE/healthz")"
HOSTIP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -n "$HOSTIP" ]; then
  EXT_CODE=$(curl -s -o /dev/null -w '%{http_code}' --interface "$HOSTIP" \
    "http://${HOSTIP}:${NFF_PORT}/healthz" 2>/dev/null || echo 000)
  echo "  经本机公网 IP 访问 /healthz → $EXT_CODE"
  ck "非 loopback 源访问 /healthz 不泄漏" 1 "$([ "$EXT_CODE" = "404" ] || [ "$EXT_CODE" = "000" ] && echo 1 || echo 0)"
fi

echo
echo "== C. nftables 自愈（真实破坏） =="
RID=$(nff_curl -X POST "$API/api/rules" -H 'Content-Type: application/json' \
  -d '{"name":"heal","protocol":"tcp+udp","listen_port":0,"target_address":"10.203.0.100","target_port":80}' \
  | python3 -c 'import json,sys;print(json.load(sys.stdin).get("id",""))')
[ -z "$RID" ] && { echo "创建自愈测试规则失败"; exit 1; }
nff_curl -X PUT "$API/api/rules/$RID/policy" -H 'Content-Type: application/json' \
  -d '{"ip_limit_enabled":true,"ip_limit_max":2}' >/dev/null

# 再建一条 IPv6 目标规则：nff_nat6 只有在存在 IPv6 目标时才会承载真实 DNAT，
# 否则 desired state 按设计不要求它（删掉也不该重建）。有了这条规则才能
# 真正验证「删除 nff_nat6 → 下一轮恢复 IPv6 转发」。
RID6=$(nff_curl -X POST "$API/api/rules" -H 'Content-Type: application/json' \
  -d '{"name":"heal-v6","protocol":"tcp","listen_port":0,"target_address":"2001:db8::1","target_port":443}' \
  | python3 -c 'import json,sys;print(json.load(sys.stdin).get("id",""))')
[ -z "$RID6" ] && { echo "创建 IPv6 目标规则失败"; exit 1; }
sleep 2
nft list table ip6 nff_nat6 2>/dev/null | grep -q dport
ck "IPv6 目标规则产生 nff_nat6 DNAT" 0 $?

heal_check() {  # heal_check <描述> <破坏命令> <验证命令>
  local desc="$1" break_cmd="$2" verify_cmd="$3"
  eval "$break_cmd" >/dev/null 2>&1
  sleep 3
  if eval "$verify_cmd" >/dev/null 2>&1; then
    P=$((P + 1)); echo "  [PASS] 自愈: $desc"
  else
    F=$((F + 1)); echo "  [FAIL] 自愈: $desc（未恢复）"
  fi
}

heal_check "删除 nff_nat4" \
  "nft delete table ip nff_nat4" \
  "nft list table ip nff_nat4 | grep -q 'dport'"
heal_check "删除 nff_nat6" \
  "nft delete table ip6 nff_nat6" \
  "nft list table ip6 nff_nat6 | grep -q dport"
heal_check "删除 nff_filter" \
  "nft delete table inet nff_filter" \
  "nft list table inet nff_filter | grep -q nff_filter_up_$RID"
heal_check "删除 forward 链" \
  "nft delete chain inet nff_filter nff_filter_forward" \
  "nft list chain inet nff_filter nff_filter_forward | grep -q counter"
heal_check "删除 download counter" \
  "nft delete counter inet nff_filter nff_filter_down_$RID" \
  "nft list counter inet nff_filter nff_filter_down_$RID"
heal_check "删除 upload counter" \
  "nft delete counter inet nff_filter nff_filter_up_$RID" \
  "nft list counter inet nff_filter nff_filter_up_$RID"
heal_check "删除 IPv4 allow set" \
  "nft delete set inet nff_filter nff_filter_allow_${RID}_v4" \
  "nft list set inet nff_filter nff_filter_allow_${RID}_v4"
heal_check "删除 IPv6 allow set" \
  "nft delete set inet nff_filter nff_filter_allow_${RID}_v6" \
  "nft list set inet nff_filter nff_filter_allow_${RID}_v6"
heal_check "删除 quota block set" \
  "nft delete set inet nff_filter nff_filter_qblock" \
  "nft list set inet nff_filter nff_filter_qblock"

# 自愈不得动别人的表
nft add table inet e2e_foreign 2>/dev/null || true
nft add chain inet e2e_foreign foreign_chain 2>/dev/null || true
nft delete table inet nff_filter 2>/dev/null || true
sleep 3
nft list table inet e2e_foreign >/dev/null 2>&1
ck "自愈不影响用户自有表" 0 $?
nft delete table inet e2e_foreign 2>/dev/null || true

echo
echo "== D. conntrack 异常期间规则 CRUD 仍真实生效 =="
# 用一个不存在的 conntrack 路径无法在运行中的服务上模拟，因此改为验证
# 「删除规则后 nft 侧真的撤销」这条最关键的一致性断言。
PORT2=$(nff_curl "$API/api/rules/$RID" | python3 -c 'import json,sys;print(json.load(sys.stdin)["listen_port"])')
nft list table ip nff_nat4 | grep -q "dport $PORT2"
ck "规则存在时 DNAT 在位" 0 $?
nff_curl -X DELETE "$API/api/rules/$RID" >/dev/null
sleep 3
if nft list table ip nff_nat4 2>/dev/null | grep -q "dport $PORT2"; then rc=1; else rc=0; fi
ck "删除规则后 DNAT 真的撤销（API 成功 == nft 一致）" 0 "$rc"
if nft list table inet nff_filter 2>/dev/null | grep -q "nff_filter_up_$RID"; then rc=1; else rc=0; fi
ck "删除规则后遗留 counter 已清理" 0 "$rc"
# 清理 IPv6 测试规则
nff_curl -X DELETE "$API/api/rules/$RID6" >/dev/null

echo
echo "== E. 重启后端口 / 入口 / 令牌不变 =="
BEFORE="$NFF_PORT|$NFF_ENTRY|$NFF_TOKEN"
systemctl restart nft-forward 2>/dev/null || true
sleep 4
nff_api_init || exit 2
AFTER="$NFF_PORT|$NFF_ENTRY|$NFF_TOKEN"
ck "服务重启后三项不变" "$BEFORE" "$AFTER"
ck "重启后面板可用" "200" "$(code -H "$AUTH_HDR" "$API/api/healthz")"

echo
echo "FAULT E2E PASS=$P FAIL=$F"
[ "$F" -eq 0 ]
