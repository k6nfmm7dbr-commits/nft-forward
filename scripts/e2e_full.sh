#!/usr/bin/env bash
# e2e_full.sh — 真实数据面端到端验收（必须在已安装 nft-forward 的 Linux 主机上跑）。
#
# 为什么必须用 network namespace 而不是从本机 curl：
#   本机自发流量走 nat OUTPUT 钩子，不经 PREROUTING / FORWARD。DNAT 规则挂在
#   prerouting、named counter 挂在 forward，因此「本机 curl 自己的转发端口」按设计
#   就不会命中规则，也不会入账 —— 那是测试方法错误，不是产品缺陷。
#   本脚本用独立 netns 客户端产生真正的转发流量，是唯一可信的验证方式。
#
# 前置：
#   bash scripts/e2e_netns.sh setup     # 建网桥 + backend + 3 个 client netns
# 用法：
#   bash scripts/e2e_full.sh
# 收尾：
#   bash scripts/e2e_netns.sh clean
set -u

APP_DIR=${APP_DIR:-/etc/nft-forward}
. "$(dirname "$0")/e2e_common.sh"
nff_api_init || exit 2
HOST_IP=${HOST_IP:-10.203.0.1}
BE=${BE:-10.203.0.100}

P=0
F=0

ck() {
  if [ "$2" = "$3" ]; then
    P=$((P + 1))
    echo "  [PASS] $1"
  else
    F=$((F + 1))
    echo "  [FAIL] $1 (期望 $2 实得 $3)"
  fi
}
j() { python3 -c "import sys,json;d=json.load(sys.stdin);$1"; }
dbq() {
  python3 - "$1" <<'PY'
import sqlite3, sys, os
db = os.environ.get("APP_DIR", "/etc/nft-forward") + "/traffic.db"
c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
r = list(c.execute(
    "select upload_bytes,download_bytes from traffic_totals where rule_id=?",
    (int(sys.argv[1]),)))
print(f"{r[0][0]} {r[0][1]}" if r else "0 0")
PY
}
export APP_DIR

ip netns list 2>/dev/null | grep -q nff-client1 || {
  echo "缺少 netns 环境，请先执行: bash scripts/e2e_netns.sh setup"
  exit 2
}

echo "== 1. 创建规则（IP 目标 / 监听端口留空由后端随机）=="
R=$(curl -s -H "$AUTH_HDR" -X POST "$API/api/rules" -H 'Content-Type: application/json' \
  -d "{\"name\":\"e2e\",\"protocol\":\"tcp\",\"listen_port\":0,\"target_address\":\"$BE\",\"target_port\":80}")
ID=$(echo "$R" | j "print(d['id'])")
PORT=$(echo "$R" | j "print(d['listen_port'])")
echo "  rule id=$ID port=$PORT"
ck "创建成功" 1 "$([ -n "$ID" ] && echo 1 || echo 0)"
ck "随机端口落在合法区间" 1 "$([ "$PORT" -ge 20000 ] && [ "$PORT" -le 59999 ] && echo 1 || echo 0)"
sleep 2

echo "== 2. 转发实通 =="
OUT=$(ip netns exec nff-client1 curl -s --max-time 10 "http://$HOST_IP:$PORT/small")
ck "client1 经转发拿到后端响应" "BACKEND_OK" "$(echo "$OUT" | tr -d '\r\n')"

echo "== 3. 大流量入账（10MiB × 3）=="
B=$(dbq "$ID")
echo "  before: $B"
TOTAL=0
for i in 1 2 3; do
  got=$(ip netns exec nff-client1 curl -s -o /dev/null -w '%{size_download}' \
    --max-time 60 "http://$HOST_IP:$PORT/")
  echo "    第 $i 次: $got bytes"
  TOTAL=$((TOTAL + got))
done
ck "客户端共收 30MiB" 31457280 "$TOTAL"
sleep 9
A=$(dbq "$ID")
echo "  after: $A"
# shellcheck disable=SC2086
set -- $B
BU=$1
BD=$2
# shellcheck disable=SC2086
set -- $A
AU=$1
AD=$2
DELTA=$(((AU - BU) + (AD - BD)))
echo "  DB 增量: $DELTA bytes (客户端 $TOTAL)"
# TCP 头部与 ACK 会让链路统计略高于应用层载荷，容差取 -5% / +15%
LO=$((TOTAL * 95 / 100))
HI=$((TOTAL * 115 / 100))
ck "流量统计误差在容差内" 1 "$([ $DELTA -ge $LO ] && [ $DELTA -le $HI ] && echo 1 || echo 0)"

echo "== 4. 配额阻断 → 重置恢复（重置不清历史）=="
curl -s -H "$AUTH_HDR" -X PUT "$API/api/rules/$ID/policy" -H 'Content-Type: application/json' \
  -d '{"quota_enabled":true,"quota_limit_bytes":1024}' >/dev/null
sleep 3
ip netns exec nff-client1 curl -s --max-time 8 -o /dev/null "http://$HOST_IP:$PORT/small"
RC=$?
ck "超限后转发被阻断" 1 "$([ $RC -ne 0 ] && echo 1 || echo 0)"
BEFORE_RESET=$(dbq "$ID")
curl -s -H "$AUTH_HDR" -X POST "$API/api/rules/$ID/quota/reset" >/dev/null
sleep 4
OUT=$(ip netns exec nff-client1 curl -s --max-time 10 "http://$HOST_IP:$PORT/small")
ck "重置后转发恢复" "BACKEND_OK" "$(echo "$OUT" | tr -d '\r\n')"
AFTER_RESET=$(dbq "$ID")
echo "  历史累计 reset 前后: [$BEFORE_RESET] → [$AFTER_RESET]"
# shellcheck disable=SC2086
set -- $BEFORE_RESET
X=$(($1 + $2))
# shellcheck disable=SC2086
set -- $AFTER_RESET
Y=$(($1 + $2))
ck "重置配额不清历史累计" 1 "$([ "$Y" -ge "$X" ] && echo 1 || echo 0)"
curl -s -H "$AUTH_HDR" -X PUT "$API/api/rules/$ID/policy" -H 'Content-Type: application/json' \
  -d '{"quota_enabled":false}' >/dev/null
sleep 3

echo "== 5. IP 限制 max=2：第三个 IP 被拒（无超卖）=="
curl -s -H "$AUTH_HDR" -X PUT "$API/api/rules/$ID/policy" -H 'Content-Type: application/json' \
  -d '{"ip_limit_enabled":true,"ip_limit_max":2}' >/dev/null
sleep 2
hold() {
  ip netns exec "$1" setsid python3 -c "
import socket,time
try:
    s=socket.socket(); s.settimeout(10); s.connect(('$HOST_IP',$PORT))
    s.sendall(b'GET /small HTTP/1.1\r\nHost: x\r\n\r\n')
    d=s.recv(200)
    open('/tmp/hold_$1','w').write('OK' if b'BACKEND_OK' in d else 'BAD')
    time.sleep(45)
except Exception as e:
    open('/tmp/hold_$1','w').write('FAIL:'+str(e))
" >/dev/null 2>&1 &
}
rm -f /tmp/hold_nff-client*
hold nff-client1
sleep 3
hold nff-client2
sleep 6
echo "  c1=$(cat /tmp/hold_nff-client1 2>/dev/null) c2=$(cat /tmp/hold_nff-client2 2>/dev/null)"
ck "前两个 IP 获得授权" "OKOK" \
  "$(cat /tmp/hold_nff-client1 2>/dev/null)$(cat /tmp/hold_nff-client2 2>/dev/null)"
OK3=0
for _ in 1 2 3; do
  R3=$(ip netns exec nff-client3 curl -s --max-time 6 "http://$HOST_IP:$PORT/small" 2>/dev/null | tr -d '\r\n')
  [ "$R3" = "BACKEND_OK" ] && OK3=1
  sleep 2
done
ck "第三个 IP 被拒" 0 "$OK3"
pkill -f 'socket.socket' 2>/dev/null
curl -s -H "$AUTH_HDR" -X PUT "$API/api/rules/$ID/policy" -H 'Content-Type: application/json' \
  -d '{"ip_limit_enabled":false}' >/dev/null
sleep 3
OUT=$(ip netns exec nff-client3 curl -s --max-time 10 "http://$HOST_IP:$PORT/small")
ck "关闭限制后 client3 恢复" "BACKEND_OK" "$(echo "$OUT" | tr -d '\r\n')"

echo "== 6. counter 不被周期 reconcile 清零 =="
C1=$(dbq "$ID")
sleep 6
C2=$(dbq "$ID")
# shellcheck disable=SC2086
set -- $C1
A1=$(($1 + $2))
# shellcheck disable=SC2086
set -- $C2
A2=$(($1 + $2))
ck "空闲 6s 后累计不减少" 1 "$([ "$A2" -ge "$A1" ] && echo 1 || echo 0)"
NFTC=$(nft list counter inet nff_filter "nff_filter_down_$ID" 2>/dev/null |
  grep -oE 'bytes [0-9]+' | awk '{print $2}')
echo "  nft counter bytes=$NFTC  db total=$A2"
ck "nft counter 未被清零" 1 "$([ "${NFTC:-0}" -gt 0 ] && echo 1 || echo 0)"

echo "== 7. 域名目标：DNS 变化不清 counter =="
RD=$(curl -s -H "$AUTH_HDR" -X POST "$API/api/rules" -H 'Content-Type: application/json' \
  -d '{"name":"e2e-domain","protocol":"tcp","listen_port":29601,"target_address":"one.one.one.one","target_port":443}')
DID=$(echo "$RD" | j "print(d['id'])")
sleep 2
python3 - "$DID" <<'PY'
import sqlite3, sys, os
db = os.environ.get("APP_DIR", "/etc/nft-forward") + "/traffic.db"
c = sqlite3.connect(db, timeout=30)
c.execute("update rules set resolved_ipv4=? where id=?", ("1.1.1.1", int(sys.argv[1])))
c.commit()
PY
sleep 3
nft list table ip nff_nat4 | grep -q 'dport 29601'
ck "域名规则有 DNAT" 0 $?
nft list table inet nff_filter | grep -q "nff_filter_up_$DID"
ck "域名规则 counter 仍存在" 0 $?
curl -s -H "$AUTH_HDR" -X DELETE "$API/api/rules/$DID" >/dev/null

echo "== 8. SSE 长连接不被 60s 掐断 =="
timeout 70 curl -sN -H "$AUTH_HDR" "$API/api/events" >/tmp/nff-sse.out 2>/dev/null &
SP=$!
sleep 68
kill $SP 2>/dev/null
LINES=$(grep -c 'event: snapshot\|: ping' /tmp/nff-sse.out 2>/dev/null || echo 0)
echo "  SSE 行数=$LINES"
ck "SSE 存活 >60s 且有心跳/快照" 1 "$([ "$LINES" -ge 4 ] && echo 1 || echo 0)"

echo "== 9. 清理测试规则 =="
curl -s -H "$AUTH_HDR" -X DELETE "$API/api/rules/$ID" >/dev/null

echo
echo "E2E PASS=$P FAIL=$F"
[ "$F" -eq 0 ]
