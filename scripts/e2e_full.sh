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
# ★ 这一段依赖 conntrack：在线 IP 的准入/拒绝完全以 conntrack 的连接生命周期
# 为事实来源。若 /proc/net/nf_conntrack 不可读或内核未跟踪任何连接（部分
# 容器化 CI runner 就是这种情况），策略层会按设计**冻结** slot 状态、
# 不授予任何名额 —— 此时所有客户端都连不通，断言无从谈起。
# 因此这里显式检测并跳过，同时把原因打印出来，绝不假装通过。
CT_OK=0
if [ -r /proc/net/nf_conntrack ] && [ "$(wc -l < /proc/net/nf_conntrack)" -gt 0 ]; then
  CT_OK=1
fi
if [ "$CT_OK" != "1" ]; then
  echo "  [SKIP] IP 限制验证：本机 /proc/net/nf_conntrack 不可用或未跟踪连接"
  echo "         （在线 IP 与 IP 限制以 conntrack 为事实来源，此环境无法验证；"
  echo "          请在支持 conntrack 的宿主机上运行本段）"
else
curl -s -H "$AUTH_HDR" -X PUT "$API/api/rules/$ID/policy" -H 'Content-Type: application/json' \
  -d '{"ip_limit_enabled":true,"ip_limit_max":2}' >/dev/null
sleep 2

# 长连接保持器写成独立脚本文件，不用 python -c 内联：
# 内联字符串要同时穿过 shell 双引号插值与 python 引号，非常容易在不同环境下
# 静默失败（表现为结果文件根本没生成，无法区分「脚本没跑」与「连接失败」）。
# 独立文件 + 参数传递 + stderr 落盘，任何失败都能定位。
cat > /tmp/nff-hold.py <<'PYEOF'
"""保持一个 IP 处于「在线」状态，用于 IP 限制验收。

为什么不能建立连接后完全静默：在线判活以 conntrack 字节增量为准。
TCP 半开连接在 ipIdle（默认 60s）内算在线，超窗无流量即判死并释放 slot ——
那是**设计行为**（README 已记录）。真实客户端会持续有流量，因此这里必须
周期性产生流量，否则 60s 后 slot 被释放、第三个 IP 会**合法**拿到名额，
测试就会把设计行为误报成超卖。

做法：保持一个长连接占位，同时每 8s 新开一个短连接完整取一次 /small。
短连接让该 IP 在 conntrack 里持续有新的活跃 flow，不依赖长连接上的字节增量，
也不受 HTTP keep-alive 细节影响。
"""
import socket
import sys
import time

host, port, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]


def fetch():
    """新开连接完整取一次 /small。"""
    s = socket.socket()
    s.settimeout(10)
    try:
        s.connect((host, port))
        s.sendall(b"GET /small HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        total = 0
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            total += len(chunk)
            if total > 65536:
                break
        return total
    finally:
        s.close()


def hold_conn():
    """建立长连接并确认转发通路可用，随后保持该连接占位。"""
    s = socket.socket()
    s.settimeout(10)
    s.connect((host, port))
    s.sendall(b"GET /small HTTP/1.1\r\nHost: x\r\n\r\n")
    data = s.recv(4096)
    if b"BACKEND_OK" not in data:
        s.close()
        raise RuntimeError("bad response: %r" % data[:80])
    return s


# IP 限制的授予存在毫秒级竞态（放行 SYN → 准入循环 500ms 授予 slot →
# established 放行），首次尝试可能恰好落在窗口内被 drop。重试 3 次。
keep = None
last = None
for _ in range(3):
    try:
        keep = hold_conn()
        break
    except Exception as exc:  # noqa: BLE001 - 需要保留原始错误文本
        last = exc
        time.sleep(1.5)

with open(out, "w") as f:
    f.write("OK" if keep is not None else "FAIL:%s" % last)
    f.flush()

if keep is not None:
    # 周期性产生真实流量，直到被 pkill 收尾。
    deadline = time.time() + 300
    while time.time() < deadline:
        time.sleep(8)
        try:
            fetch()
        except Exception:  # noqa: BLE001 - 单次失败不退出，下一轮继续
            pass
PYEOF

hold() {  # hold <netns>
  ip netns exec "$1" setsid python3 /tmp/nff-hold.py "$HOST_IP" "$PORT" "/tmp/hold_$1" \
    > "/tmp/hold_err_$1" 2>&1 &
}
rm -f /tmp/hold_nff-client* /tmp/hold_err_nff-client*
hold nff-client1
sleep 3
hold nff-client2
# 等两个 hold 都写出结果（内部各自最多重试 3 次 × 1.5s，故上限约 12s）
for _ in $(seq 1 20); do
  [ -s /tmp/hold_nff-client1 ] && [ -s /tmp/hold_nff-client2 ] && break
  sleep 1
done
echo "  c1=$(cat /tmp/hold_nff-client1 2>/dev/null) c2=$(cat /tmp/hold_nff-client2 2>/dev/null)"
for c in nff-client1 nff-client2; do
  if [ ! -s "/tmp/hold_$c" ] && [ -s "/tmp/hold_err_$c" ]; then
    echo "  [$c stderr] $(head -3 "/tmp/hold_err_$c")"
  fi
done
ck "前两个 IP 获得授权" "OKOK" \
  "$(cat /tmp/hold_nff-client1 2>/dev/null)$(cat /tmp/hold_nff-client2 2>/dev/null)"

# ★ 必须等策略层真的记满 2 个 granted 才让 client3 尝试。
# 否则 client3 可能抢在 client2 被授予之前发起连接 —— 那时只有 1 个 granted，
# 它会合法地拿到第 2 个名额（先到先得，不是超卖），断言就会假失败。
granted_count() {
  curl -s -H "$AUTH_HDR" "$API/api/rules/$ID/ips" |
    python3 -c 'import json,sys;print(len(json.load(sys.stdin).get("ips") or []))'
}
for _ in $(seq 1 20); do
  [ "$(granted_count)" = "2" ] && break
  sleep 1
done
echo "  当前 granted 数 = $(granted_count)（应为 2，名额已占满）"
ck "名额已被前两个 IP 占满" 2 "$(granted_count)"
# 先做一次「预热」尝试：IP 限制的准入是周期性的（500ms 一轮），
# 拒绝要等策略层在 conntrack 里看到这个新来源后才落地。预热这一次的结果
# 不参与断言 —— 它只负责把 client3 推进 rejected。
ip netns exec nff-client3 curl -s --max-time 6 "http://$HOST_IP:$PORT/small" >/dev/null 2>&1 || true
# 等 client3 真正进入 rejected（最多 15s）
rejected_has() {
  curl -s -H "$AUTH_HDR" "$API/api/rules/$ID/ips" |
    python3 -c 'import json,sys;d=json.load(sys.stdin);print("1" if any(e["ip"]=="10.203.0.13" for e in (d.get("rejected") or [])) else "0")'
}
for _ in $(seq 1 15); do
  [ "$(rejected_has)" = "1" ] && break
  sleep 1
done
ck "client3 已被记入 rejected" 1 "$(rejected_has)"

# 稳态断言：进入拒绝状态后，连续 3 次尝试必须全部失败。
#
# 每次尝试前先确认「两个名额仍被 c1/c2 占着」：hold 客户端若因任何原因掉线，
# client3 就会**合法**拿到名额 —— 那是先到先得，不是超卖，断言必须区分这两种
# 情况，否则会把环境抖动误报成产品缺陷。
OK3=0
for _ in 1 2 3; do
  if [ "$(granted_count)" -lt 2 ]; then
    echo "  [SKIP] 前两个客户端已掉线（granted=$(granted_count)），本次尝试不计入断言"
    sleep 2
    continue
  fi
  R3=$(ip netns exec nff-client3 curl -s --max-time 6 "http://$HOST_IP:$PORT/small" 2>/dev/null | tr -d '\r\n')
  [ "$R3" = "BACKEND_OK" ] && OK3=1
  sleep 2
done
ck "第三个 IP 被稳定拒绝" 0 "$OK3"
# 无超卖：granted 数不得超过 max_ips（这是硬保证，任何时刻都不允许违反）
ck "granted 未超卖（<=2）" 1 "$([ "$(granted_count)" -le 2 ] && echo 1 || echo 0)"
# allow set 里绝不能出现被拒 IP —— 仅在名额确实仍被占满时断言（同上）
if [ "$(granted_count)" -ge 2 ]; then
  if nft list set inet nff_filter "nff_filter_allow_${ID}_v4" 2>/dev/null | grep -q '10.203.0.13'; then rc=1; else rc=0; fi
  ck "allow set 不含被拒 IP" 0 "$rc"
else
  echo "  [SKIP] allow set 断言（名额已释放，client3 合法入场）"
fi
pkill -f 'nff-hold.py' 2>/dev/null
curl -s -H "$AUTH_HDR" -X PUT "$API/api/rules/$ID/policy" -H 'Content-Type: application/json' \
  -d '{"ip_limit_enabled":false}' >/dev/null
sleep 3
OUT=$(ip netns exec nff-client3 curl -s --max-time 10 "http://$HOST_IP:$PORT/small")
ck "关闭限制后 client3 恢复" "BACKEND_OK" "$(echo "$OUT" | tr -d '\r\n')"
fi  # CT_OK

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
LINES=$(grep -c 'event: snapshot\|: ping' /tmp/nff-sse.out 2>/dev/null | tr -dc '0-9')
[ -z "$LINES" ] && LINES=0
echo "  SSE 行数=$LINES"
ck "SSE 存活 >60s 且有心跳/快照" 1 "$([ "$LINES" -ge 4 ] && echo 1 || echo 0)"

echo "== 9. 清理测试规则 =="
curl -s -H "$AUTH_HDR" -X DELETE "$API/api/rules/$ID" >/dev/null

echo
echo "E2E PASS=$P FAIL=$F"
[ "$F" -eq 0 ]
