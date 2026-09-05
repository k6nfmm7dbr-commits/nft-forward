#!/usr/bin/env bash
# verify_quota_realtime.sh — 真机验证配额实时性（需先 e2e_netns.sh setup）。
#
# ★ 为什么必须限速客户端：
#
#	netns 内网是内存级链路（GB/s）。不限速时 100MiB 一秒就传完，策略
#	reconcile（500ms 一轮）只来得及跑 1-2 轮，任何字节级容差断言都只是在
#	测「链路有多快」，而不是「配额判定有多及时」。
#	限速到 R 字节/秒后，理论超额上界 = R × reconcile 周期(0.5s) + 单次响应粒度。
#	旧实现（只看已落库 totals，刷盘间隔 2s）的上界是 R × 2s，两者可区分。
#
# 断言：
#   1. 配额最终判定为 exceeded；
#   2. 实际放行总量 <= 配额 + 容差（容差按限速与 reconcile 周期推算）。
set -u
cd "$(dirname "$0")" || exit 2
. ./e2e_common.sh
nff_api_init || exit 2

HOST_IP=${HOST_IP:-10.203.0.1}
BE=${BE:-10.203.0.100}
QUOTA=$((8 * 1024 * 1024))   # 8 MiB
RATE=${RATE:-4M}             # 客户端限速 4 MB/s
RATE_BPS=$((4 * 1024 * 1024))
# 容差 = 限速 × (reconcile 0.5s + 采集/应用抖动 1s) 再留一倍余量
TOL=$((RATE_BPS * 3))

ip netns list 2>/dev/null | grep -q nff-client1 || {
  echo "缺少 netns 环境，请先执行: bash scripts/e2e_netns.sh setup"; exit 2; }

R=$(nff_curl -X POST "$API/api/rules" -H 'Content-Type: application/json' \
  -d "{\"name\":\"quota-rt\",\"protocol\":\"tcp\",\"listen_port\":0,\"target_address\":\"$BE\",\"target_port\":80}")
ID=$(printf '%s' "$R" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
PORT=$(printf '%s' "$R" | python3 -c 'import json,sys;print(json.load(sys.stdin)["listen_port"])')
echo "规则 id=$ID port=$PORT 配额=$((QUOTA / 1024 / 1024))MiB 限速=$RATE 容差=$((TOL / 1024 / 1024))MiB"
trap 'nff_curl -X DELETE "$API/api/rules/$ID" >/dev/null 2>&1' EXIT

nff_curl -X POST "$API/api/rules/$ID/quota/reset" >/dev/null
nff_curl -X PUT "$API/api/rules/$ID/policy" -H 'Content-Type: application/json' \
  -d "{\"quota_enabled\":true,\"quota_limit_bytes\":$QUOTA}" >/dev/null
sleep 2

echo "--- 限速下载直到被阻断（最多 8 轮 × 10MiB @ $RATE）---"
TOTAL=0
for i in $(seq 1 8); do
  got=$(ip netns exec nff-client1 curl -s --limit-rate "$RATE" -o /dev/null \
    -w '%{size_download}' --max-time 40 "http://${HOST_IP}:${PORT}/" 2>/dev/null || echo 0)
  TOTAL=$((TOTAL + got))
  echo "  第 $i 轮: $got bytes（累计 $TOTAL）"
  # 被阻断的表现：本轮拿到的字节数明显不足一个完整响应
  [ "$got" -lt $((9 * 1024 * 1024)) ] && { echo "  已被阻断"; break; }
done

sleep 3
RV=$(nff_curl "$API/api/rules/$ID")
USED=$(printf '%s' "$RV" | python3 -c 'import json,sys;d=json.load(sys.stdin);print((d.get("quota") or {}).get("quota_used_bytes",0))')
STATE=$(printf '%s' "$RV" | python3 -c 'import json,sys;d=json.load(sys.stdin);print((d.get("quota") or {}).get("quota_state",""))')
echo
echo "客户端实收总量: $TOTAL bytes ($((TOTAL / 1024 / 1024)) MiB)"
echo "面板已用:      $USED bytes ($((USED / 1024 / 1024)) MiB)"
echo "配额状态:      $STATE"
OVER=$((TOTAL - QUOTA))
echo "超额:          $OVER bytes"

RC=0
[ "$STATE" = "exceeded" ] || { echo "FAIL: 配额未判定为 exceeded"; RC=1; }
LIMIT=$((QUOTA + TOL))
if [ "$TOTAL" -le "$LIMIT" ]; then
  echo "PASS: 实际放行 $TOTAL <= 容差上限 $LIMIT（$((LIMIT / 1024 / 1024))MiB）"
else
  echo "FAIL: 超额超出容差（$TOTAL > $LIMIT）"
  RC=1
fi
exit $RC
