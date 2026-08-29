#!/usr/bin/env bash
# 验证 SSE 长连接不再被 WriteTimeout(60s) 切断
TOKEN=$(jq -r .token /etc/nft-forward/panel.json)
OUT=/tmp/sse_check.out
start=$(date +%s)
timeout 95 curl -sN "http://127.0.0.1:8090/api/events" -H "Authorization: Bearer $TOKEN" -o "$OUT"
end=$(date +%s)
alive=$((end - start))
pings=$(grep -c ping "$OUT" 2>/dev/null || echo 0)
snaps=$(grep -c snapshot "$OUT" 2>/dev/null || echo 0)
echo "存活 ${alive} 秒 (期望 ~95，旧版为 60)"
echo "ping 事件 ${pings} 个 (期望 >=5，旧版为 3)"
echo "snapshot 事件 ${snaps} 个"
rm -f "$OUT"
if [ "$alive" -ge 90 ] && [ "$pings" -ge 5 ]; then
  echo "PASS: SSE 长连接未被切断"
  exit 0
fi
echo "FAIL: SSE 仍被提前切断"
exit 1
