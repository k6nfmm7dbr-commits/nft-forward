#!/usr/bin/env bash
# 验证配额：超限后阻断转发，提高额度/重置后自动恢复（且不重建结构、不丢累计）
set -u
TOKEN=$(jq -r .token /etc/nft-forward/panel.json)
API="http://127.0.0.1:8090"
PORT=29900

rid=$(curl -s -X POST "$API/api/rules" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"name\":\"quota\",\"enabled\":true,\"protocol\":\"tcp\",\"listen_port\":${PORT},\"target_address\":\"10.203.0.100\",\"target_port\":80}" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')
echo "规则 ID = $rid"
[ -z "$rid" ] && exit 1
sleep 2

echo "--- 先跑一次 10MiB 产生用量 ---"
ip netns exec nff-client1 curl -s -o /dev/null -w "  下载 %{size_download} bytes\n" --max-time 60 "http://10.203.0.1:${PORT}/"
sleep 6

used=$(curl -s "$API/api/rules/$rid" -H "Authorization: Bearer $TOKEN" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("quota") or {}).get("quota_used_bytes",0))')
echo "  当前用量 = $used"

echo "--- 设额度 1MiB（远小于已用）应立即阻断 ---"
curl -s -X PUT "$API/api/rules/$rid/policy" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"quota_enabled":true,"quota_limit_bytes":1048576}' >/dev/null
sleep 3

curl -s "$API/api/rules/$rid" -H "Authorization: Bearer $TOKEN" | python3 -c '
import json, sys
d = json.load(sys.stdin)
q = d.get("quota") or {}
print("  quota_state =", q.get("quota_state"), " status =", d.get("status"))
'
echo "  qblock set: $(nft list set inet nff_filter nff_filter_qblock 2>/dev/null | grep -o 'elements = {[^}]*}' || echo '(空)')"

blocked=$(ip netns exec nff-client1 curl -s --max-time 8 "http://10.203.0.1:${PORT}/small" 2>/dev/null)
if [ "$blocked" = "BACKEND_OK" ]; then
  echo "  FAIL: 超限后仍能转发"
  rcA=1
else
  echo "  PASS: 超限后转发被阻断（返回 '${blocked}'）"
  rcA=0
fi

total_before=$(curl -s "$API/api/rules/$rid" -H "Authorization: Bearer $TOKEN" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("total_up",0)+d.get("total_down",0))')

echo "--- 重置用量（应恢复且保留历史累计）---"
curl -s -X POST "$API/api/rules/$rid/quota/reset" -H "Authorization: Bearer $TOKEN" >/dev/null
sleep 3

curl -s "$API/api/rules/$rid" -H "Authorization: Bearer $TOKEN" | python3 -c '
import json, sys
d = json.load(sys.stdin)
q = d.get("quota") or {}
print("  quota_state =", q.get("quota_state"), " used =", q.get("quota_used_bytes"))
'
echo "  qblock set: $(nft list set inet nff_filter nff_filter_qblock 2>/dev/null | grep -o 'elements = {[^}]*}' || echo '(空)')"

restored=$(ip netns exec nff-client1 curl -s --max-time 8 "http://10.203.0.1:${PORT}/small" 2>/dev/null)
if [ "$restored" = "BACKEND_OK" ]; then
  echo "  PASS: 重置后转发恢复"
  rcB=0
else
  echo "  FAIL: 重置后仍不通（返回 '${restored}'）"
  rcB=1
fi

total_after=$(curl -s "$API/api/rules/$rid" -H "Authorization: Bearer $TOKEN" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("total_up",0)+d.get("total_down",0))')
echo "  历史累计: 重置前=$total_before 重置后=$total_after"
if [ "$total_after" -ge "$total_before" ]; then
  echo "  PASS: 重置只清用量，历史累计保留"
  rcC=0
else
  echo "  FAIL: 历史累计被清掉了"
  rcC=1
fi

echo "--- 清理 ---"
curl -s -X DELETE "$API/api/rules/$rid" -H "Authorization: Bearer $TOKEN" >/dev/null
exit $((rcA + rcB + rcC))
