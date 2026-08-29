#!/usr/bin/env bash
# 验证 IP 限制 max=2：两个 IP 同时在线时，第三个必须被拒绝。
# 关键：三个客户端必须同时保持 ESTABLISHED，否则先前连接关闭会释放 slot。
set -u
TOKEN=$(jq -r .token /etc/nft-forward/panel.json)
API="http://127.0.0.1:8090"
PORT=29800

rid=$(curl -s -X POST "$API/api/rules" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"name\":\"ip-limit\",\"enabled\":true,\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"listen_port\":${PORT},\"target_address\":\"10.203.0.100\",\"target_port\":80}" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')
echo "规则 ID = $rid"
[ -z "$rid" ] && { echo "创建失败"; exit 1; }

curl -s -X PUT "$API/api/rules/$rid/policy" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"ip_limit_enabled":true,"ip_limit_max":2}' >/dev/null
echo "已启用 IP 限制 max=2"
sleep 2

rm -f /tmp/hold_c1 /tmp/hold_c2

# 建立连接、读一小段数据、然后保持 socket 打开不关闭 60 秒，
# 让 conntrack 维持 ESTABLISHED，slot 才会被真正占用。
hold() {
  ip netns exec "$1" setsid python3 -c "
import socket, time
try:
    s = socket.socket(); s.settimeout(10)
    s.connect(('10.203.0.1', ${PORT}))
    s.sendall(b'GET /small HTTP/1.1\r\nHost: x\r\n\r\n')
    data = s.recv(4096)
    open('/tmp/hold_$2','w').write(str(len(data)))
    time.sleep(60)
    s.close()
except Exception as e:
    open('/tmp/hold_$2','w').write('ERR '+str(e))
" >/dev/null 2>&1 &
}

echo "--- client1 建立并保持 ---"
hold nff-client1 c1
sleep 4
echo "--- client2 建立并保持 ---"
hold nff-client2 c2
sleep 6

show() {
  curl -s "$API/api/rules/$rid/ips" -H "Authorization: Bearer $TOKEN" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("  已授权:", [e["ip"] for e in d.get("ips", [])])
print("  已拒绝:", [e["ip"] for e in d.get("rejected", [])])
'
}

echo "=== 名额占用状态（应 2 个已授权）==="
show
granted=$(curl -s "$API/api/rules/$rid/ips" -H "Authorization: Bearer $TOKEN" \
  | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("ips",[])))')
echo "  granted=$granted"

echo "--- client3 尝试连接（名额已满，应失败）---"
c3out=$(ip netns exec nff-client3 curl -s --max-time 10 "http://10.203.0.1:${PORT}/small" 2>/dev/null)
sleep 4

echo "=== 最终状态 ==="
show
nft list set inet nff_filter "nff_filter_allow_${rid}_v4" 2>/dev/null | grep elements

echo "=== 两个持有者是否真正拿到数据 ==="
for t in c1 c2; do
  echo "  $t: $(cat /tmp/hold_$t 2>/dev/null || echo 无结果)"
done

echo "=== 判定 ==="
rc=0
if [ "$granted" != "2" ]; then
  echo "FAIL: 前置条件不满足，granted=$granted（应为 2）"
  rc=1
elif [ "$c3out" = "BACKEND_OK" ]; then
  echo "FAIL: 名额已满时 client3 仍拿到数据（超卖）"
  rc=1
else
  echo "PASS: 两个 IP 占满名额，client3 被拒绝（返回 '${c3out}'）"
fi

echo "--- 清理 ---"
pkill -f "10.203.0.1', ${PORT}" 2>/dev/null
rm -f /tmp/hold_c1 /tmp/hold_c2
curl -s -X DELETE "$API/api/rules/$rid" -H "Authorization: Bearer $TOKEN" >/dev/null
exit $rc
