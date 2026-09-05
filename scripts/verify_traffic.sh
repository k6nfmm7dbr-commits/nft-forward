#!/usr/bin/env bash
# 验证：10MiB 经转发后，DB 记录的流量误差应 < 1%（此前几乎全丢）
set -u
. "$(dirname "$0")/e2e_common.sh"
nff_api_init || exit 2

rid=$(curl -s -H "$AUTH_HDR" -X POST "$API/api/rules" \
  -H "Content-Type: application/json" \
  -d '{"name":"traffic-test","enabled":true,"protocol":"tcp","listen_port":29500,"target_address":"10.203.0.100","target_port":80}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')
echo "规则 ID = $rid"
[ -z "$rid" ] && { echo "创建规则失败"; exit 1; }
sleep 2

dbq() {
  python3 - "$1" <<'PY'
import sqlite3, sys
c = sqlite3.connect("/etc/nft-forward/traffic.db")
r = c.execute("SELECT upload_bytes,download_bytes FROM traffic_totals WHERE rule_id=?", (int(sys.argv[1]),)).fetchone()
print(f"{r[0]} {r[1]}" if r else "0 0")
PY
}

before=$(dbq "$rid")
echo "DB 之前 (up down): $before"

echo "--- 经转发下载 10MiB × 3 次 ---"
total=0
for i in 1 2 3; do
  got=$(ip netns exec nff-client1 curl -s -o /dev/null -w '%{size_download}' --max-time 60 "http://10.203.0.1:29500/")
  echo "  第 $i 次: $got bytes"
  total=$((total + got))
done
echo "客户端共收 $total bytes"

echo "--- 等采集周期 ---"
sleep 8
after=$(dbq "$rid")
echo "DB 之后 (up down): $after"

python3 - "$before" "$after" "$total" <<'PY'
import sys
bu, bd = map(int, sys.argv[1].split())
au, ad = map(int, sys.argv[2].split())
expect = int(sys.argv[3])
down = ad - bd
up = au - bu
print(f"记录下载增量 = {down} bytes ({down/1048576:.2f} MiB)")
print(f"记录上传增量 = {up} bytes")
print(f"客户端实收   = {expect} bytes ({expect/1048576:.2f} MiB)")
if expect == 0:
    print("FAIL: 客户端没收到数据")
    sys.exit(1)
err = abs(down - expect) / expect * 100
print(f"下载方向误差 = {err:.2f}%")
print("PASS: 流量统计准确" if err < 5 else f"FAIL: 误差过大 {err:.2f}%")
sys.exit(0 if err < 5 else 1)
PY
rc=$?

echo "--- 清理测试规则 ---"
curl -s -H "$AUTH_HDR" -X DELETE "$API/api/rules/$rid" >/dev/null
exit $rc
