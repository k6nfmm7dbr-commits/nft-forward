#!/usr/bin/env bash
# 彻底清理 netns 测试环境残留
pkill -9 -f nff-backend.py 2>/dev/null
pkill -9 -f bigserve 2>/dev/null
pkill -9 -f "http.server" 2>/dev/null
rm -f /tmp/bigserve.py /tmp/bigserve.log /tmp/dl.bin /tmp/sse.out /tmp/tl.sh
sleep 1
for c in nff-client1 nff-client2 nff-client3 nff-backend; do
  ip netns del "$c" 2>/dev/null
done
ip link del nff-br0 2>/dev/null
for v in nff-be-veth nff-c1-veth nff-c2-veth nff-c3-veth \
         nff-be-veth-p nff-c1-veth-p nff-c2-veth-p nff-c3-veth-p; do
  ip link del "$v" 2>/dev/null
done
echo "netns 残留: [$(ip netns list 2>/dev/null | tr '\n' ' ')]"
echo "veth 残留: [$(ip -br link 2>/dev/null | grep nff- | awk '{print $1}' | tr '\n' ' ')]"
echo "python 残留: [$(ps -eo cmd 2>/dev/null | grep '[n]ff-backend\|[b]igserve\|[h]ttp.server' | tr '\n' ';')]"
exit 0
