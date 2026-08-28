#!/usr/bin/env bash
# NFT Forward network-namespace E2E。
# 模拟：client(10.203.0.11) → forward host(10.203.0.1:28844) → DNAT → backend(10.203.0.100:80)。
# 用法：
#   ./e2e_netns.sh setup    搭建命名空间 + 后端
#   ./e2e_netns.sh clean    清理
#   ./e2e_netns.sh test     运行转发 + 流量 + IP 限制测试
set -u

BR=nff-br0
SUBNET=10.203.0
HOST_IP=${SUBNET}.1
BE_NS=nff-backend
BE_IP=${SUBNET}.100
CLIENTS="nff-client1:${SUBNET}.11 nff-client2:${SUBNET}.12 nff-client3:${SUBNET}.13"

cleanup() {
  for c in nff-client1 nff-client2 nff-client3; do
    ip netns del "$c" 2>/dev/null
  done
  ip netns del "$BE_NS" 2>/dev/null
  ip link del "$BR" 2>/dev/null
  for v in nff-be-veth nff-c1-veth nff-c2-veth nff-c3-veth; do
    ip link del "$v" 2>/dev/null
  done
  echo "cleaned"
}

add_client() {
  local ns="$1" ip="$2" veth="$3"
  ip netns add "$ns"
  ip link add "$veth" type veth peer name "${veth}-p"
  ip link set "$veth" netns "$ns"
  ip link set "${veth}-p" master "$BR"
  ip link set "${veth}-p" up
  ip netns exec "$ns" ip addr add "${ip}/24" dev "$veth"
  ip netns exec "$ns" ip link set "$veth" up
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip route add default via "$HOST_IP"
}

setup() {
  cleanup
  # bridge
  ip link add "$BR" type bridge
  ip addr add "${HOST_IP}/24" dev "$BR"
  ip link set "$BR" up
  # backend namespace
  ip netns add "$BE_NS"
  ip link add nff-be-veth type veth peer name nff-be-veth-p
  ip link set nff-be-veth netns "$BE_NS"
  ip link set nff-be-veth-p master "$BR"
  ip link set nff-be-veth-p up
  ip netns exec "$BE_NS" ip addr add "${BE_IP}/24" dev nff-be-veth
  ip netns exec "$BE_NS" ip link set nff-be-veth up
  ip netns exec "$BE_NS" ip link set lo up
  ip netns exec "$BE_NS" ip route add default via "$HOST_IP"
  # backend HTTP server
  ip netns exec "$BE_NS" sh -c 'echo BACKEND_OK > /tmp/index.html; (cd /tmp && nohup python3 -m http.server 80 --bind '"${BE_IP}"' >/tmp/be.log 2>&1 &)'
  sleep 1
  # clients
  add_client nff-client1 "${SUBNET}.11" nff-c1-veth
  add_client nff-client2 "${SUBNET}.12" nff-c2-veth
  add_client nff-client3 "${SUBNET}.13" nff-c3-veth
  echo "setup done; backend=${BE_IP}"
}

test_forward() {
  echo "=== client1 → forward → backend ==="
  ip netns exec nff-client1 curl -s --connect-timeout 5 http://${HOST_IP}:28844/ || echo "CURL_FAIL"
}

case "${1:-}" in
  setup) setup ;;
  clean) cleanup ;;
  test) test_forward ;;
  *) echo "usage: $0 setup|clean|test" ;;
esac
