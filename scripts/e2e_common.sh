#!/usr/bin/env bash
# e2e_common.sh — E2E 脚本共享的「面板地址 + 认证」解析。
#
# 面板不再有固定端口，也不再挂在站点根下：端口是首次安装随机生成的五位数，
# 入口是随机路径，认证走 Bearer 令牌。三者都从 panel.json 读（经 nft-forward
# config-get，避免脚本自己解析 JSON）。
#
# 用法（在脚本开头）：
#   . "$(dirname "$0")/e2e_common.sh"
#   nff_api_init            # 导出 API / NFF_TOKEN / AUTH_HDR
#   curl -s -H "$AUTH_HDR" "$API/api/summary"
set -u

APP_DIR=${APP_DIR:-/etc/nft-forward}
CORE_BIN=${CORE_BIN:-/usr/local/bin/nft-forward}

nff_cfg() {  # nff_cfg <key>
  if [ -x "$CORE_BIN" ]; then
    NFT_FORWARD_CONF="$APP_DIR/panel.json" "$CORE_BIN" config-get "$1" 2>/dev/null
  fi
}

# nff_api_init 导出：
#   API        面板 API 基址（http://127.0.0.1:<port>/<entry>）
#   NFF_TOKEN  访问令牌
#   AUTH_HDR   可直接传给 curl -H 的认证头
nff_api_init() {
  NFF_PORT=$(nff_cfg port)
  NFF_ENTRY=$(nff_cfg entry_path)
  NFF_TOKEN=$(nff_cfg token)
  if [ -z "$NFF_PORT" ] || [ -z "$NFF_ENTRY" ] || [ -z "$NFF_TOKEN" ]; then
    echo "无法从 $APP_DIR/panel.json 读取面板端口/入口/令牌（面板是否已安装并初始化？）" >&2
    return 1
  fi
  API="http://127.0.0.1:${NFF_PORT}/${NFF_ENTRY}"
  AUTH_HDR="Authorization: Bearer ${NFF_TOKEN}"
  export API AUTH_HDR NFF_TOKEN NFF_PORT NFF_ENTRY
}

# nff_curl 带认证的 curl（其余参数原样透传）。
nff_curl() { curl -s -H "$AUTH_HDR" "$@"; }
