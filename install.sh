#!/usr/bin/env bash
# NFT Forward 安装脚本。
# 用法: bash <(curl -fsSL https://raw.githubusercontent.com/k6nfmm7dbr-commits/nft-forward/main/install.sh)
set -euo pipefail

REPO="k6nfmm7dbr-commits/nft-forward"
INSTALL_DIR="/usr/local/bin"
CONF_DIR="/etc/nft-forward"
BIN="nft-forward"

echo "=== NFT Forward 安装 ==="

# 检测架构
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) echo "不支持的架构: $ARCH"; exit 1 ;;
esac

# 检测 nftables
if ! command -v nft >/dev/null 2>&1; then
  echo "未检测到 nftables，请先安装: apt install nftables / yum install nftables"
  exit 1
fi

# 下载二进制（优先 release，失败则提示手动）
URL="https://github.com/${REPO}/releases/latest/download/${BIN}-linux-${GOARCH}"
echo "下载: $URL"
if curl -fsSL -o "/tmp/${BIN}" "$URL"; then
  install -m 0755 "/tmp/${BIN}" "${INSTALL_DIR}/${BIN}"
  rm -f "/tmp/${BIN}"
else
  echo "下载失败。请手动下载 ${BIN}-linux-${GOARCH} 并放到 ${INSTALL_DIR}/${BIN}"
  exit 1
fi

# 配置目录 + 令牌
mkdir -p "$CONF_DIR"
if [ ! -f "${CONF_DIR}/panel.json" ]; then
  "${INSTALL_DIR}/${BIN}" config-ensure-token >/dev/null 2>&1 || true
fi

# systemd 服务
if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/nft-forward.service <<EOF
[Unit]
Description=NFT Forward
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BIN} serve
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable nft-forward >/dev/null 2>&1 || true
  systemctl restart nft-forward
  echo "服务已启动: systemctl status nft-forward"
else
  echo "未检测到 systemd，请手动运行: ${INSTALL_DIR}/${BIN} serve"
fi

echo "=== 安装完成 ==="
echo "面板: http://$(hostname -I 2>/dev/null | awk '{print $1}'):8090"
echo "令牌在 ${CONF_DIR}/panel.json"
