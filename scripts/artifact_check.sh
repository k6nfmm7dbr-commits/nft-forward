#!/usr/bin/env bash
# artifact_check.sh — 发布产物一致性与版本一致性自检
#
# 用法: bash scripts/artifact_check.sh <dist目录>
set -euo pipefail

DIST="${1:-dist}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIST" || exit 1

fail() { echo "[artifact-check] FAIL: $*" >&2; exit 1; }

ARCHS=(amd64 arm64 armv7 armv6 386 s390x riscv64)

[[ -s "SHA256SUMS" ]] || fail "SHA256SUMS 缺失或为空"

for a in "${ARCHS[@]}"; do
  name="nft-forward-linux-$a"
  [[ -s "$name" ]] || fail "缺少产物 $name"
  n=$(awk -v x="$name" '$2==x{c++} END{print c+0}' SHA256SUMS)
  [[ "$n" == "1" ]] || fail "$name 在 SHA256SUMS 中出现 ${n} 次（应为 1 次）"
  exp=$(awk -v x="$name" '$2==x{print $1}' SHA256SUMS)
  got=$(sha256sum "$name" | awk '{print $1}')
  [[ "$exp" == "$got" ]] || fail "$name 校验和不匹配 (SUMS=$exp actual=$got)"
  echo "  [OK] $name"
done

while read -r _ name; do
  case "$name" in
    nft-forward-linux-amd64|nft-forward-linux-arm64|nft-forward-linux-armv7|\
    nft-forward-linux-armv6|nft-forward-linux-386|nft-forward-linux-s390x|nft-forward-linux-riscv64) ;;
    *) fail "SHA256SUMS 含意外条目: $name" ;;
  esac
done < SHA256SUMS

GO_VER="$(grep '^const Version' "$ROOT/internal/version/version.go" | sed 's/.*"\(.*\)".*/\1/')"
APP_VER="$(grep -m1 '^APP_VERSION=' "$ROOT/install.sh" | sed -E 's/^APP_VERSION="?([^"]+)"?.*/\1/')"
BIN_VER="$(./nft-forward-linux-amd64 version | sed -E 's/^NFT Forward v//')"

[[ "$GO_VER" == "$APP_VER" ]] || fail "internal/version($GO_VER) 与 installer APP_VERSION($APP_VER) 不一致"
[[ "$GO_VER" == "$BIN_VER" ]] || fail "internal/version($GO_VER) 与二进制 version 输出($BIN_VER) 不一致"
echo "  [OK] 版本三方一致: v$GO_VER（无 Git Tag）"

echo "[artifact-check] ALL OK"
