#!/usr/bin/env bash
# build-release.sh — 交叉编译全部架构的 nft-forward 并生成 SHA256SUMS
# 用法: ./scripts/build-release.sh [输出目录，默认 dist]
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

OUT="${1:-dist}"
VERSION="$(grep '^const Version' internal/version/version.go | sed 's/.*"\(.*\)".*/\1/')"
[[ -n "$VERSION" ]] || VERSION="dev"
LDFLAGS="-s -w -X github.com/k6nfmm7dbr-commits/nft-forward/internal/version.Version=${VERSION}"

rm -rf "$OUT"; mkdir -p "$OUT"

build_one() { # build_one <name> <goarch> [goarm]
  local name="$1" goarch="$2" goarm="${3:-}"
  echo "==> building linux/$goarch${goarm:+ (GOARM=$goarm)} -> nft-forward-linux-$name"
  if [[ -n "$goarm" ]]; then
    env GOOS=linux GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=0 \
      go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/nft-forward-linux-$name" ./cmd/nft-forward
  else
    env GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 \
      go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/nft-forward-linux-$name" ./cmd/nft-forward
  fi
}

build_one amd64 amd64
build_one arm64 arm64
build_one armv7 arm 7
build_one armv6 arm 6
build_one 386 386
build_one s390x s390x
build_one riscv64 riscv64

cd "$OUT" || exit 1
sha256sum nft-forward-linux-* > SHA256SUMS

# 安装器自校验清单：发布版 install.sh 的 SHA256。
#
# 为什么需要它：`nff --update` 会下载新的 install.sh 并**执行**它。此前对新脚本
# 只有 `bash -n`（语法）与 APP_VERSION 存在性两项检查 —— 一个被篡改/损坏的脚本
# 只要语法正确就能在 root 下执行。这里把「发布版安装器」与它的哈希一并发布，
# 让升级路径能在执行前做密码学校验（与二进制同等对待）。
#
# 同时把 install.sh 本身也放进 dist：升级路径从**同一个 immutable revision**
# 取脚本 + 校验和 + 二进制，三者必然同源（对齐 SBX 的 dist 布局）。
cp -f ../install.sh ./install.sh
chmod 0644 ./install.sh
sha256sum install.sh > install.sh.sha256
cat install.sh.sha256

echo "---- 产物 ----"
ls -la
echo "---- SHA256SUMS ----"
cat SHA256SUMS
