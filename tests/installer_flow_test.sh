#!/usr/bin/env bash
# installer_flow_test.sh — 从 install.sh 提取真实实现做流程测试：
#   1. checksum 校验 fail-closed（不匹配/缺失/重复条目一律拒绝）
#   2. prepare_dirs 敏感文件 0600（首次创建 + 已存在收紧，umask 000 下也成立）
#   3. install_core 按内容(sha256)判断是否跳过，绝不按版本号跳过
#   4. do_update 在脚本内容相同时仍检查后端二进制
#   5. 安全边界静态检查：绝不 flush ruleset / 不动系统链 / 只删 nff_* 表
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TPL="$ROOT/install.sh"
PASS=0; FAIL=0
ck() { if [[ "$3" == "$2" ]]; then PASS=$((PASS+1)); echo "  [PASS] $1"; else FAIL=$((FAIL+1)); echo "  [FAIL] $1 (期望 $2 实得 $3)"; fi; }

TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT

echo "== installer_flow_test =="

# ---- 0. 语法 ----
bash -n "$TPL" 2>/dev/null; ck "install.sh 语法正确" 0 $?

# ---- 1. checksum fail-closed（提取真实 helpers 区块）----
sed -n '/^# >>> checksum-helpers/,/^# <<< checksum-helpers/p' "$TPL" > "$TMPD/helpers.sh"
grep -q 'verify_core_checksum()' "$TMPD/helpers.sh"; ck "提取到 checksum helpers" 0 $?
cat >> "$TMPD/helpers.sh" <<'STUBS'
warn() { echo "[warn] $*" >&2; }
STUBS

printf 'fake-binary' > "$TMPD/dl"
GOOD=$(sha256sum "$TMPD/dl" | awk '{print $1}')
BIN=nft-forward-linux-amd64

printf '%s  %s\n' "0000000000000000000000000000000000000000000000000000000000000000" "$BIN" > "$TMPD/SHA256SUMS"
( set +u; source "$TMPD/helpers.sh"; verify_core_checksum "$TMPD/dl" "$TMPD/SHA256SUMS" "$BIN" ) >/dev/null 2>&1
ck "checksum mismatch → 拒绝" 1 "$([ $? != 0 ] && echo 1 || echo 0)"

printf '%s  %s\n' "$GOOD" "$BIN" > "$TMPD/SHA256SUMS"
( set +u; source "$TMPD/helpers.sh"; verify_core_checksum "$TMPD/dl" "$TMPD/SHA256SUMS" "$BIN" ) >/dev/null 2>&1
ck "checksum 匹配 → 通过" 0 $?

printf '%s  nft-forward-linux-arm64\n' "$GOOD" > "$TMPD/SHA256SUMS"
( set +u; source "$TMPD/helpers.sh"; verify_core_checksum "$TMPD/dl" "$TMPD/SHA256SUMS" "$BIN" ) >/dev/null 2>&1
ck "缺失本架构条目 → 拒绝" 1 "$([ $? != 0 ] && echo 1 || echo 0)"

printf '%s  %s\n%s  %s\n' "$GOOD" "$BIN" "$GOOD" "$BIN" > "$TMPD/SHA256SUMS"
( set +u; source "$TMPD/helpers.sh"; verify_core_checksum "$TMPD/dl" "$TMPD/SHA256SUMS" "$BIN" ) >/dev/null 2>&1
ck "重复条目 → 拒绝" 1 "$([ $? != 0 ] && echo 1 || echo 0)"

printf '%s  %s\n' "$GOOD" "$BIN" > "$TMPD/SHA256SUMS"
: > "$TMPD/empty"
( set +u; source "$TMPD/helpers.sh"; verify_core_checksum "$TMPD/empty" "$TMPD/SHA256SUMS" "$BIN" ) >/dev/null 2>&1
ck "空二进制 → 拒绝" 1 "$([ $? != 0 ] && echo 1 || echo 0)"

# ---- 2. prepare_dirs 权限（提取真实实现）----
sed -n '/^# >>> prepare-dirs/,/^# <<< prepare-dirs/p' "$TPL" > "$TMPD/pd.sh"
grep -q 'install -m 0600' "$TMPD/pd.sh"; ck "prepare_dirs 用 install -m 0600 预创建" 0 $?
cat >> "$TMPD/pd.sh" <<'STUBS'
APP_DIR="$T/etc/nft-forward"
PANEL_CONF="$APP_DIR/panel.json"
DB_FILE="$APP_DIR/traffic.db"
NFT_CONF="$APP_DIR/nft.conf"
STUBS

T="$TMPD/case1"; export T
( set +u; umask 000; source "$TMPD/pd.sh"; prepare_dirs ) >/dev/null 2>&1
ck "首次创建(umask 000) panel.json == 600" "600" "$(stat -c %a "$T/etc/nft-forward/panel.json" 2>/dev/null)"

T="$TMPD/case2"; export T
mkdir -p "$T/etc/nft-forward"
printf '{"token":"secret"}' > "$T/etc/nft-forward/panel.json"; chmod 644 "$T/etc/nft-forward/panel.json"
printf 'db' > "$T/etc/nft-forward/traffic.db"; chmod 644 "$T/etc/nft-forward/traffic.db"
( set +u; source "$TMPD/pd.sh"; prepare_dirs ) >/dev/null 2>&1
ck "已存在 0644 panel.json → 收紧 600" "600" "$(stat -c %a "$T/etc/nft-forward/panel.json")"
ck "已存在 0644 traffic.db → 收紧 600" "600" "$(stat -c %a "$T/etc/nft-forward/traffic.db")"

# 已有配置绝不能被覆盖（token 丢失 = 用户登录不进面板）
grep -q 'token' "$T/etc/nft-forward/panel.json"; ck "prepare_dirs 不覆盖已有 panel.json" 0 $?

# ---- 3. install_core：按内容判断，不按版本号跳过 ----
sed -n '/^# >>> install-core/,/^# <<< install-core/p' "$TPL" > "$TMPD/ic.sh"
grep -q 'sha256_of "\$CORE_BIN"' "$TMPD/ic.sh"; ck "install_core 按二进制 sha256 判断是否跳过" 0 $?
grep -q 'expect_sum' "$TMPD/ic.sh"; ck "install_core 提取 SHA256SUMS 期望哈希" 0 $?
grep -q 'CORE_REPLACED=1' "$TMPD/ic.sh"; ck "install_core 替换后置 CORE_REPLACED 信号" 0 $?
if grep -q 'core_version_of "\$CORE_BIN"' "$TMPD/ic.sh"; then rc=1; else rc=0; fi
ck "install_core 不按已装版本号跳过下载" 0 "$rc"
grep -q 'cand_ver.*APP_VERSION\|"\$cand_ver" != "\$APP_VERSION"' "$TMPD/ic.sh"
ck "install_core 校验 candidate 版本与 APP_VERSION 一致" 0 $?
grep -q '现有安装未被改动' "$TMPD/ic.sh"; ck "install_core 失败路径明示未改动现有安装" 0 $?
grep -q 'CORE_BIN.bak' "$TMPD/ic.sh"; ck "install_core 替换前备份旧二进制" 0 $?
grep -q 'mv -f "\$dl" "\$CORE_BIN"' "$TMPD/ic.sh"; ck "install_core 原子 rename 替换" 0 $?

# ---- 4. do_update：脚本相同也检查二进制 ----
sed -n '/^# >>> do-update/,/^# <<< do-update/p' "$TPL" > "$TMPD/du.sh"
grep -q '检查后端二进制是否同步' "$TMPD/du.sh"; ck "do_update 脚本相同时仍检查二进制" 0 $?
grep -q 'CORE_REPLACED' "$TMPD/du.sh"; ck "do_update 依据 CORE_REPLACED 决定是否重启" 0 $?
grep -q 'bash -n "\$tmp"' "$TMPD/du.sh"; ck "do_update 下载后做语法校验" 0 $?
grep -q 'SELF_PATH.bak' "$TMPD/du.sh"; ck "do_update 升级前备份本体" 0 $?
grep -q '回滚失败' "$TMPD/du.sh"; ck "do_update 回滚失败不被吞掉" 0 $?

# ---- 5. apply_update：保留用户数据 + nft 硬依赖 ----
sed -n '/^# >>> apply-update/,/^# <<< apply-update/p' "$TPL" > "$TMPD/au.sh"
grep -q 'nft list tables' "$TMPD/au.sh"; ck "apply_update 探测 nft 真实可用性" 0 $?
grep -q 'config-migrate' "$TMPD/au.sh"; ck "apply_update 清理废弃配置键" 0 $?
if grep -qE 'rm -[rf]+ .*(traffic\.db|panel\.json)' "$TMPD/au.sh"; then rc=1; else rc=0; fi
ck "apply_update 绝不删除 traffic.db / panel.json" 0 "$rc"

# ---- 6. 安全边界（剥注释与字符串字面量后检查）----
# 为什么要剥字符串：提示文案里会出现 "可手工执行: nft delete table ..." 这类
# 帮助信息，它不是被执行的命令。只剥注释会误判。
CODE="$TMPD/code.sh"
sed -e 's/#.*$//' -e 's/"[^"]*"//g' -e "s/'[^']*'//g" "$TPL" > "$CODE"
if grep -q 'flush ruleset' "$CODE"; then rc=1; else rc=0; fi
ck "安装器无 nft flush ruleset" 0 "$rc"
if grep -qE 'iptables -F|iptables -X|nft flush table (ip|ip6|inet) filter' "$CODE"; then rc=1; else rc=0; fi
ck "安装器不清空系统防火墙" 0 "$rc"
if grep -qE 'policy drop' "$CODE"; then rc=1; else rc=0; fi
ck "安装器不修改默认 policy" 0 "$rc"
# 删表只能通过 nft-forward clear（Go 侧只删 nff_*）
DELS=$(grep -cE 'nft delete table' "$CODE" || true)
ck "安装器不直接 nft delete table（统一走 nft-forward clear）" 0 "$DELS"
if grep -qE '(^|[^-])/etc/sysctl\.conf' "$CODE"; then rc=1; else rc=0; fi
ck "不修改 /etc/sysctl.conf" 0 "$rc"
# 这条查的是「写到哪个文件」，路径本身在字符串里，因此用只剥注释的版本
sed 's/#.*$//' "$TPL" | grep -q '99-nft-forward-conntrack.conf'
ck "conntrack sysctl 写独立文件" 0 $?
sed 's/#.*$//' "$TPL" | grep -q '90-nft-forward.conf'
ck "ip_forward sysctl 写独立文件" 0 $?

# ---- 7. 版本一致性 ----
APP_VER=$(grep -m1 '^APP_VERSION=' "$TPL" | sed -E 's/^APP_VERSION="?([^"]+)"?.*/\1/')
GO_VER=$(grep '^const Version' "$ROOT/internal/version/version.go" | sed 's/.*"\(.*\)".*/\1/')
ck "APP_VERSION == Go Version" "$GO_VER" "$APP_VER"

echo
echo "  PASS=$PASS FAIL=$FAIL"
[[ "$FAIL" == 0 ]] || exit 1
