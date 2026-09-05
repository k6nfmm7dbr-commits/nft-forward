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
# ★ 备份不得在替换成功后立即删除：升级要到健康检查全过才允许删（可回滚的前提）
if grep -q 'rm -f "\$CORE_BIN.bak"' "$TMPD/ic.sh"; then rc=1; else rc=0; fi
ck "install_core 不提前删除旧二进制备份" 0 "$rc"
grep -q 'CORE_BACKUP=' "$TMPD/ic.sh"; ck "install_core 导出备份路径供回滚使用" 0 $?

# ---- 3b. start_service：三重健康确认，绝不假成功 ----
sed -n '/^# >>> start-service/,/^# <<< start-service/p' "$TPL" > "$TMPD/ss.sh"
grep -q 'panel_running' "$TMPD/ss.sh"; ck "start_service 检查服务 active" 0 $?
grep -q 'health_check' "$TMPD/ss.sh"; ck "start_service 做本机 HTTP 健康检查" 0 $?
grep -q '127.0.0.1' "$TMPD/ss.sh"; ck "健康检查走 127.0.0.1（healthz 仅 loopback）" 0 $?
grep -q 'config_ready' "$TMPD/ss.sh"; ck "提供配置就绪校验" 0 $?
grep -q 'entry_path' "$TMPD/ss.sh"; ck "配置校验含随机入口路径" 0 $?
grep -q 'token' "$TMPD/ss.sh"; ck "配置校验含访问令牌" 0 $?
CODE_SS="$TMPD/ss_code.sh"
sed -e 's/#.*$//' "$TMPD/ss.sh" > "$CODE_SS"
# `curl ... || true` 是有意为之：健康检查要在循环里重试，单次失败不能让
# `set -e` 直接终止脚本。真正禁止的是「服务启动/回滚等关键动作被 || true 吞掉」。
if grep -vE 'curl ' "$CODE_SS" | grep -qE '\|\| *true'; then rc=1; else rc=0; fi
ck "start_service 关键动作无 || true 吞错" 0 "$rc"

# ---- 3c. do_install：失败不打印「安装完成」 ----
sed -n '/^# >>> do-install/,/^# <<< do-install/p' "$TPL" > "$TMPD/di.sh"
grep -q 'ensure_panel_conf || die' "$TMPD/di.sh"; ck "do_install 配置初始化失败即中止" 0 $?
grep -q 'if ! start_service; then' "$TMPD/di.sh"; ck "do_install 检查服务启动结果" 0 $?
grep -q '安装未完成' "$TMPD/di.sh"; ck "do_install 失败时明确报错" 0 $?
if grep -qE 'start_service *\|\| *true' "$TMPD/di.sh"; then rc=1; else rc=0; fi
ck "do_install 无 start_service || true" 0 "$rc"
# 「安装完成」必须出现在 start_service 检查之后
if awk '/if ! start_service; then/{seen=1} /ok "安装完成"/{if(!seen) bad=1} END{exit bad?1:0}' "$TMPD/di.sh"; then rc=0; else rc=1; fi
ck "「安装完成」只在健康确认通过后打印" 0 "$rc"

# ---- 3d. change_panel_port：手工改端口必须走安全校验 + 事务回滚 ----
sed -n '/^# >>> change-port/,/^# <<< change-port/p' "$TPL" > "$TMPD/cp.sh"
grep -q 'change_panel_port()' "$TMPD/cp.sh"; ck "提取到 change_panel_port" 0 $?
grep -q 'panel-port-set' "$TMPD/cp.sh"; ck "改端口走后端安全校验（panel-port-set）" 0 $?
if grep -qE 'panel_set port' "$TMPD/cp.sh"; then rc=1; else rc=0; fi
ck "改端口不直接写配置（必须先校验）" 0 "$rc"
grep -q 'old_port=' "$TMPD/cp.sh"; ck "改端口记录旧端口（供回滚）" 0 $?
grep -q 'start_service' "$TMPD/cp.sh"; ck "改端口后做三重健康确认" 0 $?
grep -q 'port_listening' "$TMPD/cp.sh"; ck "改端口后确认新端口真的在监听" 0 $?
grep -q 'config-set port "\$oldp"' "$TMPD/cp.sh"; ck "失败时写回旧端口" 0 $?
grep -q '已回滚到原端口' "$TMPD/cp.sh"; ck "确认恢复成功才提示已回滚" 0 $?
grep -q '服务未能恢复' "$TMPD/cp.sh"; ck "旧端口也恢复失败时明确报错" 0 $?
if grep -qE 'restart[^|]*\|\| *true' "$TMPD/cp.sh"; then rc=1; else rc=0; fi
ck "改端口不 || true 吞错" 0 "$rc"

# ---- 3e. health_check：必须识别数据面未就绪（503）----
grep -q '"ok":true' "$TMPD/ss.sh"; ck "健康检查要求 ok:true" 0 $?
grep -q 'data plane not ready' "$TMPD/ss.sh"; ck "健康检查识别数据面未就绪(503)" 0 $?
grep -q 'healthz' "$TMPD/ss.sh"; ck "健康检查走 /healthz" 0 $?

# ---- 4. do_update：脚本相同也检查二进制 ----
sed -n '/^# >>> do-update/,/^# <<< do-update/p' "$TPL" > "$TMPD/du.sh"
grep -q '检查后端二进制是否同步' "$TMPD/du.sh"; ck "do_update 脚本相同时仍检查二进制" 0 $?
grep -q 'CORE_REPLACED' "$TMPD/du.sh"; ck "do_update 依据 CORE_REPLACED 决定是否重启" 0 $?
# 二进制被替换时必须走配置迁移（新版本可能需要新配置字段）
grep -q 'ensure_panel_conf' "$TMPD/du.sh"; ck "do_update 二进制更新后做配置迁移" 0 $?
grep -q 'PANEL_CONF.bak' "$TMPD/du.sh"; ck "do_update 快速路径也备份 panel.json" 0 $?
grep -q 'core_rollback' "$TMPD/du.sh"; ck "do_update 快速路径失败可回滚" 0 $?
grep -q 'bash -n "\$tmp"' "$TMPD/du.sh"; ck "do_update 下载后做语法校验" 0 $?
grep -q 'SELF_PATH.bak' "$TMPD/du.sh"; ck "do_update 升级前备份本体" 0 $?
grep -q '回滚失败' "$TMPD/du.sh"; ck "do_update 回滚失败不被吞掉" 0 $?
# 回滚后必须重新确认服务健康，而不是无条件宣称「已恢复」
grep -q 'panel_running && health_check' "$TMPD/du.sh"; ck "do_update 回滚后验证服务健康" 0 $?
if grep -qE 'apply-update[^|]*\|\| *true' "$TMPD/du.sh"; then rc=1; else rc=0; fi
ck "do_update 回滚不 || true 吞错" 0 "$rc"

# ---- 5. apply_update：保留用户数据 + nft 硬依赖 + 真正可回滚 ----
sed -n '/^# >>> apply-update/,/^# <<< apply-update/p' "$TPL" > "$TMPD/au.sh"
grep -q 'nft list tables' "$TMPD/au.sh"; ck "apply_update 探测 nft 真实可用性" 0 $?
grep -q 'ensure_panel_conf' "$TMPD/au.sh"; ck "apply_update 迁移/补齐配置" 0 $?
if grep -qE 'rm -[rf]+ .*(traffic\.db|panel\.json)' "$TMPD/au.sh"; then rc=1; else rc=0; fi
ck "apply_update 绝不删除 traffic.db / panel.json" 0 "$rc"
grep -q 'PANEL_CONF.bak' "$TMPD/au.sh"; ck "apply_update 备份 panel.json" 0 $?
grep -q 'core_rollback' "$TMPD/au.sh"; ck "apply_update 失败调用回滚" 0 $?
grep -q 'core_backup_commit' "$TMPD/au.sh"; ck "apply_update 成功后才提交（删备份）" 0 $?
grep -q 'selftest' "$TMPD/au.sh"; ck "apply_update 升级后跑 selftest" 0 $?
# 备份提交必须在健康检查与 selftest 之后
if awk '/selftest/{seen=1} /core_backup_commit/{if(!seen) bad=1} END{exit bad?1:0}' "$TMPD/au.sh"; then rc=0; else rc=1; fi
ck "备份仅在 selftest 通过后删除" 0 "$rc"
# 回滚实现：恢复二进制 + 恢复配置 + 重启并验证
grep -q 'mv -f "\$CORE_BACKUP" "\$CORE_BIN"' "$TMPD/au.sh"; ck "回滚恢复旧二进制" 0 $?
grep -q 'cp -p "\$CONF_BACKUP" "\$PANEL_CONF"' "$TMPD/au.sh"; ck "回滚恢复旧配置（端口/令牌/入口）" 0 $?
grep -q 'if start_service; then' "$TMPD/au.sh"; ck "回滚后重启并验证旧服务" 0 $?
grep -q '已回滚到升级前版本' "$TMPD/au.sh"; ck "确认恢复成功才提示已回滚" 0 $?
grep -q '回滚未完成' "$TMPD/au.sh"; ck "回滚失败明确报错" 0 $?
if grep -qE 'core_rollback[^|]*\|\| *true' "$TMPD/au.sh"; then rc=1; else rc=0; fi
ck "回滚不被 || true 吞掉" 0 "$rc"

# ---- 5b. ensure_panel_conf：三项安全字段 fail-closed ----
grep -q 'config-ensure-all' "$TPL"; ck "安装器调用 config-ensure-all" 0 $?
if grep -qE 'config-ensure-(all|token|port|entry)[^|]*\|\| *true' "$TPL"; then rc=1; else rc=0; fi
ck "config-ensure 错误不被吞掉" 0 "$rc"
sed -n '/^ensure_panel_conf()/,/^}/p' "$TPL" > "$TMPD/epc.sh"
grep -q '配置已损坏' "$TMPD/epc.sh"; ck "配置损坏时明确报错" 0 $?
grep -q '原文件未被改动' "$TMPD/epc.sh"; ck "配置损坏时不覆盖原文件" 0 $?
grep -q 'chmod 600' "$TMPD/epc.sh"; ck "panel.json 收紧到 0600" 0 $?
grep -q 'config_ready' "$TMPD/epc.sh"; ck "初始化后校验三项齐备" 0 $?

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
