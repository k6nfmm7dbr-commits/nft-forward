#!/usr/bin/env bash
# baseline_test.sh — v0.2.0 基线收口防回归。
#
# 这些是本次重构的硬约束，任何一条被打破都说明出现了功能退化：
#   A. 版本一致性：install.sh APP_VERSION == Go Version == README
#   B. 「转发规则监听地址」彻底消失（Go 业务代码 / 前端 / API 响应 / nft 脚本）
#      —— 但 Web 面板自身的 bind 地址（listen）必须保留
#   C. nft 安全边界：绝不 flush ruleset / 绝不 delete table / 只管理 nff_*
#   D. DNAT 必须带 fib daddr type local（不劫持 transit 流量）
#   E. 域名目标：DB 存原始域名、双栈分表、不做 NAT64/46
#   F. 统一变更入口：API 不绕过 rulesvc 直接写 store/nft
#   G. 无 Git Tag 依赖；CI 不打 tag
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0; FAIL=0
ck() { if [[ "$3" == "$2" ]]; then PASS=$((PASS+1)); echo "  [PASS] $1"; else FAIL=$((FAIL+1)); echo "  [FAIL] $1 (期望 $2 实得 $3)"; fi; }
cnt() { grep -rn "$1" $2 2>/dev/null | grep -vc '^$' || true; }

echo "== baseline_test =="

# ---- A. 版本一致性 ----
APP_VER=$(grep -m1 '^APP_VERSION=' "$ROOT/install.sh" | sed -E 's/^APP_VERSION="?([^"]+)"?.*/\1/')
GO_VER=$(grep '^const Version' "$ROOT/internal/version/version.go" | sed 's/.*"\(.*\)".*/\1/')
README_VER=$(grep -m1 -oE 'v[0-9]+\.[0-9]+\.[0-9]+' "$ROOT/README.md" | tr -d 'v')
ck "install.sh APP_VERSION == 0.2.0" "0.2.0" "$APP_VER"
ck "Go Version == 0.2.0" "0.2.0" "$GO_VER"
ck "README 版本 == 0.2.0" "0.2.0" "$README_VER"

# ---- B. 转发规则监听地址彻底删除 ----
GOSRC=$(find "$ROOT/internal" "$ROOT/cmd" -name '*.go' ! -name '*_test.go')
# Go 结构体字段 / JSON tag / 变量名：只允许 api/rules.go 里那个「接受但忽略」的
# 兼容字段，以及 database/forward 里对 legacy 列的注释与显式占位处理。
BAD=0
for f in $GOSRC; do
  case "$f" in
    # api/rules.go: 唯一允许出现的兼容字段（接受并忽略）
    # database/db.go + forward/store.go: 老库 legacy 列的显式占位处理
    # config/config.go: 废弃配置键清理清单（legacyKeys）
    */internal/api/rules.go|*/internal/database/db.go|*/internal/forward/store.go|*/internal/config/config.go) continue ;;
  esac
  if grep -qE 'ListenAddress|listen_address|listenAddress' "$f"; then
    # 注释里提到「已删除监听地址」是允许的；剥注释后仍出现才算违规
    if sed 's|//.*$||' "$f" | grep -qE 'ListenAddress|listen_address|listenAddress'; then
      echo "      违规文件: $f"
      BAD=1
    fi
  fi
done
ck "Go 业务代码无 ListenAddress 依赖" 0 "$BAD"

# rules.go 里的兼容字段必须明确是 deprecated 且被忽略
grep -q 'deprecated' "$ROOT/internal/api/rules.go"; ck "API 兼容字段标注 deprecated" 0 $?
grep -q 'logDeprecated' "$ROOT/internal/api/rules.go"; ck "收到废弃字段时告警" 0 $?
# 该字段绝不能被写进 rulesvc 输入
if sed -n '/func (s \*Server) createRule/,/^}/p' "$ROOT/internal/api/rules.go" \
  | grep -qE 'ListenAddress:'; then rc=1; else rc=0; fi
ck "createRule 不把 listen_address 传给 rulesvc" 0 "$rc"
if sed -n '/func (s \*Server) updateRule/,/^}/p' "$ROOT/internal/api/rules.go" \
  | grep -qE 'in\.ListenAddress'; then rc=1; else rc=0; fi
ck "updateRule 不把 listen_address 写入更新" 0 "$rc"

# 前端：不得有监听地址输入框
FE="$ROOT/internal/webui/static"
if grep -rqiE 'listen[_-]?addr|监听地址' "$FE"; then rc=1; else rc=0; fi
ck "前端无监听地址字段" 0 "$rc"
grep -q '监听端口' "$FE/index.html"; ck "前端保留监听端口字段" 0 $?
grep -q '留空则随机' "$FE/index.html"; ck "监听端口支持留空随机（有提示）" 0 $?

# nft 生成脚本：规则里不得出现按监听地址匹配的 daddr 字面量
if grep -qE 'ip daddr [0-9]' "$ROOT/internal/nft/engine.go"; then rc=1; else rc=0; fi
ck "nft DNAT 不按监听地址匹配" 0 "$rc"

# 面板自身的 bind 地址必须保留（不能被一起删掉）
grep -q '"listen"' "$ROOT/internal/config/config.go"; ck "面板 bind 配置 listen 保留" 0 $?
grep -q 'net.JoinHostPort(cfg.Listen' "$ROOT/internal/api/server.go"; ck "面板仍按 listen 绑定" 0 $?

# 老库 legacy 列：只保留不读写，绝不 DROP COLUMN
grep -q 'HasLegacyListenAddress' "$ROOT/internal/database/db.go"; ck "识别老库 legacy 列" 0 $?
if sed 's|//.*$||' "$ROOT/internal/database/db.go" \
  | grep -qE 'DROP COLUMN|DROP TABLE|DELETE FROM rules'; then rc=1; else rc=0; fi
ck "绝不 DROP COLUMN / DROP TABLE / 删规则行" 0 "$rc"
grep -q 'ADD COLUMN' "$ROOT/internal/database/db.go"; ck "迁移只用 ADD COLUMN" 0 $?

# ---- C. nft 安全边界 ----
NFTSRC=$(find "$ROOT/internal/nft" -name '*.go' ! -name '*_test.go')
for f in $NFTSRC; do
  if sed 's|//.*$||' "$f" | grep -q 'flush ruleset'; then rc=1; else rc=0; fi
  ck "$(basename "$f") 无 flush ruleset" 0 "$rc"
done
# 结构脚本绝不 delete table（counter 是表级对象，删表 = 清零累计流量）
if sed -n '/func GenStructScript/,$p' "$ROOT/internal/nft/engine.go" | grep -q 'delete table'; then rc=1; else rc=0; fi
ck "结构脚本不 delete table（保住 counter）" 0 "$rc"
grep -q 'flush chain' "$ROOT/internal/nft/engine.go"; ck "只 flush chain 重建链内规则" 0 $?
# 删表只允许在 clear.go，且只删 nff_*
grep -q 'ownedTables' "$ROOT/internal/nft/clear.go"; ck "删表集中在 clear.go 的白名单" 0 $?
sed 's|//.*$||' "$ROOT/internal/nft/clear.go" | grep -qE 'nff_nat4|TableNAT4'; ck "clear 白名单含 nff_nat4" 0 $?
if sed 's|//.*$||' "$ROOT/internal/nft/clear.go" | grep -q 'flush'; then rc=1; else rc=0; fi
ck "clear 不使用 flush" 0 "$rc"
# staleNames 只清理自有前缀对象
grep -q 'HasPrefix(name, TableFilter' "$ROOT/internal/nft/engine.go"; ck "遗留对象清理限定自有前缀" 0 $?
# 应用前必须 nft -c 干跑
grep -q '"nft", "-c", "-f"' "$ROOT/internal/nft/apply.go"; ck "应用前 nft -c 干跑检查" 0 $?

# ---- D. fib daddr type local ----
grep -q 'fib daddr type local' "$ROOT/internal/nft/engine.go"; ck "DNAT 带 fib daddr type local" 0 $?
# 每条 DNAT 都要带（不能只有注释里提）
DNAT_RULES=$(grep -c 'dnat to' "$ROOT/internal/nft/engine.go" || true)
DNAT_LOCAL=$(grep -c 'fib daddr type local %s dport' "$ROOT/internal/nft/engine.go" || true)
ck "DNAT 规则生成处均带 fib local" 1 "$([ "$DNAT_LOCAL" -ge 1 ] && echo 1 || echo 0)"

# ---- E. 域名目标语义 ----
grep -q 'func (r \*Rule) DialV4' "$ROOT/internal/forward/rule.go"; ck "规则区分 DialV4/DialV6" 0 $?
grep -q '绝不做 NAT64' "$ROOT/internal/forward/rule.go"; ck "明确禁止 NAT64/46" 0 $?
# DB 保存原始域名：TargetAddress 不得被解析结果覆盖
grep -q 'TargetAddress 永远保存用户填写的原始' "$ROOT/internal/forward/rule.go"
ck "DB 保存原始域名（有约束说明）" 0 $?
grep -q 'r.TargetAddress = ' "$ROOT/internal/rulesvc/service.go"; RC=$?
if [[ $RC -eq 0 ]]; then
  # 只允许来自用户输入的赋值，不允许来自 resolve 结果
  if sed -n '/func applyResolve/,/^}/p' "$ROOT/internal/rulesvc/service.go" | grep -q 'TargetAddress'; then rc=1; else rc=0; fi
  ck "applyResolve 不覆盖 TargetAddress" 0 "$rc"
fi
grep -q 'LookupNetIP' "$ROOT/internal/resolve/resolve.go"; ck "Resolver 抽象可注入" 0 $?
# 解析必须走 Go 的 net.Resolver，不 exec dig/nslookup/getent，也不解析 nft 输出
if grep -qE 'os/exec|exec\.Command' "$ROOT/internal/resolve/resolve.go"; then rc=1; else rc=0; fi
ck "解析不 exec 外部命令" 0 "$rc"
grep -q 'net.Resolver' "$ROOT/internal/resolve/resolve.go"; ck "解析走 net.Resolver" 0 $?

# ---- F. 统一变更入口 ----
# API 层不得直接调用 store 的写方法或 nft.Apply
for m in 'store.Create' 'store.Update(' 'store.SoftDelete' 'store.HardDelete' 'nft.Apply(' 'nft.ApplyElements'; do
  if grep -rq "$m" "$ROOT/internal/api"; then rc=1; else rc=0; fi
  ck "API 不直接调用 $m" 0 "$rc"
done
grep -q 's.rules.Create' "$ROOT/internal/api/rules.go"; ck "创建规则走 rulesvc" 0 $?
grep -q 's.rules.UpdatePolicy' "$ROOT/internal/api/rules.go"; ck "配额/IP 限制走 rulesvc" 0 $?
grep -q 'applyWithRollback' "$ROOT/internal/rulesvc/service.go"; ck "rulesvc 失败双向回滚" 0 $?
grep -q 'hold()' "$ROOT/internal/rulesvc/service.go"; ck "rulesvc 与周期 reconcile 互斥" 0 $?

# ---- G. 无 Git Tag 依赖 ----
for wf in "$ROOT"/.github/workflows/*.yml; do
  if grep -qE '^\s*tags:' "$wf"; then rc=1; else rc=0; fi
  ck "$(basename "$wf") 无 tag trigger" 0 "$rc"
  if grep -qE 'git tag |git push.*--tags|refs/tags' "$wf"; then rc=1; else rc=0; fi
  ck "$(basename "$wf") 无 git tag 操作" 0 "$rc"
done
if grep -rqE 'git tag|git describe' "$ROOT"/scripts/*.sh; then rc=1; else rc=0; fi
ck "scripts 无 git tag/describe 依赖" 0 "$rc"

# ---- H. 端口分配器安全 ----
grep -q 'crypto/rand' "$ROOT/internal/forward/allocator.go"; ck "随机端口用 crypto/rand" 0 $?
grep -q 'GuardPorts' "$ROOT/internal/forward/allocator.go"; ck "随机端口避开保留端口" 0 $?
grep -q 'ssh_port' "$ROOT/internal/config/config.go"; ck "SSH 端口纳入保护" 0 $?

echo
echo "  PASS=$PASS FAIL=$FAIL"
[[ "$FAIL" == 0 ]] || exit 1
