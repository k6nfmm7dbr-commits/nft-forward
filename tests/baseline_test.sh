#!/usr/bin/env bash
# baseline_test.sh — v0.3.2 基线收口防回归。
#
# 这些是硬约束，任何一条被打破都说明出现了功能退化：
#   A. 版本一致性：install.sh APP_VERSION == Go Version == README == CHANGELOG
#   B. 转发规则「可配置的监听地址」彻底消失（Go 业务代码 / 前端输入 / API 写入 / nft 脚本）
#   C. nft 安全边界：绝不 flush ruleset / 绝不 delete table / 只管理 nff_*
#   D. DNAT 必须带 fib daddr type local（不劫持 transit 流量）
#   E. 域名目标：DB 存原始域名、双栈分表、不做 NAT64/46
#   F. 统一变更入口：API 不绕过 rulesvc 直接写 store/nft
#   G. 无 Git Tag 依赖；CI 不打 tag
#   H. 端口分配安全（crypto/rand + guard + ephemeral 避让）
#   I. 认证收口（Token / Bearer+Cookie / 常量时间 / 无 query token / 无 localStorage）
#   J. 随机暴露面（无固定 8090 / 随机入口 / 极简 404 / healthz 仅 loopback）
#   K. conntrack fail-safe 与结构 enforcement 解耦
#   L. 无 N+1 查询 / 锁内 DNS
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VER="0.3.2"
PASS=0; FAIL=0
ck() { if [[ "$3" == "$2" ]]; then PASS=$((PASS+1)); echo "  [PASS] $1"; else FAIL=$((FAIL+1)); echo "  [FAIL] $1 (期望 $2 实得 $3)"; fi; }
# nocomment <file> —— 剥掉 // 注释后的源码（避免注释里的说明文字误命中）
nocomment() { sed -e 's|//.*$||' "$1"; }
# prodsrc 列出所有非测试 Go 源文件
prodsrc() { find "$ROOT/internal" "$ROOT/cmd" -name '*.go' ! -name '*_test.go'; }
# grep_prod <pattern> —— 在非测试 Go 源码（剥注释后）里搜索，命中返回 0
grep_prod() {
  local pat="$1" f
  for f in $(prodsrc); do
    if nocomment "$f" | grep -qE "$pat"; then return 0; fi
  done
  return 1
}

echo "== baseline_test (v$VER) =="

# ---- A. 版本一致性 ----
APP_VER=$(grep -m1 '^APP_VERSION=' "$ROOT/install.sh" | sed -E 's/^APP_VERSION="?([^"]+)"?.*/\1/')
GO_VER=$(grep '^const Version' "$ROOT/internal/version/version.go" | sed 's/.*"\(.*\)".*/\1/')
README_VER=$(grep -m1 -oE 'v[0-9]+\.[0-9]+\.[0-9]+' "$ROOT/README.md" | tr -d 'v')
CHANGELOG_VER=$(grep -m1 -oE '^## v[0-9]+\.[0-9]+\.[0-9]+' "$ROOT/cmd/nft-forward/CHANGELOG.md" | sed 's/^## v//')
ck "install.sh APP_VERSION == $VER" "$VER" "$APP_VER"
ck "Go Version == $VER" "$VER" "$GO_VER"
ck "README 版本 == $VER" "$VER" "$README_VER"
ck "CHANGELOG 最新版本 == $VER" "$VER" "$CHANGELOG_VER"

# ---- B. 转发规则「可配置监听地址」彻底删除 ----
GOSRC=$(find "$ROOT/internal" "$ROOT/cmd" -name '*.go' ! -name '*_test.go')
BAD=0
for f in $GOSRC; do
  case "$f" in
    */internal/api/rules.go|*/internal/database/db.go|*/internal/forward/store.go|*/internal/config/config.go|*/internal/api/handlers.go) continue ;;
  esac
  if nocomment "$f" | grep -qE 'ListenAddress|listen_address|listenAddress'; then
    echo "      违规文件: $f"
    BAD=1
  fi
done
ck "Go 业务代码无 ListenAddress 依赖" 0 "$BAD"
grep -q 'deprecated' "$ROOT/internal/api/rules.go"; ck "API 兼容字段标注 deprecated" 0 $?
grep -q 'logDeprecated' "$ROOT/internal/api/rules.go"; ck "收到废弃字段时告警" 0 $?
if sed -n '/func (s \*Server) createRule/,/^}/p' "$ROOT/internal/api/rules.go" | grep -qE 'ListenAddress:'; then rc=1; else rc=0; fi
ck "createRule 不把 listen_address 传给 rulesvc" 0 "$rc"
if sed -n '/func (s \*Server) updateRule/,/^}/p' "$ROOT/internal/api/rules.go" | grep -qE 'in\.ListenAddress'; then rc=1; else rc=0; fi
ck "updateRule 不把 listen_address 写入更新" 0 "$rc"

FE="$ROOT/internal/webui/static"
# 前端不得有任何「监听地址」相关字段：v0.3.2 起连只读展示也一并移除
# （那是主机属性而非规则属性，多网卡时必然显示错误的 IP）。
bad=$(grep -rniE 'listen[_-]?addr|监听地址|pol-listen-ip' "$FE" || true)
if [ -n "$bad" ]; then rc=1; else rc=0; fi
ck "前端无任何监听地址字段（含只读展示）" 0 "$rc"
grep -q '监听端口' "$FE/index.html"; ck "前端保留监听端口字段" 0 $?
grep -q '留空则随机' "$FE/index.html"; ck "监听端口支持留空随机（有提示）" 0 $?
grep -q 'IP 或域名' "$FE/index.html"; ck "目标地址支持 IP 或域名（占位提示）" 0 $?
# API / SSE 视图里也不得出现 listen_addr（剥注释后检查：说明性注释允许提到它）
if nocomment "$ROOT/internal/api/handlers.go" | grep -qE 'ListenAddr|listen_addr'; then rc=1; else rc=0; fi
ck "RuleView 无 listen_addr 字段" 0 "$rc"
if grep_prod 'detectHostIP|hostIP'; then rc=1; else rc=0; fi
ck "已移除本机对外 IP 探测（规则展示不需要）" 0 "$rc"

if grep -qE 'ip daddr [0-9]' "$ROOT/internal/nft/engine.go"; then rc=1; else rc=0; fi
ck "nft DNAT 不按监听地址匹配" 0 "$rc"
grep -q '"listen"' "$ROOT/internal/config/config.go"; ck "面板 bind 配置 listen 保留" 0 $?
grep -q 'net.JoinHostPort(cfg.Listen' "$ROOT/internal/api/server.go"; ck "面板仍按 listen 绑定" 0 $?
# 老库 legacy 列：保留不读写，绝不 DROP COLUMN
grep -q 'listen_address' "$ROOT/internal/database/db.go"; ck "迁移逻辑识别老库 legacy 列" 0 $?
if nocomment "$ROOT/internal/database/db.go" \
  | grep -qE 'DROP COLUMN|DROP TABLE|DELETE FROM rules'; then rc=1; else rc=0; fi
ck "绝不 DROP COLUMN / DROP TABLE / 删规则行" 0 "$rc"
grep -q 'ADD COLUMN' "$ROOT/internal/database/db.go"; ck "迁移只用 ADD COLUMN" 0 $?

# ---- C. nft 安全边界 ----
NFTSRC=$(find "$ROOT/internal/nft" -name '*.go' ! -name '*_test.go')
for f in $NFTSRC; do
  if nocomment "$f" | grep -q 'flush ruleset'; then rc=1; else rc=0; fi
  ck "$(basename "$f") 无 flush ruleset" 0 "$rc"
done
if sed -n '/func GenStructScript/,$p' "$ROOT/internal/nft/engine.go" | grep -q 'delete table'; then rc=1; else rc=0; fi
ck "结构脚本不 delete table（保住 counter）" 0 "$rc"
grep -q 'flush chain' "$ROOT/internal/nft/engine.go"; ck "只 flush chain 重建链内规则" 0 $?
grep -q 'ownedTables' "$ROOT/internal/nft/clear.go"; ck "删表集中在 clear.go 的白名单" 0 $?
nocomment "$ROOT/internal/nft/clear.go" | grep -qE 'nff_nat4|TableNAT4'; ck "clear 白名单含 nff_nat4" 0 $?
if nocomment "$ROOT/internal/nft/clear.go" | grep -q 'flush'; then rc=1; else rc=0; fi
ck "clear 不使用 flush" 0 "$rc"
grep -q 'HasPrefix(name, TableFilter' "$ROOT/internal/nft/engine.go"; ck "遗留对象清理限定自有前缀" 0 $?
grep -q '"nft", "-c", "-f"' "$ROOT/internal/nft/apply.go"; ck "应用前 nft -c 干跑检查" 0 $?

# ---- C2. 完整 Desired State 自愈 ----
grep -q 'func DesiredObjects' "$ROOT/internal/nft/desired.go"; ck "存在 Desired State 定义" 0 $?
grep -q 'func MissingObjects' "$ROOT/internal/nft/desired.go"; ck "存在缺失对象比对" 0 $?
for obj in TableNAT4 TableNAT6 TableFilter SetQuotaBlock 'AllowSetV4' 'AllowSetV6' 'CounterUp' 'CounterDown' 'ChainForward' 'ChainPrerouting' 'ChainPostrouting' 'MarksSet'; do
  grep -q "$obj" "$ROOT/internal/nft/desired.go"; ck "Desired State 覆盖 $obj" 0 $?
done
grep -q 'nft.DetectDrift' "$ROOT/internal/policy/service.go"; ck "policy 用完整漂移检测判定自愈" 0 $?
if grep -q 'structMissing' "$ROOT/internal/policy/service.go"; then rc=1; else rc=0; fi
ck "已移除旧的三项式自愈判定" 0 "$rc"

# ---- C3. 内容校验（等数量篡改也要发现）----
grep -q 'func DetectDrift' "$ROOT/internal/nft/desired.go"; ck "存在内容漂移检测" 0 $?
grep -q 'func DesiredRuleSigs' "$ROOT/internal/nft/intent.go"; ck "存在期望规则签名" 0 $?
grep -q 'func DesiredChainAttrs' "$ROOT/internal/nft/intent.go"; ck "存在期望链属性" 0 $?
grep -q 'func parseRuleFacts' "$ROOT/internal/nft/facts.go"; ck "从 nft JSON 提取规则事实" 0 $?
grep -q 'ChainRuleSigs' "$ROOT/internal/nft/state.go"; ck "State 携带链内规则签名" 0 $?
grep -q 'ChainAttrsMap' "$ROOT/internal/nft/state.go"; ck "State 携带链属性" 0 $?
for fld in DNATAddr DNATPort Proto DPort SetMark MarkSet Direction CtState Counter SAddrFamily SAddrNotInSet Verdict FibDaddrLocal Unknown; do
  grep -q "$fld" "$ROOT/internal/nft/facts.go"; ck "规则事实覆盖 $fld" 0 $?
done
for fld in Hook Priority Policy Type; do
  grep -q "$fld" "$ROOT/internal/nft/facts.go"; ck "链属性覆盖 $fld" 0 $?
done
# counter 实时读数绝不能进签名（否则有流量就重建、counter 反复清零）
if sed -n '/func (f RuleFacts) Sig/,/^}/p' "$ROOT/internal/nft/facts.go" | grep -qiE 'bytes|packets'; then rc=1; else rc=0; fi
ck "规则签名不含 counter 实时读数" 0 "$rc"
# 渲染与期望同源：脚本行必须由 ruleIntent.render 产生
grep -q 'in.render()' "$ROOT/internal/nft/engine.go"; ck "脚本规则由意图渲染（与期望同源）" 0 $?
if sed -n '/func genFilterStruct/,/^}/p' "$ROOT/internal/nft/engine.go" | grep -q 'add rule inet'; then rc=1; else rc=0; fi
ck "filter 规则不再手写 add rule 文本" 0 "$rc"
if sed -n '/func genNATStruct/,/^}/p' "$ROOT/internal/nft/engine.go" | grep -q 'dnat to'; then rc=1; else rc=0; fi
ck "NAT DNAT 不再手写文本" 0 "$rc"

# ---- D. fib daddr type local ----
# DNAT 渲染已移到 intent.go（与自愈期望签名同源），检查点随之移动。
grep -q 'fib daddr type local' "$ROOT/internal/nft/intent.go"; ck "DNAT 带 fib daddr type local" 0 $?
DNAT_LOCAL=$(grep -c 'fib daddr type local %s dport' "$ROOT/internal/nft/intent.go" || true)
ck "DNAT 规则渲染处带 fib local" 1 "$([ "$DNAT_LOCAL" -ge 1 ] && echo 1 || echo 0)"
# 期望签名里也必须要求 fib local（否则「被删掉 fib」不会被自愈发现）
grep -q 'FibDaddrLocal = true' "$ROOT/internal/nft/intent.go"; ck "期望事实要求 fib local" 0 $?
grep -q 'FibDaddrLocal' "$ROOT/internal/nft/facts.go"; ck "实际事实解析 fib local" 0 $?

# ---- E. 域名目标语义 ----
grep -q 'func (r \*Rule) DialV4' "$ROOT/internal/forward/rule.go"; ck "规则区分 DialV4/DialV6" 0 $?
grep -q '绝不做 NAT64' "$ROOT/internal/forward/rule.go"; ck "明确禁止 NAT64/46" 0 $?
grep -q 'TargetAddress 永远保存用户填写的原始' "$ROOT/internal/forward/rule.go"
ck "DB 保存原始域名（有约束说明）" 0 $?
if sed -n '/func applyResolve/,/^}/p' "$ROOT/internal/rulesvc/service.go" | grep -q 'TargetAddress'; then rc=1; else rc=0; fi
ck "applyResolve 不覆盖 TargetAddress" 0 "$rc"
grep -q 'LookupNetIP' "$ROOT/internal/resolve/resolve.go"; ck "Resolver 抽象可注入" 0 $?
if grep -qE 'os/exec|exec\.Command' "$ROOT/internal/resolve/resolve.go"; then rc=1; else rc=0; fi
ck "解析不 exec 外部命令" 0 "$rc"
grep -q 'net.Resolver' "$ROOT/internal/resolve/resolve.go"; ck "解析走 net.Resolver" 0 $?
grep -q 'TargetDomain' "$ROOT/internal/forward/target.go"; ck "目标形态含域名" 0 $?
grep -q 'TargetIPv6' "$ROOT/internal/forward/target.go"; ck "目标形态含 IPv6" 0 $?

# ---- F. 统一变更入口 ----
for m in 'store.Create' 'store.Update(' 'store.SoftDelete' 'store.HardDelete' 'nft.Apply(' 'nft.ApplyElements'; do
  if grep -rq "$m" "$ROOT/internal/api"/*.go 2>/dev/null | grep -v '_test.go'; then rc=1; else rc=0; fi
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

# ---- H. 端口分配安全 ----
grep -q 'crypto/rand' "$ROOT/internal/forward/allocator.go"; ck "随机转发端口用 crypto/rand" 0 $?
grep -q 'GuardPorts' "$ROOT/internal/forward/allocator.go"; ck "随机端口避开保留端口" 0 $?
grep -q 'ssh_port' "$ROOT/internal/config/config.go"; ck "SSH 端口纳入保护" 0 $?
grep -q 'portprobe.EphemeralRange' "$ROOT/internal/forward/allocator.go"; ck "转发端口避开 ephemeral 区间" 0 $?
grep -q 'ip_local_port_range' "$ROOT/internal/portprobe/portprobe.go"; ck "读取内核 ephemeral 区间" 0 $?
# 生产代码不得 import math/rand（注释里提到「禁止 math/rand」是允许的）
if grep_prod '^\s*(_ )?"math/rand"|math/rand\.'; then rc=1; else rc=0; fi
ck "生产代码无 math/rand" 0 "$rc"

# ---- I. 认证收口 ----
grep -q 'crypto/subtle' "$ROOT/internal/api/auth.go"; ck "令牌比较用 crypto/subtle" 0 $?
grep -q 'ConstantTimeCompare' "$ROOT/internal/api/auth.go"; ck "常量时间比较存在" 0 $?
if nocomment "$ROOT/internal/api/auth.go" | grep -qE 'given == token|token == given'; then rc=1; else rc=0; fi
ck "不使用裸 == 比较令牌" 0 "$rc"
grep -q 'Authorization' "$ROOT/internal/api/auth.go"; ck "支持 Authorization: Bearer" 0 $?
grep -q 'r.Cookie(cookieName)' "$ROOT/internal/api/auth.go"; ck "支持 HttpOnly Cookie" 0 $?
if nocomment "$ROOT/internal/api/auth.go" | grep -qE 'URL.Query\(\).Get\("token"\)|FormValue\("token"\)'; then rc=1; else rc=0; fi
ck "鉴权不读 query token" 0 "$rc"
grep -q 'HttpOnly: true' "$ROOT/internal/api/auth.go"; ck "Cookie HttpOnly=true" 0 $?
grep -q 'SameSiteLaxMode' "$ROOT/internal/api/auth.go"; ck "Cookie SameSite=Lax" 0 $?
grep -q 'cookieMaxAge = 604800' "$ROOT/internal/api/auth.go"; ck "Cookie MaxAge=604800" 0 $?
grep -q 'cfg.SecureCookie' "$ROOT/internal/api/auth.go"; ck "Secure 由 secure_cookie 决定" 0 $?
if nocomment "$ROOT/internal/api/auth.go" | grep -q 'Secure: *true'; then rc=1; else rc=0; fi
ck "不无条件设置 Secure=true" 0 "$rc"
grep -q 'maxLoginBody = 64 << 10' "$ROOT/internal/api/login.go"; ck "登录体上限 64 KiB" 0 $?
grep -q 'StatusRequestEntityTooLarge' "$ROOT/internal/api/login.go"; ck "超限返回 413" 0 $?
grep -q 'loginFailBurst  = 5' "$ROOT/internal/api/login.go"; ck "失败阈值 5 次" 0 $?
grep -q 'loginFailWindow = 5 \* time.Minute' "$ROOT/internal/api/login.go"; ck "失败窗口 5 分钟" 0 $?
grep -q 'loginFailDelay  = 2 \* time.Second' "$ROOT/internal/api/login.go"; ck "节流延迟 2 秒" 0 $?
grep -q 'loginFailMaxLen = 4096' "$ROOT/internal/api/login.go"; ck "追踪表上限 4096" 0 $?
grep -q 'gcLoginFailsLocked' "$ROOT/internal/api/login.go"; ck "过期项自动 GC" 0 $?
grep -q 'net.SplitHostPort(r.RemoteAddr)' "$ROOT/internal/api/login.go"; ck "节流键取 RemoteAddr" 0 $?
if nocomment "$ROOT/internal/api/login.go" | grep -qE 'X-Forwarded-For|X-Real-IP'; then rc=1; else rc=0; fi
ck "节流不信任 XFF" 0 "$rc"
grep -q 'loginRecordSuccess(key)' "$ROOT/internal/api/login.go"; ck "成功登录清除失败状态" 0 $?
# 成功路径必须在 sleep 之前
if awk '/tokenEqual\(given, token\)/{ok=1} /time.After\(d\)/{if(!ok) bad=1} END{exit bad?1:0}' "$ROOT/internal/api/login.go"; then rc=0; else rc=1; fi
ck "成功登录路径不被节流延迟" 0 "$rc"
# 前端绝不把令牌放 localStorage（剥注释后检查：说明性注释允许提到它）
if grep -rE 'localStorage|sessionStorage' "$FE" | grep -vE '^\s*\*|//|绝不写入' | grep -q .; then rc=1; else rc=0; fi
ck "前端不使用 localStorage/sessionStorage" 0 "$rc"
grep -q 'type="password"' "$FE/login.html"; ck "登录页令牌输入为 password 类型" 0 $?
if grep -qE 'admin|用户名|username' "$FE/login.html"; then rc=1; else rc=0; fi
ck "登录页无用户名/默认账号" 0 "$rc"
grep -q 'action="logout"' "$FE/index.html"; ck "面板提供退出登录入口" 0 $?
grep -q 'action="login"' "$FE/login.html"; ck "登录表单指向相对路径 login" 0 $?
grep -q "location.pathname.replace" "$FE/app.js"; ck "前端按入口路径拼接请求（不写死根路径）" 0 $?
if grep -qE "fetch\('/api|EventSource\('/api|new URL\('/api" "$FE/app.js"; then rc=1; else rc=0; fi
ck "前端不使用绝对 /api 路径" 0 "$rc"
grep -q "credentials: 'same-origin'" "$FE/app.js"; ck "前端请求带同源凭据" 0 $?
grep -q "r.status === 401" "$FE/app.js"; ck "前端 401 时回登录页" 0 $?
# 未认证即可取得的资源（style.css / login.html / login.js）不得含产品指纹
for f in style.css login.html login.js; do
  if grep -inE 'nft.?forward|nftables|nff_' "$FE/$f" >/dev/null 2>&1; then rc=1; else rc=0; fi
  ck "未认证可取资源 $f 无产品指纹" 0 "$rc"
done
grep -q 'config-ensure-token' "$ROOT/cmd/nft-forward/main.go"; ck "CLI 提供 config-ensure-token" 0 $?
grep -q 'func EnsureToken' "$ROOT/internal/config/config.go"; ck "config 实现 EnsureToken" 0 $?
grep -q 'tokenBytes = 16' "$ROOT/internal/config/config.go"; ck "令牌 16 bytes → 32 hex" 0 $?
grep -q 'crypto/rand' "$ROOT/internal/config/config.go"; ck "令牌用 crypto/rand" 0 $?
grep -q '0o600' "$ROOT/internal/config/config.go"; ck "配置写回 0600" 0 $?
# token 不得再被当成废弃键
if grep -q 'legacyKeys = \[\]string{"rule_listen_address", "default_listen_address"}' "$ROOT/internal/config/config.go"; then rc=0; else rc=1; fi
ck "legacyKeys 不含 token" 0 "$rc"
# 安装器不得吞掉 ensure 错误
if grep -qE 'config-ensure-(token|all|port|entry)[^|]*\|\| *true' "$ROOT/install.sh"; then rc=1; else rc=0; fi
ck "安装器不吞掉 config-ensure 错误" 0 "$rc"
grep -q 'config-ensure-all' "$ROOT/install.sh"; ck "安装器调用 config-ensure-all" 0 $?

# ---- J. 随机暴露面 ----
# 8090 只允许出现在：
#   · 注释与测试（说明历史包袱 / 反例断言）
#   · config.LegacyDefaultPort 常量（用于把老安装的固定端口一次性迁移掉）
# 除此之外任何生产代码、安装器、README 里都不得出现。
PROD_8090=0
for f in $(prodsrc); do
  if nocomment "$f" | grep -E '(^|[^0-9])8090([^0-9]|$)' | grep -qv 'LegacyDefaultPort'; then
    echo "      违规文件: $f"
    PROD_8090=1
  fi
done
if [[ "$PROD_8090" == 1 ]] \
   || sed 's/#.*$//' "$ROOT/install.sh" | grep -qE '(^|[^0-9])8090([^0-9]|$)' \
   || grep -qE '(^|[^0-9])8090([^0-9]|$)' "$ROOT/README.md" 2>/dev/null; then rc=1; else rc=0; fi
ck "生产代码/安装器/README 不再使用 8090（仅保留迁移常量）" 0 "$rc"
grep -q 'LegacyDefaultPort' "$ROOT/internal/config/config.go"; ck "定义遗留默认端口迁移常量" 0 $?
grep -q 'cfg.MigratePort()' "$ROOT/internal/provision/provision.go"; ck "升级时迁移遗留默认端口" 0 $?
grep -q 'PanelPortMin = 10000' "$ROOT/internal/config/config.go"; ck "面板端口下界 10000" 0 $?
grep -q 'PanelPortMax = 65535' "$ROOT/internal/config/config.go"; ck "面板端口上界 65535" 0 $?
grep -q 'func EnsurePanelPort' "$ROOT/internal/provision/provision.go"; ck "存在随机面板端口生成" 0 $?
grep -q 'crypto/rand' "$ROOT/internal/provision/provision.go"; ck "面板端口用 crypto/rand" 0 $?
if nocomment "$ROOT/internal/provision/provision.go" | grep -qE '8090|34567'; then rc=1; else rc=0; fi
ck "端口生成无固定 fallback" 0 "$rc"
grep -q 'func EnsureEntryPath' "$ROOT/internal/config/config.go"; ck "存在随机入口路径生成" 0 $?
grep -q 'entryPathBytes = 12' "$ROOT/internal/config/config.go"; ck "入口随机 12 bytes（96 bit）" 0 $?
for p in '/nff/' '/admin/' '/panel/' '/dashboard/'; do
  if grep -rq "\"$p\"" "$ROOT/internal"/*/*.go 2>/dev/null; then rc=1; else rc=0; fi
  ck "入口不使用固定前缀 $p" 0 "$rc"
done
grep -q 'func notFound' "$ROOT/internal/api/auth.go"; ck "存在极简 404 处理" 0 $?
if sed -n '/^func notFound/,/^}/p' "$ROOT/internal/api/auth.go" | grep -qiE 'nff|nft.?forward|version|Location'; then rc=1; else rc=0; fi
ck "404 不含品牌/版本/跳转" 0 "$rc"
grep -q 'isLoopback(r)' "$ROOT/internal/api/server.go"; ck "healthz 限定 loopback" 0 $?
if nocomment "$ROOT/internal/api/auth.go" | grep -qE 'X-Forwarded-For|X-Real-IP'; then rc=1; else rc=0; fi
ck "loopback 判定不信任 XFF" 0 "$rc"
if grep_prod 'w\.Header\(\)\.Set\("Server"|X-Powered-By'; then rc=1; else rc=0; fi
ck "不设置 Server / X-Powered-By 头" 0 "$rc"
grep -q "default-src 'self'" "$ROOT/internal/api/auth.go"; ck "CSP 为 default-src 'self'" 0 $?
if grep -qE "unsafe-eval|unsafe-inline" "$ROOT/internal/api/auth.go"; then rc=1; else rc=0; fi
ck "CSP 无 unsafe-*" 0 "$rc"
for h in 'Cache-Control' 'X-Content-Type-Options' 'Referrer-Policy' 'X-Frame-Options'; do
  grep -q "\"$h\"" "$ROOT/internal/api/auth.go"; ck "安全响应头含 $h" 0 $?
done
# 绝不宣传「防 GFW / 保证不被封」（否定式说明如「无法保证防 GFW」是允许的）
GFW_FILES="$ROOT/README.md $ROOT/install.sh $(prodsrc | tr '\n' ' ')"
# shellcheck disable=SC2086
if grep -rnE '绝对防|防 ?GFW|保证不(会)?被?封' $GFW_FILES 2>/dev/null \
     | grep -vE '不是也无法保证|无法保证|不存在这种保证'; then rc=1; else rc=0; fi
ck "文案不宣传「绝对防 GFW / 保证不被封」" 0 "$rc"
grep -q '降低公网批量扫描' "$ROOT/README.md"; ck "README 用「降低扫描暴露面」表述" 0 $?

# ---- K. conntrack fail-safe 与结构 enforcement 解耦 ----
grep -q 'func (r Result) Usable' "$ROOT/internal/connection/conntrack.go"; ck "conntrack 提供 Usable 判据" 0 $?
grep -q 'func (r Result) Complete' "$ROOT/internal/connection/conntrack.go"; ck "conntrack 区分 Complete" 0 $?
grep -q 'ctUsable := cr.Usable()' "$ROOT/internal/policy/service.go"; ck "policy 用 Usable 决策" 0 $?
# conntrack 异常时绝不提前 return（结构同步必须继续）
if awk '/cr := s.conntrack/{s=1} s&&/return nil/{if(!/applyNFT/) {bad=1; exit}} /applyNFT/{exit} END{exit bad?1:0}' "$ROOT/internal/policy/service.go"; then rc=0; else rc=1; fi
ck "conntrack 异常不提前 return（结构同步继续）" 0 "$rc"
grep -q 'ipState.AllowSet()' "$ROOT/internal/policy/service.go"; ck "冻结时重放上一轮 allow set" 0 $?
grep -q 'IPStateFrozen' "$ROOT/internal/policy/service.go"; ck "健康快照暴露冻结状态" 0 $?

# ---- L. 性能与并发 ----
grep -q 'func BuildIndex' "$ROOT/internal/connection/conntrack.go"; ck "存在 conntrack flow 索引" 0 $?
grep -q 'connection.BuildIndex' "$ROOT/internal/policy/service.go"; ck "policy 使用 flow 索引（O(R+F)）" 0 $?
grep -q 'seenFlowKeys' "$ROOT/internal/policy/service.go"; ck "flow GC 使用本轮 seen 集合" 0 $?
grep -q 'func (s \*Service) gcFlows' "$ROOT/internal/policy/service.go"; ck "存在 flow GC" 0 $?
grep -q 'func (s \*Server) totalsBatch' "$ROOT/internal/api/handlers.go"; ck "totals 批量查询（消除 N+1）" 0 $?
grep -q 'func (s \*Server) dailyBatch' "$ROOT/internal/api/handlers.go"; ck "daily 批量查询（消除 N+1）" 0 $?
if grep -qE 'func \(s \*Server\) (totals|dailyFor)\(ctx' "$ROOT/internal/api/handlers.go"; then rc=1; else rc=0; fi
ck "已移除 per-rule QueryRow" 0 "$rc"
grep -q 'placeholders(' "$ROOT/internal/api/handlers.go"; ck "批量查询用参数占位符（无拼接注入）" 0 $?
grep -q 'dnsConcurrency' "$ROOT/internal/rulesvc/service.go"; ck "DNS 刷新有并发上限" 0 $?
grep -q 's.mu.Unlock()' "$ROOT/internal/rulesvc/service.go"; ck "RefreshDNS 分段释放锁" 0 $?
grep -q '丢弃过期 DNS 解析结果' "$ROOT/internal/rulesvc/service.go"; ck "过期 DNS 结果被丢弃" 0 $?
grep -q 'func (c \*Collector) LiveSnapshot' "$ROOT/internal/traffic/collector.go"; ck "collector 暴露实时快照" 0 $?
grep -q 'live.Used(' "$ROOT/internal/policy/service.go"; ck "配额使用实时用量" 0 $?
grep -q 'func (s \*Service) allLifetimeBytes' "$ROOT/internal/policy/service.go"; ck "配额兜底路径批量读库" 0 $?
# 配额重置必须与配额判定同口径（否则重置后未落库部分会重新计入）
grep -q 'func (s \*Service) realtimeTotal' "$ROOT/internal/policy/service.go"
ck "配额重置取实时总量（与判定同口径）" 0 $?
grep -q 'quotaTotals' "$ROOT/internal/policy/service.go"; ck "记录实时累计总量供重置使用" 0 $?
# counter 低于基线时不得把当前值再加一遍（双算）
if sed -n '/func (d LiveDelta) Used/,/^}/p' "$ROOT/internal/traffic/collector.go" \
  | grep -qE 'used \+= c$'; then rc=1; else rc=0; fi
ck "实时用量不因读数错位而双算" 0 "$rc"
# 稳定期配额判定绝不 per-rule 查库
if sed -n '/func (s \*Service) quotaUsed/,/^}/p' "$ROOT/internal/policy/service.go" | grep -q 'QueryRow'; then rc=1; else rc=0; fi
ck "配额判定无 per-rule QueryRow" 0 "$rc"
# policy 不得自己再执行一次 nft list counters
if grep -q '"list", "counters"' "$ROOT/internal/policy/service.go"; then rc=1; else rc=0; fi
ck "policy 不重复执行 nft list counters" 0 "$rc"
# 每轮只读一次 nft 状态（applyNFT 复用 sync 已读的 curSt）
grep -q 'func (s \*Service) applyNFT(ctx context.Context, gi \*nft.GenInput, quotaBlocked \[\]int64, cur \*nft.State)' "$ROOT/internal/policy/service.go"
ck "applyNFT 复用已读的 nft 状态" 0 $?

# ---- M. 安装/升级不假成功 ----
if grep -qE 'start_service *\|\| *true' "$ROOT/install.sh"; then rc=1; else rc=0; fi
ck "安装器不 start_service || true" 0 "$rc"
grep -q 'health_check' "$ROOT/install.sh"; ck "安装器做本机 HTTP 健康检查" 0 $?
grep -q 'config_ready' "$ROOT/install.sh"; ck "安装器校验配置加载正常" 0 $?
grep -q 'core_rollback' "$ROOT/install.sh"; ck "升级失败可回滚" 0 $?
grep -q 'core_backup_commit' "$ROOT/install.sh"; ck "备份仅在全部验证通过后删除" 0 $?
if grep -qE 'core_rollback[^|]*\|\| *true' "$ROOT/install.sh"; then rc=1; else rc=0; fi
ck "回滚不被 || true 吞掉" 0 "$rc"
# 备份删除必须在健康检查之后
if awk '/^start_service\(\)/{seen_start=1} /rm -f "\$CORE_BIN.bak"/{if(!seen_start) bad=1} END{exit bad?1:0}' "$ROOT/install.sh"; then rc=0; else rc=1; fi
ck "旧二进制备份不在替换后立即删除" 0 "$rc"

# ---- N. 菜单极简 ----
MENU=$(sed -n '/func menu()/,/^}/p' "$ROOT/cmd/nft-forward/ops.go")
if printf '%s' "$MENU" | grep -qE '配置文件|数据库位于|sysctl|安装目录|程序目录|Web Root|/etc/'; then rc=1; else rc=0; fi
ck "nff 菜单不显示配置/数据库/sysctl 路径" 0 "$rc"
printf '%s' "$MENU" | grep -q '查看面板信息'; ck "菜单项为「查看面板信息」" 0 $?
grep -q 'func panelInfo' "$ROOT/cmd/nft-forward/ops.go"; ck "存在 panel-info 输出" 0 $?
PINFO=$(sed -n '/^func panelInfo/,/^}/p' "$ROOT/cmd/nft-forward/ops.go")
printf '%s' "$PINFO" | grep -q '面板地址'; ck "面板信息含面板地址" 0 $?
printf '%s' "$PINFO" | grep -q '访问令牌'; ck "面板信息含访问令牌" 0 $?
if printf '%s' "$PINFO" | grep -qE 'panel.json|/etc/'; then rc=1; else rc=0; fi
ck "面板信息不暴露令牌存储路径" 0 "$rc"
SELFTEST=$(sed -n '/^func selfTest/,/^}/p' "$ROOT/cmd/nft-forward/ops.go")
for item in SQLite nftables 'nft netlink' 'owned tables' ip_forward conntrack ct_acct 'web server' authentication; do
  printf '%s' "$SELFTEST" | grep -q "\"$item\""; ck "自检含 $item" 0 $?
done
if printf '%s' "$SELFTEST" | grep -qE 'cfg\.SysctlConf|panel\.json|"/etc/'; then rc=1; else rc=0; fi
ck "自检正常输出不打印文件路径" 0 "$rc"
# cfg.DB 只允许出现在 database.Open 调用里（打开库必须用路径），不得作为展示文本
if printf '%s' "$SELFTEST" | grep 'cfg.DB' | grep -qv 'database.Open'; then rc=1; else rc=0; fi
ck "自检不把数据库路径作为展示文本" 0 "$rc"
if grep -q '"\$CORE_BIN" panel-info' "$ROOT/install.sh"; then rc=0; else rc=1; fi
ck "安装器复用 panel-info 输出" 0 "$rc"
if grep -q '令牌在 /etc' "$ROOT/install.sh"; then rc=1; else rc=0; fi
ck "安装输出不提示令牌文件位置" 0 "$rc"

echo
echo "  PASS=$PASS FAIL=$FAIL"
[[ "$FAIL" == 0 ]] || exit 1
