#!/usr/bin/env bash
# =============================================================================
#  NFT Forward — nftables 端口转发 + 流量监控面板
#  安装:  按仓库 README 下载并校验安装脚本
#  管理命令:  nff
#
#  安全承诺（不可妥协）：
#   · 只创建/删除 nff_nat4 / nff_nat6 / nff_filter 三张自有表
#   · 绝不执行 nft flush ruleset，绝不清空 INPUT/OUTPUT/FORWARD，绝不改默认 policy
#   · 绝不触碰 Docker / firewalld / 用户自有防火墙规则
#   · 升级保留 traffic.db / panel.json（规则、流量历史全部不动）
# =============================================================================
set -Eeuo pipefail

APP_NAME="NFT Forward"
APP_VERSION="0.4.0"
REPO="k6nfmm7dbr-commits/nft-forward"
OFFICIAL_RAW="https://raw.githubusercontent.com/$REPO"
RAW_BASE="${NFF_RAW_BASE:-}" # optional binary mirror, never a trust source
GH_PROXY="${NFF_GH_PROXY:-}"
ROOT="${NFF_ROOT:-}"
APP_DIR="$ROOT/etc/nft-forward"
BIN_DIR="$ROOT/usr/local/bin"
CORE_BIN="$BIN_DIR/nft-forward"
PANEL_CONF="$APP_DIR/panel.json"
DB_FILE="$APP_DIR/traffic.db"
NFT_CONF="$APP_DIR/nft.conf"
SELF_PATH="$APP_DIR/nft-forward.sh"
CMD_PATH="$BIN_DIR/nff"
SYSCTL_FILE="$ROOT/etc/sysctl.d/90-nft-forward.conf"
CONNTRACK_FILE="$ROOT/etc/sysctl.d/99-nft-forward-conntrack.conf"
INIT_SYS=none
PKG=''
SERVICE_FILE=''
SERVICE_MODE=''

init_colors() {
  if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
    C_RESET=$'\033[0m'; C_B=$'\033[1m'
    C_CYAN=$'\033[38;5;44m'; C_BLUE=$'\033[38;5;39m'; C_GREEN=$'\033[38;5;42m'
    C_YEL=$'\033[38;5;214m'; C_RED=$'\033[38;5;196m'; C_DIM=$'\033[38;5;245m'
  else
    C_RESET="" C_B="" C_CYAN="" C_BLUE="" C_GREEN="" C_YEL="" C_RED="" C_DIM=""
  fi
}
info() { printf '%s[*]%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YEL" "$C_RESET" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }
hr()   { printf '%s%s%s\n' "$C_DIM" "────────────────────────────────────────────────" "$C_RESET"; }
pause() { [[ -t 0 ]] || return 0; printf '%s回车继续...%s' "$C_DIM" "$C_RESET"; read -r _ || true; }

banner() {
  [[ -t 1 ]] && clear 2>/dev/null || true
  printf '%s%s' "$C_CYAN" "$C_B"
  cat <<'EOF'
   _  _ ___ ___
  | \| | __| __|   nftables 端口转发 + 流量面板
  | .` | _|| _|
  |_|\_|_| |_|
EOF
  printf '%s  v%s%s\n\n' "$C_DIM" "$APP_VERSION" "$C_RESET"
}

require_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "需要 root 权限，请用 sudo 运行"; }

detect_platform() {
  if [[ -n "$ROOT" ]]; then
    [[ "$ROOT" == /* && "$ROOT" != / && "$ROOT" == "$(realpath -- "$ROOT")" && -d "$ROOT" ]] \
      || die "NFF_ROOT 必须是现有的、非 / 的规范绝对目录"
  fi
  if [[ -n "$ROOT" || -n "${NFF_NO_SERVICE:-}" ]]; then INIT_SYS=none; return 0; fi
  if command -v apk >/dev/null 2>&1; then PKG=apk
  elif command -v apt-get >/dev/null 2>&1; then PKG=apt
  elif command -v dnf >/dev/null 2>&1; then PKG=dnf
  elif command -v yum >/dev/null 2>&1; then PKG=yum
  else die "不支持的系统（需要 Debian/Ubuntu、RHEL 系或 Alpine）"; fi
  if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
    INIT_SYS=systemd
    SERVICE_FILE="$ROOT/etc/systemd/system/nft-forward.service"
    SERVICE_MODE=0644
  elif command -v rc-update >/dev/null 2>&1 && command -v rc-service >/dev/null 2>&1; then
    INIT_SYS=openrc
    SERVICE_FILE="$ROOT/etc/init.d/nft-forward"
    SERVICE_MODE=0755
  else die "未找到可用的 systemd 或 OpenRC"; fi
}

pkg_install() {
  case "$PKG" in
    apk) bounded 180 apk add --no-cache "$@" ;;
    apt) DEBIAN_FRONTEND=noninteractive bounded 180 apt-get install -y "$@" ;;
    dnf) bounded 180 dnf install -y "$@" ;;
    yum) bounded 180 yum install -y "$@" ;;
    *) return 1 ;;
  esac
}

arch_name() {
  case "$(uname -m)" in
    x86_64|amd64)   echo amd64 ;;
    aarch64|arm64)  echo arm64 ;;
    armv7l|armv7)   echo armv7 ;;
    armv6l|armv6)   echo armv6 ;;
    i386|i686)      echo 386 ;;
    s390x)          echo s390x ;;
    riscv64)        echo riscv64 ;;
    *) die "不支持的架构: $(uname -m)" ;;
  esac
}

# >>> checksum-helpers
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum < "$1" | awk '{print $1}'
  else openssl dgst -sha256 -r < "$1" | awk '{print $1}'; fi
}

# Count even malformed lines naming the target. Support the normal sha256sum
# text/binary markers; reject extra fields or multiple entries for this name.
manifest_hash() {
  awk -v name="$2" '
    $2==name || $2=="*" name {
      n++
      if (NF==2 && length($1)==64 && $1 !~ /[^0-9a-f]/) hash=$1
    }
    END { if (n!=1 || hash=="") exit 1; print hash }
  ' "$1"
}

verify_core_checksum() {
  local want got
  [[ -s "$1" && -s "$2" ]] || return 1
  want=$(manifest_hash "$2" "$3") || return 1
  got=$(sha256_of "$1") || return 1
  [[ "$want" == "$got" ]]
}

verify_script_checksum() {
  # A script checksum file represents exactly one script. Accept a bare hash
  # (legacy) or sha256sum output, never a mixture / extra records.
  local name="${3:-install.sh}" want got
  [[ -s "$1" && -s "$2" ]] || return 1
  want=$(awk -v name="$name" '
    NF {
      n++
      if ((NF==1 || (NF==2 && ($2==name || $2=="*" name))) &&
          length($1)==64 && $1 !~ /[^0-9a-f]/) hash=$1
    }
    END { if (n!=1 || hash=="") exit 1; print hash }
  ' "$2") || return 1
  got=$(sha256_of "$1") || return 1
  [[ "$want" == "$got" ]]
}
# <<< checksum-helpers

bounded() { timeout -k 2 "$@"; }
core_version_of() { bounded 10 "$1" version | sed -nE '1s/^NFT Forward v?([0-9]+\.[0-9]+\.[0-9]+)$/\1/p'; }
remote_version() {
  awk -F '"' '/^APP_VERSION="[0-9]+\.[0-9]+\.[0-9]+"$/ {n++; v=$2}
               END {if(n!=1) exit 1; print v}' "$1"
}

# Disable curlrc, require HTTPS for the trust chain, and don't follow redirects
# for official metadata. Mirrors can serve only bytes verified against it.
official_get() { curl -q -fsS --proto '=https' --connect-timeout 8 -m "$1" -o "$2" "$3"; }

resolve_dist_sha() {
  local ref="$1" sha
  official_get 15 "$ref" "https://api.github.com/repos/$REPO/git/ref/heads/dist" || return 1
  # The canonical Git Ref response contains one object.sha. Ignore bare hex
  # strings elsewhere; if the response is incomplete or ambiguous, fail.
  grep -Eq '"ref"[[:space:]]*:[[:space:]]*"refs/heads/dist"' "$ref" || return 1
  grep -Eq '"type"[[:space:]]*:[[:space:]]*"commit"' "$ref" || return 1
  sha=$(sed -nE 's/.*"sha"[[:space:]]*:[[:space:]]*"([0-9a-f]{40})".*/\1/p' "$ref") || return 1
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || return 1
  printf '%s\n' "$sha"
}

binary_url() { # <revision> <filename>
  local base="$OFFICIAL_RAW/$1" mirror="${RAW_BASE%/}"
  if [[ -n "$mirror" ]]; then base="${mirror%/dist}/$1"; fi
  if [[ -n "$GH_PROXY" ]]; then base="${GH_PROXY%/}/$base"; fi
  printf '%s/%s\n' "$base" "$2"
}

# No installed files, packages or host state are changed during this phase.
stage_release() { # <private directory> <path of current installer>
  local stage="$1" invoking="$2" base name expect url version
  if [[ -n "${NFF_CORE_BIN:-}" ]]; then
    [[ -n "$ROOT" && -f "$invoking" && -x "$NFF_CORE_BIN" ]] \
      || die "NFF_CORE_BIN 需要 NFF_ROOT、可执行的本地二进制和普通安装器文件"
    DIST_SHA=local
    install -m 0700 -- "$NFF_CORE_BIN" "$stage/core" || die "本地二进制暂存失败"
    cp -- "$invoking" "$stage/install.sh" || die "本地安装器暂存失败"
  else
    command -v curl >/dev/null 2>&1 || die "验证发行版需要 curl，请先安装"
    DIST_SHA="${NFF_DIST_SHA:-}"
    if [[ -n "$DIST_SHA" ]]; then
      [[ "$DIST_SHA" =~ ^[0-9a-f]{40}$ ]] || die "NFF_DIST_SHA 必须是 40 位小写 Git SHA"
    else
      DIST_SHA=$(resolve_dist_sha "$stage/ref") || die "无法解析官方 dist 提交；现有安装未被改动"
    fi
    base="$OFFICIAL_RAW/$DIST_SHA"
    info "验证官方分发提交 $DIST_SHA"
    local tmp="$stage/install.sh" sums="$stage/install.sh.sha256"
    official_get 60 "$tmp" "$base/install.sh" || die "无法获取固定提交的 install.sh"
    official_get 30 "$sums" "$base/install.sh.sha256" || die "无法获取固定提交的脚本校验和"
    verify_script_checksum "$tmp" "$sums" install.sh || die "安装器 SHA256 校验失败；现有安装未被改动"
    official_get 30 "$stage/SHA256SUMS" "$base/SHA256SUMS" || die "无法获取固定提交的二进制清单"
    name="nft-forward-linux-$(arch_name)"
    expect=$(manifest_hash "$stage/SHA256SUMS" "$name") || die "二进制清单缺少唯一有效条目: $name"
    if [[ -f "$CORE_BIN" && ! -L "$CORE_BIN" && -x "$CORE_BIN" && "$(sha256_of "$CORE_BIN")" == "$expect" ]]; then
      cp -- "$CORE_BIN" "$stage/core" || die "无法暂存已有二进制"
    else
      url=$(binary_url "$DIST_SHA" "$name")
      curl -q -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 8 -m 300 -o "$stage/core" "$url" \
        || die "无法下载固定提交的二进制: $name"
    fi
    verify_core_checksum "$stage/core" "$stage/SHA256SUMS" "$name" || die "二进制 SHA256 校验失败；现有安装未被改动"
  fi
  bash -n "$stage/install.sh" && RELEASE_VERSION=$(remote_version "$stage/install.sh") \
    || die "候选安装器语法或版本标记无效；现有安装未被改动"
  chmod 0700 "$stage/core" || die "无法准备候选二进制执行权限"
  version=$(core_version_of "$stage/core") || die "候选二进制无法执行（架构或 libc 不匹配）"
  [[ "$version" == "$RELEASE_VERSION" ]] || die "候选二进制与安装器版本不匹配（期望 $RELEASE_VERSION，实得 ${version:-未知}）"
}

install_deps() {
  [[ "$INIT_SYS" != none ]] || return 0
  if ! command -v nft >/dev/null 2>&1; then
    warn "安装 nftables 依赖（包管理器变化不属于安装器回滚）"
    if [[ "$PKG" == apt ]]; then bounded 120 apt-get update -qq || warn "apt 索引更新失败"; fi
    pkg_install nftables || die "安装 nftables 失败"
  fi
  bounded 10 nft list tables >/dev/null || die "nftables 不可用（权限或内核不支持）；未替换已安装文件"
}

run_core() { # <timeout seconds> <core path> <config path> <args...>
  local seconds="$1" core="$2" config="$3"
  shift 3
  NFT_FORWARD_DIR="$APP_DIR" NFT_FORWARD_CONF="$config" bounded "$seconds" "$core" "$@"
}
installed_core() { run_core 35 "$CORE_BIN" "$PANEL_CONF" "$@"; }
panel_get() { installed_core config-get "$1" 2>/dev/null; }
panel_set() { installed_core config-set "$1" "$2" >/dev/null; }

config_value() { run_core 10 "$1" "$2" config-get "$3"; }
valid_panel_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535)); }
config_ready() {
  local core="${1:-$CORE_BIN}" conf="${2:-$PANEL_CONF}" port token entry
  port=$(config_value "$core" "$conf" port) && token=$(config_value "$core" "$conf" token) \
    && entry=$(config_value "$core" "$conf" entry_path) || return 1
  valid_panel_port "$port" && [[ ${#token} -eq 32 && ${#entry} -ge 16 ]]
}

ensure_panel_conf() { # Migrate a private copy, never the active panel.json.
  local core="$1" conf="$2"
  if ! run_core 35 "$core" "$conf" config-ensure-all >/dev/null; then
    err "无法初始化面板或配置已损坏（$PANEL_CONF）；原文件未被改动"
    return 1
  fi
  run_core 20 "$core" "$conf" config-migrate >/dev/null && chmod 600 "$conf" && config_ready "$core" "$conf"
}

# ssh_port 探测当前 SSH 端口并写入配置，供后端做转发端口冲突保护
# （避免用户把转发监听端口设成 22 把自己关在门外）。
detect_ssh_port() {
  local p=""
  p=$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2; exit}' "$ROOT/etc/ssh/sshd_config" 2>/dev/null || true)
  [[ -z "$p" && -z "$ROOT" && "$INIT_SYS" != none ]] && p=$(ss -Hlnt 2>/dev/null | awk '{print $4}' | sed -nE 's/.*:([0-9]+)$/\1/p' | sort -u | grep -x 22 || true)
  [[ -z "$p" ]] && p=22
  echo "$p"
}

stage_service() {
  case "$INIT_SYS" in
    systemd) cat > "$1" <<EOF
[Unit]
Description=NFT Forward panel (nftables port forwarding + traffic stats)
After=network-online.target nss-lookup.target
Wants=network-online.target
# 面板是运维入口：宁可一直重试，也不要被 systemd 的默认启动次数限制
# （10 秒内 5 次）判死 —— 那会让面板「突然打不开」且必须人工 start 才能恢复。
# RestartSec=3 已提供退避，这里把限制彻底关掉。
StartLimitIntervalSec=0

[Service]
Type=simple
UMask=0077
TimeoutStopSec=30
Environment=NFT_FORWARD_DIR=$APP_DIR
Environment=NFT_FORWARD_CONF=$PANEL_CONF
ExecStart=$CORE_BIN serve
Restart=always
RestartSec=3
# 停止时不清理 nft 表：转发必须在面板重启期间继续工作，
# 且 counter 是表级对象，删表会连同累计流量一起销毁。
# 最小权限沙箱：进程需要 CAP_NET_ADMIN 执行 nft（下发规则、读 counter），
# 需要读 /proc（conntrack 判活），需要读写 $APP_DIR（SQLite + nft 脚本）。
# 不需要 CAP_NET_RAW —— nft 走 AF_NETLINK，不用 SOCK_RAW。
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
ReadWritePaths=$APP_DIR
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
      ;;
    openrc) cat > "$1" <<EOF
#!/sbin/openrc-run
name="nft-forward"
description="NFT Forward panel"
command="$CORE_BIN"
command_args="serve"
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"
umask 077
export NFT_FORWARD_DIR="$APP_DIR"
export NFT_FORWARD_CONF="$PANEL_CONF"
output_log="/var/log/nft-forward.log"
error_log="/var/log/nft-forward.log"
depend() { need net; }
EOF
      ;;
    *) return 1 ;;
  esac
}

# Service manager inventory is separate from readiness: an unavailable manager
# is not evidence that the old service was stopped.
service_inventory() {
  SERVICE_PRESENT=0 SERVICE_ACTIVE=0 SERVICE_BOOT=disabled
  local state rc=0 load='' active='' key value
  case "$INIT_SYS" in
    none) return 0 ;;
    systemd)
      state=$(bounded 8 systemctl show -p LoadState -p ActiveState -p UnitFileState nft-forward.service) || rc=$?
      while IFS='=' read -r key value; do
        case "$key" in
          LoadState) load="$value" ;;
          ActiveState) active="$value" ;;
          UnitFileState) SERVICE_BOOT="${value:-disabled}" ;;
        esac
      done <<< "$state"
      case "$load:$rc" in
        loaded:0) SERVICE_PRESENT=1 ;;
        not-found:0|not-found:1|not-found:4) ;;
        *) err "无法获取 systemd 服务状态: ${load:-未知} ($rc)"; return 1 ;;
      esac
      case "$active" in
        active) SERVICE_ACTIVE=1 ;;
        inactive|failed) ;;
        *) err "服务状态不稳定: ${active:-未知}，请稍后重试"; return 1 ;;
      esac
      ;;
    openrc)
      if [[ -f "$SERVICE_FILE" ]]; then
        SERVICE_PRESENT=1
        if bounded 8 rc-service nft-forward status >/dev/null; then
          SERVICE_ACTIVE=1
        else
          rc=$?
          # OpenRC: stopped or crashed. Other errors (including timeout) abort.
          [[ "$rc" == 1 || "$rc" == 3 ]] || return 1
        fi
      fi
      state=$(bounded 8 rc-update show default) || return 1
      if awk '$1=="nft-forward" && $2=="|" {found=1} END {exit !found}' <<< "$state"; then
        SERVICE_BOOT=enabled
      fi
      ;;
    *) return 1 ;;
  esac
}

svc_do() { # <start|stop|restart|status> <name>
  local action="$1" name="$2"
  case "$INIT_SYS" in
    systemd)
      if [[ "$action" == status ]]; then bounded 5 systemctl is-active --quiet "$name"
      else bounded 45 systemctl "$action" "$name"; fi ;;
    openrc) bounded 45 rc-service "$name" "$action" ;;
    *) return 1 ;;
  esac
}

service_reload() {
  case "$INIT_SYS" in
    systemd) bounded 15 systemctl daemon-reload ;;
    *) return 0 ;;
  esac
}

service_boot() {
  case "$INIT_SYS:$1" in
    systemd:on) bounded 15 systemctl enable nft-forward.service ;;
    systemd:off) bounded 15 systemctl disable nft-forward.service ;;
    openrc:on) bounded 15 rc-update add nft-forward default ;;
    openrc:off) bounded 15 rc-update del nft-forward default ;;
    *) return 1 ;;
  esac
}

panel_running() { svc_do status nft-forward >/dev/null 2>&1; }

# /healthz is loopback-only; require both HTTP 200 and data-plane readiness.
health_check() {
  local port body i good=0
  port=$(panel_get port) && valid_panel_port "$port" || return 1
  for ((i=0; i<15; i++)); do
    if panel_running && body=$(curl -q --noproxy '*' -fsS -m 2 -w '\n%{http_code}' 'http://127.0.0.1:'"$port"/healthz 2>/dev/null) \
      && [[ "${body##*$'\n'}" == 200 && "${body%$'\n'*}" == *'"ok":true'* ]]; then
      good=$((good+1))
      [[ "$good" == 2 ]] && return 0
    else
      # An active service can still be returning 503 (data plane not ready).
      good=0
    fi
    sleep 1
  done
  return 1
}

start_service() {
  svc_do "${1:-restart}" nft-forward && config_ready && health_check \
    || { err "服务启动或本机 /healthz 数据面健康检查失败"; return 1; }
}

# Only this application's sysctl snippets; record numeric live values before
# changing them. Missing IPv6/conntrack keys are optional. Don't load modules
# here: that would be an irreversible side effect of the installer transaction.
SYSCTL_KEYS=(net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.netfilter.nf_conntrack_acct)

stage_sysctl() {
  local n val
  for n in "${!SYSCTL_KEYS[@]}"; do
    if val=$(bounded 5 sysctl -n "${SYSCTL_KEYS[n]}" 2>/dev/null) && [[ "$val" =~ ^[0-9]+$ ]]; then
      SYSCTL_BEFORE[n]="$val"
    elif [[ "$n" == 0 ]]; then
      return 1
    else
      warn "内核参数不可用，跳过: ${SYSCTL_KEYS[n]}"
    fi
  done
  printf '# NFT Forward\nnet.ipv4.ip_forward = 1\n' > "$TXN/forward" || return 1
  if [[ -v 'SYSCTL_BEFORE[1]' ]]; then
    printf 'net.ipv6.conf.all.forwarding = 1\n' >> "$TXN/forward" || return 1
  fi
  if [[ -v 'SYSCTL_BEFORE[2]' ]]; then
    printf '# NFT Forward\nnet.netfilter.nf_conntrack_acct = 1\n' > "$TXN/conntrack" || return 1
  fi
}

apply_sysctl() {
  local n val
  for n in "${!SYSCTL_BEFORE[@]}"; do
    [[ "${SYSCTL_BEFORE[n]}" != 1 ]] || continue
    SYSCTL_TOUCHED+=("$n")
    if ! bounded 5 sysctl -w "${SYSCTL_KEYS[n]}=1" >/dev/null \
      || ! val=$(bounded 5 sysctl -n "${SYSCTL_KEYS[n]}") || [[ "$val" != 1 ]]; then
      if [[ "$n" == 2 ]]; then
        warn "无法确认 conntrack 字节计费已开启；在线 IP 判活可能降级"
      else
        err "无法启用 IP 转发: ${SYSCTL_KEYS[n]}"
        return 1
      fi
    fi
  done
}

# >>> change-port
# change_panel_port 事务化修改面板端口。
#
# 旧行为只校验 1-65535 就写配置 + restart：可以把面板端口改成 SSH 端口、
# 已被监听的端口、或某条转发规则的监听端口，结果服务起不来（或抢掉用户的转发），
# 而配置已经被改坏。
#
# 现在：
#   1. 交给后端做与首次安装等价的全部安全检查（TCP/UDP 占用、SSH、guard_ports、
#      已有转发端口、bind 探测；读不到规则库时 fail-closed 拒绝）
#   2. 检查通过才写入新端口（后端返回旧端口，供回滚）
#   3. restart → systemd active → 本机 /healthz（含数据面就绪）
#   4. 确认新端口真的在监听
#   5. 任一步失败 → 恢复旧端口 → restart → 再次验证旧端口可用 → 才提示已回滚
#   6. 旧端口也恢复失败 → 明确 ERROR
#
# Token 与随机入口路径全程不动。
change_panel_port() {  # change_panel_port <新端口>
  local newp="$1"
  [[ "$INIT_SYS" != none ]] || { err "仅配置模式下不修改面板端口"; return 1; }
  [[ ! -e "$APP_DIR/.install-transaction" ]] || { err "请先完成安装事务"; return 1; }
  if [[ ! "$newp" =~ ^[0-9]+$ ]]; then
    warn "端口必须是数字"
    return 1
  fi

  # 1-2) 后端校验 + 写入（失败时不写配置，并打印具体原因）
  local out oldp
  if ! out=$(installed_core panel-port-set "$newp" 2>&1); then
    err "端口未修改：$out"
    return 1
  fi
  oldp=$(printf '%s\n' "$out" | sed -nE 's/^old_port=([0-9]+)$/\1/p')
  printf '%s\n' "$out" | sed -nE 's/^warn=(.*)$/\1/p' | while IFS= read -r w; do
    [[ -n "$w" ]] && warn "$w"
  done
  if [[ -z "$oldp" ]]; then
    err "无法确定旧端口，已中止（配置可能已被修改，请运行 nff 查看面板信息）"
    return 1
  fi
  info "端口已写入配置（$oldp → $newp），正在重启并验证..."

  # 3-4) 重启 + 三重确认 + 确认新端口真的在监听
  if start_service && port_listening "$newp"; then
    ok "面板端口已改为 $newp"
    panel_url || warn "面板地址暂不可用，请运行 nff --panel-url"
    return 0
  fi

  # 5) 回滚
  err "新端口验证失败，正在回滚到 $oldp"
  if ! installed_core config-set port "$oldp" >/dev/null 2>&1; then
    err "严重: 旧端口写回失败！请手工执行: nft-forward config-set port $oldp"
    return 1
  fi
  if start_service && port_listening "$oldp"; then
    ok "已回滚到原端口 $oldp（服务已恢复并通过健康检查）"
    return 1
  fi
  err "严重: 已写回旧端口 $oldp，但服务未能恢复"
  err "请查看日志: journalctl -u nft-forward -n 60"
  return 1
}

# port_listening 确认某端口真的处于监听状态（最多等 10s）。
port_listening() {  # port_listening <端口>
  local p="$1" i=0
  while [[ $i -lt 10 ]]; do
    if command -v ss >/dev/null 2>&1; then
      ss -Hlnt "sport = :$p" 2>/dev/null | grep -q . && return 0
    elif command -v netstat >/dev/null 2>&1; then
      netstat -lnt 2>/dev/null | grep -qE "[:.]${p}[[:space:]]" && return 0
    else
      # 无 ss/netstat：退化为直接连一次
      (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null && { exec 3<&-; return 0; }
    fi
    sleep 1
    i=$((i+1))
  done
  return 1
}
# <<< change-port

panel_url() { installed_core panel-url; }

show_panel_info() {
  local text
  text=$(installed_core panel-info) || return 1
  printf '%s面板信息%s\n' "$C_B" "$C_RESET"
  while IFS= read -r line; do
    printf '  %s%s%s\n' "$C_CYAN" "$line" "$C_RESET"
  done <<< "$text"
}

# ---------------------------------------------------------------- Installer transaction
# Only files owned by the installer are included. SQLite, including WAL/SHM,
# and the nft rule caches are daemon-managed data: never copy or remove them.
# The previous service, when running, reconciles its owned tables on restart.
assert_managed_path() {
  local parent="${1%/*}" canonical
  if [[ -n "$ROOT" ]]; then
    while [[ ! -e "$parent" && ! -L "$parent" ]]; do parent="${parent%/*}"; done
    canonical=$(realpath -- "$parent") || return 1
    if [[ "$canonical" != "$ROOT" && "$canonical" != "$ROOT/"* ]]; then
      err "安装路径超出 NFF_ROOT: $1"
      return 1
    fi
  fi
  if [[ -L "$1" || ( -e "$1" && ! -f "$1" ) ]]; then
    err "安装目标不是普通文件: $1"
    return 1
  fi
}

add_target() { # <destination> <prepared source> <mode>
  assert_managed_path "$1" || return 1
  install -d -m 0755 -- "${1%/*}" || return 1
  local i=${#TARGETS[@]}
  TARGETS+=("$1") SOURCES+=("$2") MODES+=("$3")
  printf '%s\n' "$1" >> "$TXN/paths" || return 1
  if [[ -e "$1" ]]; then cp -a -- "$1" "$TXN/snapshot/$i" || return 1; fi
}

atomic_file() { # <source> <destination> [mode]; omit mode when restoring
  local temp
  temp=$(mktemp "${2%/*}/.nff-replace.XXXXXXXX") || return 1
  if { if [[ $# == 3 ]]; then install -m "$3" -- "$1" "$temp"; else cp -a -- "$1" "$temp"; fi; } \
    && mv -fT -- "$temp" "$2"; then return 0; fi
  rm -f -- "$temp" || warn "无法删除暂存文件: $temp"
  return 1
}

replace_slot() {
  local i="$1"
  APPLIED+=("$i")
  atomic_file "${SOURCES[i]}" "${TARGETS[i]}" "${MODES[i]}" || die "无法原子安装 ${TARGETS[i]}"
}

# Database and rule cache permissions are tightened in place (no data copy).
# Do not chmod links, or touch external configured data paths.
harden_data_modes() {
  local f mode i
  for f in "$DB_FILE" "$NFT_CONF"; do
    [[ -f "$f" && ! -L "$f" ]] || continue
    mode=$(stat -c %a -- "$f") || return 1
    [[ "$mode" != 600 ]] || continue
    i=0
    while ((i<${#DATA_PATHS[@]})) && [[ "${DATA_PATHS[i]}" != "$f" ]]; do i=$((i+1)); done
    if ((i==${#DATA_PATHS[@]})); then DATA_PATHS[i]="$f" DATA_MODES[i]="$mode"; fi
    chmod 600 "$f" || return 1
  done
}

core_rollback() {
  local failed=0 idx i dest before
  if [[ "$START_ATTEMPTED" == 1 ]] && ! svc_do stop nft-forward; then
    err "回滚时无法停止候选服务"
    failed=1
  fi
  if [[ "$ENABLE_ATTEMPTED" == 1 ]]; then
    # enable may fail after creating links; inventory to avoid deleting any
    # pre-existing enabled state. Only fresh/disabled registration reaches here.
    if ! service_inventory || { [[ "$SERVICE_BOOT" != "$WAS_BOOT" ]] && ! service_boot off; }; then
      err "无法撤销新服务的开机注册"
      failed=1
    fi
  fi
  for ((idx=${#APPLIED[@]}-1; idx>=0; idx--)); do
    i=${APPLIED[idx]} dest=${TARGETS[i]}
    if ! { if [[ -e "$TXN/snapshot/$i" ]]; then atomic_file "$TXN/snapshot/$i" "$dest"; else rm -f -- "$dest"; fi; }; then
      err "无法恢复: $dest"
      failed=1
    fi
  done
  for i in "${!DATA_PATHS[@]}"; do
    if ! chmod "${DATA_MODES[i]}" -- "${DATA_PATHS[i]}"; then
      err "无法恢复权限: ${DATA_PATHS[i]}"
      failed=1
    fi
  done
  for ((idx=${#SYSCTL_TOUCHED[@]}-1; idx>=0; idx--)); do
    i=${SYSCTL_TOUCHED[idx]} dest=${SYSCTL_KEYS[i]} before=${SYSCTL_BEFORE[i]}
    if ! { [[ "$(bounded 5 sysctl -n "$dest")" == "$before" ]] || { bounded 5 sysctl -w "$dest=$before" >/dev/null && [[ "$(bounded 5 sysctl -n "$dest")" == "$before" ]]; }; }; then
      err "无法恢复内核参数: $dest"
      failed=1
    fi
  done
  if [[ "$SERVICE_TOUCHED" == 1 ]]; then
    # Don't start an old service with a partially restored set of files.
    if ! service_reload; then failed=1; fi
    if [[ "$WAS_ACTIVE" == 1 && "$failed" == 0 ]] && ! start_service start; then failed=1; fi
    if ! service_inventory || [[ "$SERVICE_ACTIVE" != "$WAS_ACTIVE" || "$SERVICE_BOOT" != "$WAS_BOOT" || "$SERVICE_PRESENT" != "$WAS_PRESENT" ]]; then
      err "无法确认升级前的服务状态"
      failed=1
    fi
  fi
  return "$failed"
}

core_backup_commit() { COMMITTED=1; } # only after all critical checks

release_exit() {
  local rc="$1"
  trap - EXIT ERR
  trap '' HUP INT TERM
  if [[ -n "$TXN" ]]; then
    if [[ "$DIRTY" == 0 || "$COMMITTED" == 1 ]]; then
      rm -rf -- "$TXN" || warn "无法清除安装工作目录: $TXN"
    elif core_rollback; then
      err "操作失败；已回滚安装文件并验证原服务状态"
      rm -rf -- "$TXN" || warn "无法清除安装备份: $TXN"
      [[ "$rc" != 0 ]] || rc=1
    else
      err "操作失败且回滚未完成；备份保留在 $TXN"
      rc=1
    fi
  fi
  if [[ -n "$STAGE" ]]; then rm -rf -- "$STAGE" || warn "无法清除发行版暂存目录: $STAGE"; fi
  exit "$rc"
}

# One owner for the update from staging through commit. The verified replacement
# script is data in this transaction, not executed while state is half-installed.
release_worker() {
  # Invoked only as an asynchronous function; $! is this worker, not a
  # wrapper around another subshell. Exit while transaction locals are live.
  local operation="$1" force="${2:-}"
  local STAGE='' TXN='' DIST_SHA='' RELEASE_VERSION='' DIRTY=0 COMMITTED=0
  local SERVICE_TOUCHED=0 START_ATTEMPTED=0 ENABLE_ATTEMPTED=0
  local SERVICE_PRESENT SERVICE_ACTIVE SERVICE_BOOT WAS_PRESENT=0 WAS_ACTIVE=0 WAS_BOOT=disabled
  local -a TARGETS=() SOURCES=() MODES=() APPLIED=() DATA_PATHS=() DATA_MODES=() SYSCTL_BEFORE=() SYSCTL_TOUCHED=()
  local i self_slot current_port data_file
  [[ -z "$force" || "$force" == --force ]] || die "用法: nff --update [--force]"
  require_root
  detect_platform
  command -v timeout >/dev/null 2>&1 || die "需要 timeout 才能限制安装与回滚等待时间"
  trap 'release_exit "$?"' EXIT
  trap 'err "安装步骤失败（行 $LINENO）"' ERR
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  STAGE=$(mktemp -d) || die "无法创建发行版暂存目录"
  stage_release "$STAGE" "${BASH_SOURCE[0]}"
  assert_managed_path "$PANEL_CONF" && assert_managed_path "$CORE_BIN" && assert_managed_path "$SELF_PATH" \
    || die "安装路径不受支持"
  if [[ "$operation" == update && ( ! -f "$PANEL_CONF" || ! -x "$CORE_BIN" ) ]]; then
    die "未检测到已安装的 NFT Forward，无法升级"
  fi
  install -d -m 0755 -- "$APP_DIR" || die "无法建立安装目录"
  mkdir -m 0700 -- "$APP_DIR/.install-transaction" || die "另一个安装正在运行，或有未恢复的备份: $APP_DIR/.install-transaction"
  TXN="$APP_DIR/.install-transaction"
  if [[ "$operation" == update && "$force" != --force && -x "$SELF_PATH" && -x "$CMD_PATH" ]] \
    && cmp -s -- "$STAGE/install.sh" "$SELF_PATH" && cmp -s -- "$STAGE/core" "$CORE_BIN"; then
    ok "脚本与二进制已是固定分发提交 $DIST_SHA 的版本，无需升级（可加 --force）"
    exit 0
  fi
  mkdir -m 0700 -- "$TXN/snapshot" || die "无法创建回滚备份目录"
  if [[ -e "$PANEL_CONF" ]]; then
    install -m 0600 -- "$PANEL_CONF" "$TXN/panel" || die "配置暂存失败"
  else
    install -m 0600 /dev/null "$TXN/panel" || die "无法暂存面板配置"
    printf '{}\n' > "$TXN/panel" || die "无法准备面板配置"
    run_core 10 "$STAGE/core" "$TXN/panel" config-set ssh_port "$(detect_ssh_port)" >/dev/null \
      || die "无法初始化 SSH 保护端口"
  fi
  # If the existing config has no usable panel port, provisioning may open
  # (and migrate) its live rule database. Refuse instead of writing SQLite
  # before commit, or selecting a port without checking the rules.
  current_port=$(config_value "$STAGE/core" "$TXN/panel" port) || die "无法读取暂存配置"
  if ! valid_panel_port "$current_port"; then
    data_file=$(config_value "$STAGE/core" "$TXN/panel" db) || die "无法判断规则数据库位置"
    [[ ! -e "$data_file" && ! -L "$data_file" ]] || die "已有规则数据库，但未配置有效面板端口；请先安全配置端口，未改动数据库"
  fi
  ensure_panel_conf "$STAGE/core" "$TXN/panel" || die "面板配置预检/迁移失败"
  printf '#!/usr/bin/env bash\nexec bash %q "$@"\n' "$SELF_PATH" > "$TXN/wrapper" || die "无法暂存 nff 命令"
  add_target "$CORE_BIN" "$STAGE/core" 0755 && add_target "$PANEL_CONF" "$TXN/panel" 0600 \
    && add_target "$CMD_PATH" "$TXN/wrapper" 0755 || die "无法备份安装文件"
  if [[ "$INIT_SYS" != none ]]; then
    install_deps
    service_inventory || die "无法确认原服务状态"
    WAS_PRESENT=$SERVICE_PRESENT WAS_ACTIVE=$SERVICE_ACTIVE WAS_BOOT=$SERVICE_BOOT
    printf '%s\n' "$INIT_SYS present=$WAS_PRESENT active=$WAS_ACTIVE boot=$WAS_BOOT" > "$TXN/service" || die "无法记录服务状态"
    stage_service "$TXN/service-unit" || die "无法暂存服务定义"
    add_target "$SERVICE_FILE" "$TXN/service-unit" "$SERVICE_MODE" || die "无法备份服务定义"
    stage_sysctl || die "无法暂存或读取内核转发设置"
    add_target "$SYSCTL_FILE" "$TXN/forward" 0644 || die "无法备份 IP 转发配置"
    if [[ -e "$TXN/conntrack" ]]; then
      add_target "$CONNTRACK_FILE" "$TXN/conntrack" 0644 || die "无法备份 conntrack 配置"
    fi
  fi
  add_target "$SELF_PATH" "$STAGE/install.sh" 0755 || die "无法备份已安装管理脚本"
  self_slot=$((${#TARGETS[@]}-1))

  DIRTY=1
  if [[ "$WAS_ACTIVE" == 1 ]]; then
    SERVICE_TOUCHED=1
    svc_do stop nft-forward && service_inventory && [[ "$SERVICE_ACTIVE" == 0 ]] || die "无法停止原服务"
  fi
  for ((i=0; i<self_slot; i++)); do replace_slot "$i"; done
  harden_data_modes || die "无法收紧数据文件权限"
  if [[ "$INIT_SYS" != none ]]; then
    apply_sysctl || die "无法启用 IP 转发"
    SERVICE_TOUCHED=1
    service_reload || die "无法重新加载服务定义"
    START_ATTEMPTED=1
    start_service start || die "服务未通过健康确认"
    installed_core selftest || die "候选二进制自检失败"
    harden_data_modes || die "无法收紧数据文件权限"
    if [[ "$WAS_PRESENT" == 0 && "$WAS_BOOT" == disabled ]]; then
      ENABLE_ATTEMPTED=1
      service_boot on && service_inventory && [[ "$SERVICE_BOOT" == enabled ]] || die "开机自启注册或验证失败"
    elif [[ "$operation" == update && "$WAS_ACTIVE" == 0 ]]; then
      svc_do stop nft-forward && service_inventory && [[ "$SERVICE_ACTIVE" == 0 ]] || die "无法恢复升级前的停止状态"
      START_ATTEMPTED=0
    fi
  else
    info "仅配置模式：未运行服务、nft、sysctl、包管理或运行时自检"
  fi
  replace_slot "$self_slot"
  core_backup_commit
  if [[ "$operation" == install ]]; then ok "安装完成 → v$RELEASE_VERSION ($DIST_SHA)"
  else ok "升级完成 → v$RELEASE_VERSION ($DIST_SHA)"; fi
  exit 0
}

# Forward PID-directed signals to the transaction worker, then let it finish
# restoring state before the caller exits. The worker bounds manager commands.
release_operation() {
  local worker='' interruption=0 rc=0 previous
  previous=$(trap -p HUP INT TERM)
  trap 'interruption=129; [[ -z "$worker" ]] || kill -TERM "$worker" 2>/dev/null || :' HUP
  trap 'interruption=130; [[ -z "$worker" ]] || kill -TERM "$worker" 2>/dev/null || :' INT
  trap 'interruption=143; [[ -z "$worker" ]] || kill -TERM "$worker" 2>/dev/null || :' TERM
  release_worker "$@" &
  worker=$!
  if ((interruption)); then kill -TERM "$worker" 2>/dev/null || :; fi
  wait "$worker" || rc=$?
  if ((interruption)); then
    trap '' HUP INT TERM
    wait "$worker" || :
    rc=$interruption
  fi
  trap - HUP INT TERM
  if [[ -n "$previous" ]]; then eval "$previous"; fi
  return "$rc"
}

# >>> do-update
do_update() { release_operation update "${1:-}"; }
# <<< do-update

# Keep the legacy internal flag usable, but never accept an unpinned payload.
apply_update() { do_update "$@"; }

status_report() {
  detect_platform
  if [[ -e "$APP_DIR/.install-transaction" ]]; then
    err "安装事务正在进行或需恢复: $APP_DIR/.install-transaction"
    return 1
  fi
  if [[ ! -x "$CORE_BIN" || ! -f "$PANEL_CONF" ]]; then info "未安装"; return 1; fi
  local ver
  ver=$(core_version_of "$CORE_BIN") && [[ -n "$ver" ]] || { err "已安装二进制无法执行或版本不可识别"; return 1; }
  info "NFT Forward v$ver"
  if [[ "$INIT_SYS" == none ]]; then info "仅配置模式：未检查运行时状态"; return 0; fi
  service_inventory || { err "无法获取服务状态"; return 1; }
  info "管理器: $INIT_SYS / 开机状态: $SERVICE_BOOT"
  if [[ "$SERVICE_ACTIVE" == 1 ]] && config_ready && health_check; then ok "服务正在运行，数据面已就绪"; return 0; fi
  err "服务已停止或数据面未就绪"
  return 1
}

# ---------------------------------------------------------------- Uninstall
# Destructive by explicit confirmation; keep SQLite/config unless separately
# asked to remove them. The backend clear command owns the nft table allowlist.
uninstall_all() {
  local ans='' failed=0 using_service=0
  [[ ! -e "$APP_DIR/.install-transaction" ]] || { err "请先恢复安装事务"; return 1; }
  printf '确认卸载 NFT Forward（只清理本程序自有服务、文件和 nft 表）？(yes/N): '
  read -r ans || :
  [[ "$ans" == yes ]] || { info "已取消"; return 0; }
  assert_managed_path "$PANEL_CONF" && assert_managed_path "$CORE_BIN" && assert_managed_path "$CMD_PATH" \
    || { err "安装路径不受支持"; return 1; }
  if [[ "$INIT_SYS" != none ]]; then
    assert_managed_path "$SERVICE_FILE" && assert_managed_path "$SYSCTL_FILE" && assert_managed_path "$CONNTRACK_FILE" || return 1
    service_inventory || { err "无法确认服务状态，未卸载"; return 1; }
    if [[ "$SERVICE_PRESENT" == 1 ]]; then
      using_service=1
      if [[ "$SERVICE_ACTIVE" == 1 ]]; then
        svc_do stop nft-forward && service_inventory && [[ "$SERVICE_ACTIVE" == 0 ]] \
          || { err "无法停止服务，未移除文件"; return 1; }
      fi
      case "$SERVICE_BOOT" in
        enabled|enabled-runtime) service_boot off || { err "无法取消开机注册，未移除文件"; return 1; } ;;
      esac
    fi
    if [[ -x "$CORE_BIN" ]]; then
      installed_core clear || { err "自有 nft 表未成功清理；保留二进制供重试"; return 1; }
    fi
    if [[ "$using_service" == 1 ]]; then
      rm -f -- "$SERVICE_FILE" && service_reload || { err "服务定义未成功移除或重载"; return 1; }
    fi
    rm -f -- "$SYSCTL_FILE" "$CONNTRACK_FILE" || failed=1
    info "未更改正在运行的内核转发开关（其它服务可能依赖它们）"
  else
    info "仅配置模式：未触及服务、内核和 nft 规则"
  fi
  rm -f -- "$CORE_BIN" "$CMD_PATH" || failed=1
  if [[ "$failed" != 0 ]]; then err "卸载未完成：文件移除失败"; return 1; fi
  printf '同时删除数据目录 %s（含规则与历史统计）？(yes/N): ' "$APP_DIR"
  ans=''; read -r ans || :
  if [[ "$ans" == yes ]]; then rm -rf -- "$APP_DIR" || { err "无法删除数据目录"; return 1; }
  else info "数据目录和管理脚本已保留: $APP_DIR"; fi
  ok "卸载完成"
}

# ---------------------------------------------------------------- 菜单
menu_service() {
  while :; do
    banner
    printf '%s服务管理%s\n\n' "$C_B" "$C_RESET"
    printf '  状态: %s\n\n' "$(panel_running && echo "${C_GREEN}运行中${C_RESET}" || echo "${C_RED}已停止${C_RESET}")"
    echo "  1) 启动"
    echo "  2) 停止"
    echo "  3) 重启"
    echo "  4) 查看日志"
    echo "  0) 返回"
    echo
    printf '请选择: '
    local c=""; read -r c || true
    case "$c" in
      1) svc_do start nft-forward && ok "已启动" || err "启动失败"; pause ;;
      2) svc_do stop nft-forward && ok "已停止" || err "停止失败"; pause ;;
      3) svc_do restart nft-forward && ok "已重启" || err "重启失败"; pause ;;
      4) hr
         if [[ "$INIT_SYS" == "systemd" ]]; then
           journalctl -u nft-forward -n 60 --no-pager
         else
           tail -n 60 /var/log/nft-forward.log 2>/dev/null || warn "无日志"
         fi
         hr; pause ;;
      0|"") return 0 ;;
      *) warn "无效选择" ;;
    esac
  done
}

change_panel_setting() { # listen or interval; existing credentials are untouched
  local key="$1" value="$2" old active
  case "$key" in
    listen) [[ "$value" == '127.0.0.1' || "$value" == '0.0.0.0' ]] || return 1 ;;
    interval)
      if [[ ! "$value" =~ ^([1-9]|[1-5][0-9]|60)$ ]]; then warn "请输入 1–60 秒"; return 1; fi ;;
    *) return 1 ;;
  esac
  [[ "$INIT_SYS" != none && ! -e "$APP_DIR/.install-transaction" ]] || { err "当前不能修改运行配置"; return 1; }
  old=$(panel_get "$key") && [[ -n "$old" ]] && service_inventory || { err "无法确认原配置或服务状态"; return 1; }
  active=$SERVICE_ACTIVE
  if [[ "$old" == "$value" ]]; then info "设置未变更"; return 0; fi
  panel_set "$key" "$value" || { err "未能保存设置"; return 1; }
  if [[ "$active" == 0 ]] || start_service; then
    ok "设置已保存"
    if [[ "$key" == listen && "$value" == '0.0.0.0' ]]; then
      warn "面板已监听全部 IPv4 地址；不要将明文 HTTP 面板直接开放到公网"
    fi
    return 0
  fi
  if panel_set "$key" "$old" && start_service; then
    err "新设置未通过健康检查，已恢复原设置"
  else
    err "无法确认原设置已恢复，请检查面板和服务状态"
  fi
  return 1
}

menu_panel() {
  while :; do
    banner
    printf '%s面板设置与统计维护%s\n\n' "$C_B" "$C_RESET"
    printf '  端口: %s    监听: %s    采集间隔: %ss\n\n' \
      "$(panel_get port)" "$(panel_get listen)" "$(panel_get interval)"
    echo "  1) 修改面板端口"
    echo "  2) 修改采集间隔"
    echo "  3) 切换监听范围（全部 / 仅本机）"
    echo "  4) 运行统计自检"
    echo "  0) 返回"
    echo
    printf '请选择: '
    local c=""; read -r c || true
    case "$c" in
      1) printf '新端口 (1-65535): '
         local p=""; read -r p || true
         change_panel_port "$p" || :
         pause ;;
      2) printf '采集间隔 (1-60 秒): '
         local n=""; read -r n || true
         change_panel_setting interval "$n" || :
         pause ;;
      3) local cur next
         if cur=$(panel_get listen); then
           case "$cur" in
             127.*|localhost|::1|'[::1]') next=0.0.0.0 ;;
             *) next=127.0.0.1 ;;
           esac
           change_panel_setting listen "$next" || :
         else err "无法读取当前监听地址"; fi
         pause ;;
      4) hr; runtime_core selftest || :; hr; pause ;;
      0|"") return 0 ;;
      *) warn "无效选择" ;;
    esac
  done
}

menu_settings() {
  while :; do
    banner
    printf '%s系统设置与运维%s\n\n' "$C_B" "$C_RESET"
    echo "  1) 面板设置与统计维护"
    echo "  2) 查看面板信息（地址与令牌）"
    echo "  3) 服务管理"
    echo "  0) 返回"
    echo
    printf '请选择: '
    local c=""; read -r c || true
    case "$c" in
      1) menu_panel ;;
      2) banner; show_panel_info || warn "面板信息暂不可用"; echo; pause ;;
      3) menu_service ;;
      0|"") return 0 ;;
      *) warn "无效选择" ;;
    esac
  done
}

main_menu() {
  while :; do
    banner
    printf '  面板: %s    %sv%s%s\n' \
      "$(panel_running && echo "${C_GREEN}●${C_RESET} 运行中" || echo "${C_RED}●${C_RESET} 已停止")" \
      "$C_DIM" "$APP_VERSION" "$C_RESET"
    local url
    url=$(panel_url 2>/dev/null) || url='（面板地址不可用）'
    printf '  面板: %s%s%s\n\n' "$C_CYAN" "$url" "$C_RESET"
    echo "  1) 系统设置与运维"
    echo "  2) 检查更新"
    echo "  3) 卸载"
    echo "  0) 退出"
    echo
    printf '请选择: '
    local c=""; read -r c || true
    case "$c" in
      1) menu_settings ;;
      2) do_update || :; pause ;;
      3) uninstall_all || :; pause ;;
      0|"") clear 2>/dev/null || true; exit 0 ;;
      *) warn "无效选择"; sleep 1 ;;
    esac
  done
}

do_install() {
  release_operation install || return 1
  if [[ -z "$ROOT" && -z "${NFF_NO_SERVICE:-}" ]]; then
    show_panel_info || warn "面板信息暂不可用，请运行 nff --panel-info"
  fi
  info "运行 nff 打开管理菜单"
  if [[ -t 0 ]]; then pause; exec bash "$SELF_PATH"; fi
}

runtime_core() {
  detect_platform
  [[ "$INIT_SYS" != none ]] || { err "仅配置模式下不执行运行时命令"; return 1; }
  [[ ! -e "$APP_DIR/.install-transaction" ]] || { err "安装事务正在进行或需恢复"; return 1; }
  installed_core "$@"
}

main() {
  init_colors
  case "${1:-}" in
    --clear-firewall) require_root; runtime_core clear ;;
    --panel-url) detect_platform; panel_url ;;
    --panel-info) require_root; detect_platform; installed_core panel-info ;;
    --set-panel-port) require_root; detect_platform; change_panel_port "${2:-}" ;;
    --selftest) require_root; runtime_core selftest ;;
    --status) status_report ;;
    --update|update|upgrade|--apply-update)
      [[ $# -le 2 ]] || die "用法: nff --update [--force]"
      do_update "${2:-}" ;;
    --uninstall) require_root; detect_platform; uninstall_all ;;
    --version) echo "$APP_NAME v$APP_VERSION" ;;
    -h|--help)
      cat <<EOF
$APP_NAME v$APP_VERSION — nftables 端口转发 + 流量监控面板（Go 单二进制）

安装:   https://github.com/$REPO#安装（先下载并校验）
菜单:   nff
用法:   nff [选项]

选项:
  --update           在线升级（保留转发规则与流量历史、面板端口、入口路径、访问令牌）
  --update --force   强制重装当前/最新版本
  --status           检查安装、服务和数据面状态
  --selftest         自检
  --panel-url        输出面板访问地址（含随机入口路径）
  --panel-info       输出面板地址与访问令牌
  --set-panel-port N 修改面板端口（完整安全校验 + 失败自动回滚）
  --clear-firewall   只移除自有 nft 表（nff_*）
  --uninstall        卸载
  --version          版本信息
EOF
      ;;
    *)
      require_root
      detect_platform
      if [[ -f "$PANEL_CONF" && -x "$CORE_BIN" ]]; then
        # A verified, separately invoked pinned bootstrap bypasses the old menu
        # and updater (which had no pinned protocol). nff with no args is a menu.
        if [[ -n "${NFF_DIST_SHA:-}" && ! "${BASH_SOURCE[0]}" -ef "$SELF_PATH" ]]; then do_update
        else main_menu; fi
      else do_install; fi
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
