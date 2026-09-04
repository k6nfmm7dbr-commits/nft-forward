#!/usr/bin/env bash
# =============================================================================
#  NFT Forward — nftables 端口转发 + 流量监控面板
#  一键安装:  bash <(curl -fsSL https://raw.githubusercontent.com/k6nfmm7dbr-commits/nft-forward/main/install.sh)
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
APP_VERSION="0.3.0"
REPO="k6nfmm7dbr-commits/nft-forward"
RAW_URL="${NFF_RAW_URL:-https://raw.githubusercontent.com/${REPO}/main/install.sh}"
# 二进制走 dist 分支（rolling latest，与 Git Tag 无关）。raw 对同一路径总返回
# 最新提交的产物，安装器无需感知版本号；版本一致性由下载后的自检保证。
RAW_BASE="${NFF_RAW_BASE:-https://raw.githubusercontent.com/${REPO}/dist}"
GH_PROXY="${NFF_GH_PROXY:-}"

# NFF_ROOT 仅用于沙箱/测试安装，正常安装留空
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

OS_FAMILY="unknown"
INIT_SYS="unknown"
PKG=""
CORE_REPLACED=0

# ---------------------------------------------------------------- 输出样式
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

# ---------------------------------------------------------------- 环境探测
require_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "需要 root 权限，请用 sudo 运行"; }

detect_platform() {
  if [[ -f /etc/alpine-release ]]; then
    OS_FAMILY="alpine"; PKG="apk"
  elif command -v apt-get >/dev/null 2>&1; then
    OS_FAMILY="debian"; PKG="apt"
  elif command -v dnf >/dev/null 2>&1; then
    OS_FAMILY="rhel"; PKG="dnf"
  elif command -v yum >/dev/null 2>&1; then
    OS_FAMILY="rhel"; PKG="yum"
  else
    die "不支持的系统（需要 Debian/Ubuntu、RHEL 系或 Alpine）"
  fi

  if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
    INIT_SYS="systemd"
  elif command -v rc-update >/dev/null 2>&1; then
    INIT_SYS="openrc"
  elif [[ -n "${NFF_NO_SERVICE:-}" ]]; then
    INIT_SYS="none"
  else
    die "未找到 systemd 或 OpenRC，无法安装服务"
  fi
}

pkg_install() {
  case "$PKG" in
    apk) apk add --no-cache "$@" >/dev/null 2>&1 || apk add --no-cache "$@" ;;
    apt) DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null 2>&1 \
         || DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
    dnf) dnf install -y "$@" >/dev/null 2>&1 || dnf install -y "$@" ;;
    yum) yum install -y "$@" >/dev/null 2>&1 || yum install -y "$@" ;;
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

gh_url() { [[ -n "$GH_PROXY" ]] && echo "${GH_PROXY%/}/$1" || echo "$1"; }

# >>> checksum-helpers（tests/checksum_flow_test.sh 提取本区块做一致性测试）
sha256_of() {  # sha256_of <file>
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else openssl dgst -sha256 -r "$1" | awk '{print $1}'; fi
}

verify_core_checksum() {  # <binary_file> <SHA256SUMS_file> <binary_name>
  local f="$1" sums="$2" name="$3" n expect got
  [[ -s "$f" ]] || { warn "二进制为空或不存在: $f"; return 1; }
  [[ -s "$sums" ]] || { warn "SHA256SUMS 缺失或为空"; return 1; }
  # 目标 binary 必须在 SHA256SUMS 中恰好出现一次（缺失/重复/格式异常都算失败）
  n=$(awk -v x="$name" '$2==x{c++} END{print c+0}' "$sums")
  if [[ "$n" != "1" ]]; then
    warn "SHA256SUMS 中 $name 出现 ${n} 次（应为 1 次）"
    return 1
  fi
  expect=$(awk -v x="$name" '$2==x{print $1}' "$sums")
  got=$(sha256_of "$f")
  if [[ -z "$expect" || "$expect" != "$got" ]]; then
    warn "校验和不匹配: 期望 ${expect:-空} 实得 $got"
    return 1
  fi
  return 0
}
# <<< checksum-helpers

# core_version_of <binary> —— 解析 `nft-forward version` 里的纯版本号。
core_version_of() {
  "$1" version 2>/dev/null | head -1 | sed -nE 's/^NFT Forward v?([0-9]+\.[0-9]+\.[0-9]+)$/\1/p'
}

# ---------------------------------------------------------------- 依赖
install_deps() {
  info "检查依赖..."
  [[ "$PKG" == "apt" ]] && { apt-get update -qq >/dev/null 2>&1 || true; }

  local need=()
  command -v curl >/dev/null 2>&1 || need+=(curl)
  command -v awk  >/dev/null 2>&1 || need+=(awk)
  ((${#need[@]})) && { info "安装: ${need[*]}"; pkg_install "${need[@]}"; }

  # nftables 是唯一数据面后端：装不上或装完不可用一律中止，绝不静默降级。
  if ! command -v nft >/dev/null 2>&1; then
    info "安装 nftables（NFT Forward 的唯一数据面后端）"
    pkg_install nftables || true
  fi
  command -v nft >/dev/null 2>&1 \
    || die "未找到 nft 命令：本程序的转发/统计/配额/IP 限制全部由 nftables 实现，请先安装 nftables"
  # 命令存在还不够：容器/受限内核里 nft 可能无法访问 netlink。
  # 只做只读探测（list tables 不改变任何规则）。
  nft list tables >/dev/null 2>&1 \
    || die "nft 命令存在但不可用（权限不足或内核不支持 nftables），无法继续安装"

  ensure_conntrack_acct
  ok "依赖就绪（Go 单二进制，无运行时依赖）"
}

# >>> conntrack-acct
# ensure_conntrack_acct 开启 conntrack 字节计费并持久化。
#
# 为什么必需：Debian/Ubuntu 默认 net.netfilter.nf_conntrack_acct=0，此时
# /proc/net/nf_conntrack 不输出 bytes= 字段。在线 IP 判活依赖字节增量，
# 全零会导致正在使用的连接在空闲窗口后被判死 —— IP 限制开启时会把真实
# 客户端从 allow set 移除（真的踢线）。
#
# 后端已内置降级（检测到全零则退回「ESTABLISHED 即在线」），因此这里失败
# 只告警不阻断安装。
ensure_conntrack_acct() {
  local cur=""
  cur=$(sysctl -n net.netfilter.nf_conntrack_acct 2>/dev/null || true)
  [[ "$cur" == "1" ]] && return 0
  modprobe nf_conntrack 2>/dev/null || true
  if sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null 2>&1; then
    info "已开启 conntrack 字节计费（nf_conntrack_acct=1）"
  else
    warn "无法开启 nf_conntrack_acct，在线 IP 判活将降级为「ESTABLISHED 即在线」"
    return 0
  fi
  if [[ -d "$ROOT/etc/sysctl.d" ]]; then
    printf '# 由 nft-forward 写入：在线 IP 判活依赖 conntrack 字节计费\nnet.netfilter.nf_conntrack_acct = 1\n' \
      > "$ROOT/etc/sysctl.d/99-nft-forward-conntrack.conf" 2>/dev/null \
      || warn "写入 99-nft-forward-conntrack.conf 失败（重启后需手工设置）"
  fi
}
# <<< conntrack-acct

# >>> ip-forward
# ensure_ip_forward 开启内核转发。这是端口转发的前提：不开启时 DNAT 后的包
# 不会被路由出去，表现为「规则已下发但连不通」。
# 只写独立 sysctl 文件，绝不修改 /etc/sysctl.conf（那是用户的文件）。
ensure_ip_forward() {
  install -d -m 0755 "$(dirname "$SYSCTL_FILE")"
  cat > "$SYSCTL_FILE" <<'EOF'
# 由 nft-forward 安装脚本写入。删除本文件并重启即可撤销。
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
  sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
  if [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" == "1" ]]; then
    ok "IP 转发已开启（$SYSCTL_FILE）"
  else
    warn "IP 转发未开启，转发将不工作。请检查 $SYSCTL_FILE"
  fi
}
# <<< ip-forward

# ---------------------------------------------------------------- 二进制安装
# >>> install-core
# install_core 下载/更新 nft-forward 二进制。
#
# 更新判断基于「代码内容」而非版本号：dist 是 rolling latest，二进制内容会变
# 而版本号可能不变。先取 SHA256SUMS 与本地二进制做 sha256 比较，一致则跳过，
# 不一致才下载替换。绝不能用「版本号相等」判断跳过（旧二进制会永远刷不掉）。
install_core() {
  install -d -m 0755 "$BIN_DIR"
  CORE_REPLACED=0

  # 开发/测试：直接使用本地构建的二进制
  if [[ -n "${NFF_CORE_BIN:-}" && -x "${NFF_CORE_BIN}" ]]; then
    cat "$NFF_CORE_BIN" > "$CORE_BIN.tmp.$$" && chmod 0755 "$CORE_BIN.tmp.$$" \
      && mv -f "$CORE_BIN.tmp.$$" "$CORE_BIN" \
      || die "本地二进制拷贝失败；现有安装未被改动"
    CORE_REPLACED=1
    ok "使用本地二进制: $("$CORE_BIN" version 2>/dev/null | head -1)"
    return 0
  fi

  local arch name tmp dl base dist_sha
  arch="$(arch_name)"
  name="nft-forward-linux-${arch}"
  tmp=$(mktemp -d)
  # 临时文件放目标目录内：最后的 mv 是同文件系统 rename，保证原子性
  dl="$BIN_DIR/.nft-forward.dl.$$"
  cleanup_dl() { rm -rf "$tmp" "$dl" 2>/dev/null || true; }

  # 解析 dist 分支当前 commit，用 immutable revision 下载 binary 与 SHA256SUMS，
  # 避免两次下载之间 dist 被 force-push 导致版本错位。解析失败回退 RAW_BASE
  # （仍有 SHA256 校验 fail-closed 兜底，错位只会失败、不会装错）。
  dist_sha=""
  if command -v git >/dev/null 2>&1; then
    dist_sha=$(git ls-remote "https://github.com/${REPO}.git" refs/heads/dist 2>/dev/null | awk '{print $1}')
  else
    local refs_json
    refs_json=$(curl -fsSL -m 15 "https://api.github.com/repos/${REPO}/git/ref/heads/dist" 2>/dev/null) || refs_json=""
    dist_sha=$(grep -m1 '"sha"' <<< "$refs_json" | sed -E 's/.*"sha"[[:space:]]*:[[:space:]]*"([0-9a-f]+)".*/\1/')
  fi
  if [[ -n "$dist_sha" ]]; then
    base="https://raw.githubusercontent.com/${REPO}/$dist_sha"
  else
    base="$RAW_BASE"
  fi

  # 先下 SHA256SUMS（小文件），与本地二进制做内容比较
  curl -fsSL -m 60 -o "$tmp/SHA256SUMS" "$(gh_url "$base/SHA256SUMS")" \
    || { cleanup_dl; die "下载 SHA256SUMS 失败；现有安装未被改动"; }
  if [[ -x "$CORE_BIN" ]]; then
    local local_sum expect_sum
    local_sum=$(sha256_of "$CORE_BIN" 2>/dev/null || true)
    expect_sum=$(awk -v x="$name" '$2==x{print $1}' "$tmp/SHA256SUMS")
    if [[ -n "$local_sum" && -n "$expect_sum" && "$local_sum" == "$expect_sum" ]]; then
      cleanup_dl
      ok "二进制已是最新: $("$CORE_BIN" version 2>/dev/null | head -1)"
      return 0
    fi
  fi

  info "下载 nft-forward (${arch})..."
  curl -fsSL -m 300 -o "$dl" "$(gh_url "$base/${name}")" \
    || { cleanup_dl; die "下载二进制失败（可设置 NFF_GH_PROXY 使用镜像）；现有安装未被改动"; }
  verify_core_checksum "$dl" "$tmp/SHA256SUMS" "$name" \
    || { cleanup_dl; die "二进制校验失败；现有安装未被改动"; }

  chmod 0755 "$dl"
  # 替换前自检 1：新二进制必须能在本机执行
  "$dl" version >/dev/null 2>&1 \
    || { cleanup_dl; die "二进制自检失败（架构或 libc 不匹配）；现有安装未被改动"; }
  # 替换前自检 2：candidate 版本必须与安装器 APP_VERSION 严格一致（fail-closed）。
  # dist 是 rolling latest，若 CDN 未刷新或发布链异常，candidate 可能是旧版本 ——
  # 即使 SHA256 与 checksums 自洽也必须拒绝，防止脚本与后端版本错位。
  local cand_ver
  cand_ver=$(core_version_of "$dl")
  if [[ "$cand_ver" != "$APP_VERSION" ]]; then
    cleanup_dl
    die "二进制版本不匹配，已拒绝安装（现有安装未被改动）
  期望: $APP_VERSION    实际: ${cand_ver:-无法解析}
  提示: dist 分支产物可能尚未同步，请稍后重试"
  fi

  # 原子替换；保留旧版备份以备回滚（备份失败则中止，旧二进制绝不能被无备份覆盖）
  if [[ -x "$CORE_BIN" ]]; then
    cp -f "$CORE_BIN" "$CORE_BIN.bak" || { cleanup_dl; die "旧二进制备份创建失败，已中止（现有安装未被改动）"; }
  fi
  mv -f "$dl" "$CORE_BIN"
  rm -rf "$tmp"
  if ! "$CORE_BIN" version >/dev/null 2>&1; then
    [[ -f "$CORE_BIN.bak" ]] && { mv -f "$CORE_BIN.bak" "$CORE_BIN"; warn "新二进制异常，已回滚"; }
    die "安装后自检失败"
  fi
  rm -f "$CORE_BIN.bak"
  CORE_REPLACED=1
  ok "二进制安装完成: $("$CORE_BIN" version | head -1)"
}
# <<< install-core

# ---------------------------------------------------------------- 目录与配置
# >>> prepare-dirs
# prepare_dirs 创建数据目录。
#
# panel.json 含面板配置、traffic.db 含流量与规则数据：首次创建用
# install -m 0600 预建（不受 umask 影响），已存在的旧文件若权限过宽
# （历史安装/手工操作）统一收紧，避免出现「短暂 0644 暴露 token」的窗口。
prepare_dirs() {
  install -d -m 0755 "$APP_DIR"
  if [[ ! -f "$PANEL_CONF" ]]; then
    install -m 0600 /dev/null "$PANEL_CONF"
    printf '{}\n' > "$PANEL_CONF"
  fi
  chmod 600 "$PANEL_CONF"
  [[ -f "$DB_FILE" ]] && chmod 600 "$DB_FILE"
  [[ -f "$NFT_CONF" ]] && chmod 600 "$NFT_CONF"
  return 0
}
# <<< prepare-dirs

ensure_panel_conf() {
  # v0.3 起面板已无令牌机制，panel.json 只是字段表（listen/port/tz/...）。
  # 兼容性：如果老配置里残留 token 键，下一次写入会被替换覆盖；无需主动删。
  chmod 600 "$PANEL_CONF"
}

panel_get() { "$CORE_BIN" config-get "$1" 2>/dev/null; }
panel_set() { "$CORE_BIN" config-set "$1" "$2" >/dev/null; }

# ssh_port 探测当前 SSH 端口并写入配置，供后端做转发端口冲突保护
# （避免用户把转发监听端口设成 22 把自己关在门外）。
detect_ssh_port() {
  local p=""
  p=$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)
  [[ -z "$p" ]] && p=$(ss -Hlnt 2>/dev/null | awk '{print $4}' | sed -nE 's/.*:([0-9]+)$/\1/p' | sort -u | grep -x 22 || true)
  [[ -z "$p" ]] && p=22
  echo "$p"
}

# ---------------------------------------------------------------- 服务
# >>> setup-services
setup_services() {
  [[ -n "${NFF_NO_SERVICE:-}" ]] && { warn "已跳过服务注册（NFF_NO_SERVICE）"; return 0; }

  case "$INIT_SYS" in
    systemd)
      cat > /etc/systemd/system/nft-forward.service <<EOF
[Unit]
Description=NFT Forward panel (nftables port forwarding + traffic stats)
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
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
      systemctl daemon-reload
      systemctl enable nft-forward >/dev/null 2>&1 || true
      ;;

    openrc)
      cat > /etc/init.d/nft-forward <<EOF
#!/sbin/openrc-run
name="nft-forward"
description="NFT Forward panel"
command="$CORE_BIN"
command_args="serve"
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"
export NFT_FORWARD_CONF="$PANEL_CONF"
output_log="/var/log/nft-forward.log"
error_log="/var/log/nft-forward.log"
depend() { need net; }
EOF
      chmod +x /etc/init.d/nft-forward
      rc-update add nft-forward default >/dev/null 2>&1 || true
      ;;
  esac
  ok "服务已注册（开机自启）"
}
# <<< setup-services

svc_do() {  # svc_do <start|stop|restart|status> <name>
  local action="$1" name="$2"
  case "$INIT_SYS" in
    systemd)
      if [[ "$action" == "status" ]]; then
        systemctl is-active --quiet "$name"
      else
        systemctl "$action" "$name" >/dev/null 2>&1
      fi
      ;;
    openrc)
      if [[ "$action" == "status" ]]; then
        rc-service "$name" status >/dev/null 2>&1
      else
        rc-service "$name" "$action" >/dev/null 2>&1
      fi
      ;;
    *) return 0 ;;
  esac
}

panel_running() { svc_do status nft-forward; }

start_service() {
  svc_do restart nft-forward || svc_do start nft-forward || true
  sleep 1
  if panel_running; then
    ok "面板服务已启动"
  else
    err "面板服务启动失败，请查看日志: journalctl -u nft-forward -n 60"
    return 1
  fi
}

install_self() {
  install -d -m 0755 "$BIN_DIR" "$APP_DIR"
  if [[ -f "${BASH_SOURCE[0]}" ]]; then
    install -m 0755 "${BASH_SOURCE[0]}" "$SELF_PATH" 2>/dev/null || true
  fi
  if [[ ! -f "$SELF_PATH" ]]; then
    curl -fsSL -m 60 -o "$SELF_PATH" "$(gh_url "$RAW_URL")" 2>/dev/null || true
    chmod +x "$SELF_PATH" 2>/dev/null || true
  fi
  cat > "$CMD_PATH" <<EOF
#!/usr/bin/env bash
exec bash "$SELF_PATH" "\$@"
EOF
  chmod +x "$CMD_PATH"
}

panel_url() {
  local host port
  host=$(hostname -I 2>/dev/null | awk '{print $1}')
  [[ -z "$host" ]] && host="127.0.0.1"
  port=$(panel_get port); [[ -z "$port" ]] && port=8090
  echo "http://${host}:${port}/"
}

show_panel_info() {
  printf '%s面板信息%s\n' "$C_B" "$C_RESET"
  printf '  地址: %s%s%s\n' "$C_CYAN" "$(panel_url)" "$C_RESET"
  printf '  %s配置文件: %s（权限 0600）%s\n' "$C_DIM" "$PANEL_CONF" "$C_RESET"
}

# ---------------------------------------------------------------- 在线升级
remote_version() {  # 从下载的脚本里提取 APP_VERSION
  grep -m1 '^APP_VERSION=' "$1" 2>/dev/null | sed -E 's/^APP_VERSION="?([^"]+)"?.*/\1/'
}

ver_ge() {  # ver_ge A B → A >= B ?（点分版本比较）
  [[ "$1" == "$2" ]] && return 0
  local a b i
  IFS=. read -ra a <<< "$1"
  IFS=. read -ra b <<< "$2"
  for ((i=0; i<${#a[@]} || i<${#b[@]}; i++)); do
    local x=${a[i]:-0} y=${b[i]:-0}
    ((10#$x > 10#$y)) && return 0
    ((10#$x < 10#$y)) && return 1
  done
  return 0
}

# >>> do-update
# do_update 从 RAW_URL 拉最新脚本 → 语法校验 → 替换本体 → 由新脚本 --apply-update
# 更新二进制并重启。全程保留 traffic.db / panel.json（规则、流量历史不动）。
do_update() {
  local force="${1:-}"
  banner
  printf '%s在线升级%s\n\n' "$C_B" "$C_RESET"
  require_root
  detect_platform

  local tmp new_ver current_sha remote_sha same_content="no"
  tmp=$(mktemp)
  info "从 GitHub 拉取最新版本..."
  if ! curl -fsSL -m 60 -o "$tmp" "$(gh_url "$RAW_URL")"; then
    rm -f "$tmp"; die "下载失败，可设置 NFF_GH_PROXY 使用镜像后重试"
  fi
  # 基本完整性校验：语法 + 版本标记（避免把 404 页面当脚本装上）
  if ! bash -n "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "下载的脚本语法校验失败，已放弃升级（未改动现有安装）"
  fi
  if ! grep -q '^APP_VERSION=' "$tmp"; then
    rm -f "$tmp"; die "下载的脚本缺少版本标记，可能不是发布版，已放弃升级"
  fi

  new_ver=$(remote_version "$tmp"); [[ -z "$new_ver" ]] && new_ver="unknown"
  current_sha=$(sha256_of "$SELF_PATH" 2>/dev/null || true)
  remote_sha=$(sha256_of "$tmp" 2>/dev/null || true)
  [[ -n "$current_sha" && "$current_sha" == "$remote_sha" ]] && same_content="yes"
  info "当前版本: $APP_VERSION    最新版本: $new_ver"

  if [[ "$same_content" == "yes" && "$force" != "--force" ]]; then
    rm -f "$tmp"
    # 脚本相同，但 dist 的二进制可能单独更新（rolling latest）。
    # 不能只看脚本/版本号 —— 仍需按内容检查后端二进制。
    info "脚本已是最新，检查后端二进制是否同步..."
    CORE_REPLACED=0
    install_core || die "后端二进制检查/更新失败，已保留现有安装"
    if [[ "${CORE_REPLACED:-0}" == "1" ]]; then
      svc_do restart nft-forward || svc_do start nft-forward || true
      ok "后端二进制已更新"
    else
      ok "已是最新版本，无需升级"
    fi
    printf '%s如需强制重装当前版本，运行: nff --update --force%s\n' "$C_DIM" "$C_RESET"
    return 0
  fi
  if [[ "$new_ver" != "unknown" ]] && ver_ge "$APP_VERSION" "$new_ver" && [[ "$same_content" != "yes" ]]; then
    warn "版本号未递增但脚本内容不同，仍将更新（检测到远端代码变化）"
  fi

  # 备份当前本体（存在即必须备份成功，否则中止 —— 旧脚本绝不能被无备份覆盖）
  if [[ -f "$SELF_PATH" ]]; then
    cp -f "$SELF_PATH" "$SELF_PATH.bak" || { rm -f "$tmp"; die "升级前备份创建失败，已中止（当前脚本未被改动）"; }
  fi
  cat "$tmp" > "$SELF_PATH"
  chmod +x "$SELF_PATH"
  rm -f "$tmp"
  ok "脚本已更新到 $new_ver，正在应用..."

  if bash "$SELF_PATH" --apply-update; then
    ok "升级完成 → v$new_ver"
    [[ -t 0 ]] && { pause; exec bash "$SELF_PATH"; }
  else
    # 回滚；恢复本身失败绝不能吞掉（否则停在半更新状态还报"已恢复"）
    warn "应用失败，回滚到升级前版本"
    if [[ -f "$SELF_PATH.bak" ]] && cat "$SELF_PATH.bak" > "$SELF_PATH" 2>/dev/null && chmod +x "$SELF_PATH" 2>/dev/null; then
      bash "$SELF_PATH" --apply-update >/dev/null 2>&1 || true
      die "升级未成功，已恢复原版本"
    else
      die "严重: 升级失败且回滚失败! 当前脚本可能处于半更新状态，请重新运行安装命令修复"
    fi
  fi
}
# <<< do-update

# >>> apply-update
# apply_update 更新二进制 + 迁移配置 + 重启服务（升级时由新脚本调用）。
# 用户数据（traffic.db / panel.json）全程不动。
apply_update() {
  require_root
  detect_platform
  [[ -f "$PANEL_CONF" ]] || die "未检测到已安装的 NFT Forward，无法应用升级"
  install -d -m 0755 "$APP_DIR"

  # nftables 是硬依赖：确认可用后再动任何东西。用户数据此刻未被改动，中止是安全的。
  command -v nft >/dev/null 2>&1 || { info "本机缺少 nftables，正在安装..."; pkg_install nftables || true; }
  command -v nft >/dev/null 2>&1 \
    || die "未找到 nft 命令，已中止升级（规则与流量数据未被改动）"
  nft list tables >/dev/null 2>&1 \
    || die "nft 命令存在但不可用（权限或内核不支持），已中止升级（规则与流量数据未被改动）"

  info "更新后端二进制..."
  install_core
  "$CORE_BIN" version >/dev/null 2>&1 || die "升级后二进制不可用，已中止（原二进制保留）"

  # 摘掉 panel.json 里的废弃键（历史 listen_address 相关）。
  # 只删废弃键，token / port / db / tz 与用户自定义键原样保留。
  "$CORE_BIN" config-migrate >/dev/null 2>&1 \
    || warn "清理废弃配置键失败（不影响运行，可手工执行 nft-forward config-migrate）"

  prepare_dirs
  install_self
  setup_services
  ensure_ip_forward
  ensure_conntrack_acct

  # 数据库 schema 迁移由 serve 启动时的 migrate() 完成（只 ADD COLUMN，
  # 不 DROP、不重建表），因此重启即完成升级。
  if ! start_service; then
    err "面板服务重启失败！规则与流量数据未受影响，请查看日志: journalctl -u nft-forward -n 60"
    return 1
  fi
  return 0
}
# <<< apply-update

# ---------------------------------------------------------------- 卸载
# >>> uninstall
# uninstall_all 只删除本程序自有的东西：
#   · nff_nat4 / nff_nat6 / nff_filter 三张表（由 nft-forward clear 执行）
#   · 自己的 systemd/OpenRC 单元、二进制、封装命令、sysctl 片段
# 绝不 flush ruleset，绝不动用户其它表，绝不改 /etc/sysctl.conf。
# 数据目录默认保留（含流量历史），需显式确认才删。
uninstall_all() {
  require_root
  banner
  printf '%s卸载%s\n\n' "$C_B" "$C_RESET"
  printf '将执行:\n'
  printf '  · 停止并移除服务单元\n'
  printf '  · 删除自有 nft 表 (nff_nat4 / nff_nat6 / nff_filter)\n'
  printf '  · 删除二进制与 nff 命令、sysctl 片段\n'
  printf '  %s不会%s 触碰系统其它防火墙规则（Docker / firewalld / 用户自有表）\n' "$C_B" "$C_RESET"
  printf '\n确认卸载？(yes/N): '
  local ans=""
  read -r ans || true
  [[ "$ans" == "yes" ]] || { info "已取消"; return 0; }

  svc_do stop nft-forward || true
  case "$INIT_SYS" in
    systemd)
      systemctl disable nft-forward >/dev/null 2>&1 || true
      rm -f /etc/systemd/system/nft-forward.service
      systemctl daemon-reload || true
      ;;
    openrc)
      rc-update del nft-forward default >/dev/null 2>&1 || true
      rm -f /etc/init.d/nft-forward
      ;;
  esac

  if [[ -x "$CORE_BIN" ]]; then
    "$CORE_BIN" clear >/dev/null 2>&1 || warn "自有表清理失败，可手工执行: nft delete table inet nff_filter"
  fi
  rm -f "$CORE_BIN" "$CMD_PATH" "$SYSCTL_FILE" "$ROOT/etc/sysctl.d/99-nft-forward-conntrack.conf"

  printf '\n是否同时删除数据目录 %s（含流量历史）？(yes/N): ' "$APP_DIR"
  local ans2=""
  read -r ans2 || true
  if [[ "$ans2" == "yes" ]]; then
    rm -rf "$APP_DIR"
    ok "数据目录已删除"
  else
    info "数据目录已保留: $APP_DIR"
  fi
  ok "卸载完成"
}
# <<< uninstall

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

menu_panel() {
  while :; do
    banner
    printf '%s面板设置%s\n\n' "$C_B" "$C_RESET"
    printf '  端口: %s    监听: %s    采集间隔: %ss\n\n' \
      "$(panel_get port)" "$(panel_get listen)" "$(panel_get interval)"
    echo "  1) 修改面板端口"
    echo "  2) 切换监听范围（全部 / 仅本机）"
    echo "  3) 自检"
    echo "  0) 返回"
    echo
    printf '请选择: '
    local c=""; read -r c || true
    case "$c" in
      1) printf '新端口 (1-65535): '
         local p=""; read -r p || true
         if [[ "$p" =~ ^[0-9]+$ ]] && ((10#$p >= 1 && 10#$p <= 65535)); then
           panel_set port "$p" && svc_do restart nft-forward && ok "面板端口已改为 $p" || err "修改失败"
         else
           warn "端口非法"
         fi
         pause ;;
      2) local cur; cur=$(panel_get listen)
         if [[ "$cur" == "127.0.0.1" ]]; then
           panel_set listen "0.0.0.0" && ok "已切换为监听全部地址"
         else
           panel_set listen "127.0.0.1" && ok "已切换为仅本机访问"
         fi
         svc_do restart nft-forward || true; pause ;;
      4) hr; "$CORE_BIN" selftest || true; hr; pause ;;
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
    printf '  地址: %s%s%s\n\n' "$C_CYAN" "$(panel_url)" "$C_RESET"
    printf '  %s转发规则的增删改查请在 Web 面板操作%s\n\n' "$C_DIM" "$C_RESET"
    echo "  1) 面板信息（地址）"
    echo "  2) 面板设置"
    echo "  3) 服务管理"
    echo "  4) 自检"
    echo "  5) 检查更新"
    echo "  6) 卸载"
    echo "  0) 退出"
    echo
    printf '请选择: '
    local c=""; read -r c || true
    case "$c" in
      1) banner; show_panel_info; echo; pause ;;
      2) menu_panel ;;
      3) menu_service ;;
      4) banner; hr; "$CORE_BIN" selftest || true; hr; pause ;;
      5) do_update; pause ;;
      6) uninstall_all; pause ;;
      0|"") clear 2>/dev/null || true; exit 0 ;;
      *) warn "无效选择"; sleep 1 ;;
    esac
  done
}

# ---------------------------------------------------------------- 安装
do_install() {
  banner
  require_root
  detect_platform
  info "系统: $OS_FAMILY / 初始化: $INIT_SYS / 架构: $(arch_name)"
  install_deps
  prepare_dirs
  install_core
  ensure_panel_conf
  panel_set ssh_port "$(detect_ssh_port)"
  ensure_ip_forward
  install_self
  setup_services
  start_service || true

  banner
  ok "安装完成"
  hr
  show_panel_info
  printf '\n%s提示%s\n' "$C_B" "$C_RESET"
  printf '  · 随时运行 %snff%s 打开管理菜单\n' "$C_CYAN" "$C_RESET"
  printf '  · 转发规则在 Web 面板里添加：只需填监听端口（可留空随机）+ 目标地址/端口\n'
  printf '  · 目标地址支持 IPv4 / IPv6 / 域名（域名会自动跟踪 DNS 变化）\n'
  printf '  · 若有云防火墙/安全组，请放行面板端口 %s 与各转发端口\n' "$(panel_get port)"
  echo
  if [[ ! -t 0 ]]; then
    printf '%s管道运行模式下不进入交互菜单，安装已完成。运行 nff 打开菜单。%s\n' "$C_DIM" "$C_RESET"
    return 0
  fi
  pause
  main_menu
}

# ---------------------------------------------------------------- 入口
main() {
  init_colors
  case "${1:-}" in
    --clear-firewall) require_root; "$CORE_BIN" clear; exit $? ;;
    --panel-url) panel_url; exit 0 ;;
    --selftest) require_root; "$CORE_BIN" selftest; exit $? ;;
    --update|update|upgrade) do_update "${2:-}"; exit $? ;;
    --apply-update) apply_update; exit $? ;;   # 内部使用：升级时由新脚本调用
    --uninstall) require_root; detect_platform; uninstall_all; exit $? ;;
    --version) echo "$APP_NAME v$APP_VERSION"; exit 0 ;;
    -h|--help)
      cat <<EOF
$APP_NAME v$APP_VERSION — nftables 端口转发 + 流量监控面板（Go 单二进制）

安装:   bash <(curl -fsSL $RAW_URL)
菜单:   nff
用法:   nff [选项]

选项:
  --update           在线升级（保留转发规则与流量历史）
  --update --force   强制重装当前/最新版本
  --selftest         自检
  --panel-url        输出面板访问地址
  --clear-firewall   只移除自有 nft 表（nff_*）
  --uninstall        卸载
  --version          版本信息
EOF
      exit 0 ;;
  esac

  require_root
  detect_platform
  # 已安装 → 菜单；未安装 → 安装
  if [[ -f "$PANEL_CONF" && -x "$CORE_BIN" ]]; then
    main_menu
  else
    do_install
  fi
}

main "$@"
