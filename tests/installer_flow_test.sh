#!/usr/bin/env bash
# Run the actual install.sh dispatcher/lifecycle against a private fake host.
# Curl, init managers, sysctl, nft, and package commands cannot reach the host.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
TPL="$HERE/install.sh"
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT
export TPL WORK
export REF=1234567890abcdef1234567890abcdef12345678
export R2=876543210fedcba9876543210fedcba987654321
export REPO=k6nfmm7dbr-commits/nft-forward
export ORIGIN="https://raw.githubusercontent.com/$REPO"
export BINARY=nft-forward-linux-amd64
export PATH="$WORK/bin:$PATH"
export NO_COLOR=1
unset NFF_CORE_BIN NFF_RAW_BASE NFF_RAW_URL NFF_GH_PROXY NFF_DIST_SHA NFF_NO_SERVICE NFF_ROOT
mkdir "$WORK/bin"
PASS=0
pass() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$*"; }
fail() { printf '  [FAIL] %s\n' "$*" >&2; [[ ! -f "${OUT:-}" ]] || cat "$OUT" >&2; exit 1; }
check() { local message="$1"; shift; "$@" || fail "$message"; pass "$message"; }
not() { if "$@"; then return 1; fi; }

cat > "$WORK/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -eu
out=''; url=''
while (( $# )); do
  case "$1" in
    -o) out="$2"; shift ;;
    http://*|https://*) url="$1" ;;
  esac
  shift
 done
printf '%s\n' "$url" >> "$FAKE/urls"
case "$url" in
  "https://api.github.com/repos/$REPO/git/ref/heads/dist")
    [[ ! -f "$FAKE/no-ref" ]] || exit 22
    read -r rev < "$FAKE/ref"
    printf '{\n  "ref": "refs/heads/dist",\n  "object": {\n    "sha": "%s",\n    "type": "commit"\n  }\n}\n' "$rev" > "$out"
    # Simulate rolling dist moving immediately after resolving the ref.
    printf '%s\n' "$R2" > "$FAKE/ref"
    ;;
  http://127.0.0.1:*/healthz)
    [[ $(cat "$FAKE/active") == 1 ]] || exit 22
    if [[ -f "$FAKE/no-health" ]] && grep -q 'candidate-core' "$NFF_ROOT/usr/local/bin/nft-forward"; then
      printf '{"ok":false,"error":"data plane not ready"}'
      exit 22
    fi
    printf '{"ok":true}\n200'
    ;;
  "$ORIGIN/"*/install.sh|"$ORIGIN/"*/install.sh.sha256|"$ORIGIN/"*/SHA256SUMS|"$ORIGIN/"*/"$BINARY"|"https://proxy.invalid/https://mirror.invalid/repo/"*/"$BINARY")
    name=${url##*/}
    rev=${url%/*}; rev=${rev##*/}
    [[ "$rev" == "$REF" || "$rev" == "$R2" ]] || exit 22
    if [[ "$url" == 'https://proxy.invalid/'* && -f "$FAKE/mirror-binary" ]]; then cp "$FAKE/mirror-binary" "$out"
    else cp "$FAKE/$rev/$name" "$out"; fi
    ;;
  *) echo "unexpected download: $url" >&2; exit 88 ;;
esac
MOCK

cat > "$WORK/bin/manager" <<'MOCK'
#!/usr/bin/env bash
set -eu
manager=${0##*/}
printf '%s %s\n' "$manager" "$*" >> "$FAKE/actions"
action=${1:-}
if [[ "$manager" == rc-service ]]; then action=${2:-}; fi
case "$manager:$action" in
  systemctl:show)
    [[ ! -f "$FAKE/bad-inventory" ]] || exit 2
    load=not-found
    [[ ! -f "$NFF_ROOT/etc/systemd/system/nft-forward.service" ]] || load=loaded
    if [[ $(cat "$FAKE/active") == 1 ]]; then state=active; else state=inactive; fi
    printf 'LoadState=%s\nActiveState=%s\nUnitFileState=%s\n' "$load" "$state" "$(cat "$FAKE/boot")"
    ;;
  rc-update:show)
    if [[ $(cat "$FAKE/boot") == enabled ]]; then printf '            nft-forward | default\n'; fi
    printf '            another-app | default\n';
    ;;
  systemctl:is-active|rc-service:status)
    [[ $(cat "$FAKE/active") == 1 ]] || exit 3
    ;;
  systemctl:start|rc-service:start|systemctl:restart|rc-service:restart)
    if [[ -f "$FAKE/no-start" ]] && grep -q 'candidate-core' "$NFF_ROOT/usr/local/bin/nft-forward"; then exit 1; fi
    if [[ -f "$FAKE/no-restore-start" ]] && grep -q 'previous-core' "$NFF_ROOT/usr/local/bin/nft-forward"; then exit 1; fi
    printf '1\n' > "$FAKE/active"
    ;;
  systemctl:stop|rc-service:stop)
    [[ ! -f "$FAKE/no-stop" ]] || exit 1
    printf '0\n' > "$FAKE/active"
    ;;
  systemctl:daemon-reload)
    if [[ -f "$FAKE/no-reload-once" ]]; then rm "$FAKE/no-reload-once"; exit 1; fi
    ;;
  systemctl:enable|rc-update:add)
    printf 'enabled\n' > "$FAKE/boot"
    [[ ! -f "$FAKE/bad-enable" ]]
    ;;
  systemctl:disable|rc-update:del) printf 'disabled\n' > "$FAKE/boot" ;;
  *) exit 88 ;;
esac
MOCK
cat > "$WORK/bin/sysctl" <<'MOCK'
#!/usr/bin/env bash
set -eu
arg="$2"; name=${arg%=*}
printf 'sysctl %s %s\n' "$1" "$arg" >> "$FAKE/actions"
case "$1:$name" in
  -n:net.*) cat "$FAKE/$name" ;;
  -w:net.*) printf '%s\n' "${arg##*=}" > "$FAKE/$name" ;;
  *) exit 88 ;;
esac
MOCK
cat > "$WORK/bin/nft" <<'MOCK'
#!/usr/bin/env bash
printf 'nft %s\n' "$*" >> "$FAKE/actions"
[[ "$*" == 'list tables' && ! -f "$FAKE/no-nft" ]]
MOCK
cat > "$WORK/bin/deny-package" <<'MOCK'
#!/usr/bin/env bash
printf 'UNEXPECTED %s\n' "$0" >> "$FAKE/actions"
exit 88
MOCK
cat > "$WORK/bin/uname" <<'MOCK'
#!/usr/bin/env bash
[[ "$*" == '-m' ]] && echo x86_64
MOCK
chmod +x "$WORK/bin/"*
for cmd in systemctl rc-service rc-update; do ln -s manager "$WORK/bin/$cmd"; done
for cmd in apk apt-get dnf yum modprobe; do ln -s deny-package "$WORK/bin/$cmd"; done

cat > "$WORK/core" <<'MOCK'
#!/usr/bin/env bash
# candidate-core
set -eu
case "$1" in
  version) printf 'NFT Forward v%s\n' 0.4.0 ;;
  config-get|config-set|config-ensure-all|config-migrate)
    python3 - "$@" <<'PY'
import json, os, sys
p = os.environ['NFT_FORWARD_CONF']
assert p.startswith(os.environ['NFF_ROOT'] + '/')
with open(p) as f:
    cfg = json.load(f)
cmd = sys.argv[1]
app = os.environ['NFT_FORWARD_DIR']
if cmd == 'config-get':
    defaults = {'db': app+'/traffic.db', 'nft_conf': app+'/nft.conf', 'listen':'0.0.0.0'}
    k = sys.argv[2]; print(cfg.get(k, defaults.get(k, '')))
    sys.exit(0)
if cmd == 'config-set':
    cfg[sys.argv[2]] = sys.argv[3]
elif cmd == 'config-ensure-all':
    cfg.setdefault('port', 42317)
    cfg.setdefault('token', 'a'*32)
    cfg.setdefault('entry_path', 'c'*24)
else:
    cfg.pop('obsolete_key', None)
with open(p, 'w') as f:
    json.dump(cfg, f)
PY
    ;;
  selftest)
    printf '%s\n' selftest >> "$FAKE/actions"
    [[ ! -f "$FAKE/no-selftest" ]]
    ;;
  clear) printf '%s\n' clear-owned >> "$FAKE/actions" ;;
  panel-info) printf '%s\n' 'fake panel info' ;;
  *) exit 88 ;;
esac
MOCK
chmod +x "$WORK/core"

# Source safely without dispatching; root and manager detection are the only
# overrides. Everything after detection, including the subprocesses' argv,
# snapshots, rollback trap and status, is the production implementation.
cat > "$WORK/run" <<'MOCK'
#!/usr/bin/env bash
# shellcheck source=../install.sh
source "$TPL"
require_root() { :; }
if [[ "${TEST_MANAGER:-none}" != none ]]; then
  detect_platform() {
    [[ -d "$ROOT" && "$ROOT" == "$WORK/"* ]] || { echo 'not a test root' >&2; exit 89; }
    INIT_SYS=$TEST_MANAGER
    case "$INIT_SYS" in
      systemd) SERVICE_FILE="$ROOT/etc/systemd/system/nft-forward.service"; SERVICE_MODE=0644 ;;
      openrc) SERVICE_FILE="$ROOT/etc/init.d/nft-forward"; SERVICE_MODE=0755 ;;
      *) exit 89 ;;
    esac
  }
fi
# Retry logic stays real, but no waiting for fake manager state changes.
sleep() { :; }
# This sandbox does not exercise OS timeouts or wait on real daemons.
timeout() {
  [[ "$1" == -k && "$2" == 2 && "$3" =~ ^[0-9]+$ ]] || return 89
  shift 3
  "$@"
}
main "$@"
MOCK

new_case() {
  export FAKE="$WORK/$1" NFF_ROOT="$WORK/$1/root" TEST_MANAGER="${2:-none}"
  export OUT="$FAKE/out"
  APP="$NFF_ROOT/etc/nft-forward"
  CORE="$NFF_ROOT/usr/local/bin/nft-forward"
  WRAPPER="$NFF_ROOT/usr/local/bin/nff"
  SELF="$APP/nft-forward.sh"
  PANEL="$APP/panel.json"
  TX="$APP/.install-transaction"
  UNIT="$NFF_ROOT/etc/systemd/system/nft-forward.service"
  if [[ "$TEST_MANAGER" == openrc ]]; then UNIT="$NFF_ROOT/etc/init.d/nft-forward"; fi
  FWD="$NFF_ROOT/etc/sysctl.d/90-nft-forward.conf"
  CT="$NFF_ROOT/etc/sysctl.d/99-nft-forward-conntrack.conf"
  mkdir -p "$NFF_ROOT" "$FAKE/$REF" "$FAKE/$R2"
  printf '%s\n' "$REF" > "$FAKE/ref"
  printf '0\n' > "$FAKE/active"
  printf 'disabled\n' > "$FAKE/boot"
  for k in net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.netfilter.nf_conntrack_acct; do printf '0\n' > "$FAKE/$k"; done
  : > "$FAKE/actions"; : > "$FAKE/urls"
  cp "$TPL" "$FAKE/$REF/install.sh"
  cp "$WORK/core" "$FAKE/$REF/$BINARY"
  rehash
  # No assets exist at the later ref; every mixed-revision attempt must fail.
  unset NFF_GH_PROXY NFF_RAW_BASE NFF_DIST_SHA NFF_CORE_BIN
}

rehash() (
  cd "$FAKE/$REF"
  sha256sum install.sh > install.sh.sha256
  sha256sum "$BINARY" > SHA256SUMS
)

install_legacy() {
  mkdir -p "$APP" "${CORE%/*}" "${UNIT%/*}" "${FWD%/*}" "$NFF_ROOT/old-data"
  sed 's/candidate-core/previous-core/' "$WORK/core" > "$CORE"
  printf '#!/usr/bin/env bash\n# old installer\n' > "$SELF"
  printf '#!/usr/bin/env bash\n# old wrapper\n' > "$WRAPPER"
  chmod 755 "$CORE" "$WRAPPER" "$SELF"
  printf 'legacy unit\n' > "$UNIT"; chmod 640 "$UNIT"
  printf 'old forward\n' > "$FWD"
  printf 'old conntrack\n' > "$CT"
  printf '{"port":42424,"token":"0123456789abcdef0123456789abcdef","entry_path":"legacy-entry-path-value","obsolete_key":1,"db":"%s","nft_conf":"%s"}\n' \
    "$NFF_ROOT/old-data/existing.sqlite" "$NFF_ROOT/old-data/rules.nft" > "$PANEL"
  chmod 640 "$PANEL"
  # A genuine SQLite file with a persistent rule, plus a generated cache.
  python3 - "$NFF_ROOT/old-data/existing.sqlite" <<'PY'
import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as conn:
    conn.execute('create table rules (id integer, target text)')
    conn.execute('insert into rules values (1, ?)', ('test-forward',))
PY
  printf 'legacy rule cache\n' > "$NFF_ROOT/old-data/rules.nft"
  printf 'legacy default path DB\n' > "$APP/traffic.db"
  chmod 644 "$APP/traffic.db"
  mkdir "$FAKE/original"
  cp -p "$CORE" "$SELF" "$WRAPPER" "$PANEL" "$UNIT" "$FWD" "$CT" "$APP/traffic.db" "$NFF_ROOT/old-data/"* "$FAKE/original"
}

run() { bash "$WORK/run" "$@" > "$OUT" 2>&1 </dev/null; }
rollback_files() {
  local f
  for f in "$CORE" "$SELF" "$WRAPPER" "$PANEL" "$UNIT" "$FWD" "$CT" "$APP/traffic.db" "$NFF_ROOT/old-data/"*; do
    cmp -s "$FAKE/original/${f##*/}" "$f" && [[ $(stat -c %a "$FAKE/original/${f##*/}") == "$(stat -c %a "$f")" ]] || return 1
  done
}

matches() { grep -qF -- "$1" "$2"; }
state() { [[ $(cat "$FAKE/active") == "$1" && $(cat "$FAKE/boot") == "$2" ]]; }
restored_sysctls() {
  local f
  for f in "$FAKE"/net.*; do [[ $(cat "$f") == 0 ]] || return 1; done
}

printf '== installer_flow_test ==\n'
check 'installer parses as Bash' bash -n "$TPL"
new_case fresh
check 'fresh install succeeds against one discovered dist commit' run
check 'fresh install persisted distribution script' cmp -s "$FAKE/$REF/install.sh" "$SELF"
check 'fresh panel has mode 0600' test "$(stat -c %a "$PANEL")" = 600
check 'sandbox install does not call host commands' test ! -s "$FAKE/actions"
check 'sandbox status honestly reports no runtime check' run --status
check 'sandbox status output' matches '仅配置模式' "$OUT"
check 'every release asset uses the single old revision' not matches "$R2" "$FAKE/urls"
check 'ref discovery happens once' test "$(grep -c 'api.github.com' "$FAKE/urls")" = 1
check 'sandbox clear is refused' not run --clear-firewall

new_case pinned
export NFF_DIST_SHA="$REF" NFF_RAW_BASE='https://mirror.invalid/repo/dist' NFF_GH_PROXY='https://proxy.invalid'
touch "$FAKE/no-ref"
install_legacy
check 'pinned bootstrap migrates existing legacy install without its updater' run
check 'explicit bootstrap bypasses branch discovery' not matches api.github.com "$FAKE/urls"
check 'candidate script comes from canonical commit' matches "$ORIGIN/$REF/install.sh" "$FAKE/urls"
check 'script checksum comes from canonical commit' matches "$ORIGIN/$REF/install.sh.sha256" "$FAKE/urls"
check 'binary manifest comes from canonical commit' matches "$ORIGIN/$REF/SHA256SUMS" "$FAKE/urls"
check 'proxy supplies pinned binary bytes only' matches "https://proxy.invalid/https://mirror.invalid/repo/$REF/$BINARY" "$FAKE/urls"
check 'legacy panel token unchanged' matches '0123456789abcdef0123456789abcdef' "$PANEL"
check 'legacy panel entry unchanged' matches legacy-entry-path-value "$PANEL"
check 'configured SQLite path unchanged' matches "$NFF_ROOT/old-data/existing.sqlite" "$PANEL"
check 'existing SQLite contents unchanged' cmp -s "$FAKE/original/existing.sqlite" "$NFF_ROOT/old-data/existing.sqlite"
check 'existing generated nft file unchanged' cmp -s "$FAKE/original/rules.nft" "$NFF_ROOT/old-data/rules.nft"
check 'legacy permission tightened without copying DB data' test "$(stat -c %a "$APP/traffic.db")" = 600
check 'no obsolete config key' not matches obsolete_key "$PANEL"
check 'legacy internal apply-update command honors pin' run --apply-update
check 'identical script and binary are a no-op' matches '无需升级' "$OUT"
check 'explicit pinned update still verifies artifacts' run --update
cat "$WORK/core" > "$FAKE/$REF/$BINARY"
printf '# binary-only update, version unchanged\n' >> "$FAKE/$REF/$BINARY"
rehash
check 'same-script same-version binary update is not skipped' run update
check 'updated binary bytes are installed' cmp -s "$FAKE/$REF/$BINARY" "$CORE"
check 'force avoids short circuit' run upgrade --force
check 'force actually commits' matches '升级完成' "$OUT"

for failure in no-ref invalid-pin missing-script-checksum bad-script-hash duplicate-script-hash bad-syntax missing-bin-manifest duplicate-bin-hash malformed-bin-hash bad-bin-hash wrong-version bad-mirror broken-config; do
  new_case "$failure" systemd
  install_legacy
  printf '1\n' > "$FAKE/active"
  printf 'enabled\n' > "$FAKE/boot"
  case "$failure" in
    no-ref) touch "$FAKE/no-ref" ;;
    invalid-pin) export NFF_DIST_SHA="${REF^^}" ;;
    missing-script-checksum) rm "$FAKE/$REF/install.sh.sha256" ;;
    bad-script-hash) printf '# changed\n' >> "$FAKE/$REF/install.sh" ;;
    duplicate-script-hash) cat "$FAKE/$REF/install.sh.sha256" >> "$FAKE/second"; cat "$FAKE/second" >> "$FAKE/$REF/install.sh.sha256" ;;
    bad-syntax) printf '\nif then\n' >> "$FAKE/$REF/install.sh"; rehash ;;
    missing-bin-manifest) rm "$FAKE/$REF/SHA256SUMS" ;;
    duplicate-bin-hash) cat "$FAKE/$REF/SHA256SUMS" >> "$FAKE/second"; cat "$FAKE/second" >> "$FAKE/$REF/SHA256SUMS" ;;
    malformed-bin-hash) printf '%064d %s extra\n' 0 "$BINARY" > "$FAKE/$REF/SHA256SUMS" ;;
    bad-bin-hash) printf '# changed\n' >> "$FAKE/$REF/$BINARY" ;;
    wrong-version) sed -i 's/0\.4\.0/0.4.1/' "$FAKE/$REF/$BINARY"; rehash ;;
    bad-mirror)
      export NFF_RAW_BASE='https://mirror.invalid/repo/dist' NFF_GH_PROXY='https://proxy.invalid'
      printf '#!/usr/bin/env bash\ntouch "$FAKE/unverified-code-ran"\n' > "$FAKE/mirror-binary" ;;
    broken-config) printf '{bad' > "$PANEL"; cp -p "$PANEL" "$FAKE/original/panel.json" ;;
  esac
  run --update && fail "$failure unexpectedly succeeded"
  rollback_files && state 1 enabled && [[ ! -s "$FAKE/actions" && ! -e "$TX" && ! -e "$FAKE/unverified-code-ran" ]] || fail "$failure changed installation"
  pass "$failure fails before live writes or actions"
done

for failure in no-start no-health no-selftest no-reload-once; do
  new_case "$failure" systemd
  install_legacy
  printf '1\n' > "$FAKE/active"
  printf 'enabled\n' > "$FAKE/boot"
  touch "$FAKE/$failure"
  if run --update; then fail "$failure unexpectedly succeeded"; fi
  rollback_files && restored_sysctls && state 1 enabled && matches '已回滚' "$OUT" && [[ ! -e "$TX" ]] || fail "$failure did not roll back"
  pass "$failure restores all prior files, modes, sysctls and active/enabled service"
done

new_case no-old-service systemd
install_legacy
rm "$UNIT"
touch "$FAKE/bad-enable"
check 'partial boot registration failure makes install fail' not run --update
check 'new boot links are removed on rollback' state 0 disabled
check 'prior unit absence is restored' test ! -e "$UNIT"
check 'boot registration failure leaves original wrapper' cmp -s "$FAKE/original/nff" "$WRAPPER"

new_case first-failure openrc
touch "$FAKE/no-health"
check 'failed OpenRC first install reports failure' not run
check 'failed first install does not print success' not matches '安装完成' "$OUT"
check 'failed first install removes its binary' test ! -e "$CORE"
check 'failed first install removes its management script' test ! -e "$SELF"
check 'failed first install removes its unit' test ! -e "$UNIT"
check 'failed first install restores sysctls' restored_sysctls
check 'failed first install restores absent/inactive service' state 0 disabled

new_case openrc-success openrc
check 'fresh OpenRC install starts and adds default runlevel' run
check 'OpenRC start and registration verified' state 1 enabled
check 'OpenRC unit preserves legacy boot contract' matches '#!/sbin/openrc-run' "$UNIT"
check 'healthy service status successfully verifies OpenRC and HTTP' run --status
printf '0\n' > "$FAKE/active"
printf 'disabled\n' > "$FAKE/boot"
printf '%s\n' "$REF" > "$FAKE/ref"
check 'forced OpenRC update of stopped instance succeeds' run --update --force
check 'stopped and disabled state preserved on successful upgrade' state 0 disabled
check 'explicit stopped status is nonzero' not run --status

new_case retained-backup systemd
install_legacy
printf '1\n' > "$FAKE/active"
printf 'enabled\n' > "$FAKE/boot"
touch "$FAKE/no-start" "$FAKE/no-restore-start"
check 'unrecoverable start failure is reported' not run --update
check 'incomplete rollback keeps a private snapshot' test -d "$TX/snapshot"
check 'explicit incomplete rollback message' matches '回滚未完成' "$OUT"
check 'status reports retained lock' not run --status
printf '%s\n' "$REF" > "$FAKE/ref"
check 'new attempts cannot overwrite retained backup' not run --update
check 'backup remains after second attempt' test -s "$TX/snapshot/0"

# Exercise the real SSH menu functions with fake config/service calls only.
check_menu() (
  # shellcheck source=../install.sh
  source "$TPL"
  init_colors
  banner() { :; }
  pause() { :; }
  clear() { :; }
  panel_running() { return 0; }
  installed_core() {
    case "$*" in
      panel-url) printf '%s\n' 'http://127.0.0.1:19191/test/' ;;
      panel-info) printf '%s\n' '面板地址: http://127.0.0.1:19191/test/' '访问令牌: test-only-token' ;;
      *) return 1 ;;
    esac
  }
  local_menu_out=$(main_menu <<< '0') || return 1
  [[ "$local_menu_out" == *'1) 系统设置与运维'* && "$local_menu_out" == *'2) 检查更新'* && "$local_menu_out" == *'3) 卸载'* ]] || return 1
  [[ "$local_menu_out" == *'http://127.0.0.1:19191/test/'* && "$local_menu_out" != *'test-only-token'* ]] || return 1
  info_out=$(main_menu <<< $'1\n2\n0\n0') || return 1
  [[ "$info_out" == *'访问令牌: test-only-token'* ]] || return 1
  install_out=$(do_install_noninteractive) || return 1
  [[ "$install_out" == *'访问令牌: test-only-token'* && "$install_out" == *'运行 nff 打开管理菜单'* ]]
)
do_install_noninteractive() (
  ROOT=''
  unset NFF_NO_SERVICE
  release_operation() { [[ "$1" == install ]]; }
  do_install </dev/null
)
check 'SSH main menu shows URL; explicit panel info and successful install show token' check_menu

check_menu_settings() (
  # shellcheck source=../install.sh
  source "$TPL"
  init_colors
  APP_DIR="$WORK/unused-menu-app"
  INIT_SYS=systemd
  current_listen=0.0.0.0
  current_interval=2
  mock_active=1
  restarts=0
  failure=1
  panel_get() {
    case "$1" in
      listen) printf '%s\n' "$current_listen" ;;
      interval) printf '%s\n' "$current_interval" ;;
      *) return 1 ;;
    esac
  }
  service_inventory() { SERVICE_ACTIVE=$mock_active; }
  panel_set() {
    case "$1" in
      listen) current_listen=$2 ;;
      interval) current_interval=$2 ;;
      *) return 1 ;;
    esac
  }
  start_service() { restarts=$((restarts+1)); ((restarts != failure)); }
  if change_panel_setting interval 5; then return 1; fi
  [[ "$current_interval" == 2 && "$restarts" == 2 ]] || return 1
  change_panel_setting listen 127.0.0.1 || return 1
  [[ "$current_listen" == 127.0.0.1 && "$restarts" == 3 ]] || return 1
  if change_panel_setting interval 61; then return 1; fi
  mock_active=0
  change_panel_setting interval 10 || return 1
  [[ "$current_interval" == 10 && "$restarts" == 3 ]]
)
check 'panel settings verify health, restore on failure, and preserve stopped state' check_menu_settings

# Keep firewall, sysctl, and version guardrails independent from subprocess mocks.
CODE="$WORK/code"
sed -e 's/#.*$//' -e 's/"[^"]*"//g' -e "s/'[^']*'//g" "$TPL" > "$CODE"
check 'installer has no global/unrelated firewall operations' not grep -qE 'flush ruleset|iptables -[FX]|nft flush table|nft delete table|policy drop' "$CODE"
check 'installer does not modify global sysctl.conf' not grep -qF /etc/sysctl.conf "$CODE"
check 'installer uses its own conntrack file' matches '99-nft-forward-conntrack.conf' "$TPL"
check 'installer uses its own forwarding file' matches '90-nft-forward.conf' "$TPL"
APP_VER=$(sed -nE 's/^APP_VERSION="([^"]+)"$/\1/p' "$TPL")
GO_VER=$(sed -nE 's/^const Version = "([^"]+)"$/\1/p' "$HERE/internal/version/version.go")
check 'installer and Go report the same version' test "$APP_VER" = "$GO_VER"
printf '\nPASS=%s FAIL=0\n' "$PASS"
