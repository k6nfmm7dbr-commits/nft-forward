# CHANGELOG

## v0.3.1

安全加固与可靠性收口。升级保留转发规则、流量历史、访问令牌、面板端口与入口路径。

### 认证（与 SBX 当前实现对齐）

- 恢复正式 Token 认证：`crypto/rand` 16 bytes → 32 位十六进制，`panel.json` 以 0600 创建与写回。
- 鉴权来源仅 `Authorization: Bearer` 与 HttpOnly Cookie `nff_token`；**`?token=` 不再被接受**。
- 令牌比较用 `crypto/subtle.ConstantTimeCompare`（等长内容比较）。
- 新增登录页（只输入令牌，无用户名、无默认账号；令牌不进 localStorage）。
- 会话 Cookie：`HttpOnly`、`MaxAge=604800`、`SameSite=Lax`、`Path` 覆盖面板入口；
  仅当 `secure_cookie=true` 时才加 `Secure`（纯 HTTP 直连不会因此登录失效）。
- 登录失败节流：同源 IP 前 5 次正常拒绝，之后每次失败 +2s；窗口 5 分钟；
  登录成功立即清零且成功路径零延迟；追踪表上限 4096、过期项自动 GC；
  来源 IP 取 `RemoteAddr`，不信任 `X-Forwarded-For`。
- `POST /login` 请求体上限 64 KiB，超限 `413`，绝不截断后继续解析。
- 安全响应头：`Cache-Control: no-store`、`X-Content-Type-Options: nosniff`、
  `Referrer-Policy: no-referrer`、`X-Frame-Options: DENY`、
  `Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`。
- CLI 新增 `config-ensure-token` / `config-ensure-entry` / `config-ensure-port` / `config-ensure-all` / `panel-info`；
  配置损坏时一律 fail-closed（非零退出、不写回、不覆盖原文件），安装器不再吞错。
- `token` 不再被当作废弃键删除（v0.3 的误删已修正）。

### 面板暴露面

- 彻底删除「默认 8090」：`port` 没有默认值，首次安装用 `crypto/rand` 在 10000-65535 随机选取，
  避开已监听 TCP、已占用 UDP、内核 ephemeral 区间、SSH、`guard_ports`、已有转发端口；
  最多尝试 512 次，失败即明确报错，**绝不 fallback 到任何固定端口**。
- 新增随机面板入口路径（`crypto/rand` 12 bytes = 96 bit），与令牌完全独立、不可互相推导。
- 未命中入口的一切请求统一返回极简 404：不跳转、不含品牌/版本/技术栈、不设 `Server`/`X-Powered-By`。
- 未登录时 `app.js` 也返回 404（不泄漏前端指纹）；`/healthz` 只对 loopback 开放。
- `serve` 启动前强校验端口/令牌/入口三项，缺一即拒绝启动。

### conntrack fail-safe 与语义修正

- `connection.Result` 区分「数据源可用」与「读取完整」，新增 `Usable()` / `Complete()` / `Note()`。
  成功读取到 0 flows 才等于「没人在线」；读不到一律不等于没人在线。
- 结构 enforcement（DNAT / counter / quota / 规则 CRUD / 自愈）不再依赖 conntrack。
  修复「conntrack 异常 → 删除规则 → API 返回成功 → nft 旧 DNAT 仍在」的假成功。
- conntrack 异常时冻结上一轮 IP Slot：不新增、不释放、不清空 allow set，
  `/api/health` 暴露 `ip_state_frozen`。

### nftables 自愈

- 用完整 Desired State 比对替代原来的三项式检查（表存在 + up counter + v4 set）。
  覆盖三张表、必要链、`marks`/`qblock`/IPv4+IPv6 allow set、每条规则的 up **和** down counter、
  以及各链最小规则条数。任一缺失即幂等重建，仍不 `flush ruleset`、不动他人表、保留现存 counter 值。

### 性能与内存

- conntrack 扫描从 O(规则数 × flow 数) 降到 O(规则数 + flow 数)：一次遍历建
  `(protocol, 原始目标端口) → flows` 索引，同轮内顺带收集 flow GC 所需信息。
- 修复 `flowState` 无界增长：按「本轮 conntrack 是否仍存在」回收；
  空闲判活改用「最近字节变化时刻」并保留 entry（旧实现删 entry 导致空闲连接永不离线）。
- DNS 刷新移出全局锁：锁内 snapshot → 锁外并发解析（上限 8，5s 超时）→ 重新加锁校验版本后 apply；
  过期结果丢弃，`last-known-good` 不变。规则 CRUD 不再被 DNS 超时阻塞。
- API 快照消除 N+1：累计与今日流量各一条参数化批量 SQL。

### 配额实时性

- 配额判定改为「已落库累计 + (当前 nft counter − 已落库 counter 基线)」，
  读数复用 policy 本轮的 `nft -j list ruleset`，不额外系统调用、不重复计费。
- collector 暴露 thread-safe `LiveSnapshot()`；SQLite 仍是唯一历史来源，reset 只动基线。

### 安装 / 升级

- 首次安装三重健康确认（systemd active + 本机 `/healthz` + 配置加载正常），
  失败即非零退出、不打印「安装完成」、保留现场。移除 `start_service || true`。
- 升级事务化：备份二进制与 `panel.json` → 下载 → SHA256 → 架构/版本自检 → 原子替换 →
  配置迁移 → 重启 → active → localhost healthz → selftest → **全部通过才删备份**。
  失败则恢复二进制与配置、重启并再次验证，确认成功才提示「已回滚」，否则明确报错。

### 转发端口分配

- 自动随机端口读取 `/proc/sys/net/ipv4/ip_local_port_range` 并避开内核 ephemeral 区间；
  占用探测同时看 `/proc/net/{tcp,tcp6,udp,udp6}` 与实际 bind。
- `crypto/rand` 取模偏置修正（拒绝采样）。

### 菜单与自检

- `nff` 菜单保持极简，「查看面板地址」改为「查看面板信息」，只显示面板地址与访问令牌，
  不再输出配置文件/数据库/sysctl/安装目录路径，也不提示令牌存放位置。
- 自检项：SQLite / nftables / nft netlink / owned tables / ip_forward / conntrack /
  ct_acct / web server / authentication（新增：本机验证 Bearer 有效且错误令牌被拒）。

### 测试

- 新增：认证（20+ 断言）、暴露面与 404 语义、config ensure/fail-closed、
  随机面板端口、conntrack fail-safe、nft 自愈 12 种破坏场景、flow GC 与大规模性能、
  配额实时性、DNS 锁与并发竞态、portprobe、conntrack 解析与索引。
- `scripts/e2e_fault.sh`（新增）：真机故障注入验收。
- `scripts/e2e_common.sh`（新增）：E2E 脚本自动读取随机端口/入口/令牌。
- `tests/baseline_test.sh` 扩展到 180+ 断言，覆盖本次全部收口点。

## v0.3.0

- 移除面板令牌认证（本版本已恢复，见 v0.3.1）。
- 规则卡片展示监听 IP（只读）。
- UI 细节对齐 SBX。

## v0.2.0

- 移除转发规则「监听地址」字段，统一由 `fib daddr type local` 匹配本机地址。
- 统一规则变更入口 `internal/rulesvc`。
- 安装 / 分发 / UI 全面收口。
