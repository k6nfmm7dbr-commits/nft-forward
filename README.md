# NFT Forward

基于 **nftables** 的端口转发 + 流量监控面板。Go 单二进制、原生 Web UI、SQLite 持久化。

## 当前版本

```text
v0.3.1
```

## 定位

```
Web 面板   = 转发规则业务管理
Go 后端    = 控制面 / API / 统计 / 状态管理
nftables   = 数据面 / NAT / enforcement
conntrack  = 当前连接与在线 IP 生命周期事实来源
SQLite     = 永久统计与配置持久化
```

## 特性

- **端口转发**：TCP / UDP / TCP+UDP，IPv4→IPv4、IPv6→IPv6（不做 NAT64/46）。
- **只配监听端口**：规则没有「监听地址」概念，自动作用于本机所有本地地址；留空则由后端随机分配一个安全端口（避开保留端口与内核 ephemeral 区间）。
- **目标支持 IPv4 / IPv6 / 域名**：域名在后台周期解析并自动跟踪变化，双栈分别落到 IPv4 / IPv6 数据面。
- **流量统计**：上传/下载分方向，counter 挂在 **FORWARD** 链（非 NAT 链），用 `ct mark` 归属多规则同目标场景。
- **在线 IP 限制**：Slot Manager（observed/candidate/active/granted/rejected），基于 conntrack 生命周期判活。
- **流量配额**：实时判定（已落库累计 + 未落库 nft counter 增量），超出阻断该规则转发，提高/重置即恢复，历史统计不丢。
- **实时面板**：SSE 推送 + 局部 DOM 更新，原生 HTML/CSS/JS，无框架、无构建链。
- **Token 登录**：与 SBX 对齐的访问令牌认证（Bearer 头或 HttpOnly Cookie），常量时间比较 + 登录失败节流。
- **低暴露面**：面板使用随机五位数端口 + 随机入口路径，未命中入口的请求统一返回极简 404。
- **安全边界**：只管理 `nff_*` 自有 nft 表，绝不 `flush ruleset`，绝不触碰系统其它防火墙规则。

## 安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/k6nfmm7dbr-commits/nft-forward/main/install.sh)
```

安装结束时屏幕会打印两行，请完整保存：

```text
面板地址: http://<公网IP>:<随机五位端口>/<随机入口路径>/
访问令牌: <32 位十六进制>
```

之后随时运行 `nff` 打开菜单，选「查看面板信息」可再次显示这两行。

常用命令：

```bash
nff                  # 管理菜单（面板信息 / 设置 / 服务 / 自检 / 更新 / 卸载）
nff --update         # 在线升级（保留规则、流量、令牌、端口、入口路径）
nff --panel-info     # 输出面板地址与访问令牌
nff --selftest       # 自检
nff --clear-firewall # 只移除自有 nft 表
nff --uninstall      # 卸载
```

## 面板访问与认证

面板挂在一个**随机入口路径**下，形如 `http://IP:41287/3e4f65a8c24d2bd5b9e80147/`。

- 端口在首次安装时用 `crypto/rand` 在 **10000-65535** 内随机选取，并避开已监听端口、已占用 UDP 端口、内核 ephemeral 区间、SSH 端口、`guard_ports`、已有转发端口。
- 入口路径同样在首次安装生成（`crypto/rand` 12 bytes，96 bit 随机），**与令牌完全独立**，不能互相推导。
- 访问令牌是 `crypto/rand` 16 bytes 的十六进制串（32 位），存在 `panel.json`（权限 0600）。

**随机入口不是身份认证。** 必须同时满足「知道入口路径」+「知道令牌」才能进入面板：

1. 未命中入口路径的一切请求（`/`、`/admin`、`/wp-login.php`、`/favicon.ico`、未知 API 等）统一返回极简 `404 Not Found` —— 不跳转登录页、不含品牌与版本、不设置 `Server`/`X-Powered-By`。
2. 命中入口后未登录：显示登录页（只需输入令牌，没有用户名、没有默认账号）。
3. 登录成功下发 HttpOnly Cookie（`SameSite=Lax`，7 天有效，纯 HTTP 不加 `Secure`；配置 `secure_cookie=true` 时才加）。
4. API 与 SSE 只接受 `Authorization: Bearer <token>` 或该 Cookie。**`?token=` 形式一律无效** —— URL 里的令牌会进浏览器历史、access log、反向代理日志与 Referer。
5. 令牌比较走 `crypto/subtle.ConstantTimeCompare`。
6. 登录失败按来源 IP 节流：前 5 次正常拒绝，之后每次失败额外等待 2 秒；失败计数窗口 5 分钟，登录成功立即清零；追踪表上限 4096 项、过期项自动 GC。来源 IP 取 `RemoteAddr`，**不信任 `X-Forwarded-For`**（否则换个头就能绕过并撑爆状态表）。
7. `POST /login` 请求体上限 64 KiB，超限直接 `413`，绝不截断后继续解析。

`/healthz` 只对 **loopback** 开放（安装器与 systemd 检查走 `127.0.0.1`）；外部访问与未知路径一样得到普通 404，公网扫描器无法通过裸 `/healthz` 确认这是管理服务。

> 这些措施的作用是**降低公网批量扫描命中与 Web 面板指纹暴露面**，不是也无法保证「防 GFW」或「不被封 IP」。面板本身是 HTTP 明文服务，若需要传输加密请自行前置 HTTPS 反代并开启 `secure_cookie`。

## 用法

- **Web 面板**：新增/编辑/启停/删除转发规则、配额、IP 限制。添加规则只需填：名称、协议、监听端口（可留空随机）、目标地址、目标端口。
- **SSH 菜单**：服务状态/启停/日志/面板信息/更新/自检。规则 CRUD 统一走 Web 面板，避免两套写路径。

## 数据模型

转发规则字段：`id`（稳定不复用）/`name`/`enabled`/`protocol`/`listen_port`/`target_address`/`target_port`/`created_at`/`updated_at`/软删除 + 配额 + IP 限制 + 运行时解析结果（`resolved_ipv4`/`resolved_ipv6`/`resolve_status`，只读）。

`target_address` **永远保存用户填写的原始值** —— 域名保持域名，绝不被解析结果覆盖。

`panel.json` 里与安全相关的三项（`port` / `token` / `entry_path`）**没有默认值**：缺失即视为未初始化，`serve` 会 fail-closed 拒绝启动，而不是退回某个固定值。三项都由安装期的 `config-ensure-*` 用 `crypto/rand` 生成一次，此后服务重启、在线升级、重复运行安装脚本都不会改变。

## 设计要点

**所有规则变更走同一个入口。** 规则 CRUD、配额、IP 限制、DNS 更新都经过 `internal/rulesvc`：candidate → 校验 → 解析 → 冲突检查 → `nft -c` 干跑 → 应用 → DB 提交，任一步失败双向回滚。因此「API 返回成功」严格等价于「数据库与 nftables 一致」。

**nft 同步分两层，这是流量统计正确性的关键。** named counter 是 nftables 的表级对象，销毁重建表会连同累计字节一起清零。策略 reconcile 是 500ms 周期的，如果每轮都重建表，counter 会被反复清零、绝大部分流量丢失。因此：

- **结构层**（表 / 链 / counter / set 声明）：只在结构签名变化**或期望对象缺失**时同步。用幂等 `table {...}` 声明 + `flush chain` 重建链内规则，从不销毁表，已存在的 counter 保留累计值。整个脚本是单个 `nft -f` 原子事务，没有规则缺失窗口。
- **元素层**（allow set 成员、配额阻断集合）：在线 IP 上下线、配额状态翻转只走 `nft add/delete element`，完全不触碰表、链、counter。无变化时不调用 nft。

**自愈基于完整 Desired State 比对。** 每轮 reconcile 把「当前规则集应该存在的全部自有对象」与 `nft -j list ruleset` 读回的现状做比对：三张表（`nff_nat4`/`nff_nat6`/`nff_filter`）、各自的链、`marks`/`qblock`/IPv4+IPv6 allow set、每条规则的 up **和** down counter、以及各链内的最小规则条数。任何一项缺失都触发一次幂等重建，因此人为 `nft delete table/chain/counter/set` 都能在下一轮自动恢复，且仍然只碰 `nff_*` 自有对象、绝不 `flush ruleset`、尽可能保留仍存在的 counter 数值。

**每条 DNAT 都带 `fib daddr type local`。** 规则没有监听地址，若直接写 `tcp dport 5000 dnat to ...`，那么当这台机器同时承担路由/网关职责时，仅仅经过本机（目的地址是别人）的同端口流量也会被劫持。`fib daddr type local` 让规则只匹配「目的地址属于本机」的包，等价于「监听本机所有本地地址」，同时不误伤 transit 流量。

**结构 enforcement 与 IP Slot enforcement 彻底解耦。** 两者对 conntrack 的依赖完全不同：

- **静态/结构层不依赖 conntrack**：DNAT、FORWARD counter、配额阻断、规则新增/删除/修改/启停、nft 对象自愈。conntrack 挂掉时这些必须照常执行 —— 否则会出现「用户删除规则 → API 返回成功 → DB 已删 → nft 旧 DNAT 还在转发」的假成功。
- **动态 IP Slot 层依赖 conntrack**：observed / candidate / active / granted / rejected / slot 释放。

conntrack 读取失败、不完整、不可用、或无法确认真实连接状态时，**冻结上一轮 slot 状态**：不新增、不释放、不清空 allow set（`/api/health` 会给出 `ip_state_frozen`）。只有「成功读取且结果真实为空」才允许释放 slot —— 「读不到」绝不等于「没人在线」。

**conntrack 扫描是 O(规则数 + flow 数)。** 每轮先一次遍历 conntrack 建 `(protocol, 原始目标端口) → flows` 索引，之后每条规则 O(1) 取出属于自己的流；同一次扫描内顺带收集 `seenFlowKeys` 供 flow GC 使用。旧实现是「每条规则重新遍历全部 flows」的 O(R×F)。

**flowState 不会无界增长。** 每轮记录本轮出现过的流键，轮末回收「conntrack 中已不存在」的旧 entry；规则删除时按前缀清理该规则的全部流状态。空闲判活改为按「最近一次字节变化时刻」计算并保留 entry（旧实现超窗即删除 entry，下一轮同一条流又被当成新流判为有流量，导致空闲连接永不离线）。

**DNS 查询绝不在锁内进行。** 一轮域名刷新分三段：锁内 snapshot 需要解析的规则（含目标与 `updated_at` 指纹）→ 释放锁并发解析（并发上限 8，每次查询 5s 超时）→ 重新加锁校验规则未被改动后才 apply。解析期间用户改了目标或删了规则，过期结果一律丢弃。因此一次 DNS 超时不会把其它规则的 CRUD 卡住，`last-known-good` 语义保持不变。

**域名目标保留 last-known-good。** DNS 临时失败时沿用上次有效地址（状态标记 `stale`），不会因为一次解析抖动切断转发；多 A/AAAA 记录时，只要当前使用的地址仍在结果集里就不切换。解析结果变化只重写链规则，counter 不受影响。彻底解析失败（连历史地址都没有）时该规则不产生 DNAT 规则，但 counter、配额、IP 限制状态全部保留。

**配额判定是实时的。** collector 每 `interval`（默认 2s）才刷一次 SQLite，只看已落库 totals 会在高带宽下明显超额。策略层用 `已落库累计 + (当前 nft counter − 已落库 counter 基线)` 计算实时用量；当前读数取自 policy 本轮就要执行的那次 `nft -j list ruleset`，不额外增加系统调用，也不会重复计费。SQLite 仍是唯一的历史统计来源，重启后继续差分，`reset quota` 只重置基线、不删历史。

**IP 限制的 drop 规则必须限定 `ct direction original`。** FORWARD 链同时看到往返两个方向，reply 方向的源地址是后端目标，永远不在客户端 allow set 里——不限定方向会把返回包全部丢弃，启用 IP 限制等于切断转发。

**流量计数挂 FORWARD 链而非 NAT 链**，NAT 链只在连接首包做决策。多规则指向同一目标时用 `ct mark`（PREROUTING 时按监听端口打标）归属，避免流量混算。

**API 快照没有 N+1 查询。** 全量快照的累计流量与今日流量各用一条带参数占位符的批量 SQL 读取（`WHERE rule_id IN (?,?,…)`），不再对每条规则各发一次 `QueryRow`。

## 安全承诺

- 程序只管理 `nff_nat4` / `nff_nat6` / `nff_filter` 三个自有表，只删除 `nff_` 前缀的对象。
- 绝不执行 `nft flush ruleset`，绝不清空 INPUT/OUTPUT/FORWARD，绝不修改默认 policy，绝不触碰 Docker / firewalld / 用户自有表。
- 所有 nft 变更先 `nft -c -f` 干跑检查，通过后才 `nft -f` 应用；失败不写入成功状态。
- 配置写入是原子的（tmp → fsync → chmod 0600 → rename → fsync 目录）；配置损坏时 fail-closed，绝不用默认值覆盖，也绝不因此重置令牌/端口/入口路径。
- 首次安装若服务启动或健康检查未通过：退出码非 0、不打印「安装完成」、保留现场供排错。
- 升级是事务化的：备份旧二进制与 `panel.json` → 下载 → SHA256 校验 → 架构与版本自检 → 原子替换 → 配置迁移 → 重启 → systemd active → localhost `/healthz` → `selftest`，**全部通过后**才删除备份。任一步失败即恢复旧二进制与旧配置、重启旧服务并再次验证；确认恢复成功才提示「已回滚」，回滚失败会明确报错。
- 升级保留：转发规则、流量历史、访问令牌、随机面板端口、随机入口路径及其它用户设置。数据库迁移只 `ADD COLUMN`，不 DROP、不重建表。
- 卸载只删自有表与自有文件，数据目录需显式确认才删。

## 已知限制

- **IP 限制的授予存在毫秒级竞态**：方案是「放行 SYN 让 conntrack 看到候选 → 准入循环授予 slot → 后续 established 流量放行」。准入循环每 500ms 跑一轮，因此新 IP 的连接在被授予前的极短窗口内，其 established 数据包会被 drop（客户端表现为首次请求偶发失败、重试即成功）。拒绝（超出上限）是可靠的，不会超卖。
- **UDP 判活只能靠空闲窗口**：UDP 无连接状态，conntrack 流不会因对端离开而消失，因此「在线」判定依赖 `udpIdle`（默认 120s）空闲超时，收敛比 TCP 慢。
- **配额实时性受 reconcile 周期限制**：判定周期是 500ms，因此理论上最多多跑「500ms × 当前带宽」，而不是「SQLite 刷盘间隔 × 带宽」。
- 只支持同族转发（IPv4→IPv4、IPv6→IPv6），不做 NAT64/46。
- 面板是 HTTP 明文服务，不内置 TLS。需要传输加密请自行前置反代并设置 `secure_cookie=true`。

## 构建

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o nft-forward ./cmd/nft-forward
./scripts/build-release.sh dist     # 全架构交叉编译 + SHA256SUMS
bash scripts/artifact_check.sh dist # 产物与版本一致性自检
```

## 测试

```bash
gofmt -l .           # 格式
go vet ./...         # 静态检查
go test ./...        # 单元测试
go test -race ./...  # 竞态检测（需 CGO/gcc）

bash tests/installer_flow_test.sh   # 安装/升级流程（提取 install.sh 真实实现）
bash tests/baseline_test.sh         # v0.3.1 基线收口防回归
```

真实环境端到端验证（需 root + nftables，会创建 network namespace）：

```bash
bash scripts/e2e_netns.sh setup   # 搭建 client×3 / backend 命名空间 + 10MiB HTTP 后端
bash scripts/e2e_full.sh          # 转发/统计/配额/IP限制/counter/域名/SSE
bash scripts/e2e_fault.sh         # 认证/暴露面/nft 自愈/一致性/重启保持
bash scripts/e2e_netns.sh clean   # 清理
```

`e2e_full.sh` 覆盖：随机端口区间、转发实通、30MiB 流量入账误差、配额阻断与重置
（重置不清历史）、IP 限制 max=2 无超卖、周期 reconcile 不清零 counter、域名目标
DNS 变化不清 counter、SSE 存活 > 60s。

`e2e_fault.sh` 覆盖：未认证拒绝、Bearer/Cookie 有效、`?token=` 无效、登录体 413、
失败节流与「正确令牌不被拖慢」、XFF 不能绕过节流、`panel.json` 0600、五位数随机端口、
根路径与常见扫描路径的极简 404、裸 `/healthz` 不泄漏、安全响应头与 CSP、
真实删除表/链/counter/set 后的自愈、删除规则后 nft 真的撤销、重启后端口/入口/令牌不变。

单项复查脚本（同样需要先 `e2e_netns.sh setup`）：

```bash
scripts/verify_traffic.sh      # 10MiB × 3 流量统计误差 < 5%
scripts/verify_iplimit.sh      # max=2 占满后第三个 IP 被拒
scripts/verify_quota.sh        # 超限阻断 + 重置恢复 + 历史保留
scripts/verify_sse.sh          # SSE 长连接不被 60s 切断
scripts/cleanup_test_env.sh    # 清理
```

这些脚本通过 `scripts/e2e_common.sh` 自动从 `panel.json` 读取随机端口、随机入口与令牌，无需手工传参。

> 注意：不要用「本机 curl 自己的转发端口」验证转发。本机自发流量走 nat OUTPUT
> 钩子，不经 PREROUTING/FORWARD，DNAT 与 counter 按设计不会命中 —— 必须用
> netns 客户端（或真实外部机器）产生流量。
