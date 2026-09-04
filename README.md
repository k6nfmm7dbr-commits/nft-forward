# NFT Forward

基于 **nftables** 的端口转发 + 流量监控面板。Go 单二进制、原生 Web UI、SQLite 持久化。

## 当前版本

```text
v0.3.0
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
- **只配监听端口**：规则没有「监听地址」概念，自动作用于本机所有本地地址；留空则由后端随机分配一个安全端口。
- **目标支持 IPv4 / IPv6 / 域名**：域名在后台周期解析并自动跟踪变化，双栈分别落到 IPv4 / IPv6 数据面。
- **流量统计**：上传/下载分方向，counter 挂在 **FORWARD** 链（非 NAT 链），用 `ct mark` 归属多规则同目标场景。
- **在线 IP 限制**：Slot Manager（observed/candidate/active/granted/rejected），基于 conntrack 生命周期判活。
- **流量配额**：超出阻断该规则转发，提高/重置即恢复，历史统计不丢。
- **实时面板**：SSE 推送 + 局部 DOM 更新，原生 HTML/CSS/JS，无框架、无构建链。
- **安全**：只管理 `nff_*` 自有 nft 表，绝不 `flush ruleset`。面板默认仅本机监听（`0.0.0.0:8090`），无认证。

## 安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/k6nfmm7dbr-commits/nft-forward/main/install.sh)
```

安装完成后运行 `nff` 打开管理菜单。面板默认监听 `0.0.0.0:8090`，无访问令牌（仅本机监听场景）。

常用命令：

```bash
nff                  # 管理菜单（面板信息 / 设置 / 服务 / 自检 / 更新 / 卸载）
nff --update         # 在线升级（保留转发规则与流量历史）
nff --selftest       # 自检
nff --clear-firewall # 只移除自有 nft 表
nff --uninstall      # 卸载
```

## 用法

- **Web 面板**：新增/编辑/启停/删除转发规则、配额、IP 限制。添加规则只需填：名称、协议、监听端口（可留空随机）、目标地址、目标端口。
- **SSH 菜单**：服务状态/启停/日志/自检/更新。规则 CRUD 统一走 Web 面板，避免两套写路径。

## 数据模型

转发规则字段：`id`（稳定不复用）/`name`/`enabled`/`protocol`/`listen_port`/`target_address`/`target_port`/`created_at`/`updated_at`/软删除 + 配额 + IP 限制 + 运行时解析结果（`resolved_ipv4`/`resolved_ipv6`/`resolve_status`，只读）。

`target_address` **永远保存用户填写的原始值** —— 域名保持域名，绝不被解析结果覆盖。

## 设计要点

**所有规则变更走同一个入口。** 规则 CRUD、配额、IP 限制、DNS 更新都经过 `internal/rulesvc`：candidate → 校验 → 解析 → 冲突检查 → `nft -c` 干跑 → 应用 → DB 提交，任一步失败双向回滚。因此「API 返回成功」严格等价于「数据库与 nftables 一致」。

**nft 同步分两层，这是流量统计正确性的关键。** named counter 是 nftables 的表级对象，销毁重建表会连同累计字节一起清零。策略 reconcile 是 500ms 周期的，如果每轮都重建表，counter 会被反复清零、绝大部分流量丢失。因此：

- **结构层**（表 / 链 / counter / set 声明）：只在结构签名变化时同步。用幂等 `table {...}` 声明 + `flush chain` 重建链内规则，从不销毁表，已存在的 counter 保留累计值。整个脚本是单个 `nft -f` 原子事务，没有规则缺失窗口。
- **元素层**（allow set 成员、配额阻断集合）：在线 IP 上下线、配额状态翻转只走 `nft add/delete element`，完全不触碰表、链、counter。无变化时不调用 nft。

**每条 DNAT 都带 `fib daddr type local`。** 规则没有监听地址，若直接写 `tcp dport 5000 dnat to ...`，那么当这台机器同时承担路由/网关职责时，仅仅经过本机（目的地址是别人）的同端口流量也会被劫持。`fib daddr type local` 让规则只匹配「目的地址属于本机」的包，等价于「监听本机所有本地地址」，同时不误伤 transit 流量。

**域名目标保留 last-known-good。** DNS 临时失败时沿用上次有效地址（状态标记 `stale`），不会因为一次解析抖动切断转发；多 A/AAAA 记录时，只要当前使用的地址仍在结果集里就不切换，避免无意义的规则重写。解析结果变化只重写链规则，counter 不受影响。彻底解析失败（连历史地址都没有）时该规则不产生 DNAT 规则，但 counter、配额、IP 限制状态全部保留。

**IP 限制的 drop 规则必须限定 `ct direction original`。** FORWARD 链同时看到往返两个方向，reply 方向的源地址是后端目标，永远不在客户端 allow set 里——不限定方向会把返回包全部丢弃，启用 IP 限制等于切断转发。

**流量计数挂 FORWARD 链而非 NAT 链**，NAT 链只在连接首包做决策。多规则指向同一目标时用 `ct mark`（PREROUTING 时按监听端口打标）归属，避免流量混算。

**conntrack 读取不完整时进入 fail-safe**：沿用上一轮 slot，不释放、不新授、不改 nft，宁可短暂放行也不误踢在线用户。

## 安全承诺

- 程序只管理 `nff_nat4` / `nff_nat6` / `nff_filter` 三个自有表，只删除 `nff_` 前缀的对象。
- 绝不执行 `nft flush ruleset`，绝不清空 INPUT/OUTPUT/FORWARD，绝不修改默认 policy，绝不触碰 Docker / firewalld / 用户自有表。
- 所有 nft 变更先 `nft -c -f` 干跑检查，通过后才 `nft -f` 应用；失败不写入成功状态。
- 配置写入是原子的（tmp → fsync → chmod 0600 → rename → fsync 目录）；配置损坏时 fail-closed，绝不用默认值覆盖。
- 升级保留 `traffic.db` / `panel.json`；数据库迁移只 `ADD COLUMN`，不 DROP、不重建表。
- 卸载只删自有表与自有文件，数据目录需显式确认才删。

## 已知限制

- **IP 限制的授予存在毫秒级竞态**：方案是「放行 SYN 让 conntrack 看到候选 → 准入循环授予 slot → 后续 established 流量放行」。准入循环每 500ms 跑一轮，因此新 IP 的连接在被授予前的极短窗口内，其 established 数据包会被 drop（客户端表现为首次请求偶发失败、重试即成功）。拒绝（超出上限）是可靠的，不会超卖。
- **UDP 判活只能靠空闲窗口**：UDP 无连接状态，conntrack 流不会因对端离开而消失，因此「在线」判定依赖 `udpIdle`（默认 120s）空闲超时，收敛比 TCP 慢。
- 只支持同族转发（IPv4→IPv4、IPv6→IPv6），不做 NAT64/46。

## 构建

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o nft-forward ./cmd/nft-forward
./scripts/build-release.sh dist     # 全架构交叉编译 + SHA256SUMS
bash scripts/artifact_check.sh dist # 产物与版本一致性自检
```

## 测试

```bash
go test ./...        # 单元测试
go test -race ./...  # 竞态检测（需 CGO/gcc）

bash tests/installer_flow_test.sh   # 安装/升级流程（提取 install.sh 真实实现）
bash tests/baseline_test.sh         # v0.3.0 基线收口防回归
```

真实环境端到端验证（需 root + nftables，会创建 network namespace）：

```bash
bash scripts/e2e_netns.sh setup   # 搭建 client×3 / backend 命名空间 + 10MiB HTTP 后端
bash scripts/e2e_full.sh          # 一次跑完 9 组断言（转发/统计/配额/IP限制/counter/域名/SSE）
bash scripts/e2e_netns.sh clean   # 清理
```

`e2e_full.sh` 覆盖：随机端口区间、转发实通、30MiB 流量入账误差、配额阻断与重置
（重置不清历史）、IP 限制 max=2 无超卖、周期 reconcile 不清零 counter、域名目标
DNS 变化不清 counter、SSE 存活 > 60s。

单项复查脚本（同样需要先 `e2e_netns.sh setup`）：

```bash
scripts/verify_traffic.sh      # 10MiB × 3 流量统计误差 < 5%
scripts/verify_iplimit.sh      # max=2 占满后第三个 IP 被拒
scripts/verify_quota.sh        # 超限阻断 + 重置恢复 + 历史保留
scripts/verify_sse.sh          # SSE 长连接不被 60s 切断
scripts/cleanup_test_env.sh    # 清理
```

> 注意：不要用「本机 curl 自己的转发端口」验证转发。本机自发流量走 nat OUTPUT
> 钩子，不经 PREROUTING/FORWARD，DNAT 与 counter 按设计不会命中 —— 必须用
> netns 客户端（或真实外部机器）产生流量。
