# NFT Forward

基于 **nftables** 的高性能端口转发 + 流量监控面板。Go 单二进制、原生 Web UI、SQLite 持久化。

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
- **流量统计**：上传/下载分方向统计，counter 挂在 **FORWARD** 链（非 NAT 链），用 `ct mark` 归属多规则同目标场景。
- **在线 IP 限制**：Slot Manager（observed/candidate/active/granted/rejected），基于 conntrack 生命周期判活。
- **流量配额**：超出阻断该规则转发，提高/重置即恢复。
- **实时面板**：SSE 推送 + 局部 DOM 更新，原生 HTML/CSS/JS（无框架）。
- **安全**：只管理 `nff_*` 自有 nft 表，绝不 `flush ruleset`；随机高熵 token + HttpOnly Cookie。

## 安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/k6nfmm7dbr-commits/nft-forward/main/install.sh)
```

或手动：

```bash
# 下载对应架构的二进制
curl -fsSL -o /usr/local/bin/nft-forward https://github.com/k6nfmm7dbr-commits/nft-forward/releases/latest/download/nft-forward-linux-amd64
chmod +x /usr/local/bin/nft-forward
nft-forward config-ensure-token     # 生成面板令牌
nft-forward serve                   # 启动（建议配 systemd）
```

面板默认监听 `0.0.0.0:8090`，令牌在 `/etc/nft-forward/panel.json`。

## 用法

- **Web 面板**：新增/编辑/启停/删除转发规则、配额、IP 限制。
- **SSH 运维菜单**：`nft-forward`（无参数）——服务状态/启停/日志/重置令牌/自检。规则 CRUD 统一走 Web 面板。

## 数据模型

转发规则字段：`id`（稳定不复用）/`name`/`enabled`/`protocol`/`listen_address`/`listen_port`/`target_address`/`target_port`/`created_at`/`updated_at`/软删除 + 配额 + IP 限制。

## 设计要点

**nft 同步分两层，这是流量统计正确性的关键。** named counter 是 nftables 的表级对象，销毁重建表会连同累计字节一起清零。策略 reconcile 是 500ms 周期的，如果每轮都重建表，counter 会被反复清零、绝大部分流量丢失。因此：

- **结构层**（表 / 链 / counter / set 声明）：只在结构签名变化时同步。用幂等 `table {...}` 声明 + `flush chain` 重建链内规则，从不销毁表，已存在的 counter 保留累计值。整个脚本是单个 `nft -f` 原子事务，没有规则缺失窗口。
- **元素层**（allow set 成员、配额阻断集合）：在线 IP 上下线、配额状态翻转只走 `nft add/delete element`，完全不触碰表、链、counter。无变化时不调用 nft。

**IP 限制的 drop 规则必须限定 `ct direction original`。** FORWARD 链同时看到往返两个方向，reply 方向的源地址是后端目标，永远不在客户端 allow set 里——不限定方向会把返回包全部丢弃，启用 IP 限制等于切断转发。

**流量计数挂 FORWARD 链而非 NAT 链**，NAT 链只在连接首包做决策。多规则指向同一目标时用 `ct mark`（PREROUTING 时按监听端口打标）归属，避免流量混算。

**conntrack 读取不完整时进入 fail-safe**：沿用上一轮 slot，不释放、不新授、不改 nft，宁可短暂放行也不误踢在线用户。

## 安全承诺

- 程序只管理 `nff_nat4` / `nff_nat6` / `nff_filter` 三个自有表，只删除 `nff_` 前缀的对象。
- 绝不执行 `nft flush ruleset`，绝不触碰系统已有防火墙规则（Docker、SSH、firewalld 等）。
- 所有 nft 变更先 `nft -c -f` 干跑检查，通过后才 `nft -f` 应用；失败不写入成功状态。
- 卸载只删除自有表与自有文件。

## 已知限制

- **IP 限制的授予存在毫秒级竞态**：方案是「放行 SYN 让 conntrack 看到候选 → 准入循环授予 slot → 后续 established 流量放行」。准入循环每 500ms 跑一轮，因此新 IP 的连接在被授予前的极短窗口内，其 established 数据包会被 drop（客户端表现为首次请求偶发失败、重试即成功）。拒绝（超出上限）是可靠的，不会超卖。彻底消除需要「SYN 时同步授予 slot」的内核侧机制。
- **UDP 判活只能靠空闲窗口**：UDP 无连接状态，conntrack 流不会因对端离开而消失，因此「在线」判定依赖 `udpIdle`（默认 120s）空闲超时，收敛比 TCP 慢。
- 只支持同族转发（IPv4→IPv4、IPv6→IPv6），不做 NAT64/46。

## 构建

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o nft-forward ./cmd/nft-forward
```

## 测试

```bash
go test ./...        # 单元测试
go test -race ./...  # 竞态检测（需 CGO/gcc）
```

真实环境端到端验证（需 root + nftables，会创建 network namespace）：

```bash
scripts/e2e_netns.sh setup     # 搭建 client/backend 命名空间
scripts/verify_traffic.sh      # 10MiB × 3 流量统计误差 < 5%
scripts/verify_iplimit.sh      # max=2 占满后第三个 IP 被拒
scripts/verify_quota.sh        # 超限阻断 + 重置恢复 + 历史保留
scripts/verify_sse.sh          # SSE 长连接不被 60s 切断
scripts/cleanup_test_env.sh    # 清理
```
