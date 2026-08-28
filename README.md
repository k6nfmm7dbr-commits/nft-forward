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

## 安全承诺

- 程序只管理 `nff_nat4` / `nff_nat6` / `nff_filter` 三个自有表。
- 绝不执行 `nft flush ruleset`，绝不触碰系统已有防火墙规则（Docker、SSH、firewalld 等）。
- 卸载只删除自有表与自有文件。

## 已知限制

- **IP 限制存在竞态**：「放行 SYN 以观测候选、丢 ESTABLISHED 非授权流量」的方案存在固有竞态，连接的 ACK 可能在 slot 授予（500ms 周期）前被丢弃。拒绝（超容量）是可靠的，但授予存在竞态窗口。此问题需要「SYN 时同步授予 slot」的机制才能彻底解决。

## 构建

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o nft-forward ./cmd/nft-forward
```

## 测试

```bash
go test ./...        # 单元测试
go test -race ./...  # 竞态检测（需 CGO/gcc）
```
