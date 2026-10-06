# FUTURE_IMPROVEMENTS

记录评估过但**暂不实施**的改进项（稳定性优先于理论收益），以及每一轮审计的结论。
本文件与 SBX 的同名文件保持同样的定位：写清楚「为什么不动」比写「还能怎么改」更重要。

---

## 1. v0.4.0 审计（与 SBX 对齐改造）

### 1.1 本轮已做

| 项 | 证据 / 结果 |
|---|---|
| 面板改浅色主题 | 纯视觉层；JS id / `data-*` / 状态类名与接口语义未变 |
| 移除顶部品牌/状态栏 | 连接状态移入速率卡片，退出登录移到底部 |
| 规则卡片加「转发地址 + 一键复制」 | 用 `location.hostname` + 监听端口，纯 HTTP 下用 textarea 回退 |
| 前端渲染不再全量重建 | 结构签名 + 定点更新（浏览器实测：同一次轮询后卡片节点未变，改名才重建） |
| 趋势数据按规则缓存 + 过期响应丢弃 | 60 秒新鲜度 + 请求代次 |
| 轮询按页签节流 | 非总览页不再拉 2s 实时速率 |
| 内嵌资源进程内缓存 | 省掉每请求 31KB/22KB/13KB 的重复读取拷贝 |
| 安装器脚本 SHA256 自校验 | 升级路径在执行新脚本前验签；脚本/校验和/二进制同源 revision |
| CI 增加 musl 与 govulncheck | 覆盖「宣称静态单二进制」与供应链可见性 |
| systemd `StartLimitIntervalSec=0` | 防止面板被 systemd 启动次数限制判死后「突然打不开」 |

### 1.2 评估过但不做（附理由）

- **策略 reconcile 的 500ms 周期**：`runPolicy` 每 500ms 一轮，每轮包含
  1 次 SQLite 查询 + 1 次完整 conntrack 解析 + 1 次 `nft -j list` 读数
  （实测单次 `nft` exec 约 4~5ms）。这是稳态下最大的固定开销，但周期是**刻意**
  的：IP 准入要在新 IP 的 SYN 到达后尽快授予 slot，否则会出现「已放行 SYN、
  但 allow set 还没更新」的窗口。降周期或让读数与 slot 解耦都会改变
  IP 限制的响应语义与自愈延迟，需要真机 A/B 与竞态测试，本轮不做。
  重启该工作的入口：给 `nft` 读数加「结构签名未变且距上次读数 < N 秒则复用
  上一轮状态 + 本地已应用元素」的路径，并把外部漂移检测周期单独拉长；
  必须同时证明「外部删表/改内容仍能被发现」（现有 `DetectDrift` 测试是基线）。
- **`snapshotStructKey` 的全量 JSON 序列化**：用于 SSE 结构变化判据。当前只在
  **存在订阅者**时才计算（`PublishSnapshotTick` 先查订阅数），面板关闭时零成本；
  规则数量级（几十条）下不值得换成手写哈希，手写哈希一旦漏字段就会丢推送。
- **SQLite 连接数**：保持 `MaxOpenConns(1)` + `busy_timeout=30000`。WAL 下读可以
  并发，但单连接让「写事务 + 读」天然串行、彻底避免 `SQLITE_BUSY`；换成读写分离
  需要重新论证事务边界与迁移路径，收益在面板这种请求量下不明显。
- **`policy.States()` 的 map 拷贝**：每次快照构建拷贝一次规则状态 map（几十条），
  量级在微秒，改成共享只读视图会引入「调用方误改已发布状态」的风险。
- **安装器 `--update --version <x>` 降级**：需要 dist 保留版本化归档
  （`dist/archive/<version>/<commit7>/`，SBX 有）。当前升级回滚依赖本地 `.bak`
  （脚本 + 二进制 + panel.json 三份备份，且回滚后再次验证服务健康），已覆盖
  常见故障；归档的价值是「本地备份也被覆盖后再降级」，优先级低于其它项。
- **nft 计数器 netlink 直读**：省掉 `nft` fork/exec，但需要引入 netlink 依赖与
  内核特性探测，而「转发计数不能失真」是本项目最高优先级。与 SBX 的结论一致：
  留待有明确收益证据时再做。

### 1.3 稳定性排查记录：面板「有时候突然打不开」

用户报告面板偶发不可用。本轮把可能原因逐条对照代码确认，并做掉了能确定的两条：

1. **systemd 启动次数限制**（已修）：默认 `StartLimitBurst=5` / `StartLimitIntervalSec=10s`，
   服务连续快速重启到上限后 systemd **彻底停止拉起**，面板保持不可用直到人工
   `systemctl start`。这正是「突然打不开、过一会儿/手动才恢复」的典型形态。
   现在 `StartLimitIntervalSec=0`（永不放弃），退避由 `RestartSec=3` 提供。
2. **前端失败静默**（已修）：此前 API 连续失败时页面只是不再更新，看起来像坏了；
   现在状态条会明确显示「连接异常 · 正在重试」，恢复后自动切回。
3. 已确认**不存在**的怀疑项（查过代码）：
   - 沙箱写权限：所有运行期写入（`panel.json` / `traffic.db` / `nft.conf` /
     `nft.conf.elem`）都走 `fsx.WriteFileAtomic` 且都在 `$APP_DIR` 内，
     `ReadWritePaths=$APP_DIR` 已覆盖（SBX 曾在此踩坑，本项无问题）。
   - SSE 被 `WriteTimeout` 掐断：`handleEvents` 已用 `ResponseController` 清除写截止时间。
   - HTTP 层无超时：`ReadHeaderTimeout/ReadTimeout/WriteTimeout/IdleTimeout` 均已设置。
   - 入口路径尾斜杠：`/entry` 会 302 到 `/entry/`，不会出现资源 404。
   - 请求处理 panic：`recover` 中间件在位，且外部输入（nft JSON / conntrack）
     解析全部使用带 `ok` 的类型断言，没有裸断言。
4. **仍需线上证据的部分**：若再次出现，请提供当时的现象（浏览器显示的是
   「无法连接」还是 404/500 页面）+ `journalctl -u nft-forward -n 200` 与
   `systemctl status nft-forward` 输出。有了这两份，可以直接判定是进程重启、
   DB 等待（`busy_timeout` 最长 30s）还是路径/端口问题。
