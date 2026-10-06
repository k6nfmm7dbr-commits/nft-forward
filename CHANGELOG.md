# 更新日志

本项目使用「版本号 + 提交」双重标识：`APP_VERSION` 不随每次改动递增，
产物由 CI 从 `main` 的每次推送重建并发布到 `dist` 分支（rolling latest）。
安装器与它的 SHA256 也随产物一起发布，升级路径可对**脚本本身**做密码学校验。

## v0.4.0 — 浅色面板重做、安装器完整性、热路径优化

本轮是与姊妹项目 SBX 对齐的全面改造：视觉、安装链路、CI 覆盖与稳态开销。

### 面板：暗色 → 浅色

- 面板整体从暗色 Graphite 主题改为与 SBX 一致的浅色主题：调色板、卡片层级、
  抽屉/遮罩、开关、危险操作区、状态徽标全部重新配色。
- 纯视觉层改动：所有 JS id、`data-*` 钩子、状态类名与接口语义保持不变，
  没有增删任何字段或行为。`color-scheme` 与滚动条配色同步为浅色。
- 深色主题下依赖「浅色文字 + 深色底」的次级按钮（`mini-btn.primary`）改为
  主色文字 + 淡主色底，避免浅色背景上对比度不足。

### 面板：移除顶部栏、增加可复制的转发地址

- **移除顶部品牌/状态栏**（与 SBX 一致）：首页直接从「实时速率」卡片开始。
  连接状态（实时监控中 / 等待采集 / 连接异常）移到速率卡片右上角，信息不丢但
  不再占据首屏一整条；退出登录移到页面底部（低频操作）。
- **移除实时速率卡片顶部的蓝色装饰条**（`.hero::after`），首屏不再有任何纯装饰元素。
- **规则卡片去掉「监听端口」一行**：端口已在转发地址里，重复展示只占地方；
  卡片元信息只保留协议标签。
- **规则卡片新增「转发地址」行与复制**：显示 `IP 端口`（空格分隔，两个 token
  各自可点按复制），右侧「复制」按钮复制可直接粘贴的 `IP:端口`。刻意不用后端
  探测的「本机 IP」—— 那是主机属性而不是规则属性，多网卡/多 IP 时必然误导
  （后端已因此删掉 `listen_addr`）；用当前访问面板的主机则永远等于你实际能连通
  的那条路径。规则详情抽屉里也有同一份地址与复制按钮。
- 纯 HTTP 下面板拿不到 `navigator.clipboard`（非安全上下文），因此复制带
  textarea + `execCommand` 回退，保证在真实部署形态下可用。

### 稳定性

- **连接异常自愈提示**：连续 3 次 API 失败时状态条切为「连接异常 · 正在重试」，
  恢复后自动切回。此前网络/服务抖动时页面只是静止不动，看起来像「打不开」。
- **systemd 不再因启动次数超限而放弃拉起面板**：单元新增 `StartLimitIntervalSec=0`。
  systemd 默认「10 秒内 5 次启动」达到上限后会彻底停止拉起服务，那会让面板
  「突然打不开」且必须人工 `systemctl start` 才能恢复；`RestartSec=3` 已提供退避，
  因此这里把限制关掉。
- **内嵌前端资源进程内缓存**：此前每个请求都重新打开并整份拷贝 `app.js`(31KB) /
  `style.css`(22KB) / `index.html`(13KB)；资源由 `go:embed` 编进二进制，进程生命周期
  内不可能变化，改为只读共享一份。
- **前端渲染不再全量重建**：`/api/summary` 每 8 秒一次，旧实现每次都用
  `innerHTML` 把整组规则卡片销毁重建（滚动位置丢失、重排开销随规则数增长）。
  现在只在结构签名（id/名称/协议/端口/目标/启用/配额开关）变化时重建，其余
  定点更新；趋势数据按规则缓存并带 60 秒新鲜度，快速切换时用请求代次丢弃
  过期响应，绝不让旧规则的曲线覆盖当前选择。
- **轮询按页签节流**：趋势/规则页不再每 2 秒拉实时速率，总览页也不再重画隐藏的
  趋势表；离开总览即停止 live/summary 轮询，切回时立即补一次。

### 安装器：脚本自身完整性校验

- 发布产物新增 `install.sh` 与 `install.sh.sha256`（与 SBX 的 dist 布局一致）。
- `nff --update` 此前对新脚本只做 `bash -n` 与 `APP_VERSION` 存在性检查 ——
  一个语法正确的被篡改/损坏脚本会在 root 下直接执行。现在**执行前**校验
  SHA256：取到校验和就必须匹配（fail-closed），取不到才降级为告警 + 语法检查。
- 升级路径改为从**同一个 immutable dist revision** 取「脚本 + 校验和 + 二进制」，
  消除发布窗口内「新脚本 + 旧二进制」的错位组合（旧行为会白失败一次升级）。

### CI

- 新增 `test-alpine`（musl 下 gofmt/vet/test + 静态构建冒烟），覆盖「宣称静态
  单二进制」但此前只在 glibc 上验证的缺口。
- 新增 `vulncheck`（govulncheck，固定版本），独立于发布链：只提供可见信号，
  不阻断产物发布（漏洞库在线更新，卡住 dist 只会让用户停留在旧二进制上）。
- 发布流程同步发布并校验 `install.sh` / `install.sh.sha256`，且验证 raw 地址可用。

### 性能与稳定性

（见下方各条）

## v0.3.2

可靠性收口：DNS 事务一致性、nft 内容级自愈、数据面 readiness、conntrack 状态语义、
手工改端口事务、DB fail-closed、conntrack 解析性能、quota 边界。

升级保留转发规则、流量历史、访问令牌、面板端口与入口路径。

### DNS Refresh 的 DB + nft 事务一致性

- 旧顺序是「先 ApplyRules 到 nft → 再逐条 UpdateResolved 写库 → 写失败只打 warning」，
  一旦写库失败就留下「nft 用新地址、DB 记旧地址」的长期不一致
  （下一轮解析结果相同时甚至不会再触发同步）。
- 新增 `forward.Store.UpdateResolvedBatch`：`BEGIN → 批量写解析列 → ApplyRules → COMMIT`。
  - 写解析列失败 → ROLLBACK，nft 未被改动；
  - ApplyRules 失败 → ROLLBACK + nft 回滚到旧规则集；
  - COMMIT 失败 → 返回 `*forward.ErrCommitFailed`，调用方把 nft 回滚回旧状态并 ERROR。
- 一次 refresh 无论几条域名变化，都只有**一次 ApplyRules + 一次 commit**，没有多次中间状态。
- 解析期间用户改目标 / 删规则 → 过期结果丢弃，绝不覆盖新值、绝不让已删规则复活。
- `last-known-good` 语义不变：DNS 临时失败沿用旧地址、只更新状态文本。

### nft 自愈从「对象存在」升级为「内容正确」

- 旧判定只看表/链/set/counter 存在 + 链内规则条数，因此
  `dnat to 1.2.3.4:443` 被改成 `dnat to 8.8.8.8:443`（条数不变）完全漏检。
- 新增 `internal/nft/facts.go`：从 `nft -j` 的 expr 数组提取本程序关心的事实
  （协议、监听端口、DNAT 地址与端口、`ct mark` set/match、mark set 引用、
  `ct direction`、`ct state`、named counter 引用、源地址族与 allow set 引用、
  verdict、`fib daddr type local`、未识别表达式），生成 canonical signature。
- 新增 `internal/nft/intent.go`：规则意图是**文本脚本与期望签名的唯一来源**
  （`render()` 出脚本、`facts()` 出期望），杜绝「脚本改了、期望没改」的漂移。
- `State` 增加 `ChainRuleSigs` / `ChainAttrsMap`；`DetectDrift` 按序比较每条自有链的
  规则签名，并校验链的 type/hook/priority/policy。
- counter 的 packets/bytes **不参与签名**，因此有流量不会触发重建，
  named counter 累计值继续保留。
- 覆盖的篡改场景（全部新增测试）：DNAT 地址/端口/协议/监听端口被改、`ct mark` 被改、
  `fib daddr local` 被删、counter 引用被删/被换、allow set 被换错、配额 drop 改成 accept、
  masquerade 改成 accept、链 hook/priority/policy 被改、插入额外规则、
  删一条加一条（条数相同）、规则顺序被调换、`ct direction` 被改、`ct state` 被删。

### 数据面 readiness

- `/healthz` 的 200 不再只代表「Go HTTP 线程活着」，而是
  「进程已完成首轮 nft 数据面 enforcement」；未就绪返回 **503** + `{"ok":false}`。
- `Serve` 先绑定 HTTP（healthz 能应答），再做首轮 enforcement（最多重试 5 次、
  退避 1/2/3/4s）；成功才让 healthz 转 200。
- 安装器 `health_check` 等待窗口放宽到 20s 并识别 503，因此
  「HTTP 活着但转发没加载」不会再被当成安装/升级成功。
- conntrack 不可用**不影响** readiness（结构 enforcement 不依赖它，只有 IP slot 冻结）。
- `selftest` 新增 `data plane` 项：503 判 FAIL，连不上判 WARN。

### conntrack 状态语义与解析性能

- 新增 `Status` 枚举：`StatusOK` / `StatusUnavailable` / `StatusPartial` / `StatusError`，
  零值是 `StatusUnknown`（推导为不可用，fail-safe）。
  - 完整读取 + 0 条相关流 = 真的没人在线 → 允许释放 slot；
  - 文件不存在 / 无权限 / 内核未跟踪 → 冻结；
  - 读到一半失败 → 冻结；
  - **有行解析失败 → `StatusPartial` → 冻结**（旧实现静默忽略坏行并声称完整）。
- 解析改为 `bufio.Scanner` 单次流式扫描：同一趟完成条目统计、协议/状态过滤、
  字段解析、坏行计数、完整性判定。旧实现是「两次全文 `strings.Split`
  + 两次遍历 + 每行 `Fields`」。
- 协议名与 TCP 状态名 intern 成常量，去掉每条流的多余字符串分配。

### 手工修改面板端口

- 新增 CLI `panel-port-check` / `panel-port-set`，复用与首次安装等价的全部检查：
  1-65535、不等于当前端口、TCP/UDP 未占用、非 SSH 端口、非 `guard_ports`、
  非已有转发监听端口、bind 探测可用；ephemeral 区间只提示不拒绝。
- 校验失败**不写配置**。
- 安装器 `change_panel_port` 事务化：写入 → restart → active → 本机 healthz（含数据面）
  → 确认新端口真的在监听；任一步失败即写回旧端口、重启、再次验证，
  只有确认恢复才提示「已回滚」，否则明确 ERROR。Token 与入口路径全程不动。

### 规则里的「监听地址」彻底移除

- 删除 `RuleView.ListenAddr` / `listen_addr` JSON 字段、`detectHostIP()` 探测、
  前端 `pol-listen-ip` 输入框与卡片上的 `监听 <IP>:<端口>` 展示（改为「监听端口 N」）。
- 那是**主机属性而非规则属性**：多网卡/多 IP 时必然显示错误的地址，
  还会让人误以为规则只监听那一个 IP。数据面语义不变（仍由 `fib daddr type local` 决定）。
- 老客户端发送的 `listen_address` 仍被接受并忽略（升级兼容），响应里不再回显。

### DB fail-closed

- `ruleListenPorts` 现在区分「文件不存在（首次安装，返回空）」与
  「存在但打不开 / 损坏 / schema 异常 / 查询失败（返回 error）」。
- 后者会让 `EnsurePanelPort` 与 `ValidatePanelPort` 整体失败，不再在
  「不知道哪些端口正被转发占用」的情况下随机新端口（旧实现是 fail-open）。

### quota 边界

- 修正潜在双算：`LiveDelta.Used` 在「当前 counter < 已落库基线」时贡献 **0**。
  旧实现按「counter 被重置」把整个当前值再加一遍 —— 而 policy 读 nft 与
  collector 提交存在毫秒级错位，这会让用量瞬间翻倍、配额误判超限。
  真正的 counter 重置由 collector 的 reset 检测折进 committed，不会漏计。

### reconcile 原子性

- 明确：只有内核真正 apply 成功才更新 `lastStructSig`。`nft -c` 通过但 `nft -f`
  失败时保持旧签名，下一轮继续尝试修复（新增故障注入测试锁死）。

### 测试

- 新增：DNS 事务 12 项、nft 内容篡改自愈 18 项、意图↔事实同源 8 项、
  conntrack 四状态与坏行 15 项、readiness 5 项、listen_addr 移除 5 项、
  DB fail-closed 与手工改端口 14 项、quota 边界 6 项、reconcile 原子性 4 项。
- `fakeNFT` 改为「文本脚本 → 内部对象模型 → 真 JSON → 生产 `nft.ParseState`」，
  测试验证的是生产解析器而非影子实现。
- 新增 conntrack parser benchmark（1k/10k/50k）与新旧实现等价性测试。
- `tests/baseline_test.sh` 扩展到 230 断言。

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
  `Referrer-Policy: no-referrer`、`X-Frame-Options: DENY`、严格 CSP。
- CLI 新增 `config-ensure-token` / `config-ensure-entry` / `config-ensure-port` /
  `config-ensure-all` / `panel-info`；配置损坏时一律 fail-closed。
- `token` 不再被当作废弃键删除（v0.3 的误删已修正）。

### 面板暴露面

- 彻底删除「默认 8090」：`port` 没有默认值，首装 `crypto/rand` 在 10000-65535 随机，
  避开已监听/已占用/ephemeral/SSH/`guard_ports`/转发端口；两阶段 512 次，
  失败即报错，**绝不 fallback 固定端口**；老安装的 8090 升级时一次性重新随机。
- 新增随机入口路径（96 bit），与令牌完全独立。
- 未命中入口一律极简 404；未登录不返回 `app.js`；`/healthz` 仅 loopback。
- `serve` 启动前强校验端口/令牌/入口三项。

### conntrack fail-safe

- `Result` 区分数据源可用与读取完整，新增 `Usable()` / `Complete()` / `Note()`。
- 结构 enforcement（DNAT/counter/quota/CRUD/自愈）不再依赖 conntrack，
  修复「conntrack 异常 → 删规则 → API 成功 → nft 旧 DNAT 仍在」的假成功。
- conntrack 异常冻结上一轮 slot，`/api/health` 暴露 `ip_state_frozen`。

### nft 自愈

- 完整 Desired State 比对替代三项式检查：三张表 + 链 + `marks`/`qblock`/
  IPv4+IPv6 allow set + 每规则 up/down counter + 各链最小规则数。

### 性能与内存

- conntrack 扫描 O(R×F) → O(R+F)：一次扫描建 `(proto, dport)` 索引。
- 修复 `flowState` 无界增长；空闲判活改按最近字节变化时刻（保留 entry）。
- DNS 移出全局锁：锁内 snapshot → 锁外并发解析（上限 8）→ 校验版本后 apply。
- API 快照与 policy 配额兜底改批量参数化 SQL（消除 N+1）。

### 配额实时性

- `used = 已落库累计 + (当前 nft counter − 已落库基线)`，复用本轮 ruleset 读数。

### 安装/升级

- 首装三重健康确认（active + 本机 healthz + 配置就绪），移除 `start_service || true`。
- 升级事务化：备份二进制与 `panel.json` → 校验 → 替换 → 迁移 → 重启 →
  active → healthz → selftest → 全通过才删备份；失败恢复并验证后才报「已回滚」。

## v0.3.0

- 移除面板令牌认证（v0.3.1 已恢复）。
- 规则卡片展示监听 IP（只读；v0.3.2 已彻底移除）。
- UI 细节对齐 SBX。

## v0.2.0

- 移除转发规则「监听地址」字段，统一由 `fib daddr type local` 匹配本机地址。
- 统一规则变更入口 `internal/rulesvc`。
- 安装 / 分发 / UI 全面收口。
