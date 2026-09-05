// Package config 负责 nft-forward 配置加载。
//
// 默认值 + /etc/nft-forward/panel.json 覆盖。写回一律走 fsx 原子写
// （临时文件 → fsync → chmod 0600 → rename → fsync 目录）。
//
// 三个「首次安装生成、之后永久保持」的安全字段：
//
//	token       面板访问令牌（32 位十六进制，crypto/rand 16 bytes）
//	port        面板端口（随机五位数，10000-65535，见 internal/bootstrap）
//	entry_path  面板随机入口路径（≥96 bit 随机，crypto/rand 12 bytes）
//
// 三者都**没有默认值**：panel.json 里缺失即视为「尚未初始化」，由安装器调用
// config-ensure-token / config-ensure-port / config-ensure-entry 补齐；
// serve 在任一项缺失时 fail-closed 拒绝启动，绝不用固定值兜底。
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/fsx"
)

// 面板随机端口区间（仅约束**自动生成**；用户显式指定的端口只要合法即可）。
const (
	// PanelPortMin 是自动生成面板端口的下界（五位数起点）。
	PanelPortMin = 10000
	// PanelPortMax 是自动生成面板端口的上界。
	PanelPortMax = 65535
)

// entryPathBytes 是随机入口路径的随机字节数。12 bytes = 96 bit，
// hex 编码后 24 个字符。与 token 完全独立生成，不可互相推导。
const entryPathBytes = 12

// tokenBytes 是访问令牌的随机字节数（16 bytes → 32 位十六进制，与 SBX 一致）。
const tokenBytes = 16

// AppDir 返回数据目录（环境变量 NFT_FORWARD_DIR 优先）。
func AppDir() string {
	if v := os.Getenv("NFT_FORWARD_DIR"); v != "" {
		return v
	}
	return "/etc/nft-forward"
}

// ConfPath 返回配置文件路径（NFT_FORWARD_CONF 优先）。
func ConfPath() string {
	if v := os.Getenv("NFT_FORWARD_CONF"); v != "" {
		return v
	}
	return filepath.Join(AppDir(), "panel.json")
}

// defaultConf 是内置默认值。
//
// 刻意 **不含** port / token / entry_path：
//   - 固定默认端口（历史上的 8090）等于给全网扫描器一个确定指纹，已彻底删除；
//   - 固定默认 token 等于没有认证；
//   - 固定入口路径同样是指纹。
//
// 这三项由安装期的 ensure 流程用 crypto/rand 生成并持久化。
func defaultConf() map[string]any {
	dir := AppDir()
	return map[string]any{
		"db":          filepath.Join(dir, "traffic.db"),
		"nft_conf":    filepath.Join(dir, "nft.conf"),
		"sysctl_conf": filepath.Join("/etc/sysctl.d", "90-nft-forward.conf"),
		"listen":      "0.0.0.0",
		"interval":    json.Number("2"),
		"dns_refresh": json.Number("60"),
		"tz":          "Asia/Shanghai",
		"ssh_port":    json.Number("22"), // 冲突检查时避开
	}
}

// Config 是合并后的运行配置。
//
// 注意：Listen 是 **Web 面板自身的 bind 地址**（Web Server 配置），
// 与「转发规则监听地址」无关 —— 后者已彻底移除。
type Config struct {
	raw map[string]any

	DB         string
	NftConf    string
	SysctlConf string
	Listen     string // 面板 HTTP 服务 bind 地址
	Port       int    // 面板端口（0 = 尚未初始化）
	Interval   int    // 流量采集间隔（秒）
	DNSRefresh int    // 域名目标 DNS 刷新周期（秒）
	TZ         string
	SSHGuard   int // 冲突检查需避开的 SSH 端口

	// Token 是面板访问令牌（32 位十六进制）。空 = 尚未初始化，
	// 此时 serve 拒绝启动、鉴权一律拒绝（fail-closed）。
	Token string
	// EntryPath 是面板随机入口路径（不含斜杠）。空 = 尚未初始化。
	EntryPath string
	// SecureCookie 仅在用户显式开启（前置 HTTPS 反代）时给会话 Cookie 加 Secure。
	// 纯 HTTP 直连时必须为 false，否则浏览器不会回传 Cookie，表现为登录不上。
	SecureCookie bool

	// ExtraGuards 是额外保留端口（guard_ports: {"port": "说明"}）。
	ExtraGuards map[int]string
}

// Load 宽松读取（只读场景）。
func Load() *Config {
	c, _ := load(ConfPath(), false)
	if err := c.Validate(); err != nil {
		slog.Warn("配置语义校验失败(仅告警)", "err", err)
	}
	return c
}

// LoadStrict 严格读取（会修改系统状态的路径使用）。
//
// fail-closed 语义：
//   - 文件不存在：返回默认值（合法的全新安装状态）；
//   - 文件存在但读取失败 / JSON 损坏（含尾部多余数据）：返回错误，
//     绝不退回默认值，更不允许用默认值覆盖原文件。
func LoadStrict() (*Config, error) {
	c, err := load(ConfPath(), true)
	if err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func load(path string, strict bool) (*Config, error) {
	c := &Config{raw: defaultConf()}
	data, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		slog.Info("配置不存在, 使用默认值", "path", path)
	case err != nil:
		if strict {
			return nil, fmt.Errorf("配置文件读取失败, 拒绝使用默认值继续 (%s): %w", path, err)
		}
		slog.Warn("配置读取失败, 使用默认值", "path", path, "err", err)
	default:
		file, derr := decodeConfig(data)
		if derr != nil {
			if strict {
				return nil, fmt.Errorf("配置文件损坏, 拒绝使用默认值继续(请修复 %s): %w", path, derr)
			}
			slog.Warn("配置解析失败", "err", derr)
		} else {
			for k, v := range file {
				c.raw[k] = v
			}
		}
	}
	c.normalize()
	return c, nil
}

func decodeConfig(data []byte) (map[string]any, error) {
	var file map[string]any
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	if err := dec.Decode(&file); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("存在多个 JSON 值")
		}
		return nil, fmt.Errorf("尾部存在非法数据: %w", err)
	}
	return file, nil
}

// Validate 语义校验（允许「尚未初始化」的空 token / 0 端口 / 空入口路径，
// 否则全新安装时连 ensure 流程都无法读取配置）。
func (c *Config) Validate() error {
	if c.Port != 0 && (c.Port < 1 || c.Port > 65535) {
		return fmt.Errorf("port 必须在 1-65535: %d", c.Port)
	}
	if c.Interval < 1 || c.Interval > 86400 {
		return fmt.Errorf("interval 非法: %d", c.Interval)
	}
	if c.DNSRefresh < 10 || c.DNSRefresh > 3600 {
		return fmt.Errorf("dns_refresh 必须在 10-3600 秒: %d", c.DNSRefresh)
	}
	if c.DB == "" {
		return fmt.Errorf("db 路径不能为空")
	}
	if c.NftConf == "" {
		return fmt.Errorf("nft 配置路径不能为空")
	}
	if c.Token != "" && !validToken(c.Token) {
		return fmt.Errorf("token 非法（应为 32 位十六进制）")
	}
	if c.EntryPath != "" && !ValidEntryPath(c.EntryPath) {
		return fmt.Errorf("entry_path 非法（应为 16-64 位小写十六进制）")
	}
	return nil
}

// ValidateServe 是 serve 启动前的强校验：三项安全字段必须都已初始化。
//
// 为什么 fail-closed：任何一项缺失都意味着「面板处于无认证 / 固定端口 /
// 固定入口」的危险状态，宁可不启动也不能带着这种状态对外监听。
func (c *Config) ValidateServe() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("面板端口尚未初始化，请先执行: nft-forward config-ensure-port")
	}
	if c.Token == "" {
		return fmt.Errorf("面板访问令牌尚未初始化，请先执行: nft-forward config-ensure-token")
	}
	if c.EntryPath == "" {
		return fmt.Errorf("面板入口路径尚未初始化，请先执行: nft-forward config-ensure-entry")
	}
	return nil
}

func (c *Config) normalize() {
	c.DB = c.Str("db")
	c.NftConf = c.Str("nft_conf")
	c.SysctlConf = c.Str("sysctl_conf")
	c.Listen = c.Str("listen")
	c.Port = int(c.Int("port"))
	c.Interval = int(c.Int("interval"))
	if c.Interval < 1 {
		c.Interval = 1
	}
	c.DNSRefresh = int(c.Int("dns_refresh"))
	if c.DNSRefresh == 0 {
		c.DNSRefresh = 60
	}
	c.TZ = c.Str("tz")
	c.SSHGuard = int(c.Int("ssh_port"))
	c.Token = strings.TrimSpace(c.Str("token"))
	c.EntryPath = normalizeEntryPath(c.Str("entry_path"))
	c.SecureCookie = c.Bool("secure_cookie")
	c.ExtraGuards = c.guardPorts()
}

// normalizeEntryPath 去掉两端斜杠与空白（配置里写成 "/abc/" 也能用）。
func normalizeEntryPath(raw string) string {
	return strings.Trim(strings.TrimSpace(raw), "/")
}

// ValidEntryPath 报告入口路径是否合法：16-64 位小写十六进制（无斜杠）。
func ValidEntryPath(p string) bool {
	if len(p) < 16 || len(p) > 64 {
		return false
	}
	return isLowerHex(p)
}

func validToken(t string) bool { return len(t) == tokenBytes*2 && isLowerHex(t) }

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return len(s) > 0
}

// EntryRoute 返回带前导斜杠的入口路径（如 /3e4f65a8c24d2bd5b9e80147）。
// 未初始化时返回空串。
func (c *Config) EntryRoute() string {
	if c.EntryPath == "" {
		return ""
	}
	return "/" + c.EntryPath
}

// guardPorts 解析 guard_ports 配置：{"9000": "自定义服务"}。
func (c *Config) guardPorts() map[int]string {
	out := map[int]string{}
	m, ok := c.raw["guard_ports"].(map[string]any)
	if !ok {
		return out
	}
	for k, v := range m {
		p, err := strconv.Atoi(strings.TrimSpace(k))
		if err != nil || p < 1 || p > 65535 {
			continue
		}
		label := "保留端口"
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			label = s
		}
		out[p] = label
	}
	return out
}

// Bool 读取布尔配置项。
func (c *Config) Bool(key string) bool {
	switch t := c.raw[key].(type) {
	case bool:
		return t
	case string:
		v := strings.ToLower(strings.TrimSpace(t))
		return v == "true" || v == "1" || v == "yes"
	case json.Number:
		return t.String() == "1"
	default:
		return false
	}
}

// Str 读取字符串配置项。
func (c *Config) Str(key string) string {
	v := c.raw[key]
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprint(t)
	}
}

// Int 读取整数配置项。
func (c *Config) Int(key string) int64 {
	switch t := c.raw[key].(type) {
	case nil:
		return 0
	case json.Number:
		if i, err := strconv.ParseInt(t.String(), 10, 64); err == nil {
			return i
		}
	case string:
		if i, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64); err == nil {
			return i
		}
	case float64:
		return int64(t)
	case bool:
		if t {
			return 1
		}
	}
	return 0
}

// legacyKeys 是已废弃的配置键（读到即在迁移时删除）。
//
// listen_address 从未作为面板配置存在；这里列出的是历史上可能被写入的
// 转发相关键。删除它们只是清理，不改变任何行为。
//
// ★ token **不在**此列：v0.3.1 恢复了正式令牌认证，token 是必需配置。
var legacyKeys = []string{"rule_listen_address", "default_listen_address"}

// LegacyDefaultPort 是 v0.3.0 及更早版本写死的默认面板端口。
//
// 它是一个**已废弃的固定指纹值**：任何仍在使用它的安装都等于把「这里有一个
// 管理面板」写在了公网上。因此升级迁移时把它视为遗留默认值一次性重新随机
// （见 MigratePort）。用户若确有需要仍可显式 `config-set port 8090`，
// 但它不再是任何默认或回退值。
const LegacyDefaultPort = 8090

// MigratePort 报告当前端口是否是需要重新随机的遗留默认端口。
//
// 只认「恰好等于 v0.3.0 默认值」这一种情况 —— 用户自己设的其它端口一律不动。
func (c *Config) MigratePort() bool { return c.Port == LegacyDefaultPort }

// ClearPort 清空 port 配置（供迁移后重新随机）。
//
// 只删 port 键，其余配置（含令牌、入口路径、用户自定义键）原样保留。
func ClearPort() error {
	c, err := LoadStrict()
	if err != nil {
		return fmt.Errorf("拒绝修改配置: %w", err)
	}
	delete(c.raw, "port")
	if err := c.write(); err != nil {
		return err
	}
	c.normalize()
	return nil
}

// Migrate 清理废弃配置键（读取 → 改 → 原子写回）。
// 返回被删除的键。配置损坏时 fail-closed，不写回。
func Migrate() ([]string, error) {
	if _, err := os.Stat(ConfPath()); os.IsNotExist(err) {
		return nil, nil
	}
	c, err := LoadStrict()
	if err != nil {
		return nil, fmt.Errorf("拒绝迁移配置: %w", err)
	}
	var dropped []string
	for _, k := range legacyKeys {
		if _, ok := c.raw[k]; ok {
			delete(c.raw, k)
			dropped = append(dropped, k)
		}
	}
	if len(dropped) == 0 {
		return nil, nil
	}
	if err := c.write(); err != nil {
		return nil, err
	}
	return dropped, nil
}

// write 原子写回当前配置（0600）。
func (c *Config) write() error {
	data, err := fsx.MarshalIndent(c.raw)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return fsx.WriteFileAtomic(ConfPath(), data, 0o600)
}

// Set 写回单个配置项并原子落盘。
func Set(key, value string) error {
	return SetAll(map[string]string{key: value})
}

// SetAll 一次写回多个配置项（单次原子写）。
//
// 读取阶段用 LoadStrict：panel.json 存在但损坏时拒绝修改并原样返回错误，
// 绝不允许「损坏 → 回退 defaults → 把默认值写回正式文件」的覆盖路径。
func SetAll(kv map[string]string) error {
	c, err := LoadStrict()
	if err != nil {
		return fmt.Errorf("拒绝修改配置: %w", err)
	}
	for key, value := range kv {
		var v any = value
		trimmed := strings.TrimSpace(value)
		if i, err := strconv.ParseInt(trimmed, 10, 64); err == nil && trimmed != "" {
			v = json.Number(strconv.FormatInt(i, 10))
		}
		c.raw[key] = v
	}
	if err := c.write(); err != nil {
		return err
	}
	c.normalize()
	return nil
}

// EnsureToken 保证 token 非空；为空则生成 32 位十六进制随机令牌并原子写回。
//
// 语义与 SBX 的 config-ensure-token 完全一致：
//   - crypto/rand 16 bytes → hex（禁止 math/rand，禁止 shell $RANDOM）；
//   - 已存在则原样返回，绝不重新生成（升级不会重置令牌）；
//   - 读取用 LoadStrict：panel.json 损坏时直接报错，绝不基于 defaults
//     生成新文件覆盖原损坏文件（避免丢失用户已有配置）；
//   - 写回走 fsx 原子写 + 0600。
func EnsureToken() (string, error) {
	c, err := LoadStrict()
	if err != nil {
		return "", fmt.Errorf("拒绝生成访问令牌: %w", err)
	}
	if c.Token != "" {
		return c.Token, nil
	}
	tok, err := randomHex(tokenBytes)
	if err != nil {
		return "", err
	}
	c.raw["token"] = tok
	if err := c.write(); err != nil {
		return "", err
	}
	return tok, nil
}

// EnsureEntryPath 保证随机入口路径存在；为空则生成 96 bit 随机路径并写回。
//
// 与 token 完全独立：各自 crypto/rand 生成，不能互相推导，
// 令牌本身绝不作为 URL 路径使用。
func EnsureEntryPath() (string, error) {
	c, err := LoadStrict()
	if err != nil {
		return "", fmt.Errorf("拒绝生成面板入口路径: %w", err)
	}
	if c.EntryPath != "" {
		return c.EntryPath, nil
	}
	p, err := randomHex(entryPathBytes)
	if err != nil {
		return "", err
	}
	c.raw["entry_path"] = p
	if err := c.write(); err != nil {
		return "", err
	}
	return p, nil
}

// SetPort 持久化面板端口（供 ensure-port 与用户显式改端口共用）。
func SetPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("端口必须在 1-65535: %d", port)
	}
	return Set("port", strconv.Itoa(port))
}

// randomHex 返回 n 字节的密码学安全随机数据的十六进制串。
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand 不可用: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GuardPorts 返回转发规则不允许占用的保留端口表。
//
// 集中在 config 里的原因：规则变更服务（rulesvc）与 API 层都需要同一份表，
// 两处各写一遍必然漂移。
//
// 内容：面板端口 + SSH 端口 + 用户在 guard_ports 里额外声明的端口。
func (c *Config) GuardPorts() map[int]string {
	g := map[int]string{}
	if c.Port > 0 {
		g[c.Port] = "面板"
	}
	if c.SSHGuard > 0 {
		g[c.SSHGuard] = "系统保护端口（SSH）"
	}
	for p, label := range c.ExtraGuards {
		if _, taken := g[p]; !taken {
			g[p] = label
		}
	}
	return g
}

// Raw 暴露合并后的原始映射。
func (c *Config) Raw() map[string]any { return c.raw }
