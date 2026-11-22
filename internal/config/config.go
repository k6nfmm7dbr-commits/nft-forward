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
	"context"
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
	"time"

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
		if strict {
			if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
				return nil, fmt.Errorf("配置路径存在但无法读取 (%s): %w", path, err)
			}
			if _, statErr := os.Lstat(path + ".last-good"); !os.IsNotExist(statErr) {
				return nil, fmt.Errorf("配置缺失 (%s)；请检查或显式恢复最后一次健康配置", path)
			}
		}
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
	if file == nil {
		return nil, fmt.Errorf("配置必须是 JSON 对象")
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
	// Do not treat malformed persisted ports as uninitialized (which would rotate them).
	if n, ok := c.raw["port"]; ok {
		switch n.(type) {
		case json.Number, string:
			if _, err := strconv.ParseInt(strings.TrimSpace(c.Str("port")), 10, 32); err != nil {
				return fmt.Errorf("port 必须是整数")
			}
		default:
			return fmt.Errorf("port 必须是整数")
		}
	}
	for _, key := range []string{"db", "nft_conf", "listen"} {
		if v, ok := c.raw[key]; ok {
			text, ok := v.(string)
			if !ok || strings.ContainsRune(text, 0) {
				return fmt.Errorf("%s 必须是有效字符串", key)
			}
		}
	}
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

// Lock serializes read/modify/write and the daemon's rule port decisions.
func Lock(ctx context.Context) (*os.File, error) {
	return fsx.Lock(ctx, ConfPath()+".lock")
}

// Change applies one validated config mutation under the file lock. Returning
// false or an error from edit leaves the primary file untouched.
func Change(edit func(*Config) (bool, error)) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	lock, err := Lock(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	c, err := LoadStrict()
	if err != nil {
		return err
	}
	changed, err := edit(c)
	if err != nil || !changed {
		return err
	}
	c.normalize()
	if err := c.Validate(); err != nil {
		return err
	}
	return writeConfig(ConfPath(), c)
}

// Migrate removes obsolete keys without overwriting a concurrent change.
func Migrate() ([]string, error) {
	var dropped []string
	err := Change(func(c *Config) (bool, error) {
		for _, k := range legacyKeys {
			if _, ok := c.raw[k]; ok {
				delete(c.raw, k)
				dropped = append(dropped, k)
			}
		}
		return len(dropped) > 0, nil
	})
	return dropped, err
}

func writeConfig(path string, c *Config) error {
	data, err := fsx.MarshalIndent(c.raw)
	if err != nil {
		return err
	}
	return fsx.WriteFileAtomic(path, append(data, '\n'), 0o600)
}

// Set writes a single setting. Existing numeric string compatibility is
// retained, without coercing credentials or path strings into JSON numbers.
func Set(key, value string) error {
	return SetAll(map[string]string{key: value})
}

func SetAll(kv map[string]string) error {
	return Change(func(c *Config) (bool, error) {
		for key, value := range kv {
			var v any = value
			switch key {
			case "token", "entry_path", "db", "nft_conf", "sysctl_conf", "listen", "tz":
			default:
				if i, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
					v = json.Number(strconv.FormatInt(i, 10))
				}
			}
			c.raw[key] = v
		}
		return len(kv) > 0, nil
	})
}

// Ensure completes initialization in one transaction. selectPort is called
// under the lock and may retain the existing port or request a replacement.
func Ensure(selectPort func(*Config) (int, error), token, entry bool) (port int, tok, path string, err error) {
	err = Change(func(c *Config) (bool, error) {
		changed := false
		if selectPort != nil {
			p, err := selectPort(c)
			if err != nil {
				return false, err
			}
			if p < 1 || p > 65535 {
				return false, fmt.Errorf("端口必须在 1-65535")
			}
			if p != c.Port {
				c.raw["port"] = json.Number(strconv.Itoa(p))
				changed = true
			}
			port = p
		}
		tok, path = c.Token, c.EntryPath
		if token && tok == "" {
			var err error
			if tok, err = randomHex(tokenBytes); err != nil {
				return false, err
			}
			c.raw["token"] = tok
			changed = true
		}
		if entry && path == "" {
			var err error
			if path, err = randomHex(entryPathBytes); err != nil {
				return false, err
			}
			c.raw["entry_path"] = path
			changed = true
		}
		return changed, nil
	})
	return
}

func EnsureToken() (string, error) {
	_, token, _, err := Ensure(nil, true, false)
	return token, err
}

func EnsureEntryPath() (string, error) {
	_, _, path, err := Ensure(nil, false, true)
	return path, err
}

func SetPort(port int) error {
	_, _, _, err := Ensure(func(*Config) (int, error) { return port, nil }, false, false)
	return err
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
