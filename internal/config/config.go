// Package config 负责 nft-forward 配置加载。
//
// 默认值 + /etc/nft-forward/panel.json 覆盖。写回一律走 fsx 原子写
// （临时文件 → fsync → chmod 0600 → rename → fsync 目录）。
// Token 已在 v0.3 移除，面板不再需要认证令牌。
package config

import (
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

func defaultConf() map[string]any {
	dir := AppDir()
	return map[string]any{
		"db":          filepath.Join(dir, "traffic.db"),
		"nft_conf":    filepath.Join(dir, "nft.conf"),
		"sysctl_conf": filepath.Join("/etc/sysctl.d", "90-nft-forward.conf"),
		"listen":      "0.0.0.0",
		"port":        json.Number("8090"),
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
// 注意：Token 已移除（v0.3），面板不再需要认证令牌。
type Config struct {
	raw map[string]any

	DB         string
	NftConf    string
	SysctlConf string
	Listen     string // 面板 HTTP 服务 bind 地址
	Port       int    // 面板端口
	Interval   int    // 流量采集间隔（秒）
	DNSRefresh int    // 域名目标 DNS 刷新周期（秒）
	TZ         string
	SSHGuard   int // 冲突检查需避开的 SSH 端口
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

// Validate 语义校验。
func (c *Config) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
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
	c.ExtraGuards = c.guardPorts()
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
// token 是 v0.3 移除的认证令牌（面板不再需要），迁移时一并摘除。
var legacyKeys = []string{"rule_listen_address", "default_listen_address", "token"}

// Migrate 清理废弃配置键（读取 → 改 → 原子写回）。
// 返回被删除的键。配置损坏时 fail-closed，不写回。
func Migrate() ([]string, error) {
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

// write 原子写回当前配置（0600，含 token）。
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
	c, err := LoadStrict()
	if err != nil {
		return fmt.Errorf("拒绝修改配置: %w", err)
	}
	var v any = value
	trimmed := strings.TrimSpace(value)
	if i, err := strconv.ParseInt(trimmed, 10, 64); err == nil && trimmed != "" {
		v = json.Number(strconv.FormatInt(i, 10))
	}
	c.raw[key] = v
	return c.write()
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
