// Package config 负责 nft-forward 配置加载。
// 默认值 + /etc/nft-forward/panel.json 覆盖；LoadStrict fail-closed。
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
		"token":       "",
		"interval":    json.Number("2"),
		"tz":          "Asia/Shanghai",
		"ssh_port":    json.Number("22"), // 冲突检查时避开
	}
}

// Config 是合并后的运行配置。
type Config struct {
	raw map[string]any

	DB         string
	NftConf    string
	SysctlConf string
	Listen     string
	Port       int
	Token      string
	Interval   int
	TZ         string
	SSHGuard   int // 冲突检查需避开的 SSH 端口
	SecureCookie bool
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
	c.Token = strings.TrimSpace(c.Str("token"))
	c.Interval = int(c.Int("interval"))
	if c.Interval < 1 {
		c.Interval = 1
	}
	c.TZ = c.Str("tz")
	c.SSHGuard = int(c.Int("ssh_port"))
	c.SecureCookie = c.Bool("secure_cookie")
}

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
			return "True"
		}
		return "False"
	default:
		return fmt.Sprint(t)
	}
}

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
	data, err := fsx.MarshalIndent(c.raw)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return fsx.WriteFileAtomic(ConfPath(), data, 0o600)
}

// EnsureToken 保证 token 非空；为空则生成高熵随机令牌并写回。
func EnsureToken() (string, error) {
	c, err := LoadStrict()
	if err != nil {
		return "", fmt.Errorf("拒绝生成访问令牌: %w", err)
	}
	if c.Token != "" {
		return c.Token, nil
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	c.raw["token"] = tok
	data, err := fsx.MarshalIndent(c.raw)
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	if err := fsx.WriteFileAtomic(ConfPath(), data, 0o600); err != nil {
		return "", err
	}
	return tok, nil
}

// Raw 暴露合并后的原始映射。
func (c *Config) Raw() map[string]any { return c.raw }
