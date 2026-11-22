package config

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/fsx"
)

func lastGoodPath() string { return ConfPath() + ".last-good" }

// Checkpoint records a validated, running configuration. The caller must hold
// Lock from its strict load through startup and the first successful reconcile.
// It is never consulted as a runtime fallback.
func Checkpoint(c *Config) error {
	if err := c.ValidateServe(); err != nil {
		return err
	}
	data, err := os.ReadFile(ConfPath())
	if err != nil {
		return err
	}
	current, err := LoadStrict()
	if err != nil {
		return err
	}
	want, err := fsx.MarshalIndent(c.raw)
	if err != nil {
		return err
	}
	got, err := fsx.MarshalIndent(current.raw)
	if err != nil {
		return err
	}
	if !bytes.Equal(want, got) {
		return fmt.Errorf("配置在启动期间改变，拒绝记录健康配置")
	}
	if previous, err := os.ReadFile(lastGoodPath()); err == nil && bytes.Equal(previous, data) {
		return nil
	}
	return fsx.WriteFileAtomic(lastGoodPath(), data, 0o600)
}

// DatabaseExpected distinguishes a deleted previously initialized database
// from a clean installation. A damaged checkpoint must not permit creation.
func DatabaseExpected(c *Config) (bool, error) {
	good, err := loadLastGood()
	if err != nil || good == nil {
		return false, err
	}
	return filepath.Clean(good.DB) == filepath.Clean(c.DB), nil
}

func loadLastGood() (*Config, error) {
	path := lastGoodPath()
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	c, err := load(path, true)
	if err == nil {
		err = c.ValidateServe()
	}
	if err != nil {
		return nil, fmt.Errorf("健康配置快照无效 (%s): %w", path, err)
	}
	return c, nil
}

// RestoreLastGood is deliberately explicit. It preserves current contents
// (including malformed JSON) before replacing the primary configuration.
// The caller should stop the daemon before invoking recovery, then restart.
func RestoreLastGood(ctx context.Context) error {
	lock, err := Lock(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	good, err := loadLastGood()
	if err != nil {
		return err
	}
	if good == nil {
		return fmt.Errorf("没有已验证的健康配置快照")
	}
	path := ConfPath()
	if data, err := os.ReadFile(path); err == nil {
		if err := fsx.WriteFileAtomic(path+".before-restore", data, 0o600); err != nil {
			return fmt.Errorf("无法保留当前配置: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return writeConfig(path, good)
}
