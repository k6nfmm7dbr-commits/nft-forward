// Package fsx 提供文件原子写与 JSON 序列化辅助。
package fsx

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// WriteFileAtomic 原子写文件：先写临时文件再 rename，避免半写文件。
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // rename 成功后不存在；失败则清理
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// MarshalIndent 输出带缩进的 JSON。
func MarshalIndent(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }

// MarshalCompact 输出紧凑 JSON。
func MarshalCompact(v any) ([]byte, error) { return json.Marshal(v) }
