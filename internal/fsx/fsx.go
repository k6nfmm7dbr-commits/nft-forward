// Package fsx 提供文件原子写与 JSON 序列化辅助。
//
// 原子写语义（与 SBX 对齐）：写临时文件 → fsync(临时文件) → close → chmod →
// rename → fsync(父目录)。目录 fsync 保证 rename 产生的目录项在掉电场景下
// 同样持久化；缺少这一步时，崩溃后可能出现「文件内容在但目录项丢失」。
package fsx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// WriteFileAtomic 原子写文件。mode 为 0 时用 0o644。
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	if perm == 0 {
		perm = 0o644
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // rename 成功后是无害的 no-op；失败则清理

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("写入临时文件失败: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync 失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// chmod 在 rename 之前：目标文件从出现的第一刻就带最终权限，
	// 不存在「先 0600 后放宽」或「短暂 0644 暴露 token」的窗口。
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("原子替换失败: %w", err)
	}
	return syncDir(dir)
}

// RenameAtomic 将已就绪的文件原子改名到目标位置，并 fsync 目标父目录。
func RenameAtomic(oldpath, newpath string) error {
	if err := os.Rename(oldpath, newpath); err != nil {
		return err
	}
	return syncDir(filepath.Dir(newpath))
}

// syncDir 对目录执行 fsync；仅忽略「文件系统明确不支持」类错误。
func syncDir(dir string) error {
	if dir == "" || dir == "." {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("打开父目录失败: %w", err)
	}
	serr := d.Sync()
	cerr := d.Close()
	if serr != nil && !isUnsupportedSync(serr) {
		return fmt.Errorf("目录 fsync 失败: %w", serr)
	}
	if cerr != nil && !isUnsupportedSync(cerr) {
		return fmt.Errorf("目录句柄关闭失败: %w", cerr)
	}
	return nil
}

func isUnsupportedSync(err error) bool {
	return errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.EOPNOTSUPP)
}

// MarshalIndent 输出带缩进的 JSON（不转义 HTML / 非 ASCII）。
func MarshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// MarshalCompact 输出紧凑 JSON（不转义 HTML / 非 ASCII）。
func MarshalCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
