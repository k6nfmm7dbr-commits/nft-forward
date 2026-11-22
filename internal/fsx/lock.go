package fsx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Lock holds an exclusive process lock until the returned file is closed.
// The lock pathname must not be removed or replaced, even when it is idle.
func Lock(ctx context.Context, path string) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	flags := os.O_RDWR | os.O_CREATE | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", path, err)
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("invalid lock file %s", path)
	}
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for ctx.Err() == nil {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			break
		}
		select {
		case <-ctx.Done():
		case <-tick.C:
		}
	}
	_ = f.Close()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return nil, fmt.Errorf("lock %s: %w", path, err)
}
