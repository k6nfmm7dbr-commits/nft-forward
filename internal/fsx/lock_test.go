package fsx

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestLockAcrossProcesses(t *testing.T) {
	if path := os.Getenv("NFF_TEST_CHILD_LOCK"); path != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		lock, err := Lock(ctx, path)
		if lock != nil {
			lock.Close()
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("lock not held by parent: %v", err)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "panel.lock")
	lock, err := Lock(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLockAcrossProcesses$")
	cmd.Env = append(os.Environ(), "NFF_TEST_CHILD_LOCK="+path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	lock.Close()
	next, err := Lock(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}
