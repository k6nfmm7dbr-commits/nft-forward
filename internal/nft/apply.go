package nft

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/fsx"
)

// Runner 抽象命令执行（测试可注入）。
type Runner interface {
	Run(ctx context.Context, args ...string) (rc int, stdout, stderr string, err error)
}

// ExecRunner 是真实命令执行器。
type ExecRunner struct{ Timeout time.Duration }

func (e ExecRunner) Run(ctx context.Context, args ...string) (int, string, string, error) {
	if e.Timeout <= 0 {
		e.Timeout = 15 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()
	if len(args) == 0 {
		return 0, "", "", fmt.Errorf("empty command")
	}
	cmd := exec.CommandContext(cctx, args[0], args[1:]...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	rc := 0
	if err != nil {
		if cerr := cctx.Err(); cerr != nil {
			return 0, out.String(), errb.String(), cerr
		}
		if ee, ok := err.(*exec.ExitError); ok {
			rc = ee.ExitCode()
			if rc < 0 {
				rc = 1
			}
		} else {
			return 0, out.String(), errb.String(), err
		}
	}
	return rc, out.String(), errb.String(), nil
}

// Apply checks and applies the same private candidate. The conventional script
// path is diagnostic (never replayed on startup) and is only published after
// nft accepted this batch. SQLite remains the source of truth.
func Apply(ctx context.Context, runner Runner, scriptPath, script string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	dir := filepath.Dir(scriptPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(scriptPath)+".candidate-*")
	if err != nil {
		return fmt.Errorf("创建 nft 候选脚本失败: %w", err)
	}
	path := f.Name()
	defer os.Remove(path)
	if _, err := f.WriteString(script); err != nil {
		f.Close()
		return fmt.Errorf("写入 nft 候选脚本失败: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := runBatch(ctx, runner, "检查", "-c", "-f", path); err != nil {
		return err
	}
	if err := runBatch(ctx, runner, "应用", "-f", path); err != nil {
		return err
	}
	if err := fsx.RenameAtomic(path, scriptPath); err != nil {
		return fmt.Errorf("nft 已应用，但保存诊断脚本失败: %w", err)
	}
	return nil
}

func runBatch(ctx context.Context, runner Runner, step string, args ...string) error {
	rc, _, stderr, err := runner.Run(ctx, append([]string{"nft"}, args...)...)
	if err != nil {
		return fmt.Errorf("nft 规则%s失败: %w (%s)", step, err, strings.TrimSpace(stderr))
	}
	if rc != 0 {
		return fmt.Errorf("nft 规则%s失败 (exit %d): %s", step, rc, strings.TrimSpace(stderr))
	}
	return nil
}
