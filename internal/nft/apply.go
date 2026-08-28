package nft

import (
	"context"
	"fmt"
	"os/exec"
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
	cmd := exec.CommandContext(cctx, args[0], args[1:]...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	rc := 0
	if err != nil {
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

// Apply 事务化应用脚本：先写入文件 → `nft -c -f` 语法检查 → 通过后 `nft -f` 应用。
// 任何一步失败都返回错误，调用方绝不能把失败的变更当作成功。
func Apply(ctx context.Context, runner Runner, scriptPath, script string) error {
	if runner == nil {
		runner = ExecRunner{}
	}
	if err := fsx.WriteFileAtomic(scriptPath, []byte(script), 0o600); err != nil {
		return fmt.Errorf("写入 nft 脚本失败: %w", err)
	}
	// 1) 语法/语义检查（-c 干跑，不改变系统状态）。
	if rc, _, stderr, err := runner.Run(ctx, "nft", "-c", "-f", scriptPath); rc != 0 || err != nil {
		return fmt.Errorf("nft 规则检查失败: %s", strings.TrimSpace(stderr))
	}
	// 2) 应用。
	if rc, _, stderr, err := runner.Run(ctx, "nft", "-f", scriptPath); rc != 0 || err != nil {
		return fmt.Errorf("nft 规则应用失败: %s", strings.TrimSpace(stderr))
	}
	return nil
}
