package forward

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/portprobe"
)

// 自动随机端口必须避开内核 ephemeral 区间（避免与出站连接的临时端口打架）。
func TestRandomPortAvoidsEphemeralRange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "range")
	// 让 ephemeral 区间覆盖 20000-20004，分配区间 20000-20009。
	if err := os.WriteFile(path, []byte("20000 20004\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	restore := portprobe.SetEphemeralPathForTest(path)
	t.Cleanup(restore)

	a := NewAllocator(&seqRand{vals: []int{0, 1, 2, 3, 4, 5}}, freeProber{})
	a.SetRange(20000, 20009)
	p, err := a.Allocate(newRule(0, ProtoTCP, 0), nil, nil)
	if err != nil {
		t.Fatalf("Allocate 失败: %v", err)
	}
	if p < 20005 {
		t.Fatalf("应跳过 ephemeral 区间 20000-20004，实际分配 %d", p)
	}
}

// ephemeral 区间完全覆盖分配区间时不得据它排除（否则永远分配不出端口）。
func TestRandomPortIgnoresEphemeralWhenItSwallowsRange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "range")
	if err := os.WriteFile(path, []byte("1024 65535\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	restore := portprobe.SetEphemeralPathForTest(path)
	t.Cleanup(restore)

	a := NewAllocator(&seqRand{vals: []int{3}}, freeProber{})
	a.SetRange(20000, 20009)
	p, err := a.Allocate(newRule(0, ProtoTCP, 0), nil, nil)
	if err != nil {
		t.Fatalf("ephemeral 覆盖全区间时仍应能分配: %v", err)
	}
	if p != 20003 {
		t.Fatalf("期望 20003，实际 %d", p)
	}
}

// 关闭 avoidEphemeral 后不再读取该文件（测试可控性）。
func TestSetAvoidEphemeralOff(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "range")
	if err := os.WriteFile(path, []byte("20000 20009\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	restore := portprobe.SetEphemeralPathForTest(path)
	t.Cleanup(restore)

	a := NewAllocator(&seqRand{vals: []int{2}}, freeProber{})
	a.SetRange(20000, 20009)
	a.SetAvoidEphemeral(false)
	p, err := a.Allocate(newRule(0, ProtoTCP, 0), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p != 20002 {
		t.Fatalf("关闭后应直接使用随机值，实际 %d", p)
	}
}
