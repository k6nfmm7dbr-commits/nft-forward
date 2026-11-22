package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointRequiresExplicitRecovery(t *testing.T) {
	p := filepath.Join(t.TempDir(), "panel.json")
	t.Setenv("NFT_FORWARD_CONF", p)
	if _, _, _, err := Ensure(func(*Config) (int, error) { return 32123, nil }, true, true); err != nil {
		t.Fatal(err)
	}
	want, err := LoadStrict()
	if err != nil {
		t.Fatal(err)
	}
	lock, err := Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	err = Checkpoint(want)
	lock.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := Set("port", "32124"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureToken(); err == nil {
		t.Fatal("missing initialized config treated as fresh")
	}
	if err := os.WriteFile(p, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RestoreLastGood(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := LoadStrict()
	if err != nil {
		t.Fatal(err)
	}
	if got.Port != want.Port || got.Token != want.Token || got.EntryPath != want.EntryPath {
		t.Fatal("recovery did not restore the last healthy configuration")
	}
	if raw, err := os.ReadFile(p + ".before-restore"); err != nil || string(raw) != "invalid" {
		t.Fatalf("did not preserve displaced config: %v", err)
	}
}
