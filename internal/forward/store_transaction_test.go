package forward_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/database"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
)

func TestAbortedCandidateDoesNotPersistOrReuseMark(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "traffic #1.db")
	db, err := database.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := forward.NewStore(db.DB)
	id, err := st.ReserveID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("candidate not applied")
	err = st.Transaction(ctx, func(tx forward.Mutation) error {
		if err := tx.Create(&forward.Rule{ID: id, Name: "example", Protocol: "tcp", ListenPort: 30021, TargetAddress: "192.0.2.1", TargetPort: 80}); err != nil {
			return err
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("transaction error = %v", err)
	}
	rows, err := st.ListActive(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("aborted candidate persisted: %v, %v", rows, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, err := database.OpenConfigured(ctx, path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	next, err := forward.NewStore(fresh.DB).ReserveID(ctx)
	if err != nil || next <= id {
		t.Fatalf("reopened DB reused reserved mark %d: next=%d err=%v", id, next, err)
	}
}
