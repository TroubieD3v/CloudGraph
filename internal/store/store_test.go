package store_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/TroubieD3v/cloudgraph/internal/store"
	"github.com/TroubieD3v/cloudgraph/internal/testutil"
)

func TestRoundTripAndHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cg.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	a := testutil.Demo(t, "insecure-kubernetes")
	if err := st.Save(a); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// reopen: data persists
	st, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := st.Get(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Paths) != len(a.Paths) || len(got.Findings) != len(a.Findings) || got.Summary.Resources != a.Summary.Resources {
		t.Errorf("snapshot differs after round trip")
	}
	items, err := st.List()
	if err != nil || len(items) != 1 || items[0].Summary.Paths != len(a.Paths) {
		t.Errorf("history wrong: %+v %v", items, err)
	}
	if err := st.Delete(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
	if err := st.Delete(a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}
