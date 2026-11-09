package baseline

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const idOne = "0123456789abcdef"

func TestAddStoresEntry(t *testing.T) {
	b := New(filepath.Join(t.TempDir(), "baseline.json"))

	if err := b.Add(SuppressedFinding{ID: idOne, Reason: "known test token"}); err != nil {
		t.Fatal(err)
	}
	if b.Count() != 1 {
		t.Fatalf("expected 1 entry, got %d", b.Count())
	}

	entry := b.Suppressions()[0]
	if entry.Reason != "known test token" || entry.SuppressedAt.IsZero() {
		t.Fatalf("entry not stored: %+v", entry)
	}
}

func TestAddIsIdempotent(t *testing.T) {
	b := New(filepath.Join(t.TempDir(), "baseline.json"))
	entry := SuppressedFinding{ID: idOne, Reason: "duplicate"}

	for i := 0; i < 3; i++ {
		if err := b.Add(entry); err != nil {
			t.Fatal(err)
		}
	}
	if b.Count() != 1 {
		t.Fatalf("expected one entry, got %d", b.Count())
	}
}

func TestAddRejectsInvalidID(t *testing.T) {
	b := New(filepath.Join(t.TempDir(), "baseline.json"))

	for _, id := range []string{"", "abc", "ABCDEF0123456789", "0123456789abcde"} {
		if err := b.Add(SuppressedFinding{ID: id}); !errors.Is(err, ErrInvalidID) {
			t.Errorf("id %q was accepted", id)
		}
	}
	if b.Count() != 0 {
		t.Fatal("invalid ids must not be stored")
	}
}

func TestIsSuppressedMatchesOnlyTheID(t *testing.T) {
	b := New(filepath.Join(t.TempDir(), "baseline.json"))
	if err := b.Add(SuppressedFinding{ID: idOne, Reason: "accepted"}); err != nil {
		t.Fatal(err)
	}

	if !b.IsSuppressed(idOne) {
		t.Fatal("accepted id was not matched")
	}
	if b.IsSuppressed("ffffffffffffffff") || b.IsSuppressed("") {
		t.Fatal("unknown ids must not match")
	}
}

func TestLoadSaveRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")

	written := New(path)
	if err := written.Add(SuppressedFinding{ID: idOne, Reason: "first"}); err != nil {
		t.Fatal(err)
	}
	if err := written.Add(SuppressedFinding{ID: "fedcba9876543210", Reason: "second"}); err != nil {
		t.Fatal(err)
	}

	reloaded := New(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	if reloaded.Count() != 2 {
		t.Fatalf("expected 2 entries after reload, got %d", reloaded.Count())
	}
	if !reloaded.IsSuppressed(idOne) {
		t.Fatal("entry lost on reload")
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	b := New(filepath.Join(t.TempDir(), "absent.json"))
	if err := b.Load(); err != nil {
		t.Fatalf("missing baseline must not fail: %v", err)
	}
	if b.Count() != 0 {
		t.Fatalf("expected an empty baseline, got %d", b.Count())
	}
}

func TestLoadRejectsBrokenJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := New(path).Load(); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
}

func TestRemoveDropsOneEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	b := New(path)

	if err := b.Add(SuppressedFinding{ID: idOne, Reason: "first"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Add(SuppressedFinding{ID: "fedcba9876543210", Reason: "second"}); err != nil {
		t.Fatal(err)
	}

	removed, err := b.Remove(idOne)
	if err != nil || !removed {
		t.Fatalf("remove failed: %v", err)
	}
	if b.Count() != 1 || b.IsSuppressed(idOne) {
		t.Fatal("entry still present after remove")
	}

	if removed, err := b.Remove(idOne); err != nil || removed {
		t.Fatal("second remove reported success")
	}

	reloaded := New(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	if reloaded.Count() != 1 {
		t.Fatal("remove was not written to disk")
	}
}
