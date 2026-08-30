package worker

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
)

func TestSweepOrphanScanArtifacts(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "sweep.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/repo", Name: "repo"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}

	createScan := func(status db.ScanStatus, resumedFrom *uint) db.Scan {
		t.Helper()
		scan := db.Scan{
			RepositoryID:      repo.ID,
			Kind:              JobSkill,
			Status:            status,
			ResumedFromScanID: resumedFrom,
		}
		if err := gdb.Create(&scan).Error; err != nil {
			t.Fatal(err)
		}
		return scan
	}

	crashed := createScan(db.ScanRunning, nil)
	historical := createScan(db.ScanFailed, nil)
	queuedRoot := createScan(db.ScanFailed, nil)
	createScan(db.ScanQueued, &queuedRoot.ID)
	pausedRoot := createScan(db.ScanFailed, nil)
	createScan(db.ScanPaused, &pausedRoot.ID)
	queued := createScan(db.ScanQueued, nil)
	stateOnly := createScan(db.ScanFailed, nil)

	w := &Worker{DB: gdb, DataDir: t.TempDir()}
	withArtifacts := []uint{
		crashed.ID,
		historical.ID,
		queuedRoot.ID,
		pausedRoot.ID,
		queued.ID,
	}
	for _, id := range withArtifacts {
		writeScanArtifact(t, w.workRoot(id))
		writeScanArtifact(t, w.harnessStateDirID(id))
	}
	writeScanArtifact(t, w.harnessStateDirID(stateOnly.ID))
	writeScanArtifact(t, filepath.Join(w.DataDir, "scan-not-an-id"))
	if err := os.WriteFile(filepath.Join(w.DataDir, "scan-9999"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := db.SweepRunning(gdb); err != nil {
		t.Fatal(err)
	}
	removed, err := w.sweepOrphanScanArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2", removed)
	}

	for _, id := range []uint{crashed.ID, historical.ID} {
		assertPathMissing(t, w.workRoot(id))
		assertPathMissing(t, w.harnessStateDirID(id))
	}
	for _, id := range []uint{queuedRoot.ID, pausedRoot.ID, queued.ID} {
		assertPathExists(t, w.workRoot(id))
		assertPathExists(t, w.harnessStateDirID(id))
	}
	assertPathExists(t, w.harnessStateDirID(stateOnly.ID))
	assertPathExists(t, filepath.Join(w.DataDir, "scan-not-an-id"))
	assertPathExists(t, filepath.Join(w.DataDir, "scan-9999"))
}

func TestSweepOrphanScanArtifactsMissingRootIsNoop(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "sweep.db"))
	if err != nil {
		t.Fatal(err)
	}
	w := &Worker{DB: gdb, DataDir: filepath.Join(t.TempDir(), "missing")}
	removed, err := w.sweepOrphanScanArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	if removed != 0 {
		t.Fatalf("removed = %d, want 0", removed)
	}
}

func writeScanArtifact(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "artifact"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertPathExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
}

func assertPathMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected %s to be removed, stat error = %v", path, err)
	}
}
