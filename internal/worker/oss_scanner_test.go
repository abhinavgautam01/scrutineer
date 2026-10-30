package worker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"scrutineer/internal/db"
)

const ossRepoURL = "https://github.com/example/project"

func writeOSSFile(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func ossFixtureRegistry(t *testing.T) string {
	t.Helper()
	reg := t.TempDir()
	writeOSSFile(t, reg, "projects/proj/project.yaml", "repo: "+ossRepoURL+"\n")
	writeOSSFile(t, reg, "projects/proj/threat_model.md", "registry tm")
	writeOSSFile(t, reg, "projects/proj/Dockerfile", "FROM scratch")
	return reg
}

func ossWorker(reg string, err error) *Worker {
	w := &Worker{OSSScannerRegistry: "https://example.test/registry"}
	w.PrepareOSSScannerRegistry = func(context.Context, string, func(Event)) (string, error) { return reg, err }
	return w
}

func ossScan() *db.Scan {
	return &db.Scan{Repository: db.Repository{URL: ossRepoURL}}
}

func noEmit(Event) {}

func TestStageOSSScannerThreatModel(t *testing.T) {
	work := t.TempDir()
	w := ossWorker(ossFixtureRegistry(t), nil)
	scan := ossScan()
	doc := skillContext{}
	w.attachOSSScanner(t.Context(), work, "", scan, &db.Skill{Name: "threat-model"}, &doc, noEmit)

	got, err := os.ReadFile(filepath.Join(work, "oss_scanner", "threat_model.md"))
	if err != nil || string(got) != "registry tm" {
		t.Fatalf("staged threat model = %q, %v", got, err)
	}
	data, err := os.ReadFile(filepath.Join(work, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		Scrutineer struct {
			OSSScanner map[string]any `json:"oss_scanner"`
		} `json:"scrutineer"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	o := stored.Scrutineer.OSSScanner
	if o["project"] != "proj" || o["registry"] != true || o["threat_model_file"] != "oss_scanner/threat_model.md" ||
		o["dockerfile_file"] != "oss_scanner/Dockerfile" || o["registry_url"] != w.OSSScannerRegistry {
		t.Fatalf("oss_scanner = %v", o)
	}
}

func TestStageOSSScannerOtherSkillStagesNothing(t *testing.T) {
	work := t.TempDir()
	w := ossWorker(ossFixtureRegistry(t), nil)
	if got := w.stageOSSScanner(t.Context(), work, ossScan(), &db.Skill{Name: "semgrep"}, noEmit); got != nil {
		t.Fatalf("staged = %+v", got)
	}
	if _, err := os.Stat(filepath.Join(work, "oss_scanner")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oss_scanner dir exists: %v", err)
	}
}

func TestStageOSSScannerRegistryErrorKeepsFallback(t *testing.T) {
	work := t.TempDir()
	writeOSSFile(t, work, "src/.oss-scanner/Dockerfile", "FROM alpine")
	w := ossWorker("", errors.New("offline"))
	var events []Event
	got := w.stageOSSScanner(t.Context(), work, ossScan(), &db.Skill{Name: "verify"}, func(e Event) { events = append(events, e) })
	if got == nil || got.Registry || got.DockerfileFile != "oss_scanner/Dockerfile" {
		t.Fatalf("staged = %+v", got)
	}
	if len(events) == 0 || events[0].Kind != KindText {
		t.Fatalf("events = %+v", events)
	}
}

func TestStageOSSScannerDisabledAddsNothing(t *testing.T) {
	work := t.TempDir()
	w := &Worker{}
	doc := skillContext{}
	w.attachOSSScanner(t.Context(), work, "", ossScan(), &db.Skill{Name: "threat-model"}, &doc, noEmit)
	if doc.Scrutineer.OSSScanner != nil {
		t.Fatalf("oss_scanner = %+v", doc.Scrutineer.OSSScanner)
	}
	if _, err := os.Stat(filepath.Join(work, "context.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("context.json rewritten: %v", err)
	}
}

func TestOSSScannerRegistryRootReusesRecentClone(t *testing.T) {
	w := &Worker{DataDir: t.TempDir(), OSSScannerRegistry: "https://example.invalid/registry"}
	src := filepath.Join(RepoCacheRoot(w.DataDir, w.OSSScannerRegistry), "src")
	if err := os.MkdirAll(filepath.Join(src, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	w.ossScannerFetched.Store(w.OSSScannerRegistry, time.Now())

	got, err := w.ossScannerRegistryRoot(context.Background(), func(Event) {})
	if err != nil || got != src {
		t.Fatalf("registry root = %q, %v; want the cached clone %q without fetching", got, err, src)
	}
}
