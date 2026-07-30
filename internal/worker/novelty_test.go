package worker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

func TestNoveltyContextMarksUntouchedFileUnfixed(t *testing.T) {
	fixture := newNoveltyFixture(t)
	fixture.write(t, "README.md", "unrelated change\n")
	head := gitCommit(t, fixture.src, "update docs")

	got := fixture.check(t, head)
	if got.State != db.FindingNoveltyUnfixed || got.FileChanged {
		t.Fatalf("novelty = %+v, want untouched/unfixed", got)
	}
	if got.CommitLog != "" {
		t.Errorf("commit_log = %q, want empty", got.CommitLog)
	}
	fixture.requirePersisted(t, db.FindingNoveltyUnfixed, head)
}

func TestNoveltyContextStagesBoundedChangedFileEvidence(t *testing.T) {
	fixture := newNoveltyFixture(t)
	fixture.write(t, "pkg/parse.go", "package pkg\n\nfunc parse(input string) string { return clean(input) }\n")
	head := gitCommit(t, fixture.src, "guard parser input")

	got := fixture.check(t, head)
	if got.State != db.FindingNoveltyUnclear || !got.FileChanged {
		t.Fatalf("novelty = %+v, want changed/unclear", got)
	}
	if !strings.Contains(got.CommitLog, "guard parser input") || !strings.Contains(got.CommitLog, "clean(input)") {
		t.Errorf("commit_log missing bounded patch evidence:\n%s", got.CommitLog)
	}
	fixture.requirePersisted(t, db.FindingNoveltyUnclear, head)

	scan := fixture.scan(head)
	if err := stageContextWithInputs(
		fixture.workRoot, "http://127.0.0.1:8080/api", "", DefaultMetadataDir,
		scan, &fixture.repo, nil, got,
	); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(fixture.workRoot, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	var staged skillContext
	if err := json.Unmarshal(data, &staged); err != nil {
		t.Fatal(err)
	}
	if staged.Scrutineer.Novelty == nil || staged.Scrutineer.Novelty.CommitLog != got.CommitLog {
		t.Fatalf("staged novelty = %+v, want host-generated evidence", staged.Scrutineer.Novelty)
	}

	scan.FindingID = new(fixture.finding.ID)
	if err := (&Worker{DB: fixture.gdb}).parseRevalidateOutput(
		scan,
		`{"verdict":"already_fixed","reason":"the staged commit adds the missing guard"}`,
		func(Event) {},
	); err != nil {
		t.Fatal(err)
	}
	fixture.requirePersisted(t, db.FindingNoveltyFixed, head)
}

func TestNoveltyContextRecordsNotCheckedForUnsafeLocation(t *testing.T) {
	fixture := newNoveltyFixture(t)
	head := fixture.base
	fixture.finding.Location = "../outside.go:4"
	if err := fixture.gdb.Model(&fixture.finding).Update("location", fixture.finding.Location).Error; err != nil {
		t.Fatal(err)
	}

	got := fixture.check(t, head)
	if got.State != db.FindingNoveltyNotChecked {
		t.Fatalf("novelty = %+v, want not_checked", got)
	}
	if !strings.Contains(got.NotCheckedWhy, "repository-relative") {
		t.Errorf("not_checked_reason = %q", got.NotCheckedWhy)
	}
	fixture.requirePersisted(t, db.FindingNoveltyNotChecked, head)

	if err := (&Worker{DB: fixture.gdb}).parseRevalidateOutput(
		fixture.scan(head),
		`{"verdict":"true_positive","reason":"model attempted a verdict without history"}`,
		func(Event) {},
	); err != nil {
		t.Fatal(err)
	}
	fixture.requirePersisted(t, db.FindingNoveltyNotChecked, head)
}

type noveltyFixture struct {
	workRoot string
	src      string
	gdb      *gorm.DB
	repo     db.Repository
	finding  db.Finding
	base     string
}

func newNoveltyFixture(t *testing.T) noveltyFixture {
	t.Helper()
	workRoot := t.TempDir()
	src := filepath.Join(workRoot, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, src, "init")
	if err := os.MkdirAll(filepath.Join(src, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(src, "pkg", "parse.go"),
		[]byte("package pkg\n\nfunc parse(input string) string { return input }\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	base := gitCommit(t, src, "add vulnerable parser")

	gdb, err := db.Open(filepath.Join(t.TempDir(), "novelty.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "file://" + src, Name: "fixture"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	prior := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone, Commit: base}
	if err := gdb.Create(&prior).Error; err != nil {
		t.Fatal(err)
	}
	finding := db.Finding{
		ScanID: prior.ID, RepositoryID: repo.ID, Title: "parser issue",
		Severity: "High", Status: db.FindingNew, Commit: base, Location: "pkg/parse.go:3",
	}
	if err := gdb.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}
	return noveltyFixture{
		workRoot: workRoot,
		src:      src,
		gdb:      gdb,
		repo:     repo,
		finding:  finding,
		base:     base,
	}
}

func (f noveltyFixture) write(t *testing.T, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.src, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f noveltyFixture) scan(head string) *db.Scan {
	return &db.Scan{
		RepositoryID: f.repo.ID,
		Repository:   f.repo,
		FindingID:    new(f.finding.ID),
		Commit:       head,
	}
}

func (f noveltyFixture) check(t *testing.T, head string) *skillContextNovelty {
	t.Helper()
	w := &Worker{DB: f.gdb}
	got, err := w.noveltyContext(
		context.Background(), f.workRoot, f.scan(head), &db.Skill{Name: revalidateSkillName},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("novelty context is nil")
	}
	return got
}

func (f noveltyFixture) requirePersisted(t *testing.T, state db.FindingNovelty, commit string) {
	t.Helper()
	var finding db.Finding
	if err := f.gdb.First(&finding, f.finding.ID).Error; err != nil {
		t.Fatal(err)
	}
	if finding.Novelty != state || finding.NoveltyCheckedCommit != commit || finding.NoveltyCheckedAt == nil {
		t.Errorf("persisted novelty = %+v, want state=%q commit=%q checked_at", finding, state, commit)
	}
}
