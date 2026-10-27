package web

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"

	"gorm.io/gorm"
)

func TestJobs_omitsBlobsAndPreservesTableFields(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	skill := db.Skill{Name: "projection", Active: true}
	if err := s.DB.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	started := time.Now().Add(-time.Hour)
	finished := started.Add(90 * time.Second)
	var scans []db.Scan
	for _, name := range []string{"Zulu", "Alpha"} {
		repo := db.Repository{URL: "https://example.com/" + name, Name: name,
			Metadata: "metadata blob", ThreatModel: "threat model blob", ScanConfig: "config blob",
			EcosystemsRepoData: "ecosystems blob"}
		if err := s.DB.Create(&repo).Error; err != nil {
			t.Fatal(err)
		}
		scan := db.Scan{RepositoryID: repo.ID, SkillID: &skill.ID, SkillName: skill.Name,
			Kind: "skill", Status: db.ScanDone, Model: "test-model", Ref: "review-branch",
			SubPath: "packages/api", FocusArea: `{"name":"Request handlers","paths":["src/**"]}`,
			ScanGroup: "review-group", Completeness: "partial", CostCapped: true, MaxTurnsHit: true,
			FindingsCount: 7, CostUSD: 2.5, StartedAt: &started, FinishedAt: &finished,
			Log: strings.Repeat("log\n", 1<<18), Report: "report blob", Prompt: "prompt blob",
			RefusalAudit: "refusal blob", ImportPayload: []byte("import blob")}
		if err := s.DB.Create(&scan).Error; err != nil {
			t.Fatal(err)
		}
		scans = append(scans, scan)
	}
	var loaded []db.Scan
	if err := s.DB.Callback().Query().After("gorm:after_query").Register("check_scan_list_projection", func(tx *gorm.DB) {
		if rows, ok := tx.Statement.Dest.(*[]db.Scan); ok {
			loaded = append(loaded, (*rows)...)
		}
	}); err != nil {
		t.Fatal(err)
	}
	for _, sort := range []string{"", "repository", "repository.desc"} {
		t.Run("sort="+sort, func(t *testing.T) {
			loaded = nil
			req := localReq("GET", "/scans?sort="+sort)
			req.Header.Set("HX-Request", "true")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, req)
			if w.Code != 200 {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
			if len(loaded) != len(scans) {
				t.Fatalf("loaded %d scans, want %d", len(loaded), len(scans))
			}
			assertScanListProjection(t, loaded, w.Body.String(), sort, scans[0].ID)
		})
	}
}

func assertScanListProjection(t *testing.T, scans []db.Scan, body, sort string, retryID uint) {
	t.Helper()
	for _, scan := range scans {
		if scan.Log != "" || scan.Report != "" || scan.Prompt != "" || scan.RefusalAudit != "" || len(scan.ImportPayload) != 0 {
			t.Errorf("scan %d loaded unused text columns", scan.ID)
		}
		repo := scan.Repository
		if repo.Metadata != "" || repo.ThreatModel != "" || repo.ScanConfig != "" || repo.EcosystemsRepoData != "" {
			t.Errorf("scan %d loaded repository blobs", scan.ID)
		}
	}
	for _, want := range []string{"Alpha", "Zulu", "packages/api", "Request handlers", "review-group", "projection", "review-branch",
		"partial", "max turns", "cost cap", "test-model", "$2.50", ">1m</td>", fmt.Sprintf("/scans/%d/retry", retryID)} {
		if !strings.Contains(body, want) {
			t.Errorf("missing table content %q", want)
		}
	}
	if sort == "repository" && strings.Index(body, ">Alpha<") > strings.Index(body, ">Zulu<") {
		t.Error("repository ascending sort is reversed")
	}
	if sort == "repository.desc" && strings.Index(body, ">Zulu<") > strings.Index(body, ">Alpha<") {
		t.Error("repository descending sort is reversed")
	}
}
