package web

import (
	"encoding/json"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/verification"
)

func TestLoadFindingVerificationViewsToleratesUngradedRow(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: verifySkillName}
	s.DB.Create(&scan)
	ungradedScan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: verifySkillName}
	s.DB.Create(&ungradedScan)
	finding := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "graded", Severity: "High"}
	s.DB.Create(&finding)

	report := completeVerificationReport()
	validReport, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	score := report.Score()
	graded := db.FindingVerification{
		FindingID: finding.ID,
		ScanID:    scan.ID,
		Status:    report.Status,
		Score:     &score,
		Report:    string(validReport),
	}
	if err := s.DB.Create(&graded).Error; err != nil {
		t.Fatal(err)
	}

	report.Attempts[1].Number = report.Attempts[0].Number
	invalidReport, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	ungraded := db.FindingVerification{
		FindingID: finding.ID,
		ScanID:    ungradedScan.ID,
		Status:    report.Status,
		Report:    string(invalidReport),
	}
	if err := s.DB.Create(&ungraded).Error; err != nil {
		t.Fatal(err)
	}

	views, err := loadFindingVerificationViews(s.DB, finding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 2 {
		t.Fatalf("views = %d, want 2", len(views))
	}
	if views[0].ID != ungraded.ID || views[0].ScoreLabel != "ungraded" || views[0].HasRubric {
		t.Errorf("ungraded view = %+v", views[0])
	}
	if views[1].ID != graded.ID || views[1].ScoreLabel != "100%" || !views[1].HasRubric {
		t.Errorf("graded view = %+v", views[1])
	}
}

func completeVerificationReport() verification.Report {
	criterion := verification.Criterion{
		Verdict:    "pass",
		Method:     "run",
		Evidence:   "observed",
		Confidence: "high",
	}
	return verification.Report{
		Status: "confirmed",
		Attempts: []verification.Attempt{
			{Number: 1, Outcome: "reproduced", Evidence: "same panic", FailureClass: "panic", CrashSite: "parser.go:42"},
			{Number: 2, Outcome: "reproduced", Evidence: "same panic", FailureClass: "panic", CrashSite: "parser.go:42"},
			{Number: 3, Outcome: "reproduced", Evidence: "same panic", FailureClass: "panic", CrashSite: "parser.go:42"},
		},
		Criteria: &verification.Criteria{
			PoCWellFormed:                   criterion,
			ReproducesThreeOfThree:          criterion,
			ClaimedFailureClass:             criterion,
			PublicInterfaceToFirstPartySink: criterion,
			Deterministic:                   criterion,
		},
	}
}
