package worker

import (
	"strings"
	"testing"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

func TestParseSkillOutputIngestsCoverageClaim(t *testing.T) {
	initial, err := coverage.Marshal(coverage.Record{
		RequestedMode: db.ScanRescanModeDiff,
		ActualMode:    db.ScanRescanModeDiff,
		Completeness:  coverage.CompletenessPartial,
		Reason:        "scan has not reported receipts for the staged changed files",
		IncludedPaths: []string{"a.go", "b.go"},
		ThreatModel:   &coverage.ThreatModelState{Update: "updated", Material: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{Coverage: initial, Completeness: coverage.CompletenessPartial}
	report := `{"coverage":{"receipts":[
		{"path":"a.go","disposition":"reviewed_clean"},
		{"path":"b.go","disposition":"reviewed_findings"}],
		"surfaces":[{"name":"parser","disposition":"reviewed_findings","evidence_ref":"b.go:12"}],
		"open_questions":[],"dropped_findings":[]}}`
	w := &Worker{}
	if err := w.parseSkillOutput(&db.Skill{}, &scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	rec, ok := coverage.Parse(scan.Coverage)
	if !ok {
		t.Fatalf("coverage did not parse: %q", scan.Coverage)
	}
	if scan.Completeness != coverage.CompletenessComplete || rec.Completeness != coverage.CompletenessComplete {
		t.Fatalf("completeness column=%q record=%q", scan.Completeness, rec.Completeness)
	}
	if rec.RequestedMode != db.ScanRescanModeDiff || rec.ActualMode != db.ScanRescanModeDiff || rec.ThreatModel == nil {
		t.Fatalf("worker-owned fields were not preserved: %+v", rec)
	}
	if len(rec.Receipts) != 2 || len(rec.Surfaces) != 1 {
		t.Fatalf("skill evidence was not stored: %+v", rec)
	}
}

func TestParseSkillOutputKeepsDiffPartialWhenReceiptIsMissing(t *testing.T) {
	initial, err := coverage.Marshal(coverage.Record{
		ActualMode:    db.ScanRescanModeDiff,
		Completeness:  coverage.CompletenessPartial,
		IncludedPaths: []string{"a.go", "b.go"},
	})
	if err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{Coverage: initial}
	report := `{"coverage":{"receipts":[{"path":"a.go","disposition":"reviewed_clean"}]}}`
	if err := (&Worker{}).parseSkillOutput(&db.Skill{}, &scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	rec, ok := coverage.Parse(scan.Coverage)
	if !ok {
		t.Fatal("coverage did not parse")
	}
	if rec.Completeness != coverage.CompletenessPartial || rec.Reason != "staged work items have no receipt" {
		t.Fatalf("reconciled state = %q (%q)", rec.Completeness, rec.Reason)
	}
}

func TestParseSkillOutputRejectsInvalidCoverageBeforeMutation(t *testing.T) {
	initial, err := coverage.Marshal(coverage.Record{
		ActualMode:    db.ScanRescanModeDiff,
		Completeness:  coverage.CompletenessPartial,
		IncludedPaths: []string{"a.go"},
	})
	if err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{Coverage: initial, Completeness: coverage.CompletenessPartial}
	report := `{"coverage":{"receipts":[{"path":"../a.go","disposition":"reviewed_clean"}]}}`
	err = (&Worker{}).parseSkillOutput(&db.Skill{}, &scan, report, func(Event) {})
	if err == nil || !strings.Contains(err.Error(), "repository-relative") {
		t.Fatalf("error = %v, want repository-relative validation", err)
	}
	if scan.Coverage != initial || scan.Completeness != coverage.CompletenessPartial {
		t.Fatalf("invalid claim mutated scan: %+v", scan)
	}
}

func TestParseSkillOutputNeverClaimsCompleteWithoutWorkerScope(t *testing.T) {
	scan := db.Scan{}
	report := `{"coverage":{"receipts":[{"path":"a.go","disposition":"reviewed_clean"}]}}`
	if err := (&Worker{}).parseSkillOutput(&db.Skill{}, &scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	rec, ok := coverage.Parse(scan.Coverage)
	if !ok {
		t.Fatal("coverage did not parse")
	}
	if scan.Completeness != coverage.CompletenessUnknown || rec.Completeness != coverage.CompletenessUnknown {
		t.Fatalf("completeness column=%q record=%q", scan.Completeness, rec.Completeness)
	}
}
