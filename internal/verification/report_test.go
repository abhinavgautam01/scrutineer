package verification

import (
	"errors"
	"strings"
	"testing"
)

func completeReport() Report {
	criterion := Criterion{Verdict: "pass", Method: "ran PoC", Evidence: "observed", Confidence: "high"}
	return Report{
		Status: "confirmed",
		Attempts: []Attempt{
			{Number: 1, Outcome: "reproduced", Evidence: "boom", FailureClass: "panic", CrashSite: "parser.go:42"},
			{Number: 2, Outcome: "reproduced", Evidence: "boom", FailureClass: "panic", CrashSite: "parser.go:42"},
			{Number: 3, Outcome: "reproduced", Evidence: "boom", FailureClass: "panic", CrashSite: "parser.go:42"},
		},
		Criteria: &Criteria{
			PoCWellFormed:                   criterion,
			ReproducesThreeOfThree:          criterion,
			ClaimedFailureClass:             criterion,
			PublicInterfaceToFirstPartySink: criterion,
			Deterministic:                   criterion,
		},
	}
}

func TestReportValidateAndScore(t *testing.T) {
	report := completeReport()
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := report.Score(); got != 1 {
		t.Fatalf("score = %v, want 1", got)
	}
	report.Criteria.Deterministic.Verdict = "fail"
	report.Status = "inconclusive"
	if got := report.Score(); got != 0.8 {
		t.Fatalf("score = %v, want 0.8", got)
	}
}

func TestReportValidateRejectsContradictions(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Report)
		want string
	}{
		{"duplicate attempt", func(r *Report) { r.Attempts[2].Number = 2 }, "not unique"},
		{"confirmed miss", func(r *Report) { r.Attempts[2].Outcome = "not_reproduced" }, "all attempts"},
		{"confirmed failed criterion", func(r *Report) { r.Criteria.Deterministic.Verdict = "fail" }, "Deterministic"},
		{"empty evidence", func(r *Report) { r.Criteria.PoCWellFormed.Evidence = "" }, "evidence is empty"},
		{"bad confidence", func(r *Report) { r.Criteria.PoCWellFormed.Confidence = "certain" }, "confidence"},
		{"fixed passing reproduction", func(r *Report) {
			r.Status = "fixed"
			for i := range r.Attempts {
				r.Attempts[i].Outcome = "not_reproduced"
			}
		}, "reproduction criterion"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := completeReport()
			tt.edit(&report)
			if err := report.Validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestParseIdentifiesLegacyReport(t *testing.T) {
	_, err := Parse(`{"status":"confirmed","evidence":"boom"}`)
	if !errors.Is(err, ErrMissingRubric) {
		t.Fatalf("Parse() = %v, want ErrMissingRubric", err)
	}
}
