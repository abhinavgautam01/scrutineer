package verification

import (
	"errors"
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

func TestReportValidateRejectsDuplicateAttemptNumbers(t *testing.T) {
	report := completeReport()
	report.Attempts[2].Number = 2
	if err := report.Validate(); err == nil {
		t.Fatal("Validate() accepted duplicate attempt numbers")
	}
}

func TestParseIdentifiesLegacyReport(t *testing.T) {
	_, err := Parse(`{"status":"confirmed","evidence":"boom"}`)
	if !errors.Is(err, ErrMissingRubric) {
		t.Fatalf("Parse() = %v, want ErrMissingRubric", err)
	}
}
