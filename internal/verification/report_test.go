package verification

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func completeReport() Report {
	criterion := Criterion{Verdict: "pass", Method: "ran PoC", Evidence: "observed", Confidence: "high"}
	root := "AT1"
	return Report{
		Status: "confirmed",
		AttackTree: &AttackTree{
			Goal:    "Trigger the claimed parser panic through the public API",
			RootID:  root,
			Verdict: "reachable",
			Nodes: []AttackTreeNode{
				{ID: root, Kind: "goal", Description: "Trigger parser panic", Status: "satisfied", Evidence: "3/3 attempts panic at parser.go:42"},
				{ID: "AT2", ParentID: &root, Kind: "entry_point", Description: "Supply document to Parse", Status: "satisfied", Evidence: "api.go:18 calls parser"},
			},
			Blockers: []string{},
		},
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

func TestParseAcceptsPriorRubricWithoutAttackTree(t *testing.T) {
	report := completeReport()
	report.AttackTree = nil
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.AttackTree != nil {
		t.Fatalf("attack tree = %+v, want nil", parsed.AttackTree)
	}
}

func TestReportValidateRejectsInvalidAttackTrees(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Report)
		want string
	}{
		{
			name: "duplicate node",
			edit: func(r *Report) { r.AttackTree.Nodes[1].ID = r.AttackTree.Nodes[0].ID },
			want: "is not unique",
		},
		{
			name: "missing parent",
			edit: func(r *Report) {
				missing := "AT99"
				r.AttackTree.Nodes[1].ParentID = &missing
			},
			want: "names missing parent",
		},
		{
			name: "cycle",
			edit: func(r *Report) {
				third := "AT3"
				second := "AT2"
				r.AttackTree.Nodes[1].ParentID = &third
				r.AttackTree.Nodes = append(r.AttackTree.Nodes, AttackTreeNode{
					ID: third, ParentID: &second, Kind: "sink", Description: "panic", Status: "satisfied", Evidence: "parser.go:42",
				})
			},
			want: "parent cycle",
		},
		{
			name: "status mismatch",
			edit: func(r *Report) { r.AttackTree.Verdict = "blocked" },
			want: `status "confirmed" requires attack_tree.verdict "reachable"`,
		},
		{
			name: "root status mismatch",
			edit: func(r *Report) { r.AttackTree.Nodes[0].Status = "unproven" },
			want: `root status "unproven" does not match verdict "reachable"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := completeReport()
			tc.edit(&report)
			if err := report.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tc.want)
			}
		})
	}
}
