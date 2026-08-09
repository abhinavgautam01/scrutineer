package verification

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	attemptCount   = 3
	criterionCount = 5
)

// ErrMissingRubric identifies reports produced by the pre-rubric verify skill.
// The worker keeps accepting those reports so queued scans survive an upgrade.
var ErrMissingRubric = errors.New("verify report has no grading rubric")

// Report is the structured output of the verify skill.
type Report struct {
	Status     string     `json:"status"`
	Preflight  *Preflight `json:"preflight,omitempty"`
	Attempts   []Attempt  `json:"attempts"`
	Criteria   *Criteria  `json:"criteria,omitempty"`
	Reproducer string     `json:"reproducer,omitempty"`
	Evidence   string     `json:"evidence,omitempty"`
	Notes      string     `json:"notes,omitempty"`
}

// Preflight records whether the supplied reproduction is safe to execute in
// the isolated workspace.
type Preflight struct {
	Classification string `json:"classification"`
	Justification  string `json:"justification"`
}

// Attempt records one of the three independent reproduction attempts.
type Attempt struct {
	Number       int    `json:"number"`
	Outcome      string `json:"outcome"`
	Evidence     string `json:"evidence"`
	FailureClass string `json:"failure_class"`
	CrashSite    string `json:"crash_site"`
}

// Criterion records how one rubric row was judged, including facts that
// weaken the conclusion or could not be established.
type Criterion struct {
	Verdict         string `json:"verdict"`
	Method          string `json:"method"`
	Evidence        string `json:"evidence"`
	Counterevidence string `json:"counterevidence"`
	ProofGap        string `json:"proof_gap"`
	Confidence      string `json:"confidence"`
}

// Criteria is deliberately fixed-shape: every verification grades the same
// five properties and cannot silently omit a difficult row.
type Criteria struct {
	PoCWellFormed                   Criterion `json:"poc_well_formed"`
	ReproducesThreeOfThree          Criterion `json:"reproduces_three_of_three"`
	ClaimedFailureClass             Criterion `json:"claimed_failure_class"`
	PublicInterfaceToFirstPartySink Criterion `json:"public_interface_to_first_party_sink"`
	Deterministic                   Criterion `json:"deterministic"`
}

// NamedCriterion supplies stable display labels without making the report
// schema an open-ended map.
type NamedCriterion struct {
	Name      string
	Criterion Criterion
}

// Parse decodes and validates one rubric report.
func Parse(raw string) (Report, error) {
	var report Report
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		return Report{}, fmt.Errorf("decode verification report: %w", err)
	}
	if report.Criteria == nil {
		return Report{}, ErrMissingRubric
	}
	if err := report.Validate(); err != nil {
		return Report{}, err
	}
	return report, nil
}

// Validate enforces the cross-field invariants JSON Schema cannot express,
// such as unique attempt numbers and a confirmed verdict requiring 3/3 runs.
func (r Report) Validate() error {
	if !validStatus(r.Status) {
		return fmt.Errorf("status %q is not valid", r.Status)
	}
	if r.Criteria == nil {
		return ErrMissingRubric
	}
	if err := validateAttempts(r.Attempts); err != nil {
		return err
	}
	for _, named := range r.Criteria.List() {
		if err := validateCriterion(named.Name, named.Criterion); err != nil {
			return err
		}
	}
	return validateStatusConsistency(r)
}

func validateAttempts(attempts []Attempt) error {
	if len(attempts) != attemptCount {
		return fmt.Errorf("attempts has %d entries, want %d", len(attempts), attemptCount)
	}
	seen := make(map[int]bool, attemptCount)
	for i, attempt := range attempts {
		if attempt.Number < 1 || attempt.Number > attemptCount || seen[attempt.Number] {
			return fmt.Errorf("attempts[%d].number %d is not unique in 1..%d", i, attempt.Number, attemptCount)
		}
		seen[attempt.Number] = true
		if !oneOf(attempt.Outcome, "reproduced", "not_reproduced", "not_attempted") {
			return fmt.Errorf("attempts[%d].outcome %q is not valid", i, attempt.Outcome)
		}
		if strings.TrimSpace(attempt.Evidence) == "" {
			return fmt.Errorf("attempts[%d].evidence is empty", i)
		}
	}
	return nil
}

func validateStatusConsistency(r Report) error {
	switch r.Status {
	case "confirmed":
		if err := requireAttemptOutcome(r.Attempts, "reproduced", "confirmed"); err != nil {
			return err
		}
		return requireCriterionVerdict(r.Criteria.List(), "pass", "confirmed")
	case "fixed":
		if err := requireAttemptOutcome(r.Attempts, "not_reproduced", "fixed"); err != nil {
			return err
		}
		if r.Criteria.ReproducesThreeOfThree.Verdict != "fail" {
			return errors.New("fixed verification requires the reproduction criterion to fail")
		}
	case "deferred", "not_attempted":
		if err := requireAttemptOutcome(r.Attempts, "not_attempted", r.Status); err != nil {
			return err
		}
		if err := requireCriterionVerdict(r.Criteria.List(), "not_attempted", r.Status); err != nil {
			return err
		}
	}
	if r.Status == "deferred" && (r.Preflight == nil ||
		r.Preflight.Classification != "external-reach" || strings.TrimSpace(r.Preflight.Justification) == "") {
		return errors.New("deferred verification requires external-reach preflight evidence")
	}
	return nil
}

func requireAttemptOutcome(attempts []Attempt, outcome, status string) error {
	for _, attempt := range attempts {
		if attempt.Outcome != outcome {
			return fmt.Errorf("%s verification requires all attempts to be %s", status, outcome)
		}
	}
	return nil
}

func requireCriterionVerdict(criteria []NamedCriterion, verdict, status string) error {
	for _, named := range criteria {
		if named.Criterion.Verdict != verdict {
			return fmt.Errorf("%s verification requires %s to be %s", status, named.Name, verdict)
		}
	}
	return nil
}

// Score is the fraction of the five fixed criteria that passed.
func (r Report) Score() float64 {
	passed := 0
	for _, named := range r.Criteria.List() {
		if named.Criterion.Verdict == "pass" {
			passed++
		}
	}
	return float64(passed) / criterionCount
}

// List returns the fixed rubric in display order.
func (c Criteria) List() []NamedCriterion {
	return []NamedCriterion{
		{Name: "PoC well formed", Criterion: c.PoCWellFormed},
		{Name: "Reproduces 3/3", Criterion: c.ReproducesThreeOfThree},
		{Name: "Claimed failure class", Criterion: c.ClaimedFailureClass},
		{Name: "Public interface to first-party sink", Criterion: c.PublicInterfaceToFirstPartySink},
		{Name: "Deterministic", Criterion: c.Deterministic},
	}
}

func validateCriterion(name string, criterion Criterion) error {
	if !oneOf(criterion.Verdict, "pass", "fail", "not_attempted") {
		return fmt.Errorf("criterion %q verdict %q is not valid", name, criterion.Verdict)
	}
	if strings.TrimSpace(criterion.Method) == "" {
		return fmt.Errorf("criterion %q method is empty", name)
	}
	if strings.TrimSpace(criterion.Evidence) == "" {
		return fmt.Errorf("criterion %q evidence is empty", name)
	}
	if !oneOf(criterion.Confidence, "high", "medium", "low") {
		return fmt.Errorf("criterion %q confidence %q is not valid", name, criterion.Confidence)
	}
	return nil
}

func validStatus(status string) bool {
	return oneOf(status, "confirmed", "fixed", "inconclusive", "deferred", "not_attempted")
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
