package verification

import (
	"encoding/json"
	"errors"
	"fmt"
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

// Validate enforces attempt-number uniqueness, which JSON Schema cannot
// express. Structural and status-consistency rules live in schema.json.
func (r Report) Validate() error {
	if r.Criteria == nil {
		return ErrMissingRubric
	}
	seen := make(map[int]bool, attemptCount)
	for i, attempt := range r.Attempts {
		if seen[attempt.Number] {
			return fmt.Errorf("attempts[%d].number %d is not unique in 1..%d", i, attempt.Number, attemptCount)
		}
		seen[attempt.Number] = true
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
