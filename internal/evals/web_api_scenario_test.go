//go:build evals

package evals

import (
	"encoding/json"
	"testing"
)

// judgeOutcomes scores a report holding findings with the default judge and
// counts required misses and unexpected findings the way Runner does.
func judgeOutcomes(t *testing.T, sc Scenario, findings ...Finding) (failedRequired, unexpected int) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"findings": findings})
	if err != nil {
		t.Fatal(err)
	}
	matches, err := HeuristicJudge{}.Judge(sc, string(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range matches {
		if m.Matched {
			continue
		}
		switch m.Kind {
		case assertionShouldFind:
			if m.Required {
				failedRequired++
			}
		case assertionShouldNotFind:
			unexpected++
		}
	}
	return failedRequired, unexpected
}

// The default judge must count a cross-site request forgery false positive on
// the guarded display-name handler as unexpected however the model titles it,
// while a correct finding on the email endpoint that only contrasts itself
// with that handler still passes.
func TestWebAPISessionScenarioRejectsGuardedHandlerFalsePositive(t *testing.T) {
	scenario, err := LoadScenario("../../evals/web-api-session.yaml")
	if err != nil {
		t.Fatal(err)
	}
	truePositive := Finding{
		Title:      "Cross-site account email update",
		CWE:        "CWE-352",
		Location:   "services/site/server.py:36",
		Trace:      "GET /api/email carries the victim's SameSite=Lax session cookie on a top-level navigation and writes the supplied email.",
		Validation: "Unlike update_display_name in display_name.py, which checks Origin and a session token, this GET handler has neither.",
	}
	falsePositive := Finding{
		Title:    "Display name update lacks CSRF protection",
		CWE:      "CWE-352",
		Location: "services/site/display_name.py:4",
		Trace:    "POST /api/display-name changes the account name from a form submission.",
	}
	if missed, extra := judgeOutcomes(t, scenario, truePositive); missed != 0 || extra != 0 {
		t.Errorf("true positive only: missed=%d unexpected=%d, want 0 and 0", missed, extra)
	}
	if missed, extra := judgeOutcomes(t, scenario, truePositive, falsePositive); missed != 0 || extra != 1 {
		t.Errorf("false positive on the guarded handler: missed=%d unexpected=%d, want 0 and 1", missed, extra)
	}
	if missed, extra := judgeOutcomes(t, scenario, falsePositive); missed != 1 || extra != 1 {
		t.Errorf("false positive alone: missed=%d unexpected=%d, want 1 and 1", missed, extra)
	}
}
