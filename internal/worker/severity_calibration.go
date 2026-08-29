package worker

import (
	"fmt"
	"slices"

	"scrutineer/internal/db"
	"scrutineer/internal/threatmodel"
	"scrutineer/internal/verification"
)

const controlSeverityCap = "Medium"

// findingSeverityCalibration is the host-derived projection produced from a
// reconciled control-bypass gate. Evaluated distinguishes an authoritative
// no-cap result from an ungraded report that must leave the prior projection
// untouched.
type findingSeverityCalibration struct {
	Severity   string
	Caps       []string
	Incomplete bool
	Evaluated  bool
}

func calibrateControlSeverity(
	current string,
	controls *skillContextControls,
	gate *verification.ControlBypass,
) findingSeverityCalibration {
	result := findingSeverityCalibration{Severity: current, Evaluated: true}
	if controls == nil {
		return result
	}
	if gate == nil || controls.UnavailableWhy != "" || gate.UnavailableReason != "" {
		result.Incomplete = true
		return result
	}

	controlsByID := make(map[string]threatmodel.Control, len(controls.Matched))
	for _, control := range controls.Matched {
		controlsByID[control.ID] = control
	}
	for _, assessment := range gate.Assessments {
		switch assessment.Disposition {
		case "bypassed", "not_applicable":
			continue
		case "unresolved", "not_attempted":
			result.Incomplete = true
			continue
		case "held":
		default:
			result.Incomplete = true
			continue
		}

		control, ok := controlsByID[assessment.ControlID]
		if !ok {
			result.Incomplete = true
			continue
		}
		var reason string
		switch control.Kind {
		case threatmodel.KindAuthorization:
			reason = fmt.Sprintf("authorization control %q held; severity capped at %s", control.ID, controlSeverityCap)
		case threatmodel.KindSandbox:
			reason = fmt.Sprintf("sandbox control %q held; severity capped at %s", control.ID, controlSeverityCap)
		default:
			result.Incomplete = true
			continue
		}
		result.Caps = append(result.Caps, reason)
		result.Severity = capFindingSeverity(result.Severity, controlSeverityCap)
	}

	slices.Sort(result.Caps)
	if len(result.Caps) > 0 && !knownFindingSeverity(current) {
		result.Incomplete = true
	}
	return result
}

func capFindingSeverity(current, maximum string) string {
	if !knownFindingSeverity(current) || !db.SeverityAtLeast(current, maximum) {
		return current
	}
	return maximum
}

func knownFindingSeverity(severity string) bool {
	return slices.Contains(db.SeverityLevels, severity)
}
