package worker

import (
	"encoding/json"
	"fmt"
	"strings"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

func extractSkillCoverageClaim(report string) (coverage.Claim, bool, error) {
	if !strings.HasPrefix(strings.TrimSpace(report), "{") {
		return coverage.Claim{}, false, nil
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal([]byte(report), &envelope); err != nil {
		return coverage.Claim{}, false, nil
	}
	raw, present := envelope[coverage.ReportMetadataKey]
	if !present {
		return coverage.Claim{}, false, nil
	}
	claim, err := coverage.ParseClaim(raw)
	if err != nil {
		return coverage.Claim{}, false, err
	}
	return claim, true, nil
}

func applySkillCoverageClaim(scan *db.Scan, claim coverage.Claim) error {
	rec, ok := coverage.Parse(scan.Coverage)
	if !ok && strings.TrimSpace(scan.Coverage) != "" {
		var stored coverage.Record
		err := json.Unmarshal([]byte(scan.Coverage), &stored)
		return fmt.Errorf("parse worker-owned coverage record: %w", err)
	}
	var scope []string
	if rec.ActualMode == db.ScanRescanModeDiff {
		scope = rec.IncludedPaths
	}
	rec.ApplyClaim(claim, scope)
	setCoverage(scan, rec)
	return nil
}
