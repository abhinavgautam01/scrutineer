package worker

import (
	"encoding/json"
	"errors"
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
		return coverage.Claim{}, false, fmt.Errorf("decode report coverage envelope: %w", err)
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
		if err := json.Unmarshal([]byte(scan.Coverage), &stored); err != nil {
			return fmt.Errorf("parse worker-owned coverage record: %w", err)
		}
		return errors.New("parse worker-owned coverage record: valid JSON did not decode as a coverage record")
	}
	var scope []string
	if rec.ActualMode == db.ScanRescanModeDiff {
		scope = rec.IncludedPaths
	}
	rec.ApplyClaim(claim, scope)
	raw, err := coverage.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal reconciled coverage: %w", err)
	}
	scan.Coverage = raw
	scan.Completeness = rec.Completeness
	return nil
}
