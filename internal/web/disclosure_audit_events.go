package web

import (
	"fmt"

	"scrutineer/internal/db"

	"gorm.io/gorm"
)

// logDisclosureRequested records that an analyst launched a disclosure skill
// against scan.FindingID. It runs in the scan-creating transaction so a scan
// that rolls back leaves no event behind.
func logDisclosureRequested(tx *gorm.DB, scan db.Scan) error {
	if scan.FindingID == nil {
		return fmt.Errorf("disclosure audit event needs a finding scan")
	}
	return db.LogEvent(tx, db.AuditEventInput{
		Kind: db.AuditEventDisclosureRequested, SubjectType: db.AuditSubjectFinding, SubjectID: *scan.FindingID,
		Source: db.SourceAnalyst,
		Payload: map[string]any{
			scanAuditRepositoryID: scan.RepositoryID,
			"skill_name":          scan.SkillName,
			"scan_id":             scan.ID,
		},
	})
}

// logScanCreated writes the operator-action event, if any, that the scan
// options ask for. Automatic enqueues set neither option and log nothing.
func logScanCreated(tx *gorm.DB, scan db.Scan, opts ScanOpts) error {
	switch {
	case opts.AuditRetry:
		return logScanControl(tx, db.AuditEventScanRetryRequested, scan, retryLineage(scan), "", db.ScanQueued, db.SourceAnalyst)
	case opts.AuditDisclosure:
		return logDisclosureRequested(tx, scan)
	default:
		return nil
	}
}
