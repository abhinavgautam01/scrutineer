package web

import (
	"encoding/json"
	"fmt"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/verification"
)

const verificationPercentScale = 100

type findingVerificationView struct {
	db.FindingVerification
	ScoreLabel    string
	HasRubric     bool
	Criteria      []verification.NamedCriterion
	Attempts      []verification.Attempt
	AttackTree    *verification.AttackTree
	ControlBypass *verification.ControlBypass
	Prerequisites []verification.NamedPrerequisite
}

func loadFindingVerificationViews(gdb *gorm.DB, findingID uint) ([]findingVerificationView, error) {
	var rows []db.FindingVerification
	if err := gdb.Where("finding_id = ?", findingID).Order("id desc").Find(&rows).Error; err != nil {
		return nil, err
	}
	views := make([]findingVerificationView, 0, len(rows))
	for _, row := range rows {
		view := findingVerificationView{FindingVerification: row, ScoreLabel: "ungraded"}
		report, err := verification.Parse(row.Report)
		if err == nil {
			view.HasRubric = true
			view.Criteria = report.Criteria.List()
			view.Attempts = report.Attempts
			view.AttackTree = report.AttackTree
			view.ControlBypass = report.Criteria.ControlBypass
			if report.SeverityPrerequisites != nil {
				view.Prerequisites = report.SeverityPrerequisites.List()
			}
			if row.Score != nil {
				view.ScoreLabel = fmt.Sprintf("%.0f%%", *row.Score*verificationPercentScale)
			}
		}
		views = append(views, view)
	}
	return views, nil
}

func findingVerificationResponse(row *db.FindingVerification) map[string]any {
	var report any
	if err := json.Unmarshal([]byte(row.Report), &report); err != nil {
		report = row.Report
	}
	return map[string]any{
		"id":         row.ID,
		"scan_id":    row.ScanID,
		"status":     row.Status,
		"score":      row.Score,
		"report":     report,
		"created_at": row.CreatedAt,
	}
}
