package db

import (
	"encoding/json"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// maxContributionFindings bounds how many findings FindingContributions walks
// so a pathological duplicate chain cannot turn one page load into an
// unbounded scan.
const maxContributionFindings = 64

// FindingObservation is one immutable record of a scan reporting a finding.
// The Finding row is the analyst's mutable case and keeps the content of the
// first report across re-observation, so without this table the second and
// later scans that rediscover the same fingerprint would lose their own
// severity, rating and evidence. Rows are append-only history: nothing edits
// them after the scan finishes. Agreement between rows is never treated as
// verification. There is one row per (finding, scan) so parser retries stay
// idempotent. A rewrite from the same scan refreshes the row because the final
// report supersedes that scan's own streamed preview.
//
// The promoted columns support display and comparison. Evidence is a JSON
// object snapshot of the remaining evidence fields (see ObservationFromFinding)
// and is untrusted model output: it is stored and shown as data only.
type FindingObservation struct {
	ID              uint `gorm:"primarykey"`
	FindingID       uint `gorm:"index;not null;uniqueIndex:idx_finding_observation_scan,priority:1"`
	ScanID          uint `gorm:"index;not null;uniqueIndex:idx_finding_observation_scan,priority:2"`
	RepositoryID    uint `gorm:"index;not null"`
	SkillName       string
	Backend         string
	Model           string
	Commit          string
	ReportFindingID string // the finding's id inside the scan report, e.g. F1
	Fingerprint     string
	Title           string
	Severity        string
	Confidence      string
	CWE             string
	Location        string
	Reachability    string
	Rating          string `gorm:"type:text"`
	Evidence        string `gorm:"type:text"` // JSON object of the unpromoted evidence fields
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// ObservationFromFinding builds the observation row for a scan reporting f.
// f must be the content the scan itself reported (not the stored canonical
// row) and must already carry its database id.
func ObservationFromFinding(scan *Scan, f *Finding) FindingObservation {
	evidence := map[string]string{}
	for k, v := range map[string]string{
		"locations":    f.Locations,
		"sinks":        f.Sinks,
		"trace":        f.Trace,
		"boundary":     f.Boundary,
		"validation":   f.Validation,
		"reach":        f.Reach,
		"affected":     f.Affected,
		"quality_tier": f.QualityTier,
		"prior_art":    f.PriorArt,
		"dup_check":    f.DupCheck,
	} {
		if v != "" {
			evidence[k] = v
		}
	}
	raw := ""
	if len(evidence) > 0 {
		if b, err := json.Marshal(evidence); err == nil {
			raw = string(b)
		}
	}
	return FindingObservation{
		FindingID:       f.ID,
		ScanID:          scan.ID,
		RepositoryID:    scan.RepositoryID,
		SkillName:       scan.SkillName,
		Backend:         scan.Backend,
		Model:           scan.Model,
		Commit:          scan.Commit,
		ReportFindingID: f.FindingID,
		Fingerprint:     f.Fingerprint,
		Title:           f.Title,
		Severity:        f.Severity,
		Confidence:      f.Confidence,
		CWE:             f.CWE,
		Location:        f.Location,
		Reachability:    f.Reachability,
		Rating:          f.Rating,
		Evidence:        raw,
	}
}

// RecordFindingObservation upserts the observation for its (finding, scan)
// pair. A repeat write from the same scan replaces the content columns so the
// final report wins over the scan's streamed preview.
func RecordFindingObservation(gdb *gorm.DB, obs FindingObservation) error {
	return gdb.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "finding_id"}, {Name: "scan_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"repository_id", "skill_name", "backend", "model", "commit", "report_finding_id",
			"fingerprint", "title", "severity", "confidence", "cwe", "location",
			"reachability", "rating", "evidence", "updated_at",
		}),
	}).Create(&obs).Error
}

// FindingContributions returns the observations that make up a finding: its
// own plus those of findings that finding-dedup merged into it (Status
// duplicate with DuplicateOfID pointing into the set), followed transitively
// and within the same repository. The walk is capped at maxContributionFindings
// findings. Rows are ordered by creation time then id.
func FindingContributions(gdb *gorm.DB, findingID uint) ([]FindingObservation, error) {
	var root Finding
	if err := gdb.Select("id", "repository_id").First(&root, findingID).Error; err != nil {
		return nil, err
	}
	ids := []uint{root.ID}
	visited := map[uint]bool{root.ID: true}
	frontier := []uint{root.ID}
	for len(frontier) > 0 && len(ids) < maxContributionFindings {
		var children []uint
		if err := gdb.Model(&Finding{}).
			Where("repository_id = ? AND status = ? AND duplicate_of_id IN ?", root.RepositoryID, FindingDuplicate, frontier).
			Order("id").Pluck("id", &children).Error; err != nil {
			return nil, err
		}
		frontier = frontier[:0]
		for _, id := range children {
			if visited[id] || len(ids) >= maxContributionFindings {
				continue
			}
			visited[id] = true
			ids = append(ids, id)
			frontier = append(frontier, id)
		}
	}
	var rows []FindingObservation
	err := gdb.Where("finding_id IN ?", ids).Order("created_at, id").Find(&rows).Error
	return rows, err
}
