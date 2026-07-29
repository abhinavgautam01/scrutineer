package web

import (
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

const migrationGuideRowLimit = 10

type findingMigrationGuide struct {
	Health        db.RepositoryHealth
	HealthSummary string

	Packages     []db.Package
	Alternatives []db.PackageAlternative

	PriorityDependents []migrationDependentRow
	KnownSafeCount     int
	FixedCount         int
	TotalExposureRows  int
}

type migrationDependentRow struct {
	Name           string
	Ecosystem      string
	RepositoryURL  string
	DependentRepos int
	Status         string
	Rationale      string
	UpdatedAt      time.Time
}

func loadFindingMigrationGuide(gdb *gorm.DB, f db.Finding, repo db.Repository) (*findingMigrationGuide, error) {
	alternatives, err := loadPackageAlternatives(gdb, repo.ID)
	if err != nil {
		return nil, err
	}

	var packages []db.Package
	if err := gdb.Where("repository_id = ?", repo.ID).
		Order("dependent_repos desc, downloads desc, id asc").
		Limit(migrationGuideRowLimit).
		Find(&packages).Error; err != nil {
		return nil, err
	}
	var maintainers []db.Maintainer
	if err := gdb.Joins("JOIN repository_maintainers rm ON rm.maintainer_id = maintainers.id").
		Where("rm.repository_id = ?", repo.ID).Find(&maintainers).Error; err != nil {
		return nil, err
	}
	health := db.AssessRepositoryHealth(repo, packages, maintainers, time.Now())
	if health.Health == "" {
		health.Health = repo.Health
	}
	show := len(alternatives) > 0 ||
		health.Health == db.RepositoryHealthAbandoned ||
		health.Health == db.RepositoryHealthZombie
	if !show {
		return nil, nil
	}

	guide := findingMigrationGuide{
		Health:        health.Health,
		HealthSummary: health.Summary,
		Packages:      packages,
		Alternatives:  alternatives,
	}
	if err := loadMigrationGuideDependents(gdb, f.ID, &guide); err != nil {
		return nil, err
	}
	return &guide, nil
}

func loadMigrationGuideDependents(gdb *gorm.DB, findingID uint, guide *findingMigrationGuide) error {
	var exposureRows []db.FindingDependent
	if err := gdb.Where("finding_id = ?", findingID).Find(&exposureRows).Error; err != nil {
		return err
	}
	guide.TotalExposureRows = len(exposureRows)
	if len(exposureRows) == 0 {
		return nil
	}

	actionableIDs := make([]uint, 0, len(exposureRows))
	statusByDependent := make(map[uint]db.FindingDependent, len(exposureRows))
	for _, row := range exposureRows {
		row.Status = migrationExposureStatus(row.Status)
		statusByDependent[row.DependentID] = row
		if row.Status == db.ExposureKnownNotAffected {
			guide.KnownSafeCount++
			continue
		}
		if row.Status == db.ExposureFixed {
			guide.FixedCount++
			continue
		}
		actionableIDs = append(actionableIDs, row.DependentID)
	}
	if len(actionableIDs) == 0 {
		return nil
	}
	var dependents []db.Dependent
	if err := gdb.Where("id IN ?", actionableIDs).
		Order("dependent_repos desc, downloads desc, id asc").
		Limit(migrationGuideRowLimit).
		Find(&dependents).Error; err != nil {
		return err
	}
	for _, dep := range dependents {
		row := statusByDependent[dep.ID]
		if row.Status == db.ExposureKnownNotAffected || row.Status == db.ExposureFixed {
			continue
		}
		guide.PriorityDependents = append(guide.PriorityDependents, migrationDependentRow{
			Name:           dep.Name,
			Ecosystem:      dep.Ecosystem,
			RepositoryURL:  dep.RepositoryURL,
			DependentRepos: dep.DependentRepos,
			Status:         row.Status,
			Rationale:      row.Rationale,
			UpdatedAt:      row.UpdatedAt,
		})
	}
	return nil
}

func migrationExposureStatus(status string) string {
	if status == "" {
		return db.ExposureUnderInvestigation
	}
	return status
}
