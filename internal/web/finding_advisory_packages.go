package web

import (
	"errors"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// findingAdvisoryPackages selects published identities, not a transitive impact
// set. In a monorepo, neither a root finding nor an unassigned package proves
// package-level impact. Do not infer attribution from source locations.
func findingAdvisoryPackages(gdb *gorm.DB, f db.Finding) ([]db.Package, error) {
	q := gdb.Where("repository_id = ?", f.RepositoryID)
	if f.SubPath != "" {
		var sub db.Subproject
		err := gdb.Where("repository_id = ? AND path = ?", f.RepositoryID, f.SubPath).Take(&sub).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		q = q.Where("subproject_id = ?", sub.ID)
	} else {
		var count int64
		if err := gdb.Model(&db.Subproject{}).Where("repository_id = ?", f.RepositoryID).Count(&count).Error; err != nil {
			return nil, err
		}
		if count != 0 {
			return nil, nil
		}
		// Preserve root-package exports for repositories without subprojects.
		q = q.Where("subproject_id IS NULL")
	}
	var pkgs []db.Package
	if err := q.Order("id").Find(&pkgs).Error; err != nil {
		return nil, err
	}
	return pkgs, nil
}
