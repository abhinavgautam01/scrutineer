package db

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// RepositoryHealth describes the observed maintenance state of a repository.
// Empty is deliberately used for an unassessed repository: missing metadata or
// maintainer evidence must not be mistaken for abandonment.
type RepositoryHealth string

const (
	RepositoryHealthActive    RepositoryHealth = "active"
	RepositoryHealthStale     RepositoryHealth = "stale"
	RepositoryHealthAbandoned RepositoryHealth = "abandoned"
	RepositoryHealthZombie    RepositoryHealth = "zombie"

	healthActiveWindow    = 365 * 24 * time.Hour
	healthAbandonedWindow = 2 * 365 * 24 * time.Hour
	// A month is thirty days here, matching how healthAge renders one.
	healthStaleReleaseWindow = 18 * 30 * 24 * time.Hour
	healthZombieDependents   = 100
)

// RepositoryHealthAssessment is the durable classification plus the evidence
// used to reach it. Summary is derived at read time for detailed views; only
// Health is stored on the repository row.
type RepositoryHealthAssessment struct {
	Health            RepositoryHealth
	Summary           string
	DependentRepos    int
	ActiveMaintainers int
	KnownMaintainers  int
	// LastReleaseAt is the most recent release across every package the
	// repository publishes, so a monorepo counts as shipping while any one
	// of its packages still ships. Nil when no package records a release
	// date.
	LastReleaseAt *time.Time
	// RiskFlags are the supply-chain hygiene warnings the packages skill
	// reported, unioned across every package the repository publishes and
	// canonically ordered. They are surfaced in the summary as evidence and
	// never move the classification: an absent flag means "not checked"
	// rather than "checked and clean" (SKILL.md says so). The package set is
	// also replaced wholesale on every run, so scoring on a flag would let a
	// scan that skipped the check flip a stored verdict with no upstream
	// change behind it.
	RiskFlags []string
}

// AssessRepositoryHealth classifies a repository from persisted evidence.
// An old push alone can make a repository stale, but abandonment additionally
// requires an explicit archived flag or maintainer evidence showing no active
// owner. That avoids treating repositories which have not yet run maintainers
// as abandoned.
func AssessRepositoryHealth(repo Repository, packages []Package, maintainers []Maintainer, now time.Time) RepositoryHealthAssessment {
	assessment := RepositoryHealthAssessment{}
	var flags []string
	for _, pkg := range packages {
		// Published packages can share downstream repositories. The package
		// feed cannot prove those sets are disjoint, so max is conservative.
		assessment.DependentRepos = max(assessment.DependentRepos, pkg.DependentRepos)
		flags = append(flags, PackageRiskFlags(pkg.RiskFlags)...)
		if pkg.LatestReleaseAt != nil && (assessment.LastReleaseAt == nil || pkg.LatestReleaseAt.After(*assessment.LastReleaseAt)) {
			assessment.LastReleaseAt = pkg.LatestReleaseAt
		}
	}
	// The dropped return is discarded: values in the RiskFlags column were
	// already validated when the packages skill's row was written, so
	// nothing here should be unknown.
	assessment.RiskFlags, _ = NormalisePackageRiskFlags(flags)
	for _, maintainer := range maintainers {
		switch maintainer.Status {
		case MaintainerActive:
			assessment.KnownMaintainers++
			assessment.ActiveMaintainers++
		case MaintainerInactive:
			assessment.KnownMaintainers++
		}
	}

	var releaseAge time.Duration
	staleRelease := false
	if assessment.LastReleaseAt != nil {
		releaseAge = now.Sub(*assessment.LastReleaseAt)
		staleRelease = releaseAge >= healthStaleReleaseWindow
	}

	if !repo.Archived && repo.PushedAt == nil && assessment.KnownMaintainers == 0 {
		return assessment
	}

	var age time.Duration
	if repo.PushedAt != nil {
		age = now.Sub(*repo.PushedAt)
	}

	assessment.Health = repositoryHealth(repo.Archived, repo.PushedAt != nil, staleRelease, age, assessment)
	assessment.Summary = healthSummary(repo.Archived, repo.PushedAt, age, releaseAge, assessment)
	return assessment
}

func repositoryHealth(archived, hasPush, staleRelease bool, age time.Duration, assessment RepositoryHealthAssessment) RepositoryHealth {
	abandoned := archived || (hasPush && age >= healthAbandonedWindow && assessment.KnownMaintainers > 0 && assessment.ActiveMaintainers == 0)
	if abandoned {
		if assessment.DependentRepos >= healthZombieDependents {
			return RepositoryHealthZombie
		}
		return RepositoryHealthAbandoned
	}
	// A repository whose newest package release is eighteen months old is
	// not reaching its consumers however busy its commit log looks, so it is
	// held at stale. Taking the newest release across all packages keeps a
	// monorepo active while any one of its packages still ships.
	if hasPush && age <= healthActiveWindow && assessment.ActiveMaintainers > 0 && !staleRelease {
		return RepositoryHealthActive
	}
	return RepositoryHealthStale
}

func healthSummary(archived bool, pushedAt *time.Time, age, releaseAge time.Duration, assessment RepositoryHealthAssessment) string {
	var parts []string
	switch {
	case archived:
		parts = append(parts, "repository is archived")
	case pushedAt == nil:
		parts = append(parts, "last push is unknown")
	default:
		parts = append(parts, fmt.Sprintf("last push %s ago", healthAge(age)))
	}
	switch {
	case assessment.KnownMaintainers == 0:
		parts = append(parts, "maintainer activity is unknown")
	case assessment.ActiveMaintainers == 0:
		parts = append(parts, "no active maintainers identified")
	default:
		parts = append(parts, fmt.Sprintf("%d active maintainer(s)", assessment.ActiveMaintainers))
	}
	if assessment.DependentRepos > 0 {
		parts = append(parts, fmt.Sprintf("up to %d dependent repos", assessment.DependentRepos))
	}
	if assessment.LastReleaseAt != nil {
		parts = append(parts, fmt.Sprintf("last release %s ago", healthAge(releaseAge)))
	}
	if len(assessment.RiskFlags) > 0 {
		parts = append(parts, "risk flags: "+strings.Join(PackageRiskFlagLabels(assessment.RiskFlags), ", "))
	}
	return strings.Join(parts, "; ")
}

func healthAge(age time.Duration) string {
	if age < 0 {
		return "just now"
	}
	years := int(age / (365 * 24 * time.Hour))
	if years > 0 {
		return fmt.Sprintf("%d year(s)", years)
	}
	months := int(age / (30 * 24 * time.Hour))
	if months > 0 {
		return fmt.Sprintf("%d month(s)", months)
	}
	return "less than a month"
}

// RefreshRepositoryHealth recalculates and persists the health classification.
// It does not manufacture a status when the evidence is incomplete; legacy
// rows therefore remain empty until enough source data exists.
func RefreshRepositoryHealth(gdb *gorm.DB, repositoryID uint, now time.Time) (RepositoryHealthAssessment, error) {
	var repo Repository
	if err := gdb.First(&repo, repositoryID).Error; err != nil {
		return RepositoryHealthAssessment{}, fmt.Errorf("load repository health inputs: %w", err)
	}
	var packages []Package
	if err := gdb.Where("repository_id = ?", repositoryID).Find(&packages).Error; err != nil {
		return RepositoryHealthAssessment{}, fmt.Errorf("load packages for repository health: %w", err)
	}
	var maintainers []Maintainer
	if err := gdb.Joins("JOIN repository_maintainers ON repository_maintainers.maintainer_id = maintainers.id").
		Where("repository_maintainers.repository_id = ?", repositoryID).Find(&maintainers).Error; err != nil {
		return RepositoryHealthAssessment{}, fmt.Errorf("load maintainers for repository health: %w", err)
	}

	assessment := AssessRepositoryHealth(repo, packages, maintainers, now)
	if repo.Health == assessment.Health {
		return assessment, nil
	}
	if err := gdb.Model(&Repository{}).Where("id = ?", repositoryID).
		Update("health", assessment.Health).Error; err != nil {
		return RepositoryHealthAssessment{}, fmt.Errorf("save repository health: %w", err)
	}
	return assessment, nil
}
