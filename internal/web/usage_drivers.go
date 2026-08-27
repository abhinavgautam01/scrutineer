package web

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"scrutineer/internal/db"
)

const (
	usageOutlierMultiple              = 10
	usageCorrelationMinSamples        = 3
	usageCorrelationStrongThreshold   = 0.7
	usageCorrelationModerateThreshold = 0.4
)

const (
	usageDriverSLOC      = "SLOC"
	usageDriverManifests = "Dependency manifests"
	usageDriverSinks     = "Phase 1 sinks"
)

type usageDriverAnalysis struct {
	Correlations []usageDriverCorrelation
	Outliers     []usageCostOutlier
}

type usageDriverCorrelation struct {
	Skill   string
	Driver  string
	Samples int
	R       float64
	Summary string
}

type usageCostOutlier struct {
	ScanID       uint
	RepositoryID uint
	Repository   string
	Skill        string
	Model        string
	Profile      string
	Cost         float64
	Median       float64
	Multiple     float64
	Turns        int
	SLOC         string
	Manifests    string
	Sinks        string
}

type usageSnapshotKey struct {
	RepositoryID uint
	Commit       string
}

type usageSnapshotValue struct {
	ScanID uint
	Value  float64
}

type usageDriverValues struct {
	SLOC      *float64
	Manifests *float64
	Sinks     *float64
}

type usageDriverPair struct {
	Driver float64
	Cost   float64
}

func (s *Server) loadUsageDriverAnalysis(scans []db.Scan) usageDriverAnalysis {
	var sources []db.Scan
	s.DB.Select("id", "repository_id", "skill_name", "commit", "report").
		Where("status = ?", db.ScanDone).
		Where("skill_name IN ?", []string{"repo-overview", "dependencies", "security-deep-dive"}).
		Where("report != ''").
		Find(&sources)

	var repos []db.Repository
	s.DB.Select("id", "name", "full_name").Find(&repos)
	repoNames := make(map[uint]string, len(repos))
	for _, repo := range repos {
		repoNames[repo.ID] = usageRepositoryName(repo)
	}

	values := usageDriverValuesByScan(scans, sources)
	return usageDriverAnalysis{
		Correlations: usageCorrelations(scans, values),
		Outliers:     usageOutliers(scans, values, repoNames),
	}
}

func usageDriverValuesByScan(scans, sources []db.Scan) map[uint]usageDriverValues {
	slocBySnapshot := map[usageSnapshotKey]usageSnapshotValue{}
	manifestsBySnapshot := map[usageSnapshotKey]usageSnapshotValue{}
	values := map[uint]usageDriverValues{}
	for _, source := range sources {
		key := usageSnapshotKey{RepositoryID: source.RepositoryID, Commit: source.Commit}
		switch source.SkillName {
		case "repo-overview":
			if sloc, ok := repoOverviewSLOC(source.Report); ok {
				setLatestUsageSnapshot(slocBySnapshot, key, source.ID, sloc)
				v := values[source.ID]
				v.SLOC = floatPointer(sloc)
				values[source.ID] = v
			}
		case "dependencies":
			if manifests, ok := dependencyManifestCount(source.Report); ok {
				setLatestUsageSnapshot(manifestsBySnapshot, key, source.ID, manifests)
				v := values[source.ID]
				v.Manifests = floatPointer(manifests)
				values[source.ID] = v
			}
		case "security-deep-dive":
			if sinks, ok := deepDiveSinkCount(source.Report); ok {
				v := values[source.ID]
				v.Sinks = floatPointer(sinks)
				values[source.ID] = v
			}
		}
	}

	for _, scan := range scans {
		v := values[scan.ID]
		// repo-overview and dependencies describe the repository root. Applying
		// those values to narrower scans would overstate their actual scope.
		if scan.SubPath == "" && scan.FocusArea == "" && scan.Commit != "" {
			key := usageSnapshotKey{RepositoryID: scan.RepositoryID, Commit: scan.Commit}
			if snapshot, ok := slocBySnapshot[key]; ok {
				v.SLOC = floatPointer(snapshot.Value)
			}
			if snapshot, ok := manifestsBySnapshot[key]; ok {
				v.Manifests = floatPointer(snapshot.Value)
			}
		}
		values[scan.ID] = v
	}
	return values
}

func setLatestUsageSnapshot(values map[usageSnapshotKey]usageSnapshotValue, key usageSnapshotKey, scanID uint, value float64) {
	if key.Commit == "" {
		return
	}
	current, ok := values[key]
	if !ok || scanID > current.ScanID {
		values[key] = usageSnapshotValue{ScanID: scanID, Value: value}
	}
}

func repoOverviewSLOC(report string) (float64, bool) {
	var result struct {
		Lines struct {
			TotalLines *int `json:"total_lines"`
		} `json:"lines"`
	}
	if json.Unmarshal([]byte(report), &result) != nil || result.Lines.TotalLines == nil || *result.Lines.TotalLines < 0 {
		return 0, false
	}
	return float64(*result.Lines.TotalLines), true
}

func dependencyManifestCount(report string) (float64, bool) {
	var result struct {
		Analyses struct {
			Inventory *struct {
				Status string `json:"status"`
				Result []struct {
					ManifestPath string `json:"manifest_path"`
				} `json:"result"`
			} `json:"inventory"`
		} `json:"analyses"`
	}
	if json.Unmarshal([]byte(report), &result) != nil || result.Analyses.Inventory == nil || result.Analyses.Inventory.Status != "ok" {
		return 0, false
	}
	paths := map[string]struct{}{}
	for _, row := range result.Analyses.Inventory.Result {
		if path := strings.TrimSpace(row.ManifestPath); path != "" {
			paths[path] = struct{}{}
		}
	}
	return float64(len(paths)), true
}

func deepDiveSinkCount(report string) (float64, bool) {
	var result struct {
		Inventory []json.RawMessage `json:"inventory"`
	}
	if json.Unmarshal([]byte(report), &result) != nil || result.Inventory == nil {
		return 0, false
	}
	return float64(len(result.Inventory)), true
}

func usageCorrelations(scans []db.Scan, values map[uint]usageDriverValues) []usageDriverCorrelation {
	pairs := map[string]map[string][]usageDriverPair{}
	for _, scan := range scans {
		if scan.CostUSD <= 0 {
			continue
		}
		v := values[scan.ID]
		appendUsagePair(pairs, scan.SkillName, usageDriverSLOC, v.SLOC, scan.CostUSD)
		appendUsagePair(pairs, scan.SkillName, usageDriverManifests, v.Manifests, scan.CostUSD)
		appendUsagePair(pairs, scan.SkillName, usageDriverSinks, v.Sinks, scan.CostUSD)
	}

	var rows []usageDriverCorrelation
	for skill, byDriver := range pairs {
		for driver, observations := range byDriver {
			r, ok := pearsonCorrelation(observations)
			if !ok {
				continue
			}
			rows = append(rows, usageDriverCorrelation{
				Skill:   skill,
				Driver:  driver,
				Samples: len(observations),
				R:       r,
				Summary: correlationSummary(r),
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		left, right := math.Abs(rows[i].R), math.Abs(rows[j].R)
		if left != right {
			return left > right
		}
		if rows[i].Skill != rows[j].Skill {
			return rows[i].Skill < rows[j].Skill
		}
		return rows[i].Driver < rows[j].Driver
	})
	return rows
}

func appendUsagePair(pairs map[string]map[string][]usageDriverPair, skill, driver string, value *float64, cost float64) {
	if value == nil {
		return
	}
	if pairs[skill] == nil {
		pairs[skill] = map[string][]usageDriverPair{}
	}
	pairs[skill][driver] = append(pairs[skill][driver], usageDriverPair{Driver: *value, Cost: cost})
}

func pearsonCorrelation(pairs []usageDriverPair) (float64, bool) {
	if len(pairs) < usageCorrelationMinSamples {
		return 0, false
	}
	var driverMean, costMean float64
	for _, pair := range pairs {
		driverMean += pair.Driver
		costMean += pair.Cost
	}
	driverMean /= float64(len(pairs))
	costMean /= float64(len(pairs))

	var covariance, driverVariance, costVariance float64
	for _, pair := range pairs {
		driverDelta := pair.Driver - driverMean
		costDelta := pair.Cost - costMean
		covariance += driverDelta * costDelta
		driverVariance += driverDelta * driverDelta
		costVariance += costDelta * costDelta
	}
	if driverVariance == 0 || costVariance == 0 {
		return 0, false
	}
	return covariance / math.Sqrt(driverVariance*costVariance), true
}

func correlationSummary(r float64) string {
	strength := "weak"
	abs := math.Abs(r)
	if abs >= usageCorrelationStrongThreshold {
		strength = "strong"
	} else if abs >= usageCorrelationModerateThreshold {
		strength = "moderate"
	}
	direction := "positive"
	if r < 0 {
		direction = "negative"
	}
	return strength + " " + direction
}

func usageOutliers(scans []db.Scan, values map[uint]usageDriverValues, repoNames map[uint]string) []usageCostOutlier {
	costsBySkill := map[string][]float64{}
	for _, scan := range scans {
		if scan.CostUSD > 0 {
			costsBySkill[scan.SkillName] = append(costsBySkill[scan.SkillName], scan.CostUSD)
		}
	}
	medians := map[string]float64{}
	for skill, costs := range costsBySkill {
		medians[skill] = summarise(costs).Median
	}

	var rows []usageCostOutlier
	for _, scan := range scans {
		median := medians[scan.SkillName]
		if median <= 0 || scan.CostUSD < usageOutlierMultiple*median {
			continue
		}
		v := values[scan.ID]
		rows = append(rows, usageCostOutlier{
			ScanID:       scan.ID,
			RepositoryID: scan.RepositoryID,
			Repository:   repoNames[scan.RepositoryID],
			Skill:        scan.SkillName,
			Model:        scan.Model,
			Profile:      scan.Profile,
			Cost:         scan.CostUSD,
			Median:       median,
			Multiple:     scan.CostUSD / median,
			Turns:        scan.Turns,
			SLOC:         usageDriverDisplay(v.SLOC),
			Manifests:    usageDriverDisplay(v.Manifests),
			Sinks:        usageDriverDisplay(v.Sinks),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Multiple != rows[j].Multiple {
			return rows[i].Multiple > rows[j].Multiple
		}
		return rows[i].Cost > rows[j].Cost
	})
	return rows
}

func usageRepositoryName(repo db.Repository) string {
	if repo.FullName != "" {
		return repo.FullName
	}
	if repo.Name != "" {
		return repo.Name
	}
	return fmt.Sprintf("repository #%d", repo.ID)
}

func usageDriverDisplay(value *float64) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%.0f", *value)
}

func floatPointer(value float64) *float64 {
	return &value
}
