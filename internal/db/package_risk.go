package db

import (
	"slices"
	"strings"
)

// PackageRiskFlag is one supply-chain hygiene warning the packages skill
// attaches to a published package. The set is closed: an id the skill
// reports that is not one of the constants below is dropped on write, so a
// stored value only ever holds known flags.
type PackageRiskFlag string

const (
	PackageRiskSingleMaintainer        PackageRiskFlag = "single_maintainer"
	PackageRiskNoSecurityPolicy        PackageRiskFlag = "no_security_policy"
	PackageRiskNativeExtension         PackageRiskFlag = "native_extension"
	PackageRiskStaleRelease            PackageRiskFlag = "stale_release"
	PackageRiskMaintainerDomainExpired PackageRiskFlag = "maintainer_domain_expired"
)

// packageRiskFlagOrder is the canonical order flags are stored and rendered
// in, independent of the order the skill reported them.
var packageRiskFlagOrder = []PackageRiskFlag{
	PackageRiskSingleMaintainer,
	PackageRiskNoSecurityPolicy,
	PackageRiskNativeExtension,
	PackageRiskStaleRelease,
	PackageRiskMaintainerDomainExpired,
}

// NormalisePackageRiskFlags validates and canonically orders the risk-flag
// ids the packages skill reported for one package. kept holds the known ids
// in packageRiskFlagOrder, deduped, ready to be comma-joined (no space) into
// Package.RiskFlags. dropped holds the unknown ids, deduped in first-seen
// order, for callers that want to warn about them. Both are nil when there
// is nothing to report.
func NormalisePackageRiskFlags(ids []string) (kept, dropped []string) {
	seen := make(map[PackageRiskFlag]bool, len(ids))
	seenDropped := map[string]bool{}
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		flag := PackageRiskFlag(id)
		if slices.Contains(packageRiskFlagOrder, flag) {
			seen[flag] = true
			continue
		}
		if !seenDropped[id] {
			seenDropped[id] = true
			dropped = append(dropped, id)
		}
	}
	for _, f := range packageRiskFlagOrder {
		if seen[f] {
			kept = append(kept, string(f))
		}
	}
	return kept, dropped
}

// PackageRiskFlags is the read side of the comma-joined Package.RiskFlags
// column: it splits on "," and trims each element, dropping empties. Returns
// nil for an empty or all-blank input.
func PackageRiskFlags(joined string) []string {
	var out []string
	for _, part := range strings.Split(joined, ",") {
		id := strings.TrimSpace(part)
		if id == "" {
			continue
		}
		out = append(out, id)
	}
	return out
}
