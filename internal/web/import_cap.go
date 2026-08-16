package web

import "scrutineer/internal/ingest"

// An externally-produced scanner report is unbounded. One over-eager CodeQL or
// Semgrep rule can carry thousands of hits against a single repository, and the
// import path turns every one of them into a Finding row plus a revalidate job
// that chains into verify. The caps below bound that blast radius at the door.
//
// They apply only to deterministic scanner output (SARIF today), never to
// curated input: scrutineer's own sharing bundle, a hand-written minimal-JSON
// report, and the CSV/markdown exports an analyst assembled are all somebody's
// considered list of findings, not raw rule output, so they import whole.
const (
	// importPerRuleCap is the most findings one (tool, rule) pair may
	// contribute to a single imported result. Five hits are enough to show
	// what a rule is flagging; the rest are noise until somebody has triaged
	// those five.
	importPerRuleCap = 5
	// importResultCap is the most findings one imported result may contribute
	// in total, whatever the spread of rules. It backstops the per-rule cap
	// for reports that spray a thousand distinct rules.
	importResultCap = 50
)

// importCapStats records what the caps did to one result so the import
// response and the server log can tell a clean scan from a bounded one.
//
// Received counts findings as the parser produced them. Accepted counts those
// that passed both caps. The created/observed counts reported alongside are
// taken further downstream, after fingerprint dedup, so accepted is an upper
// bound on them rather than their sum.
type importCapStats struct {
	Received       int
	Accepted       int
	DroppedPerRule int
	DroppedTotal   int
}

// truncated reports whether either cap rejected anything.
func (c importCapStats) truncated() bool {
	return c.DroppedPerRule > 0 || c.DroppedTotal > 0
}

// uncappedImportStats describes a result imported whole, so a format the caps
// do not apply to still reports the same counters.
func uncappedImportStats(res ingest.Result) importCapStats {
	return importCapStats{Received: len(res.Findings), Accepted: len(res.Findings)}
}

// capScannerResult returns res with its findings bounded by the two caps, plus
// the counts describing what was dropped.
//
// Input order decides who survives: the first importPerRuleCap hits of a rule
// and the first importResultCap findings overall are the ones kept. Truncation
// is therefore deterministic for a given report, which is what lets an operator
// re-run the same file and reason about what is missing.
//
// A finding both caps would reject is counted against the per-rule cap alone,
// the more specific reason, so the two dropped counts sum to Received minus
// Accepted rather than double-counting.
func capScannerResult(res ingest.Result) (ingest.Result, importCapStats) {
	stats := importCapStats{Received: len(res.Findings)}
	accepted := make([]ingest.Finding, 0, min(len(res.Findings), importResultCap))
	perRule := make(map[string]int, len(res.Findings))
	for _, f := range res.Findings {
		key := importRuleKey(res.Tool, f)
		switch {
		case perRule[key] >= importPerRuleCap:
			stats.DroppedPerRule++
		case len(accepted) >= importResultCap:
			stats.DroppedTotal++
		default:
			perRule[key]++
			accepted = append(accepted, f)
		}
	}
	stats.Accepted = len(accepted)
	res.Findings = accepted
	return res, stats
}

// importRuleKey identifies the rule a finding fired from. One result carries
// one tool, so the tool is constant across a single call, but it rides in the
// key so the cap stays per (tool, rule) should a format ever group several
// tools into one result.
//
// SARIF does not require a result to name its ruleId. The title stands in when
// one is missing: it is derived from the rule whenever the parser resolved one,
// and where it is not, grouping by it is still closer to per-rule than lumping
// every anonymous hit into a single bucket that the fifth finding would close.
func importRuleKey(tool string, f ingest.Finding) string {
	rule := f.RuleID
	if rule == "" {
		rule = f.Title
	}
	return tool + "\x00" + rule
}
