package web

// /reporting is the corpus-wide reporting page: a running total of scan
// activity over a rolling window, alongside the cost and token averages
// that docs/cost_averages.sql computes from the command line.
//
// It deliberately overlaps /usage only on the averages. /usage answers
// "which skill costs what" by slicing cost per skill and per day; this
// page answers "what has the corpus done lately" and pairs that with the
// single-number averages, so the two can be read side by side. Both draw
// on the same cost_usd/*_tokens columns the worker writes.
//
// The cost averages are computed SQL-side so the GORM query maps clause
// for clause onto docs/cost_averages.sql, and so a growing corpus is not
// read into memory to be averaged. AVG/COUNT are standard SQL and survive
// the PostgreSQL driver swap internal/db documents.
//
// The day bucketing is the one thing done in Go: grouping by calendar day
// needs date()/strftime()/date_trunc, which differ per dialect and would
// pin this file to SQLite. /usage bins its days in Go for the same reason.

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"scrutineer/internal/db"
)

// reportDateLayout is the calendar-day key for the per-day breakdown. Days
// are UTC so a report generated in two timezones bucket-aligns.
const reportDateLayout = "2006-01-02"

// findingsField is the "findings" column name, shared by the CSV header
// and the JSON payload. Named rather than repeated so the two spellings of
// the export cannot drift apart, and so this package's count of the bare
// literal stays under goconst's threshold.
const findingsField = "findings"

// reportInterval is one selectable rolling window. Dur of 0 means all
// time. Rolling rather than calendar: the totals are a running figure, so
// they should not collapse to near-zero at midnight or on the 1st.
type reportInterval struct {
	Key   string
	Label string
	// Meaning spells the window out for the exports, where a bare "week"
	// leaves a reader guessing between a rolling 7 days and an ISO week.
	Meaning string
	Dur     time.Duration
}

const (
	reportDay   = 24 * time.Hour
	reportWeek  = 7 * reportDay
	reportMonth = 30 * reportDay
)

var reportIntervals = []reportInterval{
	{Key: "all", Label: "All time", Meaning: "every scan and finding on record"},
	{Key: "month", Label: "Month", Meaning: "rolling 30 days ending at generated_at", Dur: reportMonth},
	{Key: "week", Label: "Week", Meaning: "rolling 7 days ending at generated_at", Dur: reportWeek},
	{Key: "day", Label: "Day", Meaning: "rolling 24 hours ending at generated_at", Dur: reportDay},
}

// resolveReportInterval maps the ?interval query value to a window,
// defaulting to all time for anything unrecognised.
func resolveReportInterval(key string) reportInterval {
	for _, iv := range reportIntervals {
		if iv.Key == key {
			return iv
		}
	}
	return reportIntervals[0]
}

// reportSeverities lists the selectable minimum-severity thresholds, least
// severe first so the UI reads as a widening filter. Derived from
// db.SeverityLevels so a new level appears here automatically.
var reportSeverities = db.SeverityLevels

// resolveMinSeverity canonicalises the ?severity query value, returning ""
// (no filter) for anything unrecognised. displaySeverity folds the casing
// variants the corpus carries, so ?severity=critical works.
func resolveMinSeverity(v string) string {
	if v == "" {
		return ""
	}
	// displaySeverity folds the "CRITICAL"/"MODERATE" spellings the corpus
	// carries but not lowercase ones, and a query parameter is usually
	// typed lowercase, so upcase before asking.
	canonical := displaySeverity(strings.ToUpper(v))
	for _, level := range db.SeverityLevels {
		if level == canonical {
			return canonical
		}
	}
	return ""
}

// minSeverityRank converts a canonical severity to its severityOrder rank.
// severityOrder ranks the most severe LOWEST (Critical 0 … Low 3, unknown
// last), so "at least this severe" is `rank <= threshold`.
func minSeverityRank(level string) (int, bool) {
	for i, l := range db.SeverityLevels {
		if l == level {
			return len(db.SeverityLevels) - 1 - i, true
		}
	}
	return 0, false
}

// reportTotals is the running-total panel. ReposScanned counts distinct
// repositories with at least one scan in the window, so a repo rescanned
// ten times still counts once. Findings honours the severity filter; the
// scan counts do not, since severity is a property of findings only.
type reportTotals struct {
	ReposScanned int
	Scans        int
	ScansDone    int
	Findings     int
}

// ScansPerRepo is the mean number of scan runs each scanned repository
// accounted for. Display-only: a reader seeing 510 runs against 49
// repositories needs the ratio to know the figure is a fan-out, not an
// inflated count. One repository scan enqueues a run per skill (see
// enqueueDiffRescanGroup), so this is normally well above 1.
//
// Deliberately a method rather than a field: it is derived presentation,
// and the exports build their payloads from the fields explicitly, so
// keeping it off the struct stops it leaking into the CSV or JSON.
func (t reportTotals) ScansPerRepo() float64 {
	if t.ReposScanned == 0 {
		return 0
	}
	return float64(t.Scans) / float64(t.ReposScanned)
}

// CompletionRate is the share of scan runs that reached "done", as a
// 0..1 fraction for the pct template helper.
func (t reportTotals) CompletionRate() float64 {
	if t.Scans == 0 {
		return 0
	}
	return float64(t.ScansDone) / float64(t.Scans)
}

// reportAverages is one column of the cost-averages table: the per-scan
// means from docs/cost_averages.sql. Runs is the denominator, exposed so a
// small-sample average is recognisable as one.
//
// The population matches that SQL exactly — completed scans with a
// recorded cost — so queued, running, failed and cancelled rows don't drag
// the figures toward zero. The severity filter does not apply: these
// average scans, not findings.
type reportAverages struct {
	Runs             int     `gorm:"column:runs"`
	CostUSD          float64 `gorm:"column:cost_usd"`
	InputTokens      float64 `gorm:"column:input_tokens"`
	OutputTokens     float64 `gorm:"column:output_tokens"`
	CacheReadTokens  float64 `gorm:"column:cache_read_tokens"`
	CacheWriteTokens float64 `gorm:"column:cache_write_tokens"`
	TotalTokens      float64 `gorm:"column:total_tokens"`
}

// reportDayRow is one row of the per-day breakdown. ScansAveraged is the
// day's completed-and-costed scan count — the denominator behind that
// day's averages, and the same population the period averages use.
type reportDayRow struct {
	Date           string
	ReposScanned   int
	Scans          int
	ScansDone      int
	Findings       int
	CostUSD        float64
	TotalTokens    int
	ScansAveraged  int
	AvgCostUSD     float64
	AvgTotalTokens float64
}

// reportData is the whole snapshot. The page render and both exports read
// from this one value, so a downloaded report always matches the screen it
// was downloaded from.
type reportData struct {
	Interval    reportInterval
	MinSeverity string
	Since       *time.Time
	Generated   time.Time
	Totals      reportTotals
	Period      reportAverages
	AllTime     reportAverages
	Days        []reportDayRow
}

// reportAnchorSQL is the timestamp a scan is attributed to, as SQL: when
// it finished, falling back to when it was created for rows that never
// reached a terminal state. COALESCE is standard SQL, so this survives the
// driver swap. scanAnchor below is the Go twin of this expression and the
// two must stay in step, since the SQL bounds the window and the Go one
// picks the day bucket within it.
const reportAnchorSQL = "COALESCE(finished_at, created_at)"

// reportAveragesFor loads one column of the cost-averages table.
//
// The WHERE clause and the averaged expressions are a direct transcription
// of docs/cost_averages.sql: completed scans carrying a recorded cost, so
// queued, running, failed and cancelled rows don't drag the figures toward
// zero. since bounds the population to a rolling window; nil averages the
// whole corpus.
//
// AVG over an empty set is NULL, which will not scan into a float64, so
// each average is coalesced to zero — matching the zeroed struct an empty
// corpus should produce. Rounding is left to the display layer: the SQL
// file's ROUND(AVG(cost_usd), 2) has no round(double precision, integer)
// overload on PostgreSQL and would not survive the driver swap.
func (s *Server) reportAveragesFor(since *time.Time) reportAverages {
	var out reportAverages
	q := s.DB.Model(&db.Scan{}).
		Select(`COUNT(*) AS runs,
			COALESCE(AVG(cost_usd), 0)            AS cost_usd,
			COALESCE(AVG(input_tokens), 0)        AS input_tokens,
			COALESCE(AVG(output_tokens), 0)       AS output_tokens,
			COALESCE(AVG(cache_read_tokens), 0)   AS cache_read_tokens,
			COALESCE(AVG(cache_write_tokens), 0)  AS cache_write_tokens,
			COALESCE(AVG(input_tokens + output_tokens + cache_read_tokens + cache_write_tokens), 0) AS total_tokens`).
		Where("status = ?", db.ScanDone).
		Where("cost_usd > 0")
	if since != nil {
		q = q.Where(reportAnchorSQL+" >= ?", *since)
	}
	q.Scan(&out)
	return out
}

// scanAnchor is the timestamp a scan is attributed to: when it finished,
// falling back to when it was created for rows that never reached a
// terminal state. This is the same bucketing /usage uses for its by-day
// view, so the two pages agree on which day a scan lands in.
func scanAnchor(sc db.Scan) time.Time {
	if sc.FinishedAt != nil {
		return sc.FinishedAt.UTC()
	}
	return sc.CreatedAt.UTC()
}

// dayAccumulator gathers one calendar day's figures while the scan rows
// stream past, so the day breakdown costs one pass rather than a query
// per day.
type dayAccumulator struct {
	repos         map[uint]struct{}
	scans         int
	scansDone     int
	findings      int
	cost          float64
	tokens        int
	averagedScans int
	averagedCost  float64
	averagedToken int
}

// buildReport assembles the snapshot for one interval and severity floor.
//
// Both averages columns are aggregated in the database. Only the totals
// and the day breakdown need individual rows, and that read is bounded to
// the selected window and to the columns the report reads, so picking a
// narrower interval genuinely costs less rather than filtering a full
// table scan in memory.
func (s *Server) buildReport(iv reportInterval, minSeverity string) reportData {
	now := time.Now().UTC()
	data := reportData{Interval: iv, MinSeverity: minSeverity, Generated: now}
	if iv.Dur > 0 {
		since := now.Add(-iv.Dur)
		data.Since = &since
	}

	data.AllTime = s.reportAveragesFor(nil)
	data.Period = s.reportAveragesFor(data.Since)

	days := map[string]*dayAccumulator{}
	at := func(day string) *dayAccumulator {
		acc := days[day]
		if acc == nil {
			acc = &dayAccumulator{repos: map[uint]struct{}{}}
			days[day] = acc
		}
		return acc
	}

	// Every status counts toward the activity totals, so unlike the
	// averages this read is not narrowed to completed scans.
	var scans []db.Scan
	sq := s.DB.Model(&db.Scan{}).
		Select("repository_id", "status", "cost_usd", "input_tokens", "output_tokens",
			"cache_read_tokens", "cache_write_tokens", "finished_at", "created_at")
	if data.Since != nil {
		sq = sq.Where(reportAnchorSQL+" >= ?", *data.Since)
	}
	sq.Find(&scans)

	repos := map[uint]struct{}{}
	for _, sc := range scans {
		acc := at(scanAnchor(sc).Format(reportDateLayout))
		data.Totals.Scans++
		acc.scans++
		if sc.Status == db.ScanDone {
			data.Totals.ScansDone++
			acc.scansDone++
		}
		repos[sc.RepositoryID] = struct{}{}
		acc.repos[sc.RepositoryID] = struct{}{}
		tokens := sc.InputTokens + sc.OutputTokens + sc.CacheReadTokens + sc.CacheWriteTokens
		acc.cost += sc.CostUSD
		acc.tokens += tokens
		// Same population as reportAveragesFor, so a day's average and the
		// period average are the same measurement at two resolutions.
		if sc.Status == db.ScanDone && sc.CostUSD > 0 {
			acc.averagedScans++
			acc.averagedCost += sc.CostUSD
			acc.averagedToken += tokens
		}
	}
	data.Totals.ReposScanned = len(repos)

	// Findings are counted by creation time: a finding belongs to the
	// window it was first reported in, not to a later re-observation.
	type findingRow struct{ CreatedAt time.Time }
	var found []findingRow
	fq := s.DB.Model(&db.Finding{}).Select("created_at")
	if data.Since != nil {
		fq = fq.Where("created_at >= ?", *data.Since)
	}
	// severityOrder ranks the most severe lowest, so "at or above this
	// severity" is `<=`. Reusing that shared CASE keeps this filter from
	// ever disagreeing with the finding lists' ordering.
	if rank, ok := minSeverityRank(minSeverity); ok {
		fq = fq.Where("("+severityOrder+") <= ?", rank)
	}
	fq.Scan(&found)
	for _, f := range found {
		data.Totals.Findings++
		at(f.CreatedAt.UTC().Format(reportDateLayout)).findings++
	}

	data.Days = make([]reportDayRow, 0, len(days))
	for day, acc := range days {
		row := reportDayRow{
			Date:          day,
			ReposScanned:  len(acc.repos),
			Scans:         acc.scans,
			ScansDone:     acc.scansDone,
			Findings:      acc.findings,
			CostUSD:       acc.cost,
			TotalTokens:   acc.tokens,
			ScansAveraged: acc.averagedScans,
		}
		if acc.averagedScans > 0 {
			n := float64(acc.averagedScans)
			row.AvgCostUSD = acc.averagedCost / n
			row.AvgTotalTokens = float64(acc.averagedToken) / n
		}
		data.Days = append(data.Days, row)
	}
	sort.Slice(data.Days, func(i, j int) bool { return data.Days[i].Date > data.Days[j].Date })
	return data
}

// reportFromRequest builds the snapshot the request asks for. Shared by the
// page and both exports so a download can never disagree with the screen.
func (s *Server) reportFromRequest(r *http.Request) reportData {
	q := r.URL.Query()
	return s.buildReport(resolveReportInterval(q.Get("interval")), resolveMinSeverity(q.Get("severity")))
}

func (s *Server) reporting(w http.ResponseWriter, r *http.Request) {
	data := s.reportFromRequest(r)
	s.render(w, r, "reporting.html", map[string]any{
		"Report":     data,
		"Intervals":  reportIntervals,
		"Severities": reportSeverities,
	})
}

// reportFilename names a download after the window it covers, so reports
// pulled on different days don't overwrite each other in a downloads dir.
func reportFilename(data reportData, ext string) string {
	return fmt.Sprintf("scrutineer-report-%s-%s.%s",
		data.Interval.Key, data.Generated.Format(reportDateLayout), ext)
}

func reportTimestamp(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

// severityFilterLabel names the active filter for the exports, where an
// empty string would read as "the filter is broken" rather than "off".
func severityFilterLabel(minSeverity string) string {
	if minSeverity == "" {
		return "all"
	}
	return minSeverity
}

// reportCSVHeader is the single header row of the CSV export.
//
// The export is one rectangular table with a uniform column count so that
// Excel, Numbers and pandas all open it as a single sheet. An earlier
// version emitted a summary block, a blank line and then the daily table;
// that is two tables in one file and spreadsheets render it as a ragged
// sheet. row_type instead distinguishes the summary rows from the daily
// ones, which also makes the file filterable and pivotable in place.
//
// period and minimum_severity repeat on every row so several exports can
// be concatenated into one sheet and still be told apart.
var reportCSVHeader = []string{
	"period", "minimum_severity", "row_type", "date",
	"repositories_scanned", "scans_started", "scans_completed", findingsField,
	"cost_usd", "total_tokens", "scans_averaged", "avg_cost_usd", "avg_total_tokens",
}

func (s *Server) reportingCSV(w http.ResponseWriter, r *http.Request) {
	data := s.reportFromRequest(r)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+reportFilename(data, "csv")+`"`)

	cw := csv.NewWriter(w)
	defer cw.Flush()

	period, severity := data.Interval.Key, severityFilterLabel(data.MinSeverity)
	num := func(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }
	row := func(rowType, date string, cells ...string) []string {
		return append([]string{period, severity, rowType, date}, cells...)
	}

	_ = cw.Write(reportCSVHeader)
	// The period total leads: opened in a spreadsheet, the headline numbers
	// are the first thing under the header rather than below the daily rows.
	_ = cw.Write(row("period_total", "",
		strconv.Itoa(data.Totals.ReposScanned),
		strconv.Itoa(data.Totals.Scans),
		strconv.Itoa(data.Totals.ScansDone),
		strconv.Itoa(data.Totals.Findings),
		num(sumDayCost(data.Days)),
		strconv.Itoa(sumDayTokens(data.Days)),
		strconv.Itoa(data.Period.Runs),
		num(data.Period.CostUSD),
		num(data.Period.TotalTokens),
	))
	// All-time averages are a different population from the selected
	// period, so only the average columns are filled: the activity columns
	// would otherwise imply an all-time total this report never computed.
	_ = cw.Write(row("all_time_average", "", "", "", "", "", "", "",
		strconv.Itoa(data.AllTime.Runs),
		num(data.AllTime.CostUSD),
		num(data.AllTime.TotalTokens),
	))
	for _, d := range data.Days {
		_ = cw.Write(row("day", d.Date,
			strconv.Itoa(d.ReposScanned),
			strconv.Itoa(d.Scans),
			strconv.Itoa(d.ScansDone),
			strconv.Itoa(d.Findings),
			num(d.CostUSD),
			strconv.Itoa(d.TotalTokens),
			strconv.Itoa(d.ScansAveraged),
			num(d.AvgCostUSD),
			num(d.AvgTotalTokens),
		))
	}
}

func sumDayCost(days []reportDayRow) float64 {
	var total float64
	for _, d := range days {
		total += d.CostUSD
	}
	return total
}

func sumDayTokens(days []reportDayRow) int {
	var total int
	for _, d := range days {
		total += d.TotalTokens
	}
	return total
}

func (s *Server) reportingJSON(w http.ResponseWriter, r *http.Request) {
	data := s.reportFromRequest(r)
	days := make([]map[string]any, 0, len(data.Days))
	for _, d := range data.Days {
		days = append(days, map[string]any{
			"date":                 d.Date,
			"repositories_scanned": d.ReposScanned,
			"scans_started":        d.Scans,
			"scans_completed":      d.ScansDone,
			findingsField:          d.Findings,
			"cost_usd":             d.CostUSD,
			"total_tokens":         d.TotalTokens,
			"scans_averaged":       d.ScansAveraged,
			"avg_cost_usd":         d.AvgCostUSD,
			"avg_total_tokens":     d.AvgTotalTokens,
		})
	}
	period := map[string]any{
		"key":       data.Interval.Key,
		"label":     data.Interval.Label,
		"meaning":   data.Interval.Meaning,
		"starts_at": nil,
		"ends_at":   data.Generated.Format(time.RFC3339),
	}
	if data.Since != nil {
		period["starts_at"] = reportTimestamp(data.Since)
	}
	var minSeverity any
	if data.MinSeverity != "" {
		minSeverity = data.MinSeverity
	}
	out := map[string]any{
		"generated_at": data.Generated.Format(time.RFC3339),
		"period":       period,
		"filters": map[string]any{
			// null means unfiltered; the scan counts are never filtered by
			// severity, which belongs to findings alone.
			"minimum_severity":  minSeverity,
			"applies_to":        []string{findingsField},
			"severity_ordering": db.SeverityLevels,
		},
		"activity_in_period": map[string]any{
			"repositories_scanned": data.Totals.ReposScanned,
			"scans_started":        data.Totals.Scans,
			"scans_completed":      data.Totals.ScansDone,
			findingsField:          data.Totals.Findings,
		},
		"cost_averages_per_scan": map[string]any{
			"population": "completed scans with a recorded cost",
			"in_period":  averageJSON(data.Period),
			"all_time":   averageJSON(data.AllTime),
		},
		"activity_by_day": days,
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+reportFilename(data, "json")+`"`)
	writeJSON(w, http.StatusOK, out)
}

func averageJSON(a reportAverages) map[string]any {
	return map[string]any{
		"scans_averaged":         a.Runs,
		"avg_cost_usd":           a.CostUSD,
		"avg_input_tokens":       a.InputTokens,
		"avg_output_tokens":      a.OutputTokens,
		"avg_cache_read_tokens":  a.CacheReadTokens,
		"avg_cache_write_tokens": a.CacheWriteTokens,
		"avg_total_tokens":       a.TotalTokens,
	}
}
