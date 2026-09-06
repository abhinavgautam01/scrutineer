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
	"time"

	"scrutineer/internal/db"
)

// reportDateLayout is the calendar-day key for the per-day breakdown. Days
// are UTC so a report generated in two timezones bucket-aligns.
const reportDateLayout = "2006-01-02"

// reportInterval is one selectable rolling window. Dur of 0 means all
// time. Rolling rather than calendar: the totals are a running figure, so
// they should not collapse to near-zero at midnight or on the 1st.
type reportInterval struct {
	Key   string
	Label string
	Dur   time.Duration
}

const (
	reportDay   = 24 * time.Hour
	reportWeek  = 7 * reportDay
	reportMonth = 30 * reportDay
)

var reportIntervals = []reportInterval{
	{Key: "all", Label: "All time"},
	{Key: "month", Label: "Month", Dur: reportMonth},
	{Key: "week", Label: "Week", Dur: reportWeek},
	{Key: "day", Label: "Day", Dur: reportDay},
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

// reportTotals is the running-total panel. ReposScanned counts distinct
// repositories with at least one scan in the window, so a repo rescanned
// ten times still counts once.
type reportTotals struct {
	ReposScanned int
	Scans        int
	ScansDone    int
	Findings     int
}

// reportAverages is one column of the cost-averages table: the per-scan
// means from docs/cost_averages.sql. Runs is the denominator, exposed so a
// small-sample average is recognisable as one.
//
// The population matches that SQL exactly — completed scans with a
// recorded cost — so queued, running, failed and cancelled rows don't drag
// the figures toward zero.
type reportAverages struct {
	Runs             int     `gorm:"column:runs"`
	CostUSD          float64 `gorm:"column:cost_usd"`
	InputTokens      float64 `gorm:"column:input_tokens"`
	OutputTokens     float64 `gorm:"column:output_tokens"`
	CacheReadTokens  float64 `gorm:"column:cache_read_tokens"`
	CacheWriteTokens float64 `gorm:"column:cache_write_tokens"`
	TotalTokens      float64 `gorm:"column:total_tokens"`
}

// reportDayRow is one row of the per-day breakdown carried by the exports.
type reportDayRow struct {
	Date         string
	ReposScanned int
	Scans        int
	Findings     int
	CostUSD      float64
	TotalTokens  int
}

// reportData is the whole snapshot. The page render and both exports read
// from this one value, so a downloaded report always matches the screen it
// was downloaded from.
type reportData struct {
	Interval  reportInterval
	Since     *time.Time
	Generated time.Time
	Totals    reportTotals
	Window    reportAverages
	AllTime   reportAverages
	Days      []reportDayRow
}

// reportAnchorSQL is the timestamp a scan is attributed to, as SQL: when
// it finished, falling back to when it was created for rows that never
// reached a terminal state. COALESCE is standard SQL, so this survives the
// driver swap. scanAnchor below is the Go twin of this expression and the
// two must stay in step, since the SQL bounds the window and the Go one
// picks the day bucket within it.
const reportAnchorSQL = "COALESCE(finished_at, created_at)"

// reportAverages loads one column of the cost-averages table.
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

// buildReport assembles the snapshot for one interval.
//
// Both averages columns are aggregated in the database. Only the totals
// and the day breakdown need individual rows, and that read is bounded to
// the selected window and to the columns the report reads, so picking a
// narrower interval genuinely costs less rather than filtering a full
// table scan in memory.
func (s *Server) buildReport(iv reportInterval) reportData {
	now := time.Now().UTC()
	data := reportData{Interval: iv, Generated: now}
	if iv.Dur > 0 {
		since := now.Add(-iv.Dur)
		data.Since = &since
	}

	data.AllTime = s.reportAveragesFor(nil)
	data.Window = s.reportAveragesFor(data.Since)

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
	reposByDay := map[string]map[uint]struct{}{}
	scansByDay := map[string]int{}
	costByDay := map[string]float64{}
	tokensByDay := map[string]int{}

	for _, sc := range scans {
		day := scanAnchor(sc).Format(reportDateLayout)
		data.Totals.Scans++
		if sc.Status == db.ScanDone {
			data.Totals.ScansDone++
		}
		repos[sc.RepositoryID] = struct{}{}
		if reposByDay[day] == nil {
			reposByDay[day] = map[uint]struct{}{}
		}
		reposByDay[day][sc.RepositoryID] = struct{}{}
		scansByDay[day]++
		costByDay[day] += sc.CostUSD
		tokensByDay[day] += sc.InputTokens + sc.OutputTokens + sc.CacheReadTokens + sc.CacheWriteTokens
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
	fq.Scan(&found)
	findingsByDay := map[string]int{}
	for _, f := range found {
		data.Totals.Findings++
		findingsByDay[f.CreatedAt.UTC().Format(reportDateLayout)]++
	}

	// A day appears if it saw either activity, so a day with findings
	// carried over from an earlier scan is not silently dropped.
	days := map[string]struct{}{}
	for day := range scansByDay {
		days[day] = struct{}{}
	}
	for day := range findingsByDay {
		days[day] = struct{}{}
	}
	data.Days = make([]reportDayRow, 0, len(days))
	for day := range days {
		data.Days = append(data.Days, reportDayRow{
			Date:         day,
			ReposScanned: len(reposByDay[day]),
			Scans:        scansByDay[day],
			Findings:     findingsByDay[day],
			CostUSD:      costByDay[day],
			TotalTokens:  tokensByDay[day],
		})
	}
	sort.Slice(data.Days, func(i, j int) bool { return data.Days[i].Date > data.Days[j].Date })
	return data
}

func (s *Server) reporting(w http.ResponseWriter, r *http.Request) {
	data := s.buildReport(resolveReportInterval(r.URL.Query().Get("interval")))
	s.render(w, r, "reporting.html", map[string]any{
		"Report":    data,
		"Intervals": reportIntervals,
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

// reportingCSV writes the snapshot as two CSV blocks: a metric/value
// summary, a blank line, then the per-day table. One file rather than two
// downloads, at the cost of a reader needing to split on the blank line —
// the two halves have genuinely different shapes and flattening them into
// one wide table would pad every day row with repeated summary columns.
func (s *Server) reportingCSV(w http.ResponseWriter, r *http.Request) {
	data := s.buildReport(resolveReportInterval(r.URL.Query().Get("interval")))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+reportFilename(data, "csv")+`"`)

	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"metric", "value"})
	summary := [][2]string{
		{"interval", data.Interval.Key},
		{"generated_at", data.Generated.Format(time.RFC3339)},
		{"window_start", reportTimestamp(data.Since)},
		{"repos_scanned", strconv.Itoa(data.Totals.ReposScanned)},
		{"scans", strconv.Itoa(data.Totals.Scans)},
		{"scans_done", strconv.Itoa(data.Totals.ScansDone)},
		{"findings", strconv.Itoa(data.Totals.Findings)},
	}
	summary = append(summary, averageCSVRows("window", data.Window)...)
	summary = append(summary, averageCSVRows("alltime", data.AllTime)...)
	for _, row := range summary {
		_ = cw.Write([]string{row[0], row[1]})
	}

	// csv.Writer quotes nothing here, so a bare blank line separates the
	// two blocks; it must be flushed first to land in the right order.
	cw.Flush()
	_, _ = w.Write([]byte("\n"))

	_ = cw.Write([]string{"date", "repos_scanned", "scans", "findings", "cost_usd", "total_tokens"})
	for _, d := range data.Days {
		_ = cw.Write([]string{
			d.Date,
			strconv.Itoa(d.ReposScanned),
			strconv.Itoa(d.Scans),
			strconv.Itoa(d.Findings),
			strconv.FormatFloat(d.CostUSD, 'f', 2, 64),
			strconv.Itoa(d.TotalTokens),
		})
	}
}

// averageCSVRows flattens one averages column under a prefix, so the
// window and all-time figures share a key namespace in the flat CSV.
func averageCSVRows(prefix string, a reportAverages) [][2]string {
	f := func(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }
	return [][2]string{
		{prefix + "_scans_costed", strconv.Itoa(a.Runs)},
		{prefix + "_avg_cost_usd", f(a.CostUSD)},
		{prefix + "_avg_input_tokens", f(a.InputTokens)},
		{prefix + "_avg_output_tokens", f(a.OutputTokens)},
		{prefix + "_avg_cache_read_tokens", f(a.CacheReadTokens)},
		{prefix + "_avg_cache_write_tokens", f(a.CacheWriteTokens)},
		{prefix + "_avg_total_tokens", f(a.TotalTokens)},
	}
}

func (s *Server) reportingJSON(w http.ResponseWriter, r *http.Request) {
	data := s.buildReport(resolveReportInterval(r.URL.Query().Get("interval")))
	days := make([]map[string]any, 0, len(data.Days))
	for _, d := range data.Days {
		days = append(days, map[string]any{
			"date":          d.Date,
			"repos_scanned": d.ReposScanned,
			"scans":         d.Scans,
			"findings":      d.Findings,
			"cost_usd":      d.CostUSD,
			"total_tokens":  d.TotalTokens,
		})
	}
	out := map[string]any{
		"interval":       data.Interval.Key,
		"interval_label": data.Interval.Label,
		"generated_at":   data.Generated.Format(time.RFC3339),
		"window_start":   nil,
		"totals": map[string]any{
			"repos_scanned": data.Totals.ReposScanned,
			"scans":         data.Totals.Scans,
			"scans_done":    data.Totals.ScansDone,
			"findings":      data.Totals.Findings,
		},
		"averages": map[string]any{
			"window":   averageJSON(data.Window),
			"all_time": averageJSON(data.AllTime),
		},
		"days": days,
	}
	if data.Since != nil {
		out["window_start"] = data.Since.Format(time.RFC3339)
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+reportFilename(data, "json")+`"`)
	writeJSON(w, http.StatusOK, out)
}

func averageJSON(a reportAverages) map[string]any {
	return map[string]any{
		"scans_costed":           a.Runs,
		"avg_cost_usd":           a.CostUSD,
		"avg_input_tokens":       a.InputTokens,
		"avg_output_tokens":      a.OutputTokens,
		"avg_cache_read_tokens":  a.CacheReadTokens,
		"avg_cache_write_tokens": a.CacheWriteTokens,
		"avg_total_tokens":       a.TotalTokens,
	}
}
