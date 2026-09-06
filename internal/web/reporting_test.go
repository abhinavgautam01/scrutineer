package web

import (
	"encoding/csv"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
)

// seedReportCorpus lays down scans and findings either side of the rolling
// window boundaries so each interval selects a known subset:
//
//	repo 1: one costed scan 2h ago, one costed scan 3 days ago
//	repo 2: one costed scan 10 days ago
//	repo 3: one costed scan 100 days ago, plus a failed and a queued scan
//
// Day sees repo 1 only; week sees repos 1-2; month adds nothing further;
// all time adds repo 3. Findings carry three different severities so the
// minimum-severity filter has something to bite on.
func seedReportCorpus(t *testing.T, s *Server) {
	t.Helper()
	now := time.Now().UTC()
	mkRepo := func(name string) db.Repository {
		repo := db.Repository{URL: "https://example.test/" + name, Name: name, FullName: "acme/" + name}
		if err := s.DB.Create(&repo).Error; err != nil {
			t.Fatal(err)
		}
		return repo
	}
	r1, r2, r3 := mkRepo("one"), mkRepo("two"), mkRepo("three")

	mkScan := func(repo db.Repository, status db.ScanStatus, cost float64, in, out, cr, cw int, ago time.Duration) db.Scan {
		at := now.Add(-ago)
		sc := db.Scan{
			RepositoryID: repo.ID, Kind: "skill", Status: status, SkillName: "vuln-scan",
			CostUSD: cost, InputTokens: in, OutputTokens: out,
			CacheReadTokens: cr, CacheWriteTokens: cw,
			FinishedAt: &at, CreatedAt: at,
		}
		if err := s.DB.Create(&sc).Error; err != nil {
			t.Fatal(err)
		}
		return sc
	}

	inWindow := mkScan(r1, db.ScanDone, 2.00, 100, 10, 1000, 50, 2*time.Hour)
	mkScan(r1, db.ScanDone, 4.00, 300, 30, 3000, 150, 3*reportDay)
	mkScan(r2, db.ScanDone, 6.00, 200, 20, 2000, 100, 10*reportDay)
	mkScan(r3, db.ScanDone, 8.00, 400, 40, 4000, 200, 100*reportDay)
	// Failed and queued rows are activity but not costed scans, so they
	// move the scan totals without touching the averages.
	mkScan(r3, db.ScanFailed, 1.00, 10, 1, 10, 1, time.Hour)
	mkScan(r3, db.ScanQueued, 0, 0, 0, 0, 0, time.Hour)

	recent := now.Add(-2 * time.Hour)
	old := now.Add(-100 * reportDay)
	for _, f := range []struct {
		severity string
		at       time.Time
	}{
		{"Critical", recent},
		{"Low", recent},
		{"High", old},
	} {
		row := db.Finding{
			RepositoryID: r1.ID, ScanID: inWindow.ID, Title: "x",
			Severity: f.severity, CreatedAt: f.at,
		}
		if err := s.DB.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func TestResolveReportInterval(t *testing.T) {
	for _, tc := range []struct {
		key  string
		want string
		dur  time.Duration
	}{
		{"day", "day", reportDay},
		{"week", "week", reportWeek},
		{"month", "month", reportMonth},
		{"all", "all", 0},
		{"", "all", 0},
		{"fortnight", "all", 0},
	} {
		got := resolveReportInterval(tc.key)
		if got.Key != tc.want || got.Dur != tc.dur {
			t.Errorf("resolveReportInterval(%q) = %q/%v, want %q/%v", tc.key, got.Key, got.Dur, tc.want, tc.dur)
		}
	}
}

func TestResolveMinSeverity(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Critical", "Critical"},
		{"critical", "Critical"},
		{"CRITICAL", "Critical"},
		{"MODERATE", "Medium"},
		{"Low", "Low"},
		{"", ""},
		{"catastrophic", ""},
		// Not a severity: must not leak through as a filter value.
		{"'; DROP TABLE findings; --", ""},
	} {
		if got := resolveMinSeverity(tc.in); got != tc.want {
			t.Errorf("resolveMinSeverity(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// minSeverityRank must agree with severityOrder, which ranks the most
// severe lowest. If these drift, the filter silently selects the wrong end
// of the scale.
func TestMinSeverityRankMatchesSeverityOrder(t *testing.T) {
	critical, ok := minSeverityRank("Critical")
	if !ok || critical != 0 {
		t.Fatalf("Critical rank = %d, %v, want 0, true", critical, ok)
	}
	low, ok := minSeverityRank("Low")
	if !ok || low != 3 {
		t.Fatalf("Low rank = %d, %v, want 3, true", low, ok)
	}
	if _, ok := minSeverityRank("nonsense"); ok {
		t.Error("minSeverityRank accepted a non-severity")
	}
}

func TestBuildReportIntervalTotals(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	for _, tc := range []struct {
		interval                                     string
		repos, scans, done, findings, costedInWindow int
	}{
		// Day: repo 1's 2h scan, plus repo 3's failed and queued rows.
		{"day", 2, 3, 1, 2, 1},
		// Week: adds repo 1's 3-day scan; repo 2's 10-day scan is out.
		{"week", 2, 4, 2, 2, 2},
		// Month: adds repo 2's 10-day scan.
		{"month", 3, 5, 3, 2, 3},
		// All time: adds repo 3's 100-day scan and the old finding.
		{"all", 3, 6, 4, 3, 4},
	} {
		t.Run(tc.interval, func(t *testing.T) {
			got := s.buildReport(resolveReportInterval(tc.interval), "")
			if got.Totals.ReposScanned != tc.repos {
				t.Errorf("ReposScanned = %d, want %d", got.Totals.ReposScanned, tc.repos)
			}
			if got.Totals.Scans != tc.scans {
				t.Errorf("Scans = %d, want %d", got.Totals.Scans, tc.scans)
			}
			if got.Totals.ScansDone != tc.done {
				t.Errorf("ScansDone = %d, want %d", got.Totals.ScansDone, tc.done)
			}
			if got.Totals.Findings != tc.findings {
				t.Errorf("Findings = %d, want %d", got.Totals.Findings, tc.findings)
			}
			if got.Period.Runs != tc.costedInWindow {
				t.Errorf("Period.Runs = %d, want %d", got.Period.Runs, tc.costedInWindow)
			}
			// The all-time column never moves with the selector.
			if got.AllTime.Runs != 4 {
				t.Errorf("AllTime.Runs = %d, want 4", got.AllTime.Runs)
			}
		})
	}
}

// The severity floor must filter findings and leave scan activity alone.
func TestBuildReportMinSeverityFiltersFindingsOnly(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	all := reportIntervals[0]
	for _, tc := range []struct {
		severity string
		findings int
	}{
		{"", 3},         // Critical + Low + High
		{"Low", 3},      // the floor admits everything
		{"Medium", 2},   // drops Low
		{"High", 2},     // Critical + High
		{"Critical", 1}, // Critical only
	} {
		got := s.buildReport(all, tc.severity)
		if got.Totals.Findings != tc.findings {
			t.Errorf("severity %q: findings = %d, want %d", tc.severity, got.Totals.Findings, tc.findings)
		}
		// Scan-side numbers are a property of scans, not findings.
		if got.Totals.Scans != 6 || got.Totals.ScansDone != 4 || got.AllTime.Runs != 4 {
			t.Errorf("severity %q moved scan totals: %+v", tc.severity, got.Totals)
		}
	}
}

func TestBuildReportMinSeverityAppliesToDayRows(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	unfiltered := s.buildReport(reportIntervals[0], "")
	filtered := s.buildReport(reportIntervals[0], "Critical")
	sum := func(days []reportDayRow) int {
		var n int
		for _, d := range days {
			n += d.Findings
		}
		return n
	}
	if got := sum(unfiltered.Days); got != 3 {
		t.Errorf("unfiltered day findings = %d, want 3", got)
	}
	if got := sum(filtered.Days); got != 1 {
		t.Errorf("Critical-only day findings = %d, want 1", got)
	}
}

// The averages must reproduce docs/cost_averages.sql: mean over completed
// scans with a positive cost, so the failed and queued rows stay out.
func TestBuildReportAveragesMatchCostAveragesSQL(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	got := s.buildReport(reportIntervals[0], "").AllTime
	// (2+4+6+8)/4
	if got.CostUSD != 5 {
		t.Errorf("avg cost = %v, want 5", got.CostUSD)
	}
	// (100+300+200+400)/4
	if got.InputTokens != 250 {
		t.Errorf("avg input = %v, want 250", got.InputTokens)
	}
	if got.OutputTokens != 25 {
		t.Errorf("avg output = %v, want 25", got.OutputTokens)
	}
	if got.CacheReadTokens != 2500 {
		t.Errorf("avg cache read = %v, want 2500", got.CacheReadTokens)
	}
	if got.CacheWriteTokens != 125 {
		t.Errorf("avg cache write = %v, want 125", got.CacheWriteTokens)
	}
	if got.TotalTokens != 2900 {
		t.Errorf("avg total = %v, want 2900", got.TotalTokens)
	}
}

// A day's averages and the period averages must be the same measurement at
// two resolutions, so the per-day denominators have to add up to the
// period denominator the SQL aggregate returned.
func TestBuildReportDayAveragesShareThePeriodPopulation(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	got := s.buildReport(reportIntervals[0], "")
	var averaged int
	var cost float64
	for _, d := range got.Days {
		averaged += d.ScansAveraged
		cost += d.AvgCostUSD * float64(d.ScansAveraged)
	}
	if averaged != got.AllTime.Runs {
		t.Errorf("day denominators sum to %d, period says %d", averaged, got.AllTime.Runs)
	}
	if want := got.AllTime.CostUSD * float64(got.AllTime.Runs); cost != want {
		t.Errorf("day costs sum to %v, period implies %v", cost, want)
	}
}

func TestBuildReportEmptyCorpus(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	got := s.buildReport(resolveReportInterval("week"), "")
	if got.Totals.Scans != 0 || got.AllTime.Runs != 0 || len(got.Days) != 0 {
		t.Fatalf("empty corpus report = %+v, want zeroed", got)
	}
	// A zero denominator must not produce NaN in the rendered averages.
	if got.AllTime.CostUSD != 0 || got.AllTime.TotalTokens != 0 {
		t.Errorf("averages over no runs = %+v, want zeros", got.AllTime)
	}
}

func TestReportingPageRenders(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/reporting?interval=week"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{
		"Reporting",
		"Repositories scanned",
		"Cost averages",
		"Daily breakdown",
		"Minimum severity",
		"/reporting/report.csv?interval=week",
		"/reporting/report.json?interval=week",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	// The orphaned right-aligned caption is gone; the wording now lives in
	// the paragraph under the heading.
	if strings.Contains(body, `<span class="text-xs text-muted-foreground">per completed scan with a recorded cost</span>`) {
		t.Error("floating cost-averages caption is still present")
	}
	if !strings.Contains(body, "Averaged per completed scan with a recorded cost.") {
		t.Error("cost-averages population is not explained in the prose")
	}
	if !strings.Contains(body, `href="/reporting" aria-current="page"`) {
		t.Error("sidebar Reporting entry not marked current")
	}
}

// Selecting a severity must survive into the period links and both export
// links, or switching period silently drops the filter.
func TestReportingPagePreservesSeverityInLinks(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/reporting?interval=week&severity=High"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{
		"/reporting?interval=day&amp;severity=High",
		"/reporting/report.csv?interval=week&amp;severity=High",
		"/reporting/report.json?interval=week&amp;severity=High",
		"Findings (High+)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestReportingNavKey(t *testing.T) {
	if got := navKey("/reporting"); got != "reporting" {
		t.Errorf("navKey(/reporting) = %q, want reporting", got)
	}
	// The neighbouring repository routes must not be captured by the new prefix.
	if got := navKey("/repositories/1"); got != "repos" {
		t.Errorf("navKey(/repositories/1) = %q, want repos", got)
	}
}

// The CSV must be one rectangular table: a single header, a uniform column
// count and no blank separator line. Anything else opens as a ragged sheet
// in Excel and breaks strict parsers.
func TestReportingCSVIsOneRectangularTable(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/reporting/report.csv?interval=week"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") ||
		!strings.Contains(cd, "scrutineer-report-week-") || !strings.Contains(cd, ".csv") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if strings.Contains(w.Body.String(), "\n\n") {
		t.Error("CSV contains a blank line; it is no longer a single table")
	}

	// FieldsPerRecord defaults to the first record's count and errors on
	// any row that disagrees, so a successful ReadAll proves rectangularity.
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("not a rectangular CSV: %v", err)
	}
	if strings.Join(rows[0], ",") != strings.Join(reportCSVHeader, ",") {
		t.Fatalf("header = %v, want %v", rows[0], reportCSVHeader)
	}
	if len(rows) < 3 {
		t.Fatalf("expected a period_total, an all_time_average and day rows, got %d", len(rows)-1)
	}

	byType := map[string][]string{}
	for _, row := range rows[1:] {
		if len(row) != len(reportCSVHeader) {
			t.Fatalf("row %v has %d cells, want %d", row, len(row), len(reportCSVHeader))
		}
		if row[0] != "week" {
			t.Errorf("period column = %q, want week", row[0])
		}
		if row[1] != "all" {
			t.Errorf("minimum_severity column = %q, want all", row[1])
		}
		byType[row[2]] = row
	}
	total, ok := byType["period_total"]
	if !ok {
		t.Fatal("no period_total row")
	}
	// repositories_scanned, scans_started, scans_completed, findings
	if total[4] != "2" || total[5] != "4" || total[6] != "2" || total[7] != "2" {
		t.Errorf("period_total activity = %v", total[4:8])
	}
	if total[11] != "3.00" {
		t.Errorf("period avg_cost_usd = %q, want 3.00", total[11])
	}
	allTime, ok := byType["all_time_average"]
	if !ok {
		t.Fatal("no all_time_average row")
	}
	if allTime[11] != "5.00" {
		t.Errorf("all-time avg_cost_usd = %q, want 5.00", allTime[11])
	}
	// The all-time row must not imply activity totals it never computed.
	if allTime[4] != "" || allTime[7] != "" {
		t.Errorf("all_time_average leaked activity figures: %v", allTime)
	}
	if _, ok := byType["day"]; !ok {
		t.Fatal("no day rows")
	}
}

func TestReportingCSVCarriesSeverityFilter(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/reporting/report.csv?interval=all&severity=Critical"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows[1:] {
		if row[1] != "Critical" {
			t.Fatalf("minimum_severity column = %q, want Critical", row[1])
		}
		if row[2] == "period_total" && row[7] != "1" {
			t.Errorf("filtered findings total = %q, want 1", row[7])
		}
	}
}

func TestReportingJSONExport(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/reporting/report.json?interval=all"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "scrutineer-report-all-") {
		t.Errorf("Content-Disposition = %q", cd)
	}

	var out struct {
		GeneratedAt string `json:"generated_at"`
		Period      struct {
			Key      string  `json:"key"`
			Label    string  `json:"label"`
			Meaning  string  `json:"meaning"`
			StartsAt *string `json:"starts_at"`
			EndsAt   string  `json:"ends_at"`
		} `json:"period"`
		Filters struct {
			MinimumSeverity *string  `json:"minimum_severity"`
			AppliesTo       []string `json:"applies_to"`
		} `json:"filters"`
		Activity struct {
			RepositoriesScanned int `json:"repositories_scanned"`
			ScansStarted        int `json:"scans_started"`
			ScansCompleted      int `json:"scans_completed"`
			Findings            int `json:"findings"`
		} `json:"activity_in_period"`
		Averages struct {
			Population string             `json:"population"`
			InPeriod   map[string]float64 `json:"in_period"`
			AllTime    map[string]float64 `json:"all_time"`
		} `json:"cost_averages_per_scan"`
		ByDay []struct {
			Date           string  `json:"date"`
			ScansStarted   int     `json:"scans_started"`
			ScansCompleted int     `json:"scans_completed"`
			Findings       int     `json:"findings"`
			CostUSD        float64 `json:"cost_usd"`
		} `json:"activity_by_day"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v\n%s", err, w.Body)
	}

	// The old ambiguous key names must be gone.
	var raw map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &raw)
	for _, gone := range []string{"totals", "days", "averages", "window_start", "interval"} {
		if _, ok := raw[gone]; ok {
			t.Errorf("ambiguous key %q is still present at the top level", gone)
		}
	}
	if _, ok := out.Averages.InPeriod["avg_cost_usd"]; !ok {
		t.Error("cost_averages_per_scan.in_period missing avg_cost_usd")
	}

	if out.Period.Key != "all" || out.Period.Label != "All time" || out.Period.Meaning == "" {
		t.Errorf("period = %+v", out.Period)
	}
	if out.Period.StartsAt != nil {
		t.Errorf("starts_at = %v, want null for all time", *out.Period.StartsAt)
	}
	if out.Period.EndsAt == "" || out.GeneratedAt == "" {
		t.Error("generated_at/ends_at should always be set")
	}
	if out.Filters.MinimumSeverity != nil {
		t.Errorf("minimum_severity = %v, want null", *out.Filters.MinimumSeverity)
	}
	if len(out.Filters.AppliesTo) != 1 || out.Filters.AppliesTo[0] != "findings" {
		t.Errorf("applies_to = %v, want [findings]", out.Filters.AppliesTo)
	}
	if out.Activity.RepositoriesScanned != 3 || out.Activity.ScansStarted != 6 ||
		out.Activity.ScansCompleted != 4 || out.Activity.Findings != 3 {
		t.Errorf("activity_in_period = %+v", out.Activity)
	}
	if out.Averages.Population == "" {
		t.Error("cost_averages_per_scan.population should explain the denominator")
	}
	if out.Averages.AllTime["avg_cost_usd"] != 5 {
		t.Errorf("all_time avg_cost_usd = %v, want 5", out.Averages.AllTime["avg_cost_usd"])
	}
	// All time makes both columns the same population.
	if out.Averages.InPeriod["avg_total_tokens"] != out.Averages.AllTime["avg_total_tokens"] {
		t.Errorf("in_period and all_time should agree over the all-time period: %v vs %v",
			out.Averages.InPeriod["avg_total_tokens"], out.Averages.AllTime["avg_total_tokens"])
	}
	if len(out.ByDay) == 0 {
		t.Fatal("activity_by_day is empty")
	}
	for i := 1; i < len(out.ByDay); i++ {
		if out.ByDay[i-1].Date < out.ByDay[i].Date {
			t.Fatalf("activity_by_day not newest first: %q then %q", out.ByDay[i-1].Date, out.ByDay[i].Date)
		}
	}
}

func TestReportingJSONCarriesSeverityFilter(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/reporting/report.json?interval=all&severity=high"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var out struct {
		Filters struct {
			MinimumSeverity *string `json:"minimum_severity"`
		} `json:"filters"`
		Activity struct {
			Findings       int `json:"findings"`
			ScansCompleted int `json:"scans_completed"`
		} `json:"activity_in_period"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	// Lowercase input is canonicalised on the way in.
	if out.Filters.MinimumSeverity == nil || *out.Filters.MinimumSeverity != "High" {
		t.Errorf("minimum_severity = %v, want High", out.Filters.MinimumSeverity)
	}
	if out.Activity.Findings != 2 {
		t.Errorf("findings = %d, want 2 (Critical + High)", out.Activity.Findings)
	}
	if out.Activity.ScansCompleted != 4 {
		t.Errorf("scans_completed = %d, want 4; severity must not touch scan counts", out.Activity.ScansCompleted)
	}
}
