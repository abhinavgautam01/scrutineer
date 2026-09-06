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
// all time adds repo 3.
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
	for _, at := range []time.Time{recent, recent, old} {
		f := db.Finding{
			RepositoryID: r1.ID, ScanID: inWindow.ID, Title: "x",
			Severity: "Low", CreatedAt: at,
		}
		if err := s.DB.Create(&f).Error; err != nil {
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
		// Week: adds repo 1's 3-day scan and repo 2's 10-day scan is out.
		{"week", 2, 4, 2, 2, 2},
		// Month: adds repo 2's 10-day scan.
		{"month", 3, 5, 3, 2, 3},
		// All time: adds repo 3's 100-day scan and the old finding.
		{"all", 3, 6, 4, 3, 4},
	} {
		t.Run(tc.interval, func(t *testing.T) {
			got := s.buildReport(resolveReportInterval(tc.interval))
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
			if got.Window.Runs != tc.costedInWindow {
				t.Errorf("Window.Runs = %d, want %d", got.Window.Runs, tc.costedInWindow)
			}
			// The all-time column never moves with the selector.
			if got.AllTime.Runs != 4 {
				t.Errorf("AllTime.Runs = %d, want 4", got.AllTime.Runs)
			}
		})
	}
}

// The averages must reproduce docs/cost_averages.sql: mean over completed
// scans with a positive cost, so the failed and queued rows stay out.
func TestBuildReportAveragesMatchCostAveragesSQL(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	got := s.buildReport(resolveReportInterval("all")).AllTime
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

func TestBuildReportEmptyCorpus(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	got := s.buildReport(resolveReportInterval("week"))
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
		"/reporting/report.csv?interval=week",
		"/reporting/report.json?interval=week",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	// The sidebar entry is present and marked current on this page.
	if !strings.Contains(body, `href="/reporting" aria-current="page"`) {
		t.Error("sidebar Reporting entry not marked current")
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

func TestReportingCSVExport(t *testing.T) {
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

	blocks := strings.SplitN(strings.TrimRight(w.Body.String(), "\n"), "\n\n", 2)
	if len(blocks) != 2 {
		t.Fatalf("expected a summary block and a daily block, got %d:\n%s", len(blocks), w.Body.String())
	}

	summary := map[string]string{}
	rows, err := csv.NewReader(strings.NewReader(blocks[0])).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if rows[0][0] != "metric" || rows[0][1] != "value" {
		t.Fatalf("summary header = %v", rows[0])
	}
	for _, row := range rows[1:] {
		summary[row[0]] = row[1]
	}
	for key, want := range map[string]string{
		"interval":                 "week",
		"repos_scanned":            "2",
		"scans":                    "4",
		"scans_done":               "2",
		"findings":                 "2",
		"window_scans_costed":      "2",
		"window_avg_cost_usd":      "3.00",
		"alltime_scans_costed":     "4",
		"alltime_avg_cost_usd":     "5.00",
		"alltime_avg_total_tokens": "2900.00",
	} {
		if summary[key] != want {
			t.Errorf("summary[%q] = %q, want %q", key, summary[key], want)
		}
	}
	if summary["window_start"] == "" {
		t.Error("bounded interval should record a window_start")
	}

	daily, err := csv.NewReader(strings.NewReader(blocks[1])).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	wantHeader := []string{"date", "repos_scanned", "scans", "findings", "cost_usd", "total_tokens"}
	if strings.Join(daily[0], ",") != strings.Join(wantHeader, ",") {
		t.Fatalf("daily header = %v, want %v", daily[0], wantHeader)
	}
	if len(daily) < 2 {
		t.Fatal("daily block has no rows")
	}
	// Newest day first.
	for i := 2; i < len(daily); i++ {
		if daily[i-1][0] < daily[i][0] {
			t.Fatalf("daily rows not sorted newest first: %v then %v", daily[i-1][0], daily[i][0])
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
		Interval    string  `json:"interval"`
		WindowStart *string `json:"window_start"`
		Totals      struct {
			ReposScanned int `json:"repos_scanned"`
			Scans        int `json:"scans"`
			ScansDone    int `json:"scans_done"`
			Findings     int `json:"findings"`
		} `json:"totals"`
		Averages struct {
			Window  map[string]float64 `json:"window"`
			AllTime map[string]float64 `json:"all_time"`
		} `json:"averages"`
		Days []struct {
			Date        string  `json:"date"`
			Scans       int     `json:"scans"`
			CostUSD     float64 `json:"cost_usd"`
			TotalTokens int     `json:"total_tokens"`
		} `json:"days"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v\n%s", err, w.Body)
	}
	if out.Interval != "all" {
		t.Errorf("interval = %q, want all", out.Interval)
	}
	if out.WindowStart != nil {
		t.Errorf("window_start = %v, want null for all time", *out.WindowStart)
	}
	if out.Totals.ReposScanned != 3 || out.Totals.Scans != 6 || out.Totals.ScansDone != 4 || out.Totals.Findings != 3 {
		t.Errorf("totals = %+v", out.Totals)
	}
	if out.Averages.AllTime["avg_cost_usd"] != 5 {
		t.Errorf("all_time avg_cost_usd = %v, want 5", out.Averages.AllTime["avg_cost_usd"])
	}
	// All time makes both columns the same population.
	if out.Averages.Window["avg_total_tokens"] != out.Averages.AllTime["avg_total_tokens"] {
		t.Errorf("window and all-time should agree over the all-time interval: %v vs %v",
			out.Averages.Window["avg_total_tokens"], out.Averages.AllTime["avg_total_tokens"])
	}
	if len(out.Days) == 0 {
		t.Fatal("days is empty")
	}
}
