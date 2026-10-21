package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"

	"scrutineer/internal/db"
)

func TestExportFindings_repositoryScopeAndTimeFilters(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/findings-filters"}
	other := db.Repository{URL: "https://example.com/findings-other"}
	for _, row := range []*db.Repository{&repo, &other} {
		if err := s.DB.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	curated := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	scanner := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "semgrep"}
	otherScan := db.Scan{RepositoryID: other.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	for _, row := range []*db.Scan{&curated, &scanner, &otherScan} {
		if err := s.DB.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	cutoff := time.Date(2026, time.September, 1, 12, 0, 0, 123456789, time.UTC)
	later := cutoff.Add(time.Hour)
	findings := []db.Finding{
		{ScanID: curated.ID, RepositoryID: repo.ID, Title: "curated at cutoff", Severity: sevHigh, Status: db.FindingNew, CreatedAt: cutoff, UpdatedAt: cutoff},
		{ScanID: curated.ID, RepositoryID: repo.ID, Title: "curated before cutoff", Severity: "Low", Status: db.FindingTriaged, CreatedAt: cutoff.Add(-time.Nanosecond), UpdatedAt: cutoff.Add(-time.Nanosecond)},
		{ScanID: curated.ID, RepositoryID: repo.ID, Title: "curated modified later", Severity: sevHigh, Status: db.FindingTriaged, CreatedAt: cutoff.Add(-time.Hour), UpdatedAt: later},
		{ScanID: scanner.ID, RepositoryID: repo.ID, Title: "scanner at cutoff", Severity: sevHigh, Status: db.FindingTriaged, CreatedAt: cutoff, UpdatedAt: cutoff},
		{ScanID: otherScan.ID, RepositoryID: other.ID, Title: "other repo", Severity: sevHigh, Status: db.FindingNew, CreatedAt: cutoff, UpdatedAt: cutoff},
	}
	if err := s.DB.Create(&findings).Error; err != nil {
		t.Fatal(err)
	}
	var stored db.Finding
	if err := s.DB.First(&stored, findings[2].ID).Error; err != nil {
		t.Fatal(err)
	}
	if !stored.UpdatedAt.Equal(later) {
		t.Fatalf("stored updated_at = %v, want %v", stored.UpdatedAt, later)
	}
	repoID := strconv.FormatUint(uint64(repo.ID), 10)
	cut := cutoff.Format(time.RFC3339Nano)
	for _, tt := range []struct {
		name  string
		query url.Values
		want  []int
	}{
		{"unfiltered", nil, []int{4, 3, 2, 1, 0}},
		{"repository", url.Values{"repository_id": {repoID}}, []int{3, 2, 1, 0}},
		{"missing repository", url.Values{"repository_id": {"9223372036854775807"}}, nil},
		{"scope", url.Values{"scope": {"findings"}}, []int{4, 2, 1, 0}},
		{"empty scope", url.Values{"scope": {""}}, []int{4, 3, 2, 1, 0}},
		{"since", url.Values{"since": {cut}}, []int{4, 3, 0}},
		{"updated_since", url.Values{"updated_since": {cut}}, []int{4, 3, 2, 0}},
		{"future since", url.Values{"since": {later.Format(time.RFC3339Nano)}}, nil},
		{"future updated_since", url.Values{"updated_since": {later.Add(time.Nanosecond).Format(time.RFC3339Nano)}}, nil},
		{"updated_since at later", url.Values{"updated_since": {later.Format(time.RFC3339Nano)}}, []int{2}},
		{"repository scope since", url.Values{"repository_id": {repoID}, "scope": {"findings"}, "since": {cut}}, []int{0}},
		{"scope severity", url.Values{"scope": {"findings"}, "severity": {sevHigh}}, []int{4, 2, 0}},
		{"updated_since status", url.Values{"updated_since": {cut}, "status": {string(db.FindingTriaged)}}, []int{3, 2}},
		{"since and updated_since", url.Values{"since": {cut}, "updated_since": {later.Format(time.RFC3339Nano)}}, nil},
		{"all filters", url.Values{
			"repository_id": {repoID}, "scope": {"findings"}, "severity": {sevHigh},
			"status": {string(db.FindingTriaged)}, "updated_since": {cut},
		}, []int{2}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := exportFindingIDs(t, s, tt.query)
			var want []uint
			for _, index := range tt.want {
				want = append(want, findings[index].ID)
			}
			if !slices.Equal(got, want) {
				t.Errorf("finding IDs = %v, want %v", got, want)
			}
		})
	}
}

func TestExportFindings_timeOffsetsAndPrecision(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/findings-time"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	for _, param := range []string{"since", "updated_since"} {
		t.Run(param, func(t *testing.T) {
			for _, instant := range []string{"2026-09-01T12:00:00Z", "2026-09-01T12:00:00.123456789Z", "2026-09-01T12:00:00.999999999Z"} {
				t.Run(instant, func(t *testing.T) {
					cutoff, err := time.Parse(time.RFC3339Nano, instant)
					if err != nil {
						t.Fatal(err)
					}
					for _, offset := range []string{"+00:00", "-07:00", "+05:30"} {
						t.Run(offset, func(t *testing.T) {
							checkExportFindingCutoff(t, s, scan, param, cutoff, offset)
						})
					}
				})
			}
		})
	}
}

// checkExportFindingCutoff stores findings 1ns either side of cutoff in the
// offset zone, with the other timestamp column held far in the past, then
// expects param to select the cutoff row and the one after it.
func checkExportFindingCutoff(t *testing.T, s *Server, scan db.Scan, param string, cutoff time.Time, offset string) {
	t.Helper()
	zone, err := time.Parse("-07:00", offset)
	if err != nil {
		t.Fatal(err)
	}
	old := cutoff.Add(-24 * time.Hour).In(zone.Location())
	var findings []db.Finding
	for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		at := cutoff.Add(delta).In(zone.Location())
		f := db.Finding{ScanID: scan.ID, RepositoryID: scan.RepositoryID, Title: "time", CreatedAt: old, UpdatedAt: at}
		if param == "since" {
			f.CreatedAt, f.UpdatedAt = at, old
		}
		findings = append(findings, f)
	}
	if err := s.DB.Create(&findings).Error; err != nil {
		t.Fatal(err)
	}
	for _, bound := range []time.Time{cutoff, cutoff.In(zone.Location())} {
		got := exportFindingIDs(t, s, url.Values{param: {bound.Format(time.RFC3339Nano)}})
		if want := []uint{findings[2].ID, findings[1].ID}; !slices.Equal(got, want) {
			t.Errorf("%s %s: finding IDs = %v, want %v", param, bound, got, want)
		}
	}
	if err := s.DB.Delete(&findings).Error; err != nil {
		t.Fatal(err)
	}
}

func exportFindingIDs(t *testing.T, s *Server, params url.Values) []uint {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, "/api/v1/findings?"+params.Encode()))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var ids []uint
	for _, row := range readJSONL(t, w.Body.String()) {
		ids = append(ids, uint(row["id"].(float64)))
	}
	return ids
}

func TestExportFindings_rejectsInvalidFiltersBeforeStreaming(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedFindings(t, s)
	queries := []string{
		"repository_id=", "repository_id=0", "repository_id=-1", "repository_id=abc",
		"repository_id=1.5", "repository_id=9223372036854775808",
		"scope=bogus", "scope=FINDINGS",
	}
	for _, param := range []string{"since", "updated_since"} {
		for _, value := range []string{"", "yesterday", "2026-09-01", "2026-09-01T12:00:00", "2026-02-30T12:00:00Z"} {
			queries = append(queries, param+"="+value)
		}
	}
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, localReq(http.MethodGet, "/api/v1/findings?"+query))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if got := w.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
				t.Errorf("Content-Type = %q, want JSON error before JSONL streaming", got)
			}
		})
	}
}
