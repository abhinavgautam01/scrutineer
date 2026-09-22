package worker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

func newBackendCache(t *testing.T) *BackendPreflightCache {
	t.Helper()
	c, err := NewBackendPreflightCache(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBackendCacheTTLAndConfiguration(t *testing.T) {
	c := newBackendCache(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	calls := 0
	run := func(context.Context) coverage.BackendProbe {
		calls++
		return coverage.BackendProbe{Status: coverage.PreflightReady}
	}
	first, err := c.check(t.Context(), []byte("secret-config"), run)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.check(t.Context(), []byte("secret-config"), run)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !second.Reused || first.Reused || first.ProbeID != second.ProbeID || first.ConfigHash == "secret-config" {
		t.Fatalf("first=%+v second=%+v calls=%d", first, second, calls)
	}
	now = now.Add(time.Hour)
	third, err := c.check(t.Context(), []byte("secret-config"), run)
	if err != nil {
		t.Fatal(err)
	}
	if third.Reused || third.ProbeID == first.ProbeID || calls != 2 {
		t.Fatalf("expired=%+v calls=%d", third, calls)
	}
	if _, err := c.check(t.Context(), []byte("changed-model-tools-or-credentials"), run); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatal("changed config reused cache")
	}
	if newBackendCache(t).key([]byte("secret-config")) == c.key([]byte("secret-config")) {
		t.Fatal("digest is reusable across processes")
	}
}

func TestBackendCacheConcurrentAndCanceledWaiter(t *testing.T) {
	c := newBackendCache(t)
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	run := func(context.Context) coverage.BackendProbe {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return coverage.BackendProbe{Status: coverage.PreflightReady}
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			if _, err := c.check(t.Context(), []byte("same"), run); err != nil {
				t.Error(err)
			}
		})
	}
	<-started
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.check(ctx, []byte("same"), run); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestBackendCacheFailuresAndLeaderCancellation(t *testing.T) {
	c := newBackendCache(t)
	run := func(context.Context) coverage.BackendProbe { return blockedBackendProbe("backend rejected request") }
	first, err := c.check(t.Context(), []byte("bad"), run)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.check(t.Context(), []byte("bad"), func(context.Context) coverage.BackendProbe {
		t.Fatal("failure not cached")
		return coverage.BackendProbe{}
	})
	if err != nil || !second.Reused || first.ProbeID != second.ProbeID {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	_, err = c.check(ctx, []byte("canceled"), func(context.Context) coverage.BackendProbe {
		cancel()
		return coverage.BackendProbe{Status: coverage.PreflightReady}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	result, err := c.check(t.Context(), []byte("canceled"), run)
	if err != nil || result.Reused {
		t.Fatalf("cancellation cached: %+v %v", result, err)
	}
	for _, ttl := range []time.Duration{0, -time.Second} {
		if _, err := NewBackendPreflightCache(ttl); err == nil {
			t.Fatal("invalid TTL accepted")
		}
	}
}

func TestBackendPreflightPersistence(t *testing.T) {
	w, repo := newStreamWorker(t)
	w.BackendPreflight = newBackendCache(t)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanRunning, Kind: JobSkill, Recipe: `{"version":1}`}
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	sj := SkillJob{WorkRoot: t.TempDir()}
	doc := skillContext{Repository: skillContextRepo{Name: "keep"}}
	w.configureCapabilityPreflight(t.Context(), &scan, &db.Skill{}, &sj, doc)
	w.configureBackendPreflight(t.Context(), &scan, &sj, doc)
	if err := sj.RecordPreflight(coverage.Preflight{Status: coverage.PreflightDegraded, Missing: []string{"command:cargo"}, Degraded: true}); err != nil {
		t.Fatal(err)
	}
	run := func(context.Context) coverage.BackendProbe {
		return coverage.BackendProbe{Status: coverage.PreflightReady}
	}
	for range 2 {
		if err := sj.checkBackend(t.Context(), []byte("credential-secret"), run); err != nil {
			t.Fatal(err)
		}
	}
	var receipts []db.ScanPreflightReceipt
	if err := w.DB.Find(&receipts).Error; err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 || receipts[0].RecipeSHA256 != textDigest(scan.Recipe) || strings.Contains(receipts[0].Report, "credential-secret") {
		t.Fatalf("receipts=%+v", receipts)
	}
	if scan.Recipe != `{"version":1}` {
		t.Fatal("claim-time recipe mutated")
	}
	if err := sj.RecordPreflight(coverage.Preflight{Status: coverage.PreflightReady}); err != nil {
		t.Fatal(err)
	}
	rec, ok := coverage.Parse(scan.Coverage)
	if !ok || rec.Preflight.Backend == nil || rec.Preflight.Backend.ReceiptID != receipts[0].ID || rec.Preflight.Status != coverage.PreflightDegraded || scan.Completeness != coverage.CompletenessPartial {
		t.Fatalf("coverage=%s", scan.Coverage)
	}
	contents, err := os.ReadFile(filepath.Join(sj.WorkRoot, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	var staged skillContext
	if err := json.Unmarshal(contents, &staged); err != nil {
		t.Fatal(err)
	}
	if staged.Repository.Name != "keep" || staged.Scrutineer.Preflight.Backend.ProbeID != rec.Preflight.Backend.ProbeID {
		t.Fatalf("context=%s", contents)
	}
	if err := sj.checkBackend(t.Context(), []byte("bad"), func(context.Context) coverage.BackendProbe { return blockedBackendProbe("rejected") }); err == nil {
		t.Fatal("blocked probe allowed scan")
	}
	if err := applySkillCoverageClaim(&scan, coverage.Claim{Receipts: []coverage.Receipt{}}); err != nil {
		t.Fatal(err)
	}
	if scan.Completeness != coverage.CompletenessPartial {
		t.Fatal("claim erased backend failure")
	}
}

func TestBackendPreflightPersistenceFailure(t *testing.T) {
	w, repo := newStreamWorker(t)
	w.BackendPreflight = newBackendCache(t)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanRunning}
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	sj := SkillJob{WorkRoot: t.TempDir()}
	w.configureBackendPreflight(t.Context(), &scan, &sj, skillContext{})
	if err := w.DB.Callback().Update().Before("gorm:update").Register("test:reject_preflight", func(tx *gorm.DB) { _ = tx.AddError(errors.New("forced failure")) }); err != nil {
		t.Fatal(err)
	}
	run := func(context.Context) coverage.BackendProbe {
		return coverage.BackendProbe{Status: coverage.PreflightReady}
	}
	if err := sj.checkBackend(t.Context(), []byte("key"), run); err == nil {
		t.Fatal("ignored DB failure")
	}
	var count int64
	if err := w.DB.Model(&db.ScanPreflightReceipt{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 || scan.Coverage != "" {
		t.Fatal("partial persistence on rollback")
	}
	if _, err := os.Stat(filepath.Join(sj.WorkRoot, "context.json")); !os.IsNotExist(err) {
		t.Fatal("staged uncommitted evidence")
	}
}

func TestBackendProbeStream(t *testing.T) {
	const success = `{"type":"result","subtype":"success","result":"SCRUTINEER_BACKEND_READY","total_cost_usd":0.02,"usage":{"input_tokens":2,"output_tokens":3}}`
	for _, tc := range []struct {
		name, output string
		ready        bool
	}{
		{"success", success, true},
		{"empty", "", false},
		{"malformed", "not json", false},
		{"wrong-answer", strings.ReplaceAll(success, backendProbeAnswer, "wrong"), false},
		{"error", `{"type":"result","subtype":"error_during_execution","is_error":true,"result":"credential-secret"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := "printf '%s\\n' '" + tc.output + "'"
			ctx, cancel := context.WithTimeout(t.Context(), time.Second*5)
			defer cancel()
			result := runBackendProbe(ctx, ClaudeHarness{}, "/bin/sh", []string{"-c", script}, os.Environ(), t.TempDir())
			if (result.Status == coverage.PreflightReady) != tc.ready || strings.Contains(result.Error, "credential-secret") {
				t.Fatalf("result=%+v", result)
			}
			if tc.ready && (result.InputTokens != 2 || result.OutputTokens != 3 || result.CostUSD != 0.02) {
				t.Fatalf("usage=%+v", result)
			}
		})
	}
}

func TestBackendProbeCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	result := runBackendProbe(ctx, ClaudeHarness{}, "/bin/sh", []string{"-c", "sleep 30"}, os.Environ(), t.TempDir())
	if result.Status != coverage.PreflightBlocked || time.Since(start) > 5*time.Second {
		t.Fatalf("result=%+v elapsed=%s", result, time.Since(start))
	}
}

func TestBackendProbeOtherStreams(t *testing.T) {
	for _, tc := range []struct {
		name   string
		h      Harness
		stream string
	}{
		{"codex", CodexHarness{}, `{"type":"item.completed","item":{"type":"agent_message","text":"SCRUTINEER_BACKEND_READY"}}
{"type":"turn.completed","usage":{"input_tokens":4,"output_tokens":2}}`},
		{"opencode", OpencodeHarness{}, `{"type":"text","part":{"type":"text","text":"SCRUTINEER_BACKEND_READY"}}
{"type":"step_finish","part":{"type":"step-finish","tokens":{"input":4,"output":2}}}`},
		{"copilot", CopilotHarness{}, `{"type":"assistant.message","data":{"content":"SCRUTINEER_BACKEND_READY","turnId":"0","outputTokens":2}}
{"type":"assistant.turn_end","data":{"turnId":"0"}}
{"type":"result","sessionId":"session","exitCode":0}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runBackendProbe(t.Context(), tc.h, "/bin/sh", []string{"-c", "printf '%s\\n' '" + tc.stream + "'"}, os.Environ(), t.TempDir())
			if result.Status != coverage.PreflightReady {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestBackendProbeRejectsTools(t *testing.T) {
	stream := `{"type":"tool","part":{"type":"tool","tool":"bash","state":{"input":{"command":"secret-command"}}}}
{"type":"text","part":{"type":"text","text":"SCRUTINEER_BACKEND_READY"}}
{"type":"step_finish","part":{"type":"step-finish"}}`
	result := runBackendProbe(t.Context(), OpencodeHarness{}, "/bin/sh", []string{"-c", "printf '%s\\n' '" + stream + "'"}, os.Environ(), t.TempDir())
	if result.Status != coverage.PreflightBlocked || strings.Contains(result.Error, "secret") {
		t.Fatalf("result=%+v", result)
	}
}

func TestBackendCacheBounded(t *testing.T) {
	c := newBackendCache(t)
	for i := 0; i < backendPreflightCacheLimit+10; i++ {
		if _, err := c.check(t.Context(), []byte{byte(i / 256), byte(i % 256)}, func(context.Context) coverage.BackendProbe {
			return coverage.BackendProbe{Status: coverage.PreflightReady}
		}); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.entries) != backendPreflightCacheLimit {
		t.Fatalf("entries=%d", len(c.entries))
	}
}
