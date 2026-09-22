//go:build evals

package evals

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"scrutineer/internal/worker"
)

func TestPackageManagerAuditLive(t *testing.T) {
	if os.Getenv("SCRUTINEER_RUN_EVALS") != "1" {
		t.Skip("set SCRUTINEER_RUN_EVALS=1 to execute model-backed skill evals")
	}
	scenario, err := LoadScenario("../../evals/package-manager-bin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	runner := Runner{
		Runner: worker.LocalClaude{}, SkillsRoot: "../../skills", EvalsRoot: "../../evals",
		WorkRoot: t.TempDir(), Model: os.Getenv("SCRUTINEER_EVAL_MODEL"),
	}
	result, err := runner.RunScenario(context.Background(), scenario)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("report: %s", result.Report)
	if result.FailedRequired != 0 || result.Unexpected != 0 {
		t.Fatalf("required misses=%d unexpected=%d", result.FailedRequired, result.Unexpected)
	}
}

type triageModeRunner struct {
	worker.LocalClaude
	apiBase string
}

func (r triageModeRunner) RunSkill(ctx context.Context, job worker.SkillJob, emit func(worker.Event)) (worker.SkillResult, error) {
	for _, dir := range []string{job.WorkRoot, job.SkillDir} {
		path := filepath.Join(dir, "context.json")
		raw, err := os.ReadFile(path)
		if err != nil {
			return worker.SkillResult{}, err
		}
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			return worker.SkillResult{}, err
		}
		document["scrutineer"] = map[string]any{
			"api_base": r.apiBase, "token": "fixture-token", "repository_id": 1,
		}
		raw, err = json.Marshal(document)
		if err != nil {
			return worker.SkillResult{}, err
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			return worker.SkillResult{}, err
		}
	}
	return r.LocalClaude.RunSkill(ctx, job, emit)
}

func TestPackageManagerTriageLive(t *testing.T) {
	if os.Getenv("SCRUTINEER_RUN_EVALS") != "1" {
		t.Skip("set SCRUTINEER_RUN_EVALS=1 to execute model-backed skill evals")
	}
	for _, tc := range []struct {
		fixture string
		matched bool
	}{
		{"package-manager-bin", true},
		{"package-consumer", false},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			requests := make(chan string, 100)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if req.Header.Get("Authorization") != "Bearer fixture-token" {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				if req.Method == http.MethodPost {
					requests <- req.URL.Path
					w.WriteHeader(http.StatusCreated)
					_, _ = fmt.Fprint(w, `{"id":1}`)
					return
				}
				_, _ = fmt.Fprint(w, `[]`)
			}))
			defer server.Close()
			runner := Runner{
				Runner:     triageModeRunner{apiBase: server.URL + "/api"},
				SkillsRoot: "../../skills", EvalsRoot: "../../evals",
				WorkRoot: t.TempDir(), Model: os.Getenv("SCRUTINEER_EVAL_MODEL"),
			}
			result, err := runner.RunScenario(context.Background(), Scenario{
				Skill: "triage", Fixture: "fixtures/" + tc.fixture,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("report: %s", result.Report)
			var enqueued []string
			for len(requests) > 0 {
				enqueued = append(enqueued, <-requests)
			}
			auditPath := "/api/repositories/1/skills/audit-package-manager/run"
			if slices.Contains(enqueued, auditPath) != tc.matched {
				t.Fatalf("enqueued=%v, want package manager match=%v", enqueued, tc.matched)
			}
			if !slices.Contains(enqueued, "/api/repositories/1/skills/threat-model/run") {
				t.Fatalf("standard threat model not enqueued: %v", enqueued)
			}
			assertTriageModeReport(t, result.Report, tc.matched)
		})
	}
}

func assertTriageModeReport(t *testing.T, raw string, want bool) {
	t.Helper()
	var report struct {
		Modes []struct {
			Name     string   `json:"name"`
			Evidence []string `json:"evidence"`
		} `json:"modes"`
	}
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		t.Fatal(err)
	}
	matched := false
	for _, mode := range report.Modes {
		if mode.Name == "package-manager" {
			matched = true
			if len(mode.Evidence) == 0 || strings.TrimSpace(mode.Evidence[0]) == "" {
				t.Fatal("mode has no classification evidence")
			}
		}
	}
	if matched != want {
		t.Fatalf("mode match=%v, want %v", matched, want)
	}
}
