package worker

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type historyCandidateList struct {
	Head               string   `json:"head"`
	CacheReusable      bool     `json:"cache_reusable"`
	CacheInvalidReason string   `json:"cache_invalid_reason"`
	Shallow            bool     `json:"shallow"`
	Ecosystems         []string `json:"ecosystems"`
	TotalMatched       int      `json:"total_matched"`
	Candidates         []struct {
		Commit       string   `json:"commit"`
		Title        string   `json:"title"`
		MatchedTerms []string `json:"matched_terms"`
	} `json:"candidates"`
}

type historyDiffBatch struct {
	Commits []struct {
		Commit        string   `json:"commit"`
		ChangedPaths  []string `json:"changed_paths"`
		Diff          string   `json:"diff"`
		DiffTruncated bool     `json:"diff_truncated"`
	} `json:"commits"`
}

func historyScriptPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs("../../skills/history/scripts/history_candidates.py")
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func historyGit(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func historyCommit(t *testing.T, repo, message, path, content string) string {
	t.Helper()
	full := filepath.Join(repo, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	historyGit(t, repo, "add", path)
	historyGit(t, repo, "-c", "commit.gpgsign=false", "commit", "-m", message)
	return historyGit(t, repo, "rev-parse", "HEAD")
}

func historyTestRepo(t *testing.T) (string, string) {
	t.Helper()
	repo := t.TempDir()
	historyGit(t, repo, "init")
	historyGit(t, repo, "config", "user.name", "History Test")
	historyGit(t, repo, "config", "user.email", "history@example.invalid")
	historyCommit(t, repo, "initial import", "src/parser.c", "int parse(int n) { return n; }\n")
	largeGuard := "int parse(int n) {\n  if (n > 1024) return -1;\n  return n;\n}\n" + strings.Repeat("/* bounded input */\n", 100)
	securityCommit := historyCommit(t, repo, "fix parser bounds check", "src/parser.c", largeGuard)
	historyCommit(t, repo, "update parser documentation", "README.md", "Parser documentation.\n")
	return repo, securityCommit
}

func runHistoryList(t *testing.T, repo string, extra ...string) historyCandidateList {
	t.Helper()
	args := append([]string{historyScriptPath(t), "list", "--repo", repo}, extra...)
	cmd := exec.Command("python3", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("history list: %v\n%s", err, out)
	}
	var got historyCandidateList
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decode history list: %v\n%s", err, out)
	}
	return got
}

func TestHistoryCandidates_filtersAndChecksCacheAncestry(t *testing.T) {
	repo, securityCommit := historyTestRepo(t)
	got := runHistoryList(t, repo)
	if got.Shallow {
		t.Error("ordinary test repository reported as shallow")
	}
	if len(got.Ecosystems) != 1 || got.Ecosystems[0] != "c-cpp" {
		t.Fatalf("ecosystems = %v, want [c-cpp]", got.Ecosystems)
	}
	if got.TotalMatched != 1 || len(got.Candidates) != 1 {
		t.Fatalf("candidates = %+v, total = %d, want one", got.Candidates, got.TotalMatched)
	}
	if got.Candidates[0].Commit != securityCommit || got.Candidates[0].Title != "fix parser bounds check" {
		t.Errorf("candidate = %+v, want security commit %s", got.Candidates[0], securityCommit)
	}

	incremental := runHistoryList(t, repo, "--base", securityCommit)
	if !incremental.CacheReusable || incremental.CacheInvalidReason != "" {
		t.Fatalf("cache = reusable %v reason %q", incremental.CacheReusable, incremental.CacheInvalidReason)
	}
	if incremental.TotalMatched != 0 || len(incremental.Candidates) != 0 {
		t.Errorf("incremental candidates = %+v, want none after cached fix", incremental.Candidates)
	}

	invalid := runHistoryList(t, repo, "--base", strings.Repeat("0", 40))
	if invalid.CacheReusable || !strings.Contains(invalid.CacheInvalidReason, "unavailable") {
		t.Errorf("invalid cache = reusable %v reason %q", invalid.CacheReusable, invalid.CacheInvalidReason)
	}

	historyGit(t, repo, "switch", "-c", "rewritten", securityCommit+"^")
	historyCommit(t, repo, "rewrite documentation", "README.md", "Rewritten history.\n")
	nonAncestor := runHistoryList(t, repo, "--base", securityCommit)
	if nonAncestor.CacheReusable || !strings.Contains(nonAncestor.CacheInvalidReason, "not an ancestor") {
		t.Errorf("non-ancestor cache = reusable %v reason %q", nonAncestor.CacheReusable, nonAncestor.CacheInvalidReason)
	}
}

func TestHistoryCandidates_capsDiffsAndDetectsShallowClone(t *testing.T) {
	repo, securityCommit := historyTestRepo(t)
	cmd := exec.Command(
		"python3", historyScriptPath(t), "batch", "--repo", repo,
		"--commit", securityCommit, "--max-diff-bytes", "1024",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("history batch: %v\n%s", err, out)
	}
	var batch historyDiffBatch
	if err := json.Unmarshal(out, &batch); err != nil {
		t.Fatalf("decode history batch: %v\n%s", err, out)
	}
	if len(batch.Commits) != 1 || batch.Commits[0].Commit != securityCommit {
		t.Fatalf("batch = %+v", batch.Commits)
	}
	if !batch.Commits[0].DiffTruncated || !strings.Contains(batch.Commits[0].Diff, "diff truncated") {
		t.Errorf("bounded diff was not marked truncated: %+v", batch.Commits[0])
	}
	if len(batch.Commits[0].ChangedPaths) != 1 || batch.Commits[0].ChangedPaths[0] != "src/parser.c" {
		t.Errorf("changed paths = %v", batch.Commits[0].ChangedPaths)
	}

	clone := filepath.Join(t.TempDir(), "shallow")
	cloneCmd := exec.Command("git", "clone", "--depth", "1", "file://"+repo, clone)
	if cloneOut, cloneErr := cloneCmd.CombinedOutput(); cloneErr != nil {
		t.Fatalf("shallow clone: %v\n%s", cloneErr, cloneOut)
	}
	if got := runHistoryList(t, clone); !got.Shallow {
		t.Error("depth-1 clone was not reported as shallow")
	}
}

func TestHistoryCandidates_rejectsInvalidScopePaths(t *testing.T) {
	repo, _ := historyTestRepo(t)
	for _, path := range []string{"/absolute", "../outside", "src/../outside", `src\parser.c`} {
		t.Run(path, func(t *testing.T) {
			cmd := exec.Command("python3", historyScriptPath(t), "list", "--repo", repo, "--path", path)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("history list accepted invalid path %q", path)
			}
			if !strings.Contains(string(out), "normalized repository-relative path") {
				t.Fatalf("history list error = %q", out)
			}
		})
	}
}
