package worker

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type poutineReport struct {
	Findings []struct {
		ID         string `json:"id"`
		Title      string `json:"title"`
		Severity   string `json:"severity"`
		Location   string `json:"location"`
		Trace      string `json:"trace"`
		Rating     string `json:"rating"`
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
	} `json:"findings"`
	Error string `json:"error"`
}

func TestPoutineWrapperMapsNativeReport(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required to exercise the bundled Poutine wrapper")
	}

	workspace := t.TempDir()
	if err := os.Mkdir(filepath.Join(workspace, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(workspace, "bin")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	argsPath := filepath.Join(workspace, "args")
	envPath := filepath.Join(workspace, "env")
	fake := `#!/bin/sh
printf '%s\n' "$*" > "$POUTINE_ARGS_FILE"
printf '%s\n' "${POUTINE_DISABLE_VERSION_CHECK:-}" > "$POUTINE_ENV_FILE"
cat "$POUTINE_FIXTURE"
`
	if err := os.WriteFile(filepath.Join(binDir, "poutine"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}

	script, err := filepath.Abs("../../skills/poutine/scripts/scan.py")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := filepath.Abs("../../skills/poutine/testdata/native.json")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, script)
	cmd.Dir = workspace
	cmd.Env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"POUTINE_ARGS_FILE="+argsPath,
		"POUTINE_ENV_FILE="+envPath,
		"POUTINE_FIXTURE="+fixture,
	)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run wrapper: %v", err)
	}

	assertPoutineInvocation(t, argsPath, envPath)
	assertPoutineReport(t, out)
	schema, err := os.ReadFile("../../skills/poutine/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := ValidateReportSchema(string(schema), string(out)); got != "" {
		t.Fatalf("mapped Poutine report failed its bundled schema: %s\n%s", got, out)
	}
}

func TestPoutineWrapperReportsMissingBinary(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required to exercise the bundled Poutine wrapper")
	}
	workspace := t.TempDir()
	if err := os.Mkdir(filepath.Join(workspace, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs("../../skills/poutine/scripts/scan.py")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, script)
	cmd.Dir = workspace
	cmd.Env = []string{"PATH=" + t.TempDir()}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run wrapper: %v", err)
	}
	var report poutineReport
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("decode wrapper output: %v\n%s", err, out)
	}
	if len(report.Findings) != 0 || report.Error != "poutine not on PATH" {
		t.Fatalf("missing-binary report = %+v", report)
	}
}

func assertPoutineInvocation(t *testing.T, argsPath, envPath string) {
	t.Helper()
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	const wantArgs = "analyze_local . --format json --quiet --disable-version-check"
	if got := strings.TrimSpace(string(args)); got != wantArgs {
		t.Errorf("Poutine args = %q, want %q", got, wantArgs)
	}
	env, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(env)); got != "1" {
		t.Errorf("POUTINE_DISABLE_VERSION_CHECK = %q, want 1", got)
	}
}

func assertPoutineReport(t *testing.T, out []byte) {
	t.Helper()
	var report poutineReport
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("decode wrapper output: %v\n%s", err, out)
	}
	if report.Error != "" || len(report.Findings) != 3 {
		t.Fatalf("mapped report = %+v", report)
	}
	wants := []struct {
		id       string
		title    string
		severity string
		location string
	}{
		{"F1", "Code injection in a workflow step", "Medium", ".github/workflows/pr.yml:15"},
		{"F2", "Untrusted checkout is executed", "High", "workflow:8"},
		{"F3", "Unverified script execution", "Low", ".github/workflows/release.yml:27"},
	}
	for i, want := range wants {
		got := report.Findings[i]
		if got.ID != want.id || got.Title != want.title || got.Severity != want.severity || got.Location != want.location {
			t.Errorf("finding %d = %+v, want id=%s title=%q severity=%s location=%s",
				i, got, want.id, want.title, want.severity, want.location)
		}
	}
	first := report.Findings[0]
	for _, want := range []string{
		"Details: A pull request title reaches a shell step.",
		"Rule: Untrusted expression data is evaluated by a shell.",
		"Event triggers: pull_request_target",
		"Injection sources: github.event.pull_request.title",
		"Referenced secrets: DEPLOY_TOKEN",
	} {
		if !strings.Contains(first.Trace, want) {
			t.Errorf("first finding trace %q does not contain %q", first.Trace, want)
		}
	}
	if len(first.References) != 1 || first.References[0].URL != "https://github.com/boostsecurityio/poutine/blob/main/docs/content/results/injection.md" {
		t.Errorf("first finding references = %+v; non-HTTP references must be removed", first.References)
	}
}
