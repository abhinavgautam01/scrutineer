package worker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/coverage"
)

const backendSuccessJSON = `{"type":"result","subtype":"success","result":"SCRUTINEER_BACKEND_READY"}`

func probeCacheCallback(t *testing.T, c *BackendPreflightCache) func(context.Context, []byte, func(context.Context) coverage.BackendProbe) error {
	t.Helper()
	return func(ctx context.Context, config []byte, run func(context.Context) coverage.BackendProbe) error {
		result, err := c.check(ctx, config, run)
		if err != nil {
			return err
		}
		if result.Status != coverage.PreflightReady {
			t.Fatalf("probe failed: %+v", result)
		}
		return nil
	}
}

func TestBackendLocalRunnerUsesCacheAndActualArgs(t *testing.T) {
	bin := t.TempDir()
	log := filepath.Join(bin, "invocations")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$PROBE_TEST_LOG\"\nprintf '%s\\n' '" + backendSuccessJSON + "'\n"
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PROBE_TEST_LOG", log)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	c := newBackendCache(t)
	sj := SkillJob{WorkRoot: t.TempDir(), SrcReady: true, Model: "model-a", AllowedTools: "Read,Grep", RequiresCommands: []string{"sh"}, checkBackend: probeCacheCallback(t, c)}
	if err := os.Mkdir(filepath.Join(sj.WorkRoot, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := (LocalClaude{}).RunSkill(t.Context(), sj, func(Event) {}); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), backendProbeAnswer) != 1 || strings.Count(string(data), "--model model-a") != 3 || !strings.Contains(string(data), "--max-turns 1") || !strings.Contains(string(data), "Read,Grep,Skill") {
		t.Fatalf("argv=%s", data)
	}
	sj.AllowedTools = "Read"
	if err := (LocalClaude{}).checkBackendPreflight(t.Context(), sj); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANTHROPIC_API_KEY", "rotated")
	if err := (LocalClaude{}).checkBackendPreflight(t.Context(), sj); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), backendProbeAnswer) != 3 {
		t.Fatalf("key failed to change: %s", data)
	}
}

func TestBackendContainerProbeIsolationAndCache(t *testing.T) {
	bin := t.TempDir()
	log := filepath.Join(bin, "invocations")
	runtime := filepath.Join(bin, "runtime")
	script := `#!/bin/sh
case "$1" in
 image) printf '%s\n' 'sha256:fixture'; exit 0;;
 rm) exit 0;;
esac
printf '%s\n' "$*" >> "$PROBE_TEST_LOG"
for arg in "$@"; do
 case "$arg" in
  *:/work) work=${arg%:/work}; [ -z "$(ls -A "$work")" ] || exit 19;;
 esac
done
printf '%s\n' '` + backendSuccessJSON + `'
`
	if err := os.WriteFile(runtime, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROBE_TEST_LOG", log)
	t.Setenv("ANTHROPIC_API_KEY", "first-credential")
	d := ContainerRunner{Runtime: ContainerRuntime{Bin: runtime}, Image: "fixture", Harness: ClaudeHarness{}, ModelBaseURL: "https://provider.invalid"}
	sj := SkillJob{WorkRoot: t.TempDir(), Model: "model", AllowedTools: "Read", OutputFile: "report.json", ResumeSessionID: "scan-session", Prompt: "scan-secret", checkBackend: probeCacheCallback(t, newBackendCache(t))}
	for range 2 {
		if err := d.checkBackendPreflight(t.Context(), sj, "fixture", hardenedNet{}, opencodeProvider{}, ""); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), backendProbeAnswer) != 1 || strings.Contains(string(data), sj.WorkRoot+":/work") || strings.Contains(string(data), "scan-secret") || strings.Contains(string(data), "scan-session") || !strings.Contains(string(data), "--permission-mode acceptEdits") || !strings.Contains(string(data), "--max-turns 1") || !strings.Contains(string(data), "ANTHROPIC_BASE_URL=https://provider.invalid") {
		t.Fatalf("argv=%s", data)
	}
	t.Setenv("ANTHROPIC_API_KEY", "second-credential")
	if err := d.checkBackendPreflight(t.Context(), sj, "fixture", hardenedNet{}, opencodeProvider{}, ""); err != nil {
		t.Fatal(err)
	}
	d.ModelBaseURL = "https://changed.invalid"
	if err := d.checkBackendPreflight(t.Context(), sj, "fixture", hardenedNet{}, opencodeProvider{}, ""); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), backendProbeAnswer) != 3 {
		t.Fatalf("did not invalidate: %s", data)
	}
}

func TestBackendPreflightDoesNotBypassStaticBlock(t *testing.T) {
	sj := SkillJob{WorkRoot: t.TempDir(), SrcReady: true, RequiresCommands: []string{"scrutineer-definitely-missing"}, checkBackend: func(context.Context, []byte, func(context.Context) coverage.BackendProbe) error {
		t.Fatal("live probe ran despite static block")
		return nil
	}}
	if _, err := (LocalClaude{}).RunSkill(t.Context(), sj, func(Event) {}); err == nil {
		t.Fatal("static block ignored")
	}
}

func TestBackendKeyIncludesToolsWithoutNativeAllowlistFlag(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "runtime")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s\\n' 'sha256:fixture'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	d := ContainerRunner{Runtime: ContainerRuntime{Bin: bin}, Harness: CodexHarness{}}
	var keys []string
	sj := SkillJob{Model: "model", AllowedTools: "Read", checkBackend: func(_ context.Context, key []byte, _ func(context.Context) coverage.BackendProbe) error {
		keys = append(keys, string(key))
		return nil
	}}
	for _, tools := range []string{"Read", "Read,Bash"} {
		sj.AllowedTools = tools
		if err := d.checkBackendPreflight(t.Context(), sj, "fixture", hardenedNet{}, opencodeProvider{}, ""); err != nil {
			t.Fatal(err)
		}
	}
	if len(keys) != 2 || keys[0] == keys[1] {
		t.Fatal("different harness toolsets shared a key")
	}
}
