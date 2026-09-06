package worker

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"scrutineer/internal/db"
)

const ExplorationRandomDig = "random-dig"

// ValidateExploration rejects combinations that would silently turn a blind
// source audit back into a planned, finding-scoped, or diff-only audit.
func ValidateExploration(skill, mode, target, focus, rescan string, findingID *uint) error {
	if mode == "" && target == "" {
		return nil
	}
	if mode != ExplorationRandomDig || skill != deepDiveSkillName || focus != "" || rescan == db.ScanRescanModeDiff || findingID != nil {
		return fmt.Errorf("invalid exploratory audit inputs")
	}
	if target != "" && target != "." {
		clean, err := CleanSubPath(target)
		if err != nil || clean != target {
			return fmt.Errorf("invalid exploratory audit path %q", target)
		}
	}
	return nil
}

type skillContextExploration struct {
	Mode string `json:"mode"`
	Path string `json:"path"`
}

// prepareExploration runs after all operator and skill path filters. Only
// directories containing regular source files are candidates, never symlinks.
// Persisting the chosen directory keeps explicit retries on the same target.
func (w *Worker) prepareExploration(ctx context.Context, workRoot string, scan *db.Scan) error {
	if scan.ExplorationMode == "" {
		return nil
	}
	if err := ValidateExploration(scan.SkillName, scan.ExplorationMode, scan.ExplorationPath, scan.FocusArea, scan.RescanMode, scan.FindingID); err != nil {
		return err
	}
	dirs, err := exploratoryDirectories(ctx, filepath.Join(workRoot, "src"), scan.SubPath)
	if err != nil {
		return fmt.Errorf("select exploratory source directory: %w", err)
	}
	if len(dirs) == 0 {
		return fmt.Errorf("no eligible source directory for exploratory audit")
	}
	if scan.ExplorationPath != "" {
		if !slices.Contains(dirs, scan.ExplorationPath) {
			return fmt.Errorf("exploratory directory %q is no longer eligible", scan.ExplorationPath)
		}
		return nil
	}
	seed := scan.ID
	if scan.TriageScanID != nil {
		seed = *scan.TriageScanID
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "random-dig:%d", seed))
	target := dirs[binary.BigEndian.Uint64(sum[:])%uint64(len(dirs))]
	result := w.DB.Model(scan).Update("exploration_path", target)
	if result.Error != nil {
		return fmt.Errorf("persist exploratory directory: %w", result.Error)
	}
	if result.RowsAffected != 1 {
		return fmt.Errorf("scan disappeared before exploratory directory was saved")
	}
	scan.ExplorationPath = target
	return nil
}

func exploratoryDirectories(ctx context.Context, src, subPath string) ([]string, error) {
	clean, err := CleanSubPath(subPath)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(src)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	dirs := map[string]bool{}
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return fs.SkipDir
			}
			if clean != "" && name != "." && name != clean && !strings.HasPrefix(clean, name+"/") && !strings.HasPrefix(name, clean+"/") {
				return fs.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() || (clean != "" && !strings.HasPrefix(name, clean+"/")) {
			return nil
		}
		if exploratorySourceFile(name) {
			dirs[path.Dir(name)] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(dirs))
	for dir := range dirs {
		result = append(result, dir)
	}
	slices.Sort(result)
	return result, nil
}

// A conservative source-only candidate set avoids sampling docs, lockfiles,
// binary assets, or manifests as the sole target of an expensive audit.
var exploratorySourceExtensions = strings.Fields(".c .h .cc .cpp .cxx .hpp .m .mm .go .rs .py .pyw .js .jsx .ts .tsx .mjs .cjs .rb .php .java .kt .kts .scala .sc .cs .fs .fsx .swift .pl .pm .lua .sh .bash .zsh .ex .exs .erl .hrl .hs .ml .mli .clj .cljs .cljc .dart .r .jl .zig .f .f90 .f95 .sol .vue .svelte")

func exploratorySourceFile(name string) bool {
	return slices.Contains(exploratorySourceExtensions, strings.ToLower(path.Ext(name)))
}

func stageExploratoryWorkspace(workRoot, skillDir, apiBase string, scan *db.Scan, skill *db.Skill) error {
	if err := ValidateExploration(skill.Name, scan.ExplorationMode, scan.ExplorationPath, scan.FocusArea, scan.RescanMode, scan.FindingID); err != nil {
		return err
	}
	if scan.ExplorationPath == "" || skill.SourcePath == "" {
		return fmt.Errorf("exploratory audit requires a selected directory and a skill reference pack")
	}
	body, err := os.ReadFile(filepath.Join(skill.SourcePath, "references", "random-dig.md"))
	if err != nil {
		return fmt.Errorf("read random-dig instructions: %w", err)
	}
	// The loaded skill is scan-local. Update it too so the logged prompt and
	// any report-repair invocation describe the instructions actually staged.
	skill.Body = string(body)
	if err := stageSkill(skill, workRoot, skillDir); err != nil {
		return err
	}
	// Keep repository identity and scope, not any model-derived guidance.
	// apiAuth limits this scan's token to validating its own output schema.
	blind := *scan
	blind.Repository.ScanConfig = ""
	blind.Repository.ThreatModel = ""
	return stageContext(workRoot, skillDir, apiBase, "", "", &blind, &blind.Repository)
}
