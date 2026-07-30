package worker

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/findingnorm"
)

const (
	revalidateSkillName     = "revalidate"
	noveltyLogMaxCommits    = 20
	noveltyLogMaxBytes      = 64 * 1024
	noveltyUnavailableNoGit = "repository history is unavailable"
)

type skillContextNovelty struct {
	State         db.FindingNovelty `json:"state"`
	ScannedCommit string            `json:"scanned_commit,omitempty"`
	CheckedCommit string            `json:"checked_commit,omitempty"`
	FindingFile   string            `json:"finding_file,omitempty"`
	FileChanged   bool              `json:"file_changed"`
	CommitLog     string            `json:"commit_log,omitempty"`
	LogTruncated  bool              `json:"log_truncated,omitempty"`
	NotCheckedWhy string            `json:"not_checked_reason,omitempty"`
}

func (w *Worker) noveltyContext(
	ctx context.Context,
	workRoot string,
	scan *db.Scan,
	skill *db.Skill,
) (*skillContextNovelty, error) {
	if skill.Name != revalidateSkillName || scan.FindingID == nil {
		return nil, nil
	}

	var finding db.Finding
	if err := w.DB.First(&finding, *scan.FindingID).Error; err != nil {
		return nil, fmt.Errorf("load finding for novelty check: %w", err)
	}
	if finding.Status.Closed() {
		return nil, nil
	}

	novelty := checkFindingNovelty(ctx, filepath.Join(workRoot, "src"), scan.Repository.IsLocal(), &finding, scan.Commit)
	now := w.now().UTC()
	if err := w.DB.Model(&db.Finding{}).Where("id = ?", finding.ID).Updates(map[string]any{
		"novelty":                novelty.State,
		"novelty_checked_commit": novelty.CheckedCommit,
		"novelty_checked_at":     &now,
	}).Error; err != nil {
		return nil, fmt.Errorf("persist finding novelty: %w", err)
	}
	return novelty, nil
}

func checkFindingNovelty(
	ctx context.Context,
	src string,
	local bool,
	finding *db.Finding,
	headCommit string,
) *skillContextNovelty {
	result := &skillContextNovelty{
		State:         db.FindingNoveltyNotChecked,
		ScannedCommit: strings.TrimSpace(finding.Commit),
		CheckedCommit: strings.TrimSpace(headCommit),
	}
	result.FindingFile = noveltyFindingPath(finding.SubPath, finding.Location)
	if result.FindingFile == "" {
		result.NotCheckedWhy = "finding location is not a repository-relative file"
		return result
	}
	if !validGitOID(result.ScannedCommit) || !validGitOID(result.CheckedCommit) {
		result.NotCheckedWhy = "scanned or checked commit is unavailable"
		return result
	}
	if !commitReachable(ctx, src, result.CheckedCommit) {
		result.NotCheckedWhy = noveltyUnavailableNoGit
		return result
	}
	if !commitReachable(ctx, src, result.ScannedCommit) {
		if local || fetchNoveltyHistory(ctx, src) != nil || !commitReachable(ctx, src, result.ScannedCommit) {
			result.NotCheckedWhy = "scanned commit is unavailable from repository history"
			return result
		}
	}
	if _, err := git(ctx, "-C", src, "merge-base", "--is-ancestor", result.ScannedCommit, result.CheckedCommit); err != nil {
		result.NotCheckedWhy = "scanned commit is not an ancestor of checked HEAD"
		return result
	}

	revisionRange := result.ScannedCommit + ".." + result.CheckedCommit
	logOutput, err := git(ctx, "-C", src, "log",
		fmt.Sprintf("--max-count=%d", noveltyLogMaxCommits),
		"--format=commit %H%nAuthorDate: %aI%nSubject: %s",
		"--patch", revisionRange, "--", result.FindingFile)
	if err != nil {
		result.NotCheckedWhy = "git history check failed"
		return result
	}
	if strings.TrimSpace(logOutput) == "" {
		result.State = db.FindingNoveltyUnfixed
		return result
	}

	result.State = db.FindingNoveltyUnclear
	result.FileChanged = true
	result.CommitLog, result.LogTruncated = truncateNoveltyLog(logOutput)
	return result
}

func noveltyFindingPath(subPath, location string) string {
	file := findingnorm.LocationFile(location)
	subPath = findingnorm.RepoPath(subPath)
	if !validNoveltyPath(file) || (subPath != "" && !validNoveltyPath(subPath)) {
		return ""
	}
	return path.Join(subPath, file)
}

func validNoveltyPath(p string) bool {
	return p != "" && p != "." && !strings.HasPrefix(p, "/") && !findingnorm.HasParentPathSegment(p)
}

func validGitOID(value string) bool {
	if len(value) < 7 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}

func fetchNoveltyHistory(ctx context.Context, src string) error {
	shallow, err := git(ctx, "-C", src, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return err
	}
	args := []string{"-C", src, "fetch", "--quiet"}
	if strings.TrimSpace(shallow) == "true" {
		args = append(args, "--unshallow")
	}
	args = append(args, "origin")
	_, err = git(ctx, args...)
	return err
}

func truncateNoveltyLog(logOutput string) (string, bool) {
	if len(logOutput) <= noveltyLogMaxBytes {
		return logOutput, false
	}
	return logOutput[:noveltyLogMaxBytes] + "\n[truncated]\n", true
}
