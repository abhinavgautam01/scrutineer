package worker

import (
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/threatmodel"
	"scrutineer/internal/verification"
)

func TestCalibrateControlSeverity(t *testing.T) {
	authz := threatmodel.Control{ID: "authz", Kind: threatmodel.KindAuthorization}
	sandbox := threatmodel.Control{ID: "sandbox", Kind: threatmodel.KindSandbox}
	unknown := threatmodel.Control{ID: "custom", Kind: "hardware-boundary"}

	for _, tc := range []struct {
		name           string
		controls       *skillContextControls
		gate           *verification.ControlBypass
		wantCaps       int
		wantIncomplete bool
	}{
		{
			name:     "held authorization produces cap",
			controls: calibrationControls(authz), gate: calibrationGate("authz", "held"),
			wantCaps: 1,
		},
		{
			name:     "held sandbox produces cap",
			controls: calibrationControls(sandbox), gate: calibrationGate("sandbox", "held"),
			wantCaps: 1,
		},
		{
			name:     "bypassed control does not cap",
			controls: calibrationControls(authz), gate: calibrationGate("authz", "bypassed"),
		},
		{
			name:     "unresolved control is incomplete",
			controls: calibrationControls(authz), gate: calibrationGate("authz", "unresolved"),
			wantIncomplete: true,
		},
		{
			name:     "unknown held control is incomplete",
			controls: calibrationControls(unknown), gate: calibrationGate("custom", "held"),
			wantIncomplete: true,
		},
		{
			name:           "unavailable controls are incomplete",
			controls:       &skillContextControls{UnavailableWhy: "model unavailable"},
			gate:           &verification.ControlBypass{UnavailableReason: "model unavailable"},
			wantIncomplete: true,
		},
		{name: "no controls is authoritative"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := calibrateControlSeverity(tc.controls, tc.gate)
			if !got.Evaluated || len(got.Caps) != tc.wantCaps || got.Incomplete != tc.wantIncomplete {
				t.Fatalf("calibration = %+v, want caps=%d incomplete=%t", got, tc.wantCaps, tc.wantIncomplete)
			}
		})
	}
}

func TestParseVerifyRemovesInactiveSeverityCapReasons(t *testing.T) {
	for _, severity := range []string{"Low", "UNKNOWN"} {
		t.Run(severity, func(t *testing.T) {
			testParseVerifyRemovesInactiveSeverityCapReasons(t, severity)
		})
	}
}

func testParseVerifyRemovesInactiveSeverityCapReasons(t *testing.T, severity string) {
	t.Helper()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "severity-cap-inactive.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x", ThreatModel: controlsModel}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	prior := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone}
	if err := gdb.Create(&prior).Error; err != nil {
		t.Fatal(err)
	}
	finding := db.Finding{
		ScanID: prior.ID, RepositoryID: repo.ID, Location: "internal/web/server.go:120",
		Title: "cross-tenant read", Severity: severity, Status: db.FindingNew,
	}
	if err := gdb.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Repository: repo, FindingID: new(finding.ID), SkillName: verifySkillName}
	if err := gdb.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	report := verificationReport(t, "inconclusive", func(report *verification.Report) {
		report.Criteria.ControlBypass = calibrationGate("web-authz", "held")
	})
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := w.parseVerifyOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var got db.Finding
	if err := gdb.First(&got, finding.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Severity != severity || got.SeverityCaps != "" {
		t.Fatalf("finding severity = %q caps = %q", got.Severity, got.SeverityCaps)
	}
	if got.SeverityCalibrationIncomplete != (severity == "UNKNOWN") {
		t.Fatalf("calibration incomplete = %t", got.SeverityCalibrationIncomplete)
	}
	notes := findingNotes(gdb, finding.ID)
	if len(notes) != 1 || strings.Contains(notes[0].Body, "severity cap:") {
		t.Fatalf("verify notes = %+v", notes)
	}
}

func TestParseVerifyRestoresSeverityWhenControlCapClears(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "severity-cap-clear.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x", ThreatModel: controlsModel}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	prior := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone}
	if err := gdb.Create(&prior).Error; err != nil {
		t.Fatal(err)
	}
	finding := db.Finding{
		ScanID: prior.ID, RepositoryID: repo.ID, Location: "internal/web/server.go:120",
		Title: "cross-tenant read", Severity: "Critical", Status: db.FindingNew,
	}
	if err := gdb.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	heldScan := db.Scan{RepositoryID: repo.ID, Repository: repo, FindingID: new(finding.ID), SkillName: verifySkillName}
	if err := gdb.Create(&heldScan).Error; err != nil {
		t.Fatal(err)
	}
	heldReport := verificationReport(t, "inconclusive", func(report *verification.Report) {
		report.Criteria.ControlBypass = calibrationGate("web-authz", "held")
	})
	if err := w.parseVerifyOutput(&heldScan, heldReport, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	bypassedScan := db.Scan{RepositoryID: repo.ID, Repository: repo, FindingID: new(finding.ID), SkillName: verifySkillName}
	if err := gdb.Create(&bypassedScan).Error; err != nil {
		t.Fatal(err)
	}
	bypassedReport := verificationReport(t, "confirmed", func(report *verification.Report) {
		report.Criteria.ControlBypass = calibrationGate("web-authz", "bypassed")
	})
	if err := w.parseVerifyOutput(&bypassedScan, bypassedReport, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var got db.Finding
	if err := gdb.First(&got, finding.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Severity != "Critical" || got.SeverityCaps != "" || got.SeverityCalibrationIncomplete {
		t.Fatalf("finding calibration = severity %q caps %q incomplete %t", got.Severity, got.SeverityCaps, got.SeverityCalibrationIncomplete)
	}
	var history []db.FindingHistory
	if err := gdb.Where("finding_id = ? AND field = ?", finding.ID, "severity").Order("id").Find(&history).Error; err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 || history[1].OldValue != "Medium" || history[1].NewValue != "Critical" {
		t.Fatalf("severity history = %+v", history)
	}
}

func TestParseVerifyAppliesControlSeverityCapAtomically(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "severity-cap.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x", ThreatModel: controlsModel}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	prior := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone}
	if err := gdb.Create(&prior).Error; err != nil {
		t.Fatal(err)
	}
	finding := db.Finding{
		ScanID: prior.ID, RepositoryID: repo.ID, Location: "internal/web/server.go:120",
		Title: "cross-tenant read", Severity: "Critical", Status: db.FindingNew,
	}
	if err := gdb.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Repository: repo, FindingID: new(finding.ID), SkillName: verifySkillName}
	if err := gdb.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	report := verificationReport(t, "inconclusive", func(report *verification.Report) {
		report.Criteria.ControlBypass = calibrationGate("web-authz", "held")
	})
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := w.parseVerifyOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var got db.Finding
	if err := gdb.First(&got, finding.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Severity != "Medium" || got.SeverityCalibrationIncomplete || len(got.SeverityCapList()) != 1 {
		t.Fatalf("finding calibration = severity %q caps %v incomplete %t", got.Severity, got.SeverityCapList(), got.SeverityCalibrationIncomplete)
	}
	if !strings.Contains(got.SeverityCaps, `authorization control "web-authz" held`) {
		t.Fatalf("severity caps = %q", got.SeverityCaps)
	}

	var history []db.FindingHistory
	if err := gdb.Where("finding_id = ? AND field = ?", finding.ID, "severity").Find(&history).Error; err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].OldValue != "Critical" || history[0].NewValue != "Medium" || history[0].Source != db.SourceSystem || history[0].By != verifySkillName {
		t.Fatalf("severity history = %+v", history)
	}
	notes := findingNotes(gdb, finding.ID)
	if len(notes) != 1 || !strings.Contains(notes[0].Body, "severity cap: authorization control") {
		t.Fatalf("verify notes = %+v", notes)
	}

	if err := w.parseVerifyOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var historyCount int64
	if err := gdb.Model(&db.FindingHistory{}).Where("finding_id = ? AND field = ?", finding.ID, "severity").Count(&historyCount).Error; err != nil {
		t.Fatal(err)
	}
	if historyCount != 1 || len(findingNotes(gdb, finding.ID)) != 1 {
		t.Fatalf("retry duplicated severity history or note: history=%d notes=%d", historyCount, len(findingNotes(gdb, finding.ID)))
	}
}

func TestParseVerifyUngradedReportPreservesSeverityCalibration(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "severity-cap-ungraded.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x", ThreatModel: controlsModel}
	gdb.Create(&repo)
	prior := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone}
	gdb.Create(&prior)
	finding := db.Finding{
		ScanID: prior.ID, RepositoryID: repo.ID, Location: "internal/web/server.go:120", Title: "x",
		Severity: "Medium", SeverityCaps: "prior authoritative cap", SeverityCalibrationIncomplete: true,
	}
	gdb.Create(&finding)
	scan := db.Scan{RepositoryID: repo.ID, Repository: repo, FindingID: new(finding.ID), SkillName: verifySkillName}
	gdb.Create(&scan)
	report := verificationReport(t, "confirmed", func(report *verification.Report) {
		report.Criteria.ControlBypass = &verification.ControlBypass{MatchedControls: []string{}, Assessments: []verification.ControlAssessment{}}
	})
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := w.parseVerifyOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var got db.Finding
	gdb.First(&got, finding.ID)
	if got.Severity != "Medium" || got.SeverityCaps != "prior authoritative cap" || !got.SeverityCalibrationIncomplete {
		t.Fatalf("ungraded report changed prior calibration: %+v", got)
	}
	var row db.FindingVerification
	gdb.Where("finding_id = ?", finding.ID).First(&row)
	if row.Score != nil {
		t.Fatalf("ungraded verification score = %v, want nil", row.Score)
	}
}

func TestRecordVerifyOutputAppliesCapToLatestSeverity(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "severity-cap-latest.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	prior := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone}
	gdb.Create(&prior)
	finding := db.Finding{ScanID: prior.ID, RepositoryID: repo.ID, Title: "x", Severity: "Critical"}
	gdb.Create(&finding)
	scan := db.Scan{RepositoryID: repo.ID, FindingID: new(finding.ID), SkillName: verifySkillName}
	gdb.Create(&scan)

	report := verificationReport(t, "inconclusive", func(report *verification.Report) {
		report.Criteria.ControlBypass = calibrationGate("web-authz", "held")
	})
	result, rubric, score, gradingError, err := decodeVerifyOutput(report)
	if err != nil {
		t.Fatal(err)
	}
	calibration := calibrateControlSeverity(
		calibrationControls(threatmodel.Control{ID: "web-authz", Kind: threatmodel.KindAuthorization}),
		rubric.Criteria.ControlBypass,
	)

	staleFinding := finding
	if err := gdb.Model(&db.Finding{}).Where("id = ?", finding.ID).Update("severity", "Low").Error; err != nil {
		t.Fatal(err)
	}
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := w.recordVerifyOutput(&scan, staleFinding, result, report, rubric, score, gradingError, "", calibration); err != nil {
		t.Fatal(err)
	}

	var got db.Finding
	gdb.First(&got, finding.ID)
	if got.Severity != "Low" {
		t.Fatalf("latest lower severity was raised to %q", got.Severity)
	}
	var severityHistory int64
	gdb.Model(&db.FindingHistory{}).Where("finding_id = ? AND field = ?", finding.ID, "severity").Count(&severityHistory)
	if severityHistory != 0 {
		t.Fatalf("severity history rows = %d, want 0", severityHistory)
	}
}

func TestParseVerifySeverityCalibrationRollsBackWithVerification(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "severity-cap-rollback.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x", ThreatModel: controlsModel}
	gdb.Create(&repo)
	prior := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone}
	gdb.Create(&prior)
	finding := db.Finding{
		ScanID: prior.ID, RepositoryID: repo.ID, Location: "internal/web/server.go:120",
		Title: "cross-tenant read", Severity: "Critical", Status: db.FindingNew,
	}
	gdb.Create(&finding)
	scan := db.Scan{RepositoryID: repo.ID, Repository: repo, FindingID: new(finding.ID), SkillName: verifySkillName}
	gdb.Create(&scan)
	report := verificationReport(t, "inconclusive", func(report *verification.Report) {
		report.Criteria.ControlBypass = calibrationGate("web-authz", "held")
	})

	const callbackName = "test:fail_verification_insert"
	if err := gdb.Callback().Create().Before("gorm:create").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement.Table == "finding_verifications" {
			_ = tx.AddError(errors.New("injected verification insert failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gdb.Callback().Create().Remove(callbackName) }()

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := w.parseVerifyOutput(&scan, report, func(Event) {}); err == nil || !strings.Contains(err.Error(), "injected verification insert failure") {
		t.Fatalf("parseVerifyOutput() error = %v, want injected failure", err)
	}

	var got db.Finding
	gdb.First(&got, finding.ID)
	if got.Severity != "Critical" || got.SeverityCaps != "" || got.SeverityCalibrationIncomplete {
		t.Fatalf("failed verification left calibration changes behind: %+v", got)
	}
	var historyCount, verificationCount, noteCount int64
	gdb.Model(&db.FindingHistory{}).Where("finding_id = ?", finding.ID).Count(&historyCount)
	gdb.Model(&db.FindingVerification{}).Where("finding_id = ?", finding.ID).Count(&verificationCount)
	gdb.Model(&db.FindingNote{}).Where("finding_id = ?", finding.ID).Count(&noteCount)
	if historyCount != 0 || verificationCount != 0 || noteCount != 0 {
		t.Fatalf("failed verification persisted partial rows: history=%d verifications=%d notes=%d", historyCount, verificationCount, noteCount)
	}
}

func calibrationControls(controls ...threatmodel.Control) *skillContextControls {
	return &skillContextControls{Matched: controls, IDs: threatmodel.IDs(controls)}
}

func calibrationGate(id, disposition string) *verification.ControlBypass {
	return &verification.ControlBypass{
		MatchedControls: []string{id},
		Assessments:     []verification.ControlAssessment{{ControlID: id, Disposition: disposition, Evidence: "verified evidence"}},
	}
}
