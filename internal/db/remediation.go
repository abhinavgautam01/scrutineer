package db

import "gorm.io/gorm"

const (
	RemediationVerificationIncomplete = "verification_incomplete"
	RemediationVerifiedSecure         = "verified_secure"
)

// LatestRemediationAttempt returns the newest gated patch for a finding.
func LatestRemediationAttempt(gdb *gorm.DB, findingID uint) (*RemediationAttempt, error) {
	var row RemediationAttempt
	result := gdb.Where("finding_id = ?", findingID).Order("attempt desc").Limit(1).Find(&row)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, nil
	}
	return &row, nil
}

// LatestRemediationValidation returns the newest re-attack result for an
// immutable patch attempt. Missing validation is normal and means the patch
// remains verification_incomplete.
func LatestRemediationValidation(gdb *gorm.DB, attemptID uint) (*RemediationValidation, error) {
	var row RemediationValidation
	result := gdb.Where("remediation_attempt_id = ?", attemptID).Order("id desc").Limit(1).Find(&row)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, nil
	}
	return &row, nil
}

// RemediationPatchStatus derives the current gate from immutable records.
// It deliberately fails closed: only a complete, successful re-attack can
// produce verified_secure.
func RemediationPatchStatus(validation *RemediationValidation) string {
	if validation == nil {
		return RemediationVerificationIncomplete
	}
	if validation.RootCauseStatus == ReattackBypassedPatch {
		return ReattackBypassedPatch
	}
	if validation.RootCauseStatus == ReattackFailedToBypass &&
		validation.ValidVariants >= 3 && validation.BenignControlPassed {
		return RemediationVerifiedSecure
	}
	return RemediationVerificationIncomplete
}
