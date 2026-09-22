package worker

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

const backendProbeTimeout = 2 * time.Minute
const backendPreflightCacheLimit = 256

// BackendPreflightCache is process-local. A restart intentionally re-probes;
// persisted receipts are provenance, not authority to trust an old credential.
type BackendPreflightCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	salt    [32]byte
	entries map[string]*backendProbeEntry
	now     func() time.Time
}

type backendProbeEntry struct {
	done   chan struct{}
	result coverage.BackendProbe
	err    error
}

func NewBackendPreflightCache(ttl time.Duration) (*BackendPreflightCache, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("backend preflight TTL must be positive")
	}
	c := &BackendPreflightCache{ttl: ttl, entries: make(map[string]*backendProbeEntry), now: time.Now}
	if _, err := rand.Read(c.salt[:]); err != nil {
		return nil, err
	}
	return c, nil
}

// Inputs can contain credentials. Only a process-keyed digest is retained.
func (c *BackendPreflightCache) key(config []byte) string {
	h := hmac.New(sha256.New, c.salt[:])
	_, _ = h.Write(config)
	return hex.EncodeToString(h.Sum(nil))
}

func (c *BackendPreflightCache) check(ctx context.Context, config []byte, run func(context.Context) coverage.BackendProbe) (coverage.BackendProbe, error) {
	key := c.key(config)
	for {
		if err := ctx.Err(); err != nil {
			return coverage.BackendProbe{}, err
		}
		c.mu.Lock()
		entry, ok := c.entries[key]
		if ok {
			select {
			case <-entry.done:
				if entry.err == nil && c.now().Before(entry.result.ExpiresAt) {
					result := entry.result
					result.Reused = true
					c.mu.Unlock()
					return result, nil
				}
				delete(c.entries, key)
			default:
				c.mu.Unlock()
				select {
				case <-ctx.Done():
					return coverage.BackendProbe{}, ctx.Err()
				case <-entry.done:
					continue
				}
			}
		}
		c.prune()
		entry = &backendProbeEntry{done: make(chan struct{})}
		c.entries[key] = entry
		c.mu.Unlock()
		probeCtx, cancel := context.WithTimeout(ctx, backendProbeTimeout)
		result := run(probeCtx)
		if probeCtx.Err() != nil {
			result.Status, result.Error = coverage.PreflightBlocked, "backend probe canceled or timed out"
		}
		cancel()
		result.ProbeID = randomProbeID()
		result.ConfigHash = key
		result.CheckedAt = c.now().UTC()
		result.ExpiresAt = result.CheckedAt.Add(c.ttl)
		c.mu.Lock()
		entry.result = result
		entry.err = ctx.Err()
		close(entry.done)
		c.mu.Unlock()
		return result, entry.err
	}
}

// Called under mu. Never evict in-flight probes: that would defeat deduplication.
func (c *BackendPreflightCache) prune() {
	var oldest string
	var expiry time.Time
	for key, entry := range c.entries {
		select {
		case <-entry.done:
			if !c.now().Before(entry.result.ExpiresAt) {
				delete(c.entries, key)
				continue
			}
			if oldest == "" || entry.result.ExpiresAt.Before(expiry) {
				oldest, expiry = key, entry.result.ExpiresAt
			}
		default:
		}
	}
	if len(c.entries) >= backendPreflightCacheLimit && oldest != "" {
		delete(c.entries, oldest)
	}
}

func randomProbeID() string {
	var id [16]byte
	_, _ = rand.Read(id[:])
	return hex.EncodeToString(id[:])
}

func (w *Worker) configureBackendPreflight(ctx context.Context, scan *db.Scan, sj *SkillJob, document skillContext) {
	if w.BackendPreflight == nil {
		return
	}
	sj.checkBackend = func(runCtx context.Context, config []byte, run func(context.Context) coverage.BackendProbe) error {
		result, err := w.BackendPreflight.check(runCtx, config, run)
		if err != nil {
			return err
		}
		preflight, err := w.recordBackendPreflight(ctx, scan, result)
		if err != nil {
			return err
		}
		document.Scrutineer.Preflight = preflight
		if err := writeSkillContext(sj.WorkRoot, sj.SkillDir, document); err != nil {
			return err
		}
		if result.Status != coverage.PreflightReady {
			return fmt.Errorf("backend preflight blocked: %s", result.Error)
		}
		return nil
	}
}

func (w *Worker) recordBackendPreflight(ctx context.Context, scan *db.Scan, result coverage.BackendProbe) (*coverage.Preflight, error) {
	rec, ok := coverage.Parse(scan.Coverage)
	if !ok && scan.Coverage != "" {
		return nil, fmt.Errorf("stored coverage did not decode")
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	receipt := db.ScanPreflightReceipt{ScanID: scan.ID, ProbeID: result.ProbeID, RecipeSHA256: textDigest(scan.Recipe), Report: string(raw)}
	updated := *scan
	if err := w.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "scan_id"}, {Name: "probe_id"}}, DoNothing: true}).Create(&receipt).Error; err != nil {
			return err
		}
		if err := tx.Where("scan_id = ? AND probe_id = ?", scan.ID, result.ProbeID).First(&receipt).Error; err != nil {
			return err
		}
		result.ReceiptID = receipt.ID
		if rec.Preflight == nil {
			rec.Preflight = &coverage.Preflight{Status: coverage.PreflightReady, Missing: []string{}}
		}
		rec.Preflight.Backend = &result
		if rec.Completeness == "" {
			rec.Completeness = coverage.CompletenessUnknown
		}
		setCoverage(&updated, rec)
		update := tx.Model(&db.Scan{}).Where("id = ?", scan.ID).Updates(map[string]any{"coverage": updated.Coverage, "completeness": updated.Completeness})
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected != 1 {
			return fmt.Errorf("scan no longer exists")
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("record backend preflight: %w", err)
	}
	scan.Coverage, scan.Completeness = updated.Coverage, updated.Completeness
	return rec.Preflight, nil
}
