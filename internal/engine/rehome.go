package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// rehomeWait is how long a recompute of an owner that Rehome moved findings to, and found absent, is
// skipped while the owner is not stored. After it the recompute proceeds, so an owner that never
// comes back resolves its findings.
const rehomeWait = 15 * time.Minute

// FindingMove moves the stored finding Fingerprint to the owner To on image repository ToRepo.
type FindingMove struct {
	Fingerprint string
	To          model.OwnerRef
	ToRepo      string
}

// Rehome is one cutover between owners: the owner to store, the findings to move and the owner keys
// to delete.
type Rehome struct {
	Upsert *model.Owner
	Moves  []FindingMove
	Drop   []string
}

// Rehome moves findings between owners without transitions (the ContainerRuntime cutover). Under the
// recompute lock, so no recompute reads a half-moved owner, it loads the moved findings (one that is
// gone, pruned meanwhile, is skipped), gives each the fingerprint of its advisory on To and ToRepo,
// and writes r through Store.Rehome in one transaction. It then queues the upserted owner, every
// dropped owner and each To owner that is stored. A To owner that is not stored yet is not queued,
// since recomputing it would resolve the moved findings: its recompute is skipped for rehomeWait
// unless OnOwnersChanged names it first. Nothing is queued when the write fails.
func (e *Engine) Rehome(ctx context.Context, r Rehome) error {
	if r.Upsert == nil && len(r.Moves) == 0 && len(r.Drop) == 0 {
		return nil
	}
	queue, wrote, err := e.rehomeLocked(ctx, r)
	if err != nil || !wrote {
		return err
	}
	e.enqueue(queue, model.TriggerInventoryChange)
	e.signal()
	return nil
}

// rehomeLocked is Rehome's read and write under the recompute lock. It returns the owner keys to
// queue and whether anything was written.
func (e *Engine) rehomeLocked(ctx context.Context, r Rehome) ([]string, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	fps := make([]string, len(r.Moves))
	for i, m := range r.Moves {
		fps[i] = m.Fingerprint
	}
	stored, err := e.o.Store.FindingsByFingerprint(ctx, fps)
	if err != nil {
		return nil, false, fmt.Errorf("engine: rehome: moved findings: %w", err)
	}
	var (
		moves []store.FindingMove
		tos   []string
		seen  = map[string]bool{}
	)
	upsertKey := ""
	if r.Upsert != nil {
		upsertKey = r.Upsert.Ref.Key()
	}
	for _, m := range r.Moves {
		f, ok := stored[m.Fingerprint]
		if !ok {
			continue
		}
		moves = append(moves, store.FindingMove{
			OldFingerprint: f.Fingerprint,
			NewFingerprint: model.FindingFingerprint(e.o.Config.ClusterName, m.To, m.ToRepo, f.AdvisoryID),
			Owner:          m.To,
			ImageRepo:      m.ToRepo,
		})
		if k := m.To.Key(); k != upsertKey && !seen[k] {
			seen[k] = true
			tos = append(tos, k)
		}
	}
	if r.Upsert == nil && len(moves) == 0 && len(r.Drop) == 0 {
		return nil, false, nil
	}
	if err := e.o.Store.Rehome(ctx, r.Upsert, moves, r.Drop); err != nil {
		return nil, false, fmt.Errorf("engine: rehome: %w", err)
	}
	var queue []string
	if upsertKey != "" {
		queue = append(queue, upsertKey)
	}
	queue = append(queue, r.Drop...)
	for _, k := range tos {
		_, ok, err := e.o.Store.GetOwner(ctx, k)
		if ok {
			queue = append(queue, k)
			continue
		}
		e.qmu.Lock()
		e.awaiting[k] = e.now()
		e.qmu.Unlock()
		if err != nil {
			// The findings have moved, so the write is not undone. The owner is awaited and queued: its
			// recompute looks it up again and is skipped while it is absent.
			e.o.Log.Error(err, "reading a re-homed owner failed; awaiting it", "owner", k)
			queue = append(queue, k)
		}
	}
	return queue, true, nil
}

// awaited reports whether the recompute of key should be skipped because Rehome moved findings to it
// while it was absent, less than rehomeWait before now, and it is still not stored. An expired entry,
// or one whose owner is now stored, is cleared.
func (e *Engine) awaited(ctx context.Context, key string, now time.Time) (bool, error) {
	e.qmu.Lock()
	at, ok := e.awaiting[key]
	if ok && now.Sub(at) >= rehomeWait {
		delete(e.awaiting, key)
		ok = false
	}
	e.qmu.Unlock()
	if !ok {
		return false, nil
	}
	_, stored, err := e.o.Store.GetOwner(ctx, key)
	if err != nil {
		return false, fmt.Errorf("owner: %w", err)
	}
	if stored {
		e.qmu.Lock()
		delete(e.awaiting, key)
		e.qmu.Unlock()
		return false, nil
	}
	return true, nil
}
