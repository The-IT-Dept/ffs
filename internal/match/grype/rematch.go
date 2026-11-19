package grype

import (
	"context"
	"fmt"

	"github.com/the-it-dept/ffs/internal/feeds/grypedb"
	"github.com/the-it-dept/ffs/internal/match"
)

// Affected returns the sorted digests whose grype search keys include a changed package (or, for
// ecosystem "cpe", a changed CPE product): the digests a new DB's diff can change grype's matches
// on. The engine re-matches them one at a time. Before Load it returns match.ErrNotReady.
func (m *Matcher) Affected(ctx context.Context, changed []grypedb.PackageKey) ([]string, error) {
	if !m.loaded() {
		return nil, match.ErrNotReady
	}
	var pkgNames, cpeProducts []string
	for _, k := range changed {
		if k.Ecosystem == "cpe" {
			cpeProducts = append(cpeProducts, k.Name)
		} else {
			pkgNames = append(pkgNames, k.Name)
		}
	}
	digests, err := m.st.DigestsForGrypeKeys(ctx, pkgNames, cpeProducts)
	if err != nil {
		return nil, fmt.Errorf("grype: digests for changed packages: %w", err)
	}
	return digests, nil
}

func (m *Matcher) loaded() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.vp != nil
}
