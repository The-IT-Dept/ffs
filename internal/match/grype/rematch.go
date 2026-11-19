package grype

import (
	"context"
	"fmt"
	"slices"

	"github.com/the-it-dept/ffs/internal/feeds/grypedb"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// Rematch re-matches the digests whose grype search keys include a changed package (or, for
// ecosystem "cpe", a changed CPE product). The Delta's scope is grype's matches on the digests it
// re-matched. Before Load it returns match.ErrNotReady.
func (m *Matcher) Rematch(ctx context.Context, changed []grypedb.PackageKey) (match.Delta, error) {
	if !m.loaded() {
		return match.Delta{}, match.ErrNotReady
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
		return match.Delta{}, fmt.Errorf("grype: digests for changed packages: %w", err)
	}
	return m.rematch(ctx, digests)
}

// RematchAll re-matches every image digest in use or matched before. An image catalogued before the
// first database loaded has no search keys yet, so the digests in use are needed as well.
func (m *Matcher) RematchAll(ctx context.Context) (match.Delta, error) {
	if !m.loaded() {
		return match.Delta{}, match.ErrNotReady
	}
	inUse, err := m.st.DigestsInUse(ctx)
	if err != nil {
		return match.Delta{}, fmt.Errorf("grype: digests in use: %w", err)
	}
	keyed, err := m.st.GrypeDigests(ctx)
	if err != nil {
		return match.Delta{}, fmt.Errorf("grype: matched digests: %w", err)
	}
	digests := slices.Concat(inUse, keyed)
	slices.Sort(digests)
	return m.rematch(ctx, slices.Compact(digests))
}

// rematch matches each digest that has a stored SBOM, with its current OSV matches as hints.
// Synthetic digests and digests without an SBOM are left out of the scope.
func (m *Matcher) rematch(ctx context.Context, digests []string) (match.Delta, error) {
	d := match.Delta{Scope: store.MatchScope{Source: model.SourceGrype}}
	for _, digest := range digests {
		if match.IsSynthetic(digest) {
			continue
		}
		sbom, ok, err := m.st.GetSBOM(ctx, digest)
		if err != nil {
			return match.Delta{}, fmt.Errorf("grype: SBOM of %s: %w", digest, err)
		}
		if !ok {
			continue
		}
		pkgs, err := m.st.PackagesForImage(ctx, digest)
		if err != nil {
			return match.Delta{}, fmt.Errorf("grype: packages of %s: %w", digest, err)
		}
		current, err := m.st.MatchesForDigests(ctx, []string{digest})
		if err != nil {
			return match.Delta{}, fmt.Errorf("grype: matches of %s: %w", digest, err)
		}
		hints := slices.DeleteFunc(current, func(mt model.Match) bool { return mt.Source != model.SourceOSV })
		ms, err := m.MatchImage(ctx, match.ImageInput{Digest: digest, SyftJSON: sbom, Packages: pkgs, Hints: hints})
		if err != nil {
			return match.Delta{}, err
		}
		d.Scope.Digests = append(d.Scope.Digests, digest)
		d.Matches = append(d.Matches, ms...)
	}
	return d, nil
}

func (m *Matcher) loaded() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.vp != nil
}
