package engine

import (
	"context"
	"fmt"
	"slices"

	"github.com/the-it-dept/ffs/internal/findings"
	"github.com/the-it-dept/ffs/internal/model"
)

// ScoreMatches returns the findings owner would have on repo if it ran the digests of ms, which are
// an upgrade candidate's matches (MatchCandidate), with the owner's own context: its exposure,
// privilege and service account, the active exceptions and the Grype DB builds. The owner's
// containers on repo are replaced by one per distinct digest of ms; the other containers stay, as
// they count towards the owner's context. Nothing is written and the recompute lock is not taken.
func (e *Engine) ScoreMatches(ctx context.Context, owner model.Owner, repo string, ms []model.Match) ([]model.Finding, error) {
	var digests, ids []string
	for _, m := range ms {
		if !slices.Contains(digests, m.ImageDigest) {
			digests = append(digests, m.ImageDigest)
		}
		if !slices.Contains(ids, m.AdvisoryID) {
			ids = append(ids, m.AdvisoryID)
		}
	}

	template := model.ContainerUse{Name: repo, Kind: model.ContainerRegular, Repo: repo}
	if i := slices.IndexFunc(owner.Containers, func(c model.ContainerUse) bool { return c.Repo == repo }); i >= 0 {
		template = owner.Containers[i]
	}
	o := owner
	o.Containers = slices.DeleteFunc(slices.Clone(owner.Containers), func(c model.ContainerUse) bool { return c.Repo == repo })
	for _, d := range digests {
		c := template
		c.Digest, c.Platform = d, ""
		o.Containers = append(o.Containers, c)
	}

	pkgs := map[string]model.Package{}
	users := map[string]string{}
	for i, c := range o.Containers {
		if c.Digest == "" {
			continue
		}
		img, ok, err := e.o.Store.GetImage(ctx, c.Digest)
		if err != nil {
			return nil, fmt.Errorf("engine: image %s: %w", c.Digest, err)
		}
		if !ok || img.Status != model.ImageCatalogued {
			continue
		}
		users[c.Digest] = img.ConfigUser
		if c.Repo != repo {
			continue
		}
		o.Containers[i].Platform = img.Platform
		ps, err := e.o.Store.PackagesForImage(ctx, c.Digest)
		if err != nil {
			return nil, fmt.Errorf("engine: packages of %s: %w", c.Digest, err)
		}
		for _, p := range ps {
			pkgs[p.ID] = p
		}
	}

	advs, err := e.o.Store.Advisories(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("engine: advisories: %w", err)
	}
	builds, err := e.o.Store.GrypeDBBuilds(ctx)
	if err != nil {
		return nil, fmt.Errorf("engine: grype DB builds: %w", err)
	}
	var rules []findings.ExceptionRule
	if e.o.Exceptions != nil {
		if rules, err = e.o.Exceptions.ExceptionRules(ctx); err != nil {
			return nil, fmt.Errorf("engine: exception rules: %w", err)
		}
	}
	built := findings.Build(findings.BuildInput{
		Cluster:        e.o.Config.ClusterName,
		Owner:          o,
		Matches:        ms,
		Packages:       pkgs,
		Advisories:     advs,
		Exceptions:     rules,
		GrypeDBBuilds:  builds,
		ImageUsers:     users,
		Now:            e.now(),
		PriorityConfig: e.o.Config.Priority,
	})
	return slices.DeleteFunc(built, func(f model.Finding) bool { return f.ImageRepo != repo }), nil
}
