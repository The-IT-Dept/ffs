// Package eol evaluates whether a product version has reached end of life, from the endoflife.date
// cycles the eol feed stores (spec §6.7).
package eol

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// warnWithin is how far ahead of an end-of-life date Text starts to mention it.
const warnWithin = 90 * 24 * time.Hour

const dateFmt = "2006-01-02"

// Status is the lifecycle position of one product version.
type Status struct {
	Product, Cycle string
	EOLDate        *time.Time
	IsEOL          bool
	Latest         string
	Note           string // override products with no dated lifecycle
}

// Evaluator answers lifecycle questions from an in-memory snapshot of the stored cycles.
type Evaluator struct {
	st  *store.Store
	now func() time.Time

	mu     sync.RWMutex
	cycles map[string][]store.EOLCycle
}

// New returns an Evaluator with an empty snapshot; call Reload to load the stored cycles.
func New(st *store.Store, now func() time.Time) *Evaluator {
	return &Evaluator{st: st, now: now, cycles: map[string][]store.EOLCycle{}}
}

// Reload replaces the snapshot with the stored cycles.
func (e *Evaluator) Reload(ctx context.Context) error {
	all, err := e.st.ListEOL(ctx)
	if err != nil {
		return err
	}
	m := map[string][]store.EOLCycle{}
	for _, c := range all {
		m[c.Product] = append(m[c.Product], c)
	}
	e.mu.Lock()
	e.cycles = m
	e.mu.Unlock()
	return nil
}

// Evaluate returns the lifecycle status of product at version; ok is false when the product or its
// cycle is unknown.
func (e *Evaluator) Evaluate(product, version string) (Status, bool) {
	ov := overrides[product]
	if ov.use == "" && ov.note != "" {
		cycle := "rolling"
		if !ov.rolling {
			cycle = firstTwo(trimVersion(version))
		}
		return Status{Product: product, Cycle: cycle, Note: ov.note}, true
	}
	source := product
	if ov.use != "" {
		source = ov.use
	}
	e.mu.RLock()
	cs := e.cycles[source]
	e.mu.RUnlock()
	byName := make(map[string]store.EOLCycle, len(cs))
	for _, c := range cs {
		byName[c.Cycle] = c
	}
	v := trimVersion(version)
	for v != "" {
		if c, ok := byName[v]; ok {
			return e.status(product, c), true
		}
		i := strings.LastIndex(v, ".")
		if i < 0 {
			break
		}
		v = v[:i]
	}
	return Status{}, false
}

func (e *Evaluator) status(product string, c store.EOLCycle) Status {
	isEOL := c.IsEOL || (c.EOLDate != nil && !e.now().Before(*c.EOLDate))
	return Status{Product: product, Cycle: c.Cycle, EOLDate: c.EOLDate, IsEOL: isEOL, Latest: c.Latest}
}

func trimVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	return strings.TrimPrefix(v, "go")
}

func firstTwo(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) > 2 {
		parts = parts[:2]
	}
	return strings.Join(parts, ".")
}

// ImageEOL evaluates an image's distro and language runtimes, once per product cycle.
func (e *Evaluator) ImageEOL(repo string, pkgs []model.Package) []Status {
	var pvs []ProductVersion
	for _, p := range pkgs {
		if p.Distro != nil {
			if pv, ok := DistroProduct(p.Distro, repo); ok {
				pvs = append(pvs, pv)
			}
			break
		}
	}
	pvs = append(pvs, RuntimeProducts(pkgs)...)
	var out []Status
	seen := map[[2]string]bool{}
	for _, pv := range pvs {
		s, ok := e.Evaluate(pv.Product, pv.Version)
		if !ok || seen[[2]string{s.Product, s.Cycle}] {
			continue
		}
		seen[[2]string{s.Product, s.Cycle}] = true
		out = append(out, s)
	}
	return out
}

// Text describes s as a sentence fragment: "debian 10 reached end of life 2024-06-30", or
// "containerd 2.0 reaches end of life 2027-01-15" within warnWithin of the date. It is empty when
// there is nothing to report.
func Text(s Status, now time.Time) string {
	switch {
	case s.IsEOL && s.EOLDate != nil:
		return fmt.Sprintf("%s %s reached end of life %s", s.Product, s.Cycle, s.EOLDate.Format(dateFmt))
	case s.IsEOL:
		return fmt.Sprintf("%s %s reached end of life", s.Product, s.Cycle)
	case s.EOLDate != nil && s.EOLDate.Sub(now) <= warnWithin:
		return fmt.Sprintf("%s %s reaches end of life %s", s.Product, s.Cycle, s.EOLDate.Format(dateFmt))
	}
	return ""
}

// JoinText joins the non-empty Texts of ss with "; ".
func JoinText(ss []Status, now time.Time) string {
	var parts []string
	for _, s := range ss {
		if t := Text(s, now); t != "" {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, "; ")
}
