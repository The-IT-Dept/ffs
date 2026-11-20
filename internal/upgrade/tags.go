// Package upgrade finds upgrade candidates for container images.
package upgrade

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
)

// TagVersion is a docker tag parsed into comparable parts.
type TagVersion struct {
	Tag      string // original tag
	Prefix   string // "v" or "" (always "" under a Pattern rule)
	Release  []int  // numeric components; precision preserved ("1.25" has len 2)
	Pre      string // letters+digits glued to the release ("rc2" in "19rc2"); non-empty = unstable
	Revision int    // -rN, -security-NN; 0 when absent
	Suffix   string // compatibility key: text after the first '-'
	Date     bool   // all-digit date tag: 20241010, 202410101200, 20241010120000
}

var (
	genericTag = regexp.MustCompile(`^(v?)(\d+(?:\.\d+)*)([a-z]+\d*)?(?:-(.+))?$`)
	shaLike    = regexp.MustCompile(`^(?:sha-)?[0-9a-f]{7,40}$`)
	dateTag    = regexp.MustCompile(`^(?:19|20)(?:\d{6}|\d{10}|\d{12})$`)
)

// ParseTag parses a tag with the generic Docker-tag pattern.
func ParseTag(tag string) (TagVersion, bool) {
	if shaLike.MatchString(tag) && strings.ContainsAny(tag, "abcdef") {
		return TagVersion{}, false
	}
	m := genericTag.FindStringSubmatch(tag)
	if m == nil {
		return TagVersion{}, false
	}
	tv := TagVersion{Tag: tag, Prefix: m[1], Pre: m[3], Suffix: m[4]}
	for _, part := range strings.Split(m[2], ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return TagVersion{}, false
		}
		tv.Release = append(tv.Release, n)
	}
	tv.Date = len(tv.Release) == 1 && dateTag.MatchString(m[2])
	return tv, true
}

func digits(v TagVersion) int { return len(strconv.Itoa(v.Release[0])) }

// Compatible reports whether two tags belong to the same tag line (prefix, suffix, precision, date-ness).
func Compatible(a, b TagVersion) bool {
	if a.Prefix != b.Prefix || a.Suffix != b.Suffix || len(a.Release) != len(b.Release) || a.Date != b.Date {
		return false
	}
	return !a.Date || digits(a) == digits(b)
}

func releaseAt(v TagVersion, i int) int {
	if i < len(v.Release) {
		return v.Release[i]
	}
	return 0
}

// firstDiff returns the first differing release index, or -1 when releases are equal.
func firstDiff(a, b TagVersion) int {
	n := max(len(a.Release), len(b.Release))
	for i := range n {
		if releaseAt(a, i) != releaseAt(b, i) {
			return i
		}
	}
	return -1
}

// Compare orders by Release, then Pre (stable > any pre), then Revision.
func Compare(a, b TagVersion) int {
	if i := firstDiff(a, b); i >= 0 {
		if releaseAt(a, i) < releaseAt(b, i) {
			return -1
		}
		return 1
	}
	if a.Pre != b.Pre {
		switch {
		case a.Pre == "":
			return 1
		case b.Pre == "":
			return -1
		}
		return strings.Compare(a.Pre, b.Pre)
	}
	switch {
	case a.Revision < b.Revision:
		return -1
	case a.Revision > b.Revision:
		return 1
	}
	return 0
}

// TierBetween classifies the step from cur to cand.
func TierBetween(cur, cand TagVersion) model.Tier {
	i := firstDiff(cur, cand)
	switch {
	case i < 0:
		if cur.Pre != cand.Pre || cur.Revision != cand.Revision {
			return model.TierPatch
		}
		return model.TierRefresh
	case cand.Date || cur.Date:
		return model.TierPatch
	case i == 0:
		return model.TierMajor
	case i == 1:
		return model.TierMinor
	}
	return model.TierPatch
}

// channelTags are floating tags that name a release channel rather than a variant: they carry no
// compatibility key of their own.
var channelTags = map[string]bool{"latest": true, "stable": true, "mainline": true, "lts": true, "current": true}

// FloatingVersion derives a version for a floating tag from its version annotation. The
// compatibility key (spec §6.7.1) is the annotation's own suffix when it has one ("7.4.1-alpine"),
// else the text after the tag's first '-' ("stable-alpine" → "alpine"), else the whole tag when it
// is a variant rather than a channel ("alpine", "slim"), so a variant is never offered another
// base image's tags.
func FloatingVersion(tag, annotation string) (TagVersion, bool) {
	v, ok := ParseTag(annotation)
	if !ok {
		return TagVersion{}, false
	}
	v.Tag = tag
	if v.Suffix != "" {
		return v, true
	}
	if _, after, found := strings.Cut(tag, "-"); found {
		v.Suffix = after
	} else if tag != "" && !channelTags[tag] {
		v.Suffix = tag
	}
	return v, true
}

// Parser parses tags using config overrides, then built-in quirks, then the generic pattern.
type Parser struct {
	overrides *ruleSet
	quirks    *ruleSet
}

// NewParser compiles the overrides; an invalid pattern returns an error naming its key.
func NewParser(overrides map[string]config.TagOverride) (*Parser, error) {
	o, err := newRuleSet(overrideRules(overrides))
	if err != nil {
		return nil, err
	}
	q, err := newRuleSet(quirks)
	if err != nil {
		return nil, err
	}
	return &Parser{overrides: o, quirks: q}, nil
}

// Parse parses tag for repo (a normalised repo name).
func (p *Parser) Parse(repo, tag string) (TagVersion, bool) {
	if r := p.overrides.lookup(repo); r != nil {
		return r.parse(tag)
	}
	if r := p.quirks.lookup(repo); r != nil {
		return r.parse(tag)
	}
	return ParseTag(tag)
}

// Best returns the highest compatible stable candidate per tier newer than cur.
func (p *Parser) Best(repo string, cur TagVersion, tags []string) map[model.Tier]TagVersion {
	best := map[model.Tier]TagVersion{}
	for _, t := range tags {
		if registry.IsArtifactTag(t) {
			continue
		}
		cand, ok := p.Parse(repo, t)
		if !ok || !Compatible(cur, cand) || Compare(cand, cur) <= 0 {
			continue
		}
		if cand.Pre != "" && cur.Pre == "" {
			continue
		}
		tier := TierBetween(cur, cand)
		if b, found := best[tier]; !found || Compare(cand, b) > 0 {
			best[tier] = cand
		}
	}
	return best
}
