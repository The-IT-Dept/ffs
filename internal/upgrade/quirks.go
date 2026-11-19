package upgrade

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/the-it-dept/ffs/internal/config"
)

// rule customises tag parsing for the repos matching Repo. It has the same shape as
// config.TagOverride plus the repo glob.
type rule struct {
	Repo    string
	Pattern string
	Ignore  []string
}

// quirks are the built-in rules for repos whose tags do not follow the generic pattern.
var quirks = []rule{
	{Repo: "docker.io/bitnami/*", Pattern: bitnamiPattern},
	{Repo: "docker.io/bitnamilegacy/*", Pattern: bitnamiPattern},
	{Repo: "docker.io/grafana/grafana*", Pattern: `^(?P<version>\d+(?:\.\d+)*)(?:-security-(?P<revision>\d+))?(?:-(?P<suffix>[a-z][a-z-]*))?$`},
	{Repo: "quay.io/jetstack/cert-manager-*", Pattern: vPatternThree},
	{Repo: "docker.io/velero/velero*", Pattern: vPatternThree},
}

const (
	bitnamiPattern = `^(?P<version>\d+(?:\.\d+)*)(?:-(?P<suffix>debian-\d+)-r(?P<revision>\d+))?$`
	vPatternThree  = `^v(?P<version>\d+\.\d+\.\d+)$`
)

// compiledRule is a rule with its pattern compiled and group indexes resolved.
type compiledRule struct {
	rule
	re                          *regexp.Regexp
	version, suffix, revisionIx int
}

func compileRule(r rule) (*compiledRule, error) {
	re, err := regexp.Compile(r.Pattern)
	if err != nil {
		return nil, err
	}
	c := &compiledRule{rule: r, re: re, version: re.SubexpIndex("version"), suffix: re.SubexpIndex("suffix"), revisionIx: re.SubexpIndex("revision")}
	if c.version < 0 {
		return nil, fmt.Errorf("pattern has no named group %q", "version")
	}
	return c, nil
}

// parse applies the rule to a tag. Tags in the ignore list or not matching the pattern are rejected.
func (c *compiledRule) parse(tag string) (TagVersion, bool) {
	for _, g := range c.Ignore {
		if ok, _ := path.Match(g, tag); ok {
			return TagVersion{}, false
		}
	}
	m := c.re.FindStringSubmatch(tag)
	if m == nil {
		return TagVersion{}, false
	}
	tv := TagVersion{Tag: tag}
	for _, part := range strings.Split(m[c.version], ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return TagVersion{}, false
		}
		tv.Release = append(tv.Release, n)
	}
	if c.suffix >= 0 {
		tv.Suffix = m[c.suffix]
	}
	if c.revisionIx >= 0 && m[c.revisionIx] != "" {
		n, err := strconv.Atoi(m[c.revisionIx])
		if err != nil {
			return TagVersion{}, false
		}
		tv.Revision = n
	}
	return tv, true
}

// ruleSet holds compiled rules keyed by repo glob (or exact repo).
type ruleSet struct {
	exact map[string]*compiledRule
	globs []*compiledRule
}

func newRuleSet(rules []rule) (*ruleSet, error) {
	s := &ruleSet{exact: map[string]*compiledRule{}}
	for _, r := range rules {
		c, err := compileRule(r)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.Repo, err)
		}
		if strings.ContainsAny(r.Repo, "*?[") {
			s.globs = append(s.globs, c)
		} else {
			s.exact[r.Repo] = c
		}
	}
	sort.Slice(s.globs, func(i, j int) bool { return s.globs[i].Repo < s.globs[j].Repo })
	return s, nil
}

// lookup returns the rule for repo: an exact key first, then the first matching glob.
func (s *ruleSet) lookup(repo string) *compiledRule {
	if c, ok := s.exact[repo]; ok {
		return c
	}
	for _, c := range s.globs {
		if ok, _ := path.Match(c.Repo, repo); ok {
			return c
		}
	}
	return nil
}

func overrideRules(o map[string]config.TagOverride) []rule {
	out := make([]rule, 0, len(o))
	for repo, v := range o {
		out = append(out, rule{Repo: repo, Pattern: v.Pattern, Ignore: v.Ignore})
	}
	return out
}
