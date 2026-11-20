package upgrade

import (
	"cmp"
	"fmt"
	"path"
	"regexp"
	"slices"
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
	if _, err := path.Match(r.Repo, ""); err != nil {
		return nil, fmt.Errorf("repository glob: %w", err)
	}
	for _, g := range r.Ignore {
		if _, err := path.Match(g, ""); err != nil {
			return nil, fmt.Errorf("ignore %q: %w", g, err)
		}
	}
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
// The ignore globs were checked by compileRule, so path.Match cannot fail here.
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
	globs []*compiledRule // most specific first (moreSpecific)
}

func newRuleSet(rules []rule) (*ruleSet, error) {
	s := &ruleSet{exact: map[string]*compiledRule{}}
	for _, r := range rules {
		c, err := compileRule(r)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.Repo, err)
		}
		if strings.ContainsAny(r.Repo, globChars) {
			s.globs = append(s.globs, c)
		} else {
			s.exact[r.Repo] = c
		}
	}
	slices.SortFunc(s.globs, func(a, b *compiledRule) int { return moreSpecific(a.Repo, b.Repo) })
	return s, nil
}

// globChars are the characters that make a repository key a path.Match glob.
const globChars = "*?[\\"

// moreSpecific orders repository globs most specific first: the longer literal prefix (the text
// before the first glob character), then the longer glob, then alphabetically. So for
// docker.io/bitnami/postgresql, "docker.io/bitnami/postgres*" wins over "docker.io/bitnami/*".
func moreSpecific(a, b string) int {
	return cmp.Or(cmp.Compare(literalPrefix(b), literalPrefix(a)), cmp.Compare(len(b), len(a)), strings.Compare(a, b))
}

// literalPrefix is the length of g before its first glob character.
func literalPrefix(g string) int {
	if i := strings.IndexAny(g, globChars); i >= 0 {
		return i
	}
	return len(g)
}

// lookup returns the rule for repo: an exact key first, then the most specific matching glob.
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

// overrideRules turns the configured overrides into rules keyed by normalised repository
// (config.NormalizeRepoKey), so "postgres" applies to docker.io/library/postgres.
func overrideRules(o map[string]config.TagOverride) []rule {
	out := make([]rule, 0, len(o))
	for repo, v := range o {
		out = append(out, rule{Repo: config.NormalizeRepoKey(repo), Pattern: v.Pattern, Ignore: v.Ignore})
	}
	return out
}
