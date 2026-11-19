package upstream

import (
	"cmp"
	"slices"
	"strings"
	"unicode"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/match/osvrange"
	"github.com/the-it-dept/ffs/internal/model"
)

// CompareVersions compares two upstream release versions and returns -1, 0 or +1 as a is below,
// equal to or above b. A leading "v" is ignored, and each version is split into maximal runs of
// digits and of letters (anything else separates them). Runs are compared pairwise: numbers
// numerically, letters as lowercase strings, and a number above letters. When one version runs
// out, it is compared against the other's next run: a number counts the missing side as 0,
// alpha/beta/rc/pre/dev/a/b make the longer version the smaller (3.0.0-alpha1 < 3.0.0), and any
// other letters make it the larger (1.1.1w > 1.1.1).
func CompareVersions(a, b string) int {
	ta, tb := tokens(a), tokens(b)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		switch {
		case i >= len(ta):
			if c := missing(tb[i]); c != 0 {
				return -c
			}
		case i >= len(tb):
			if c := missing(ta[i]); c != 0 {
				return c
			}
		default:
			if c := compareTokens(ta[i], tb[i]); c != 0 {
				return c
			}
		}
	}
	return 0
}

// token is one run of a version: digits (num) or letters, lowercased.
type token struct {
	s   string
	num bool
}

// Run kinds while tokenising.
const (
	runNone = iota
	runDigits
	runLetters
)

// tokens splits v, without a leading "v", into runs of digits (leading zeros trimmed, so a zero is
// "") and of letters.
func tokens(v string) []token {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	var out []token
	start, kind := 0, runNone
	flush := func(end int) {
		switch kind {
		case runDigits:
			out = append(out, token{s: strings.TrimLeft(v[start:end], "0"), num: true})
		case runLetters:
			out = append(out, token{s: strings.ToLower(v[start:end])})
		}
	}
	for i, r := range v {
		k := runNone
		switch {
		case '0' <= r && r <= '9':
			k = runDigits
		case unicode.IsLetter(r):
			k = runLetters
		}
		if k != kind {
			flush(i)
			start, kind = i, k
		}
	}
	flush(len(v))
	return out
}

// compareTokens compares two runs: numbers by value (leading zeros were trimmed, so by length
// then digits), letters as strings, and a number above letters.
func compareTokens(a, b token) int {
	switch {
	case a.num && b.num:
		if c := cmp.Compare(len(a.s), len(b.s)); c != 0 {
			return c
		}
		return strings.Compare(a.s, b.s)
	case a.num:
		return 1
	case b.num:
		return -1
	}
	return strings.Compare(a.s, b.s)
}

// preRelease are the letter runs that mark a version before the release they extend.
var preRelease = map[string]bool{"alpha": true, "beta": true, "rc": true, "pre": true, "dev": true, "a": true, "b": true}

// missing returns how the version holding the extra run t compares to the one that ran out.
func missing(t token) int {
	switch {
	case t.num && t.s == "":
		return 0 // a zero: 1.2 == 1.2.0
	case t.num:
		return 1
	case preRelease[t.s]:
		return -1
	}
	return 1
}

// CNARanges is the affected entry of a CVE record for one product, as stored by the cvelist feed
// with store.PutUpstreamRanges.
type CNARanges struct {
	DefaultStatus string       `json:"defaultStatus"`
	Versions      []CNAVersion `json:"versions"`
}

// CNAVersion is one CVE 5 version range: Version is the lower bound (or the only version), and
// LessThan or LessThanOrEqual the upper bound. Changes are status changes inside the range.
type CNAVersion struct {
	Version         string      `json:"version"`
	LessThan        string      `json:"lessThan,omitempty"`
	LessThanOrEqual string      `json:"lessThanOrEqual,omitempty"`
	Status          string      `json:"status"`
	VersionType     string      `json:"versionType,omitempty"`
	Changes         []CNAChange `json:"changes,omitempty"`
}

// CNAChange is a status change at a version inside a range.
type CNAChange struct {
	At     string `json:"at"`
	Status string `json:"status"`
}

const (
	statusAffected   = "affected"
	statusUnaffected = "unaffected"
)

// placeholders are Version values that name no lower bound.
var placeholders = map[string]bool{"": true, "0": true, "*": true, "n/a": true, "unspecified": true, "-": true}

// Affects reports whether version is in one of the affected ranges. The default status never
// creates a match, and ranges of versionType "git" (commit ids) are skipped. fs is FixFixed when an
// affecting range has a concrete upper bound (a lessThan, a lessThanOrEqual, or an unaffected
// change above version), else FixUnknown; fixed holds the smallest fixed version found (a lessThan,
// a GitHub-style "<" operand or the unaffected change), and is nil for a lessThanOrEqual bound. An
// unaffected version gives an empty fs and no fixed versions.
func (r CNARanges) Affects(version string) (affected bool, fs model.FixState, fixed []string) {
	if strings.TrimSpace(version) == "" {
		return false, "", nil
	}
	for _, v := range r.Versions {
		hit, concrete, fix := v.affects(version)
		if !hit {
			continue
		}
		affected = true
		if concrete {
			fs = model.FixFixed
		} else if fs == "" {
			fs = model.FixUnknown
		}
		if fix != "" {
			fixed = append(fixed, fix)
		}
	}
	if !affected {
		return false, "", nil
	}
	if len(fixed) > 1 {
		fixed = []string{slices.MinFunc(fixed, CompareVersions)}
	}
	return true, fs, fixed
}

// bound is the upper end of a range.
type bound struct {
	v         string
	inclusive bool
}

// affects evaluates one range: whether version lies in it, whether its upper bound is concrete,
// and the fixed version it names.
func (cv CNAVersion) affects(version string) (hit, concrete bool, fixed string) {
	if !strings.EqualFold(cv.Status, statusAffected) || strings.EqualFold(cv.VersionType, "git") {
		return false, false, ""
	}
	start := strings.TrimSpace(cv.Version)
	if strings.ContainsAny(start, "<>=") {
		return githubRange(start, version)
	}

	lower := start // inclusive; "" for none
	if placeholders[strings.ToLower(start)] {
		lower = ""
	}
	lower = strings.TrimSuffix(lower, ".*")
	var upper *bound
	switch {
	case cv.LessThan != "":
		u, ok, isConcrete := upperBound(cv.LessThan, false)
		if !ok {
			return false, false, ""
		}
		upper, concrete = u, isConcrete
		if isConcrete {
			fixed = u.v
		}
	case cv.LessThanOrEqual != "":
		u, ok, isConcrete := upperBound(cv.LessThanOrEqual, true)
		if !ok {
			return false, false, ""
		}
		upper, concrete = u, isConcrete
	case lower == "":
		return false, false, ""
	case strings.HasSuffix(start, ".*"):
		// "8.3.*" alone: every 8.3 release.
		next, ok := increment(lower)
		if !ok {
			return false, false, ""
		}
		upper = &bound{v: next}
	default:
		return CompareVersions(version, start) == 0, false, ""
	}
	if !within(version, lower, upper) {
		return false, false, ""
	}

	// The last change at or below version decides; the first unaffected change above it fixes it.
	changes := slices.Clone(cv.Changes)
	slices.SortStableFunc(changes, func(a, b CNAChange) int { return CompareVersions(a.At, b.At) })
	status := statusAffected
	for _, c := range changes {
		if c.At == "" {
			continue
		}
		if CompareVersions(version, c.At) >= 0 {
			status = strings.ToLower(c.Status)
			continue
		}
		if strings.EqualFold(c.Status, statusUnaffected) {
			return status != statusUnaffected, true, c.At
		}
	}
	return status != statusUnaffected, concrete, fixed
}

// upperBound parses a lessThan (or, inclusive, lessThanOrEqual) value: "*" is no bound, "N.*" or
// "N.M.*" is below the prefix with its last part incremented and not concrete, and anything else is
// a concrete bound. ok is false for a wildcard that cannot be incremented.
func upperBound(s string, inclusive bool) (b *bound, ok, concrete bool) {
	s = strings.TrimSpace(s)
	if s == "*" {
		return nil, true, false
	}
	if prefix, wild := strings.CutSuffix(s, ".*"); wild {
		next, ok := increment(prefix)
		if !ok {
			return nil, false, false
		}
		return &bound{v: next}, true, false
	}
	return &bound{v: s, inclusive: inclusive}, true, true
}

// increment returns prefix with its last dot-separated part, which must be a number, plus one:
// "4" → "5", "8.3" → "8.4".
func increment(prefix string) (string, bool) {
	head, last := "", prefix
	if i := strings.LastIndexByte(prefix, '.'); i >= 0 {
		head, last = prefix[:i+1], prefix[i+1:]
	}
	if last == "" || strings.Trim(last, "0123456789") != "" {
		return "", false
	}
	// Add one to a decimal string of any length.
	d := []byte(last)
	i := len(d) - 1
	for ; i >= 0 && d[i] == '9'; i-- {
		d[i] = '0'
	}
	if i < 0 {
		d = append([]byte{'1'}, d...)
	} else {
		d[i]++
	}
	return head + string(d), true
}

// within reports whether version lies between lower (inclusive) and upper; an empty lower and a
// nil upper are open.
func within(version, lower string, upper *bound) bool {
	if lower != "" && CompareVersions(version, lower) < 0 {
		return false
	}
	if upper == nil {
		return true
	}
	c := CompareVersions(version, upper.v)
	return c < 0 || upper.inclusive && c == 0
}

// githubRange evaluates a GitHub-style range such as ">= 7.4.0, < 7.4.2": comma-separated
// comparators that must all hold. The "<" operand is the fixed version; "<", "<=" and "=" bounds
// are concrete. A comparator that does not parse matches nothing.
func githubRange(rng, version string) (hit, concrete bool, fixed string) {
	for part := range strings.SplitSeq(rng, ",") {
		part = strings.TrimSpace(part)
		var op string
		for _, o := range []string{">=", "<=", "==", "!=", ">", "<", "="} {
			if strings.HasPrefix(part, o) {
				op = o
				break
			}
		}
		operand := strings.TrimSpace(strings.TrimPrefix(part, op))
		if op == "" || operand == "" {
			return false, false, ""
		}
		c := CompareVersions(version, operand)
		var ok bool
		switch op {
		case ">=":
			ok = c >= 0
		case ">":
			ok = c > 0
		case "<=":
			ok, concrete = c <= 0, true
		case "<":
			ok, concrete, fixed = c < 0, true, operand
		case "=", "==":
			ok, concrete = c == 0, true
		case "!=":
			ok = c != 0
		}
		if !ok {
			return false, false, ""
		}
	}
	return true, concrete, fixed
}

// MatchGitRecord evaluates an OSV GIT record against version, using the affected entries that have
// a GIT range for repo (osv.NormalizeRepo form). The version is affected when one of tags (its
// release tags in repo) is in the entry's versions list or, for an entry without one, when it lies
// in a range of the range's database_specific.extracted_events, evaluated with CompareVersions. fs
// is FixFixed with the fixed version when the extracted range holding version ends in a fixed
// event, FixFixed with no version when it ends in last_affected, and FixUnknown otherwise. A
// withdrawn record matches nothing.
func MatchGitRecord(v *osvschema.Vulnerability, repo string, tags []string, version string) (ok bool, fs model.FixState, fixed []string) {
	if v.GetWithdrawn() != nil || strings.TrimSpace(version) == "" {
		return false, "", nil
	}
	lastAffected := false
	for _, a := range v.GetAffected() {
		listed := slices.ContainsFunc(tags, func(t string) bool { return slices.Contains(a.GetVersions(), t) })
		for _, r := range a.GetRanges() {
			if r.GetType() != osvschema.Range_GIT || osv.NormalizeRepo(r.GetRepo()) != repo {
				continue
			}
			inRange := false
			var rangeFixed []string
			rangeLast := false
			for _, events := range extractedRanges(r) {
				res := osvrange.Evaluate(events, CompareVersions, version)
				if !res.Affected {
					continue
				}
				inRange = true
				switch {
				case res.EndsInLastAffected:
					rangeLast = true
				case len(res.Fixed) > 0:
					rangeFixed = append(rangeFixed, res.Fixed[0])
				}
			}
			if !listed && (len(a.GetVersions()) > 0 || !inRange) {
				continue
			}
			ok = true
			fixed = append(fixed, rangeFixed...)
			lastAffected = lastAffected || rangeLast
		}
	}
	switch {
	case !ok:
		return false, "", nil
	case len(fixed) > 0:
		return true, model.FixFixed, []string{slices.MinFunc(fixed, CompareVersions)}
	case lastAffected:
		return true, model.FixFixed, nil
	}
	return true, model.FixUnknown, nil
}

// extractedRanges returns the event lists of a GIT range's database_specific.extracted_events:
// each element's "range" holds introduced / fixed / last_affected versions.
func extractedRanges(r *osvschema.Range) [][]osvrange.Event {
	var out [][]osvrange.Event
	for _, x := range r.GetDatabaseSpecific().GetFields()["extracted_events"].GetListValue().GetValues() {
		var events []osvrange.Event
		for _, e := range x.GetStructValue().GetFields()["range"].GetListValue().GetValues() {
			f := e.GetStructValue().GetFields()
			events = append(events, osvrange.Event{
				Introduced:   stringField(f, "introduced"),
				Fixed:        stringField(f, "fixed"),
				LastAffected: stringField(f, "last_affected"),
			})
		}
		if len(events) > 0 {
			out = append(out, events)
		}
	}
	return out
}

func stringField(f map[string]*structpb.Value, k string) string {
	return strings.TrimSpace(f[k].GetStringValue())
}
