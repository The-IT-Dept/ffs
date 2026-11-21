package osv

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// HashVersion names the AffectedHash recipe. Records cached under another version are rehashed
// silently (see Feed.rehash) before anything compares hashes, so a change to the recipe does not
// look like a change to every record and re-match the cluster. v1 hashed what a record matches; v2
// added its ratings to that one sum; v3 keeps the two apart (see AffectedHash).
const HashVersion = "3"

// AffectedHash returns "<match>:<rating>", two hex sha256 sums of the parts of an OSV record that
// decide what it matches and how its findings are rated. The match sum covers its affected entries
// as canonical JSON (object keys sorted, numbers kept verbatim), its sorted aliases and its
// withdrawn time: the v1 recipe, so a v1 hash equals the match sum. The rating sum covers its
// top-level severity (CVSS vectors and the Ubuntu priority) and its database_specific.severity (the
// GHSA rating). published and modified are in neither, so a record whose only change is a timestamp
// hashes the same. The cache hands a record off when either sum changes, and moves its observation
// time only when the match sum does (see store.PutOSVRecordAt): a rating-only change re-rates
// findings without making new matches on the record provisional again.
func AffectedHash(raw []byte) (string, error) {
	var r struct {
		Affected         json.RawMessage `json:"affected"`
		Aliases          []string        `json:"aliases"`
		Withdrawn        string          `json:"withdrawn"`
		Severity         json.RawMessage `json:"severity"`
		DatabaseSpecific struct {
			Severity json.RawMessage `json:"severity"`
		} `json:"database_specific"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", fmt.Errorf("osv: record: %w", err)
	}
	parts := make([]string, 0, 3)
	for _, f := range []struct {
		name string
		raw  json.RawMessage
	}{{"affected", r.Affected}, {"severity", r.Severity}, {"database_specific.severity", r.DatabaseSpecific.Severity}} {
		c, err := canonicalJSON(f.raw)
		if err != nil {
			return "", fmt.Errorf("osv: record %s: %w", f.name, err)
		}
		parts = append(parts, c)
	}
	aliases := slices.Clone(r.Aliases)
	slices.Sort(aliases)
	match := sha256.Sum256([]byte(parts[0] + "\n" + strings.Join(aliases, ",") + "\n" + r.Withdrawn))
	rating := sha256.Sum256([]byte(parts[1] + "\n" + parts[2]))
	return hex.EncodeToString(match[:]) + ":" + hex.EncodeToString(rating[:]), nil
}

// canonicalJSON re-encodes raw with object keys sorted and numbers kept verbatim; absent is "null".
func canonicalJSON(raw json.RawMessage) (string, error) {
	var v any
	if len(raw) > 0 {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if err := d.Decode(&v); err != nil {
			return "", err
		}
	}
	out, err := json.Marshal(v)
	return string(out), err
}

// recordInfo is the part of an OSV record the feed reads: its identity, modified time, and what
// its index names and GIT repositories come from.
type recordInfo struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type string `json:"type"`
			Repo string `json:"repo"`
		} `json:"ranges"`
	} `json:"affected"`
}

func parseRecord(raw []byte) (recordInfo, error) {
	var r recordInfo
	if err := json.Unmarshal(raw, &r); err != nil {
		return recordInfo{}, fmt.Errorf("osv: record: %w", err)
	}
	return r, nil
}

// modified returns the record's modified time, or fallback when it has none.
func (r recordInfo) modified(fallback time.Time) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, r.Modified); err == nil {
		return t.UTC()
	}
	return fallback
}

// gitRepos returns the normalised repositories of the record's GIT ranges, deduplicated.
func (r recordInfo) gitRepos() []string {
	var out []string
	for _, a := range r.Affected {
		for _, rg := range a.Ranges {
			if rg.Type == "GIT" && rg.Repo != "" {
				if n := NormalizeRepo(rg.Repo); !slices.Contains(out, n) {
					out = append(out, n)
				}
			}
		}
	}
	return out
}

// names returns the record's index names in bucket: the GIT range repositories in the GIT bucket,
// else IndexName of each affected package whose ecosystem belongs to bucket.
func (r recordInfo) names(bucket string) []string {
	if bucket == BucketGIT {
		return r.gitRepos()
	}
	var out []string
	for _, a := range r.Affected {
		if a.Package.Name == "" || BucketOf(a.Package.Ecosystem) != bucket {
			continue
		}
		if n := IndexName(bucket, a.Package.Name); !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}
