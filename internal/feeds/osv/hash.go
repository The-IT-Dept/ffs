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

// AffectedHash returns the hex sha256 of the parts of an OSV record that decide what it matches:
// its affected entries as canonical JSON (object keys sorted, numbers kept verbatim), its sorted
// aliases and its withdrawn time. published and modified are not part of it, so a record whose
// only change is a timestamp hashes the same.
func AffectedHash(raw []byte) (string, error) {
	var r struct {
		Affected  json.RawMessage `json:"affected"`
		Aliases   []string        `json:"aliases"`
		Withdrawn string          `json:"withdrawn"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", fmt.Errorf("osv: record: %w", err)
	}
	var affected any
	if len(r.Affected) > 0 {
		d := json.NewDecoder(bytes.NewReader(r.Affected))
		d.UseNumber()
		if err := d.Decode(&affected); err != nil {
			return "", fmt.Errorf("osv: record affected: %w", err)
		}
	}
	canonical, err := json.Marshal(affected)
	if err != nil {
		return "", fmt.Errorf("osv: record affected: %w", err)
	}
	aliases := slices.Clone(r.Aliases)
	slices.Sort(aliases)
	sum := sha256.Sum256([]byte(string(canonical) + "\n" + strings.Join(aliases, ",") + "\n" + r.Withdrawn))
	return hex.EncodeToString(sum[:]), nil
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
