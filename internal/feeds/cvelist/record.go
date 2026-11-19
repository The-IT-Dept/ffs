package cvelist

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/match/upstream"
	"github.com/the-it-dept/ffs/internal/model"
)

// cisaADP is the providerMetadata.shortName of CISA's Authorized Data Publisher container, whose
// CVSS is the severity fallback when the CNA gives none.
const cisaADP = "CISA-ADP"

// Record is the part of a CVE 5 record the feed uses.
type Record struct {
	ID, State, Assigner, Title string
	Published, Updated         time.Time
	// Severity and CVSS come from the CNA's CVSS (4.0, then 3.1, then 3.0), or else from CISA-ADP's;
	// SeveritySource is the assigner's short name or "CISA-ADP", and "" when there is none.
	Severity       model.Severity
	CVSS           float64
	SeveritySource string
	Affected       []Affected
	Links          []string
}

// Affected is one CNA affected entry: a vendor and product with its version ranges.
type Affected struct {
	Vendor, Product string
	Ranges          upstream.CNARanges
}

// cveRecord is the CVE JSON 5 layout, reduced to the fields ParseRecord reads.
type cveRecord struct {
	CVEMetadata struct {
		CVEID         string `json:"cveId"`
		State         string `json:"state"`
		Assigner      string `json:"assignerShortName"`
		DatePublished string `json:"datePublished"`
		DateUpdated   string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Title    string `json:"title"`
			Affected []struct {
				Vendor  string `json:"vendor"`
				Product string `json:"product"`
				upstream.CNARanges
			} `json:"affected"`
			Metrics    []metric `json:"metrics"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cna"`
		ADP []struct {
			ProviderMetadata struct {
				ShortName string `json:"shortName"`
			} `json:"providerMetadata"`
			Metrics []metric `json:"metrics"`
		} `json:"adp"`
	} `json:"containers"`
}

type metric struct {
	CVSSv40 *cvss `json:"cvssV4_0"`
	CVSSv31 *cvss `json:"cvssV3_1"`
	CVSSv30 *cvss `json:"cvssV3_0"`
}

type cvss struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

func (c *cvss) empty() bool { return c == nil || c.BaseScore == 0 && c.BaseSeverity == "" }

// ParseRecord decodes a CVE JSON 5 record.
func ParseRecord(raw []byte) (Record, error) {
	var c cveRecord
	if err := json.Unmarshal(raw, &c); err != nil {
		return Record{}, fmt.Errorf("cvelist: record: %w", err)
	}
	m, cna := c.CVEMetadata, c.Containers.CNA
	r := Record{
		ID:        strings.TrimSpace(m.CVEID),
		State:     m.State,
		Assigner:  m.Assigner,
		Title:     strings.TrimSpace(cna.Title),
		Published: parseTime(m.DatePublished),
		Updated:   parseTime(m.DateUpdated),
	}
	if r.ID == "" {
		return Record{}, errors.New("cvelist: record without a cveId")
	}
	if s, ok := severity(cna.Metrics); ok {
		r.Severity, r.CVSS, r.SeveritySource = model.ParseSeverity(s.BaseSeverity), s.BaseScore, r.Assigner
	} else {
		for _, adp := range c.Containers.ADP {
			if adp.ProviderMetadata.ShortName != cisaADP {
				continue
			}
			if s, ok := severity(adp.Metrics); ok {
				r.Severity, r.CVSS, r.SeveritySource = model.ParseSeverity(s.BaseSeverity), s.BaseScore, cisaADP
				break
			}
		}
	}
	for _, a := range cna.Affected {
		r.Affected = append(r.Affected, Affected{Vendor: a.Vendor, Product: a.Product, Ranges: a.CNARanges})
	}
	for _, ref := range cna.References {
		if u := strings.TrimSpace(ref.URL); u != "" && !slices.Contains(r.Links, u) {
			r.Links = append(r.Links, u)
		}
	}
	return r, nil
}

// severity returns the first non-empty CVSS of metrics, preferring 4.0 over 3.1 over 3.0.
func severity(metrics []metric) (*cvss, bool) {
	for _, pick := range []func(metric) *cvss{
		func(m metric) *cvss { return m.CVSSv40 },
		func(m metric) *cvss { return m.CVSSv31 },
		func(m metric) *cvss { return m.CVSSv30 },
	} {
		for _, m := range metrics {
			if s := pick(m); !s.empty() {
				return s, true
			}
		}
	}
	return nil, false
}

// parseTime reads a CVE 5 timestamp, which may lack a zone (then UTC); a bad one gives zero.
func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
