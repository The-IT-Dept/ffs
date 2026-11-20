package match

import (
	"strings"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"

	"github.com/ossf/osv-schema/bindings/go/osvschema"

	"github.com/the-it-dept/ffs/internal/model"
)

// RecordSeverity rates an OSV record's CVSS vectors: the highest CVSS v3 base score, else the
// highest v4 score, else the highest v2 base score, rated with that version's bands. A record with
// no vector that parses is unknown. For CVE records converted from NVD (the GIT ecosystem) the
// vector is NVD's; findings use it only when no vendor, CNA or NVD rating exists (spec §6.5).
func RecordSeverity(v *osvschema.Vulnerability) model.Severity {
	best := map[osvschema.Severity_Type]float64{}
	for _, s := range v.GetSeverity() {
		score, ok := cvssScore(s.GetType(), strings.TrimSpace(s.GetScore()))
		if ok && score >= best[s.GetType()] {
			best[s.GetType()] = score
		}
	}
	for _, typ := range []osvschema.Severity_Type{osvschema.Severity_CVSS_V3, osvschema.Severity_CVSS_V4, osvschema.Severity_CVSS_V2} {
		if score, ok := best[typ]; ok {
			return cvssRating(typ, score)
		}
	}
	return model.SeverityUnknown
}

// cvssScore returns the base score of a CVSS vector of type typ.
func cvssScore(typ osvschema.Severity_Type, vector string) (float64, bool) {
	switch typ {
	case osvschema.Severity_CVSS_V3:
		if strings.HasPrefix(vector, "CVSS:3.0/") {
			c, err := gocvss30.ParseVector(vector)
			if err != nil {
				return 0, false
			}
			return c.BaseScore(), true
		}
		c, err := gocvss31.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return c.BaseScore(), true
	case osvschema.Severity_CVSS_V4:
		c, err := gocvss40.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return c.Score(), true
	case osvschema.Severity_CVSS_V2:
		c, err := gocvss20.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return c.BaseScore(), true
	}
	return 0, false
}

// cvssRating rates a base score with the qualitative bands of its CVSS version: v2 has no critical
// band (7.0 and up is high), and a v3 or v4 score of 0 is none.
func cvssRating(typ osvschema.Severity_Type, score float64) model.Severity {
	switch {
	case typ != osvschema.Severity_CVSS_V2 && score >= 9:
		return model.SeverityCritical
	case score >= 7:
		return model.SeverityHigh
	case score >= 4:
		return model.SeverityMedium
	case score > 0 || typ == osvschema.Severity_CVSS_V2:
		return model.SeverityLow
	}
	return model.SeverityNegligible
}
