package match_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/model"
)

func TestRecordSeverity(t *testing.T) {
	for _, c := range []struct {
		name, severity string
		want           model.Severity
	}{
		{"no vectors", `[]`, model.SeverityUnknown},
		{"v3.1 high", `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]`, model.SeverityHigh},
		{"v3.0 critical", `[{"type": "CVSS_V3", "score": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]`, model.SeverityCritical},
		{"highest v3 wins", `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},
			{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]`, model.SeverityHigh},
		{"v3 before v4", `[{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
			{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"}]`, model.SeverityLow},
		{"v4 alone", `[{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]`, model.SeverityCritical},
		{"v2 has no critical", `[{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:C/I:C/A:C"}]`, model.SeverityHigh},
		{"unparsable vector", `[{"type": "CVSS_V3", "score": "CVSS:3.1/bogus"}]`, model.SeverityUnknown},
		{"Ubuntu priority is not CVSS", `[{"type": "Ubuntu", "score": "high"}]`, model.SeverityUnknown},
	} {
		t.Run(c.name, func(t *testing.T) {
			v, err := match.ParseOSV([]byte(`{"id": "GHSA-x", "severity": ` + c.severity + `}`))
			require.NoError(t, err)
			require.Equal(t, c.want, match.RecordSeverity(v))
		})
	}
}
