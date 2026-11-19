package sbom

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreatorIsSyft(t *testing.T) {
	for name, tc := range map[string]struct {
		doc  string
		want bool
	}{
		"spdx syft":           {`{"creationInfo":{"creators":["Organization: Anchore, Inc","Tool: syft-1.57.2"]}}`, true},
		"spdx buildkit+syft":  {`{"creationInfo":{"creators":["Tool: buildkit-v0.36","Tool: syft-v1.50.0"]}}`, true},
		"spdx trivy":          {`{"creationInfo":{"creators":["Tool: trivy-0.60"]}}`, false},
		"cyclonedx 1.4 syft":  {`{"metadata":{"tools":[{"vendor":"anchore","name":"syft"}]}}`, true},
		"cyclonedx 1.5 syft":  {`{"metadata":{"tools":{"components":[{"type":"application","name":"syft"}]}}}`, true},
		"cyclonedx 1.4 trivy": {`{"metadata":{"tools":[{"name":"trivy"}]}}`, false},
		"cyclonedx 1.5 trivy": {`{"metadata":{"tools":{"components":[{"name":"trivy"}]}}}`, false},
		"no creator":          {`{}`, false},
		"not json":            {`nope`, false},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, creatorIsSyft([]byte(tc.doc)))
		})
	}
}

func TestStatementFromLayer(t *testing.T) {
	const hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pred := `{"spdxVersion":"SPDX-2.3"}`
	stmt := `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"x","digest":{"sha256":"` + hex + `"}}],` +
		`"predicateType":"https://spdx.dev/Document","predicate":` + pred + `}`
	env := `{"payloadType":"application/vnd.in-toto+json","payload":"` + base64.StdEncoding.EncodeToString([]byte(stmt)) + `","signatures":[]}`
	bundle := `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","dsseEnvelope":` + env + `}`

	for name, mt := range map[string]struct{ mediaType, body string }{
		"statement": {mtInToto, stmt},
		"dsse":      {mtDSSE, env},
		"bundle":    {mtBundle, bundle},
	} {
		t.Run(name, func(t *testing.T) {
			pt, p, subs, err := statementFromLayer(mt.mediaType, strings.NewReader(mt.body))
			require.NoError(t, err)
			require.Equal(t, "https://spdx.dev/Document", pt)
			require.JSONEq(t, pred, string(p))
			require.Equal(t, []string{hex}, subs)
		})
	}

	t.Run("bare spdx", func(t *testing.T) {
		pt, p, subs, err := statementFromLayer(mtSPDX, strings.NewReader(pred))
		require.NoError(t, err)
		require.Equal(t, "https://spdx.dev/Document", pt)
		require.JSONEq(t, pred, string(p))
		require.Empty(t, subs)
	})
	t.Run("bare cyclonedx", func(t *testing.T) {
		pt, _, _, err := statementFromLayer(mtCycloneDX, strings.NewReader(`{"bomFormat":"CycloneDX"}`))
		require.NoError(t, err)
		require.Equal(t, "https://cyclonedx.org/bom", pt)
	})
	t.Run("other predicate type", func(t *testing.T) {
		other, _ := json.Marshal(map[string]any{"predicateType": "https://slsa.dev/provenance/v1", "predicate": map[string]any{}})
		_, _, _, err := statementFromLayer(mtInToto, bytes.NewReader(other))
		require.Error(t, err)
	})
	t.Run("unknown media type", func(t *testing.T) {
		_, _, _, err := statementFromLayer("application/octet-stream", strings.NewReader(stmt))
		require.Error(t, err)
	})
	t.Run("size limit", func(t *testing.T) {
		r := &countingReader{}
		_, _, _, err := statementFromLayer(mtSPDX, r)
		require.Error(t, err)
		require.LessOrEqual(t, r.n, int64(maxLayerBytes+1))
	})
}

// countingReader yields endless bytes and counts how many were read.
type countingReader struct{ n int64 }

func (c *countingReader) Read(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

var _ io.Reader = (*countingReader)(nil)
