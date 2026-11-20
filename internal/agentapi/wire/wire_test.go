package wire

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

// keysOf returns the top-level JSON keys of v, in encoding order.
func keysOf(t *testing.T, v any) []string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	require.NoError(t, err)
	require.Equal(t, json.Delim('{'), tok)
	var keys []string
	for dec.More() {
		k, err := dec.Token()
		require.NoError(t, err)
		keys = append(keys, k.(string))
		var skip json.RawMessage
		require.NoError(t, dec.Decode(&skip))
	}
	return keys
}

func roundTrip[T any](t *testing.T, v T) {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	var got T
	require.NoError(t, json.Unmarshal(b, &got))
	require.Equal(t, v, got)
}

func TestWire_JSONKeys(t *testing.T) {
	at := time.Date(2026, 11, 20, 1, 2, 3, 0, time.UTC)
	full := Report{
		Node: "worker-1", AgentVersion: "v0.0.1", BootID: "b1", Instance: "0123456789abcdef0123456789abcdef", StartedAt: at, Seq: 7, Kind: KindFull,
		CollectedAt: at.Add(time.Minute), KernelRelease: "7.0.0-34-generic", Arch: "amd64",
		Host: &Host{
			PackageDB: "dpkg",
			Binaries:  []Binary{{Name: "containerd", Path: "/usr/bin/containerd", Size: 12}},
			SyftJSON:  json.RawMessage(`{"artifacts":[]}`),
		},
		Images: &Images{ContentStore: true, Digests: []CachedImage{{
			Digest: "sha256:aa", MediaType: "application/vnd.oci.image.index.v1+json", ConfigDigest: "sha256:cc",
			Platform: "linux/amd64", Manifests: []string{"sha256:bb"}, Size: 10, Complete: true,
		}}},
		Problems: []Problem{{Code: ProblemPermissionDenied, Path: "/var/lib/rpm", Detail: "permission denied"}},
	}
	b, err := json.Marshal(full)
	require.NoError(t, err)
	require.Equal(t, `{"node":"worker-1","agentVersion":"v0.0.1","bootID":"b1","instance":"0123456789abcdef0123456789abcdef","startedAt":"2026-11-20T01:02:03Z","seq":7,`+
		`"kind":"full","collectedAt":"2026-11-20T01:03:03Z","kernelRelease":"7.0.0-34-generic","arch":"amd64",`+
		`"host":{"packageDB":"dpkg","binaries":[{"name":"containerd","path":"/usr/bin/containerd","size":12}],"syftJSON":{"artifacts":[]}},`+
		`"images":{"contentStore":true,"digests":[{"digest":"sha256:aa","mediaType":"application/vnd.oci.image.index.v1+json",`+
		`"configDigest":"sha256:cc","platform":"linux/amd64","manifests":["sha256:bb"],"size":10,"complete":true}]},`+
		`"problems":[{"code":"permission_denied","path":"/var/lib/rpm","detail":"permission denied"}]}`, string(b))
	roundTrip(t, full)

	require.Equal(t, []string{"node", "agentVersion", "bootID", "instance", "startedAt", "seq", "kind", "collectedAt", "kernelRelease", "arch"},
		keysOf(t, Report{}), "host, images and problems are omitted when empty")
	require.Equal(t, []string{"packageDB", "binaries", "syftJSON"}, keysOf(t, Host{}))
	require.Equal(t, []string{"name", "path", "size"}, keysOf(t, Binary{}))
	require.Equal(t, []string{"contentStore", "digests"}, keysOf(t, Images{}))
	require.Equal(t, []string{"digest", "mediaType", "configDigest", "platform", "size", "complete"}, keysOf(t, CachedImage{}),
		"manifests is omitted when empty")
	require.Equal(t, []string{"code", "detail"}, keysOf(t, Problem{}), "path is omitted when empty")

	resp := ReportResponse{
		Applied: true,
		Work:    []WorkRequest{{ID: "w1", Digest: "sha256:aa", Platform: "linux/amd64", Deadline: at}},
		Config:  AgentConfig{ReportIntervalSeconds: 21600, ImageListIntervalSeconds: 300, JitterPercent: 10, MaxImageBytes: 1, MaxReportBytes: 2},
	}
	require.Equal(t, []string{"applied", "work", "config"}, keysOf(t, resp), "hostRetry is omitted when false")
	retry := resp
	retry.HostRetry = true
	require.Equal(t, []string{"applied", "hostRetry", "work", "config"}, keysOf(t, retry))
	roundTrip(t, retry)
	require.Equal(t, []string{"id", "digest", "platform", "deadline"}, keysOf(t, resp.Work[0]))
	require.Equal(t, []string{"reportIntervalSeconds", "imageListIntervalSeconds", "jitterPercent", "maxImageBytes", "maxReportBytes"},
		keysOf(t, resp.Config))
	roundTrip(t, resp)
	roundTrip(t, resp.Work[0])
	roundTrip(t, resp.Config)

	res := SBOMResult{
		ID: "w1", Node: "worker-1", AgentVersion: "v0.0.1", Digest: "sha256:aa", SyftJSON: json.RawMessage(`{"artifacts":[]}`),
		Coverage: model.Coverage{UnattributedELF: 1}, Unavailable: UnavailableTooLarge, Failure: "failed: boom",
	}
	require.Equal(t, []string{"id", "node", "agentVersion", "digest", "syftJSON", "coverage", "unavailable", "failure"}, keysOf(t, res))
	require.Equal(t, []string{"id", "node", "agentVersion", "digest", "coverage"}, keysOf(t, SBOMResult{}),
		"syftJSON, unavailable and failure are omitted when empty")
	roundTrip(t, res)
}
