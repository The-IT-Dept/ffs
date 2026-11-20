package osv

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestObjectURL(t *testing.T) {
	const api = "https://storage.googleapis.com/storage/v1/b/"
	for _, tc := range []struct {
		name, base, dir, file, want string
	}{
		{"default bucket", DefaultURL, "PyPI", "modified_id.csv",
			api + "osv-vulnerabilities/o/PyPI%2Fmodified_id.csv?alt=media"},
		{"default bucket, trailing slash", DefaultURL + "/", "Go", "all.zip",
			api + "osv-vulnerabilities/o/Go%2Fall.zip?alt=media"},
		{"default bucket, record", DefaultURL, "Rocky Linux", "RLSA-2024:1234.json",
			api + "osv-vulnerabilities/o/Rocky%20Linux%2FRLSA-2024:1234.json?alt=media"},
		{"default bucket, http", "http://osv-vulnerabilities.storage.googleapis.com", "PyPI", "all.zip",
			api + "osv-vulnerabilities/o/PyPI%2Fall.zip?alt=media"},
		{"path-style bucket", "https://storage.googleapis.com/osv-vulnerabilities/", "PyPI", "modified_id.csv",
			api + "osv-vulnerabilities/o/PyPI%2Fmodified_id.csv?alt=media"},
		{"bucket with prefix", "https://my.mirror.storage.googleapis.com/osv/v1", "Debian", "DSA-1-1.json",
			api + "my.mirror/o/osv%2Fv1%2FDebian%2FDSA-1-1.json?alt=media"},
		{"mirror", "https://osv.example.com/mirror/", "Rocky Linux", "modified_id.csv",
			"https://osv.example.com/mirror/Rocky%20Linux/modified_id.csv"},
		{"mirror on loopback", "http://127.0.0.1:8080", "PyPI", "PYSEC-2024-1.json",
			"http://127.0.0.1:8080/PyPI/PYSEC-2024-1.json"},
		{"bare storage host is not a bucket", "https://storage.googleapis.com", "PyPI", "all.zip",
			"https://storage.googleapis.com/PyPI/all.zip"},
		{"lookalike host is a mirror", "https://osv.storage.googleapis.com.example.net", "PyPI", "all.zip",
			"https://osv.storage.googleapis.com.example.net/PyPI/all.zip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, parseObjectBase(tc.base).url(tc.dir, tc.file))
		})
	}
}

func TestFeedBucketURL_DefaultsToJSONAPI(t *testing.T) {
	require.Equal(t, "https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o/GIT%2Fall.zip?alt=media",
		New(Options{}).bucketURL(BucketGIT, "all.zip"))
}
