package osv

import (
	"net/url"
	"strings"
)

const gcsHost = "storage.googleapis.com"

// objectBase builds the URLs of the bucket objects the feed reads from the configured base URL.
//
// A Cloud Storage bucket, virtual-hosted (https://<bucket>.storage.googleapis.com) or path-style
// (https://storage.googleapis.com/<bucket>), is read through the JSON API media endpoint. The bucket
// host's edge serves an object stale for up to its max-age (an hour for OSV), even to requests with
// Cache-Control: no-cache, so a modified_id.csv read through it can lag OSV by that long. The JSON
// API serves the current generation, answers Range reads and sends x-goog-generation too. Any other
// base (a mirror) is read as <base>/<dir>/<file>.
type objectBase struct {
	base   string // the configured URL without trailing slashes
	bucket string // the Cloud Storage bucket it names; "" for any other server
	prefix string // the object name prefix within bucket: "" or ending in "/"
}

func parseObjectBase(raw string) objectBase {
	o := objectBase{base: strings.TrimRight(raw, "/")}
	u, err := url.Parse(o.base)
	if err != nil {
		return o
	}
	host, path := strings.ToLower(u.Hostname()), strings.Trim(u.Path, "/")
	var bucket string
	switch {
	case strings.HasSuffix(host, "."+gcsHost):
		bucket = strings.TrimSuffix(host, "."+gcsHost)
	case host == gcsHost:
		bucket, path, _ = strings.Cut(path, "/")
	}
	if bucket == "" {
		return o
	}
	o.bucket = bucket
	if path != "" {
		o.prefix = path + "/"
	}
	return o
}

// url returns the URL of the object dir/file.
func (o objectBase) url(dir, file string) string {
	if o.bucket == "" {
		return o.base + "/" + url.PathEscape(dir) + "/" + url.PathEscape(file)
	}
	return "https://" + gcsHost + "/storage/v1/b/" + url.PathEscape(o.bucket) + "/o/" +
		url.PathEscape(o.prefix+dir+"/"+file) + "?alt=media"
}
