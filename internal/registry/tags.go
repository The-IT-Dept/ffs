package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

const (
	maxTagPages     = 100
	maxTags         = 50000
	maxTagPageBytes = 8 << 20
)

// ListTags lists repo's tags through tags/list paging: it follows a same-host Link rel="next" header,
// falls back to last=<last tag> after a full page without one, and stops on a short page, a page with
// no new tags, 100 pages or 50,000 tags. tags/list does not consume the manifest budget.
func (c *Client) ListTags(ctx context.Context, repo string, cs CredSet) ([]string, error) {
	tags, err := c.listTags(ctx, repo, cs)
	return tags, Classify(err)
}

func (c *Client) listTags(ctx context.Context, repo string, cs CredSet) ([]string, error) {
	r, err := name.NewRepository(c.PullRepo(repo))
	if err != nil {
		return nil, err
	}
	rt, err := c.rawTransport(ctx, r, cs)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: rt}
	base := &url.URL{Scheme: r.Scheme(), Host: r.RegistryStr(), Path: fmt.Sprintf("/v2/%s/tags/list", r.RepositoryStr())}
	pageURL := func(last string) *url.URL {
		u := *base
		q := url.Values{"n": {strconv.Itoa(c.pageSize)}}
		if last != "" {
			q.Set("last", last)
		}
		u.RawQuery = q.Encode()
		return &u
	}

	seen := map[string]bool{}
	var tags []string
	next := pageURL("")
	for page := 0; page < maxTagPages && next != nil; page++ {
		got, link, err := tagsPage(ctx, client, next)
		if err != nil {
			return nil, err
		}
		added := 0
		for _, t := range got {
			if !seen[t] {
				seen[t] = true
				tags = append(tags, t)
				added++
			}
		}
		switch {
		case added == 0 || len(tags) >= maxTags:
			next = nil
		case link != nil:
			next = link
		case len(got) < c.pageSize:
			next = nil
		default:
			next = pageURL(got[len(got)-1])
		}
	}
	if len(tags) > maxTags {
		tags = tags[:maxTags]
	}
	return tags, nil
}

// tagsPage fetches one tags/list page and returns its tags and the same-host next link, if any.
func tagsPage(ctx context.Context, client *http.Client, u *url.URL) ([]string, *url.URL, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := transport.CheckError(resp, http.StatusOK); err != nil {
		return nil, nil, err
	}
	var body struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTagPageBytes)).Decode(&body); err != nil {
		return nil, nil, fmt.Errorf("decoding tags/list from %s: %w", u.Host, err)
	}
	return body.Tags, nextLink(u, resp.Header.Values("Link")), nil
}

var linkNext = regexp.MustCompile(`<([^>]+)>\s*;(?:[^,]*;)?\s*rel="?next"?`)

// nextLink returns the rel="next" target resolved against the current page, or nil when there is
// none or it points at another host.
func nextLink(cur *url.URL, headers []string) *url.URL {
	for _, h := range headers {
		m := linkNext.FindStringSubmatch(h)
		if m == nil {
			continue
		}
		ref, err := url.Parse(strings.TrimSpace(m[1]))
		if err != nil {
			return nil
		}
		next := cur.ResolveReference(ref)
		if next.Host != cur.Host {
			return nil
		}
		return next
	}
	return nil
}

var (
	signatureTag = regexp.MustCompile(`^sha256-[0-9a-f]{64}(\.(sig|att|sbom))?$`)
	rcCommitTag  = regexp.MustCompile(`^rc-[0-9a-f]{7,40}$`)
	commitSuffix = regexp.MustCompile(`-([0-9a-f]{7,8})$`)
)

// IsArtifactTag reports tags that name build artifacts rather than releases: signature, attestation
// and SBOM tags (sha256-<hex>[.sig|.att|.sbom]), *-metadata, rc-<commit>, and a -<7 or 8 hex> commit
// suffix that contains a letter (so date-like digit runs stay versions).
func IsArtifactTag(tag string) bool {
	if signatureTag.MatchString(tag) || strings.HasSuffix(tag, "-metadata") || rcCommitTag.MatchString(tag) {
		return true
	}
	m := commitSuffix.FindStringSubmatch(tag)
	return m != nil && strings.ContainsAny(m[1], "abcdef")
}
