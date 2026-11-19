// Package dashboard serves the read-only HTML dashboard over the same service as the API.
package dashboard

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/findings"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/web/api"
)

//go:embed templates/*.html assets/style.css
var assets embed.FS

var pages = []string{"attention", "workloads", "owner", "images", "image", "vulnerabilities", "vulnerability",
	"cluster", "node", "excepted", "feeds", "search", "notfound"}

// Dashboard is the HTML dashboard. It only reads.
type Dashboard struct {
	svc  *api.Service
	tmpl map[string]*template.Template
	css  []byte
	mux  *http.ServeMux
}

// page is what every template renders.
type page struct {
	Title   string
	Cluster string
	Data    any
}

var funcs = template.FuncMap{
	"ownerPath": api.OwnerPath,
	"keyPath":   keyPath,
	"keyLabel":  keyLabel,
	"date":      func(t *time.Time) string { return formatDate(t) },
	"priorityClass": func(p model.Priority) string {
		return "p-" + p.String()
	},
	"statusLabel": statusLabel,
	"count": func(m map[model.Priority]int, name string) int {
		p, _ := model.ParsePriority(name)
		return m[p]
	},
	"join":     strings.Join,
	"refLabel": func(kind, ns, name string) string { return keyLabel(kind + "/" + ns + "/" + name) },
}

func formatDate(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func statusLabel(s string) string {
	switch s {
	case string(model.ImagePending):
		return "Pending"
	case string(model.ImageCatalogued):
		return "Catalogued"
	case string(model.ImageUnresolvable):
		return "Unresolvable"
	case string(model.ImageCatalogFailed):
		return "Catalogue failed"
	}
	return s
}

// keyPath turns an owner key ("Deployment/shop/web", "Cluster//test") into its URL path.
func keyPath(key string) string {
	parts := strings.SplitN(key, "/", 3)
	if len(parts) != 3 {
		return key
	}
	return api.OwnerPath(model.OwnerRef{Kind: parts[0], Namespace: parts[1], Name: parts[2]})
}

// keyLabel turns an owner key into "Deployment shop/web", or "Cluster test" without a namespace.
func keyLabel(key string) string {
	parts := strings.SplitN(key, "/", 3)
	if len(parts) != 3 {
		return key
	}
	if parts[1] == "" {
		return parts[0] + " " + parts[2]
	}
	return parts[0] + " " + parts[1] + "/" + parts[2]
}

// New parses every template and returns the dashboard. Any parse error is returned.
func New(svc *api.Service) (*Dashboard, error) {
	d := &Dashboard{svc: svc, tmpl: map[string]*template.Template{}}
	for _, p := range pages {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/"+p+".html")
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", p, err)
		}
		d.tmpl[p] = t
	}
	css, err := fs.ReadFile(assets, "assets/style.css")
	if err != nil {
		return nil, fmt.Errorf("read style.css: %w", err)
	}
	d.css = css
	d.mux = http.NewServeMux()
	for pattern, fn := range map[string]http.HandlerFunc{
		"/{$}":                              d.attention,
		"/workloads":                        d.workloads,
		"/images":                           d.images,
		"/images/{digest}":                  d.image,
		"/owners/{kind}/{namespace}/{name}": d.owner,
		"/vulnerabilities":                  d.vulnerabilities,
		"/vulnerabilities/{id}":             d.vulnerability,
		"/advisories/{id}":                  d.vulnerability,
		"/cluster":                          d.cluster,
		"/nodes/{name}":                     d.node,
		"/excepted":                         d.excepted,
		"/feeds":                            d.feeds,
		"/search":                           d.search,
		"/assets/style.css":                 d.style,
	} {
		d.mux.HandleFunc("GET "+pattern, fn)
	}
	d.mux.HandleFunc("/", d.notFound)
	return d, nil
}

// ServeHTTP implements http.Handler.
func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) { d.mux.ServeHTTP(w, r) }

func (d *Dashboard) render(w http.ResponseWriter, status int, name, title string, data any) {
	var buf bytes.Buffer
	if err := d.tmpl[name].ExecuteTemplate(&buf, "layout.html", page{Title: title, Cluster: d.svc.ClusterName(), Data: data}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (d *Dashboard) fail(w http.ResponseWriter, _ error) {
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func (d *Dashboard) notFound(w http.ResponseWriter, _ *http.Request) {
	d.render(w, http.StatusNotFound, "notfound", "Not found", nil)
}

func (d *Dashboard) style(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(d.css)
}

func (d *Dashboard) attention(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var fs []api.FindingView
	for offset := 0; ; {
		pg, err := d.svc.Findings(ctx, api.FindingQuery{MinPriority: model.PriorityHigh,
			States: []model.FindingState{model.StateOpen}, Limit: 1000, Offset: offset})
		if err != nil {
			d.fail(w, err)
			return
		}
		fs = append(fs, pg.Items...)
		offset += len(pg.Items)
		if len(pg.Items) == 0 || offset >= pg.Total {
			break
		}
	}
	owners, err := d.svc.Owners(ctx)
	if err != nil {
		d.fail(w, err)
		return
	}
	byKey := make(map[string]api.OwnerView, len(owners))
	for _, o := range owners {
		byKey[o.ID] = o
	}
	sgs, err := d.svc.Suggestions(ctx)
	if err != nil {
		d.fail(w, err)
		return
	}
	d.render(w, http.StatusOK, "attention", "Needs attention", Attention(fs, byKey, sgs))
}

func (d *Dashboard) workloads(w http.ResponseWriter, r *http.Request) {
	os, err := d.svc.Owners(r.Context())
	if err != nil {
		d.fail(w, err)
		return
	}
	d.render(w, http.StatusOK, "workloads", "Workloads", os)
}

func (d *Dashboard) images(w http.ResponseWriter, r *http.Request) {
	is, err := d.svc.Images(r.Context())
	if err != nil {
		d.fail(w, err)
		return
	}
	d.render(w, http.StatusOK, "images", "Images", is)
}

func (d *Dashboard) image(w http.ResponseWriter, r *http.Request) {
	img, ok, err := d.svc.Image(r.Context(), r.PathValue("digest"))
	if err != nil {
		d.fail(w, err)
		return
	}
	if !ok {
		d.notFound(w, r)
		return
	}
	d.render(w, http.StatusOK, "image", "Image "+img.Repo, img)
}

type ownerPage struct {
	api.OwnerDetail
	Groups []findings.StdlibGroup
	Rest   []api.FindingView
}

func (d *Dashboard) owner(w http.ResponseWriter, r *http.Request) {
	ref := api.ParseOwnerPath(r.PathValue("kind"), r.PathValue("namespace"), r.PathValue("name"))
	o, ok, err := d.svc.Owner(r.Context(), ref)
	if err != nil {
		d.fail(w, err)
		return
	}
	if !ok {
		d.notFound(w, r)
		return
	}
	groups, rest := groupStdlib(o.Findings)
	d.render(w, http.StatusOK, "owner", keyLabel(ref.Key()), ownerPage{OwnerDetail: o, Groups: groups, Rest: rest})
}

func (d *Dashboard) vulnerabilities(w http.ResponseWriter, r *http.Request) {
	vs, err := d.svc.Vulnerabilities(r.Context())
	if err != nil {
		d.fail(w, err)
		return
	}
	d.render(w, http.StatusOK, "vulnerabilities", "Vulnerabilities", vs)
}

func (d *Dashboard) vulnerability(w http.ResponseWriter, r *http.Request) {
	v, ok, err := d.svc.Vulnerability(r.Context(), r.PathValue("id"))
	if err != nil {
		d.fail(w, err)
		return
	}
	if !ok {
		d.notFound(w, r)
		return
	}
	d.render(w, http.StatusOK, "vulnerability", v.ID, v)
}

type clusterPage struct {
	api.ClusterView
	Nodes []api.NodeView
}

func (d *Dashboard) cluster(w http.ResponseWriter, r *http.Request) {
	c, err := d.svc.Cluster(r.Context())
	if err != nil {
		d.fail(w, err)
		return
	}
	ns, err := d.svc.Nodes(r.Context())
	if err != nil {
		d.fail(w, err)
		return
	}
	d.render(w, http.StatusOK, "cluster", "Cluster", clusterPage{ClusterView: c, Nodes: ns})
}

func (d *Dashboard) node(w http.ResponseWriter, r *http.Request) {
	n, ok, err := d.svc.Node(r.Context(), r.PathValue("name"))
	if err != nil {
		d.fail(w, err)
		return
	}
	if !ok {
		d.notFound(w, r)
		return
	}
	d.render(w, http.StatusOK, "node", "Node "+n.Name, n)
}

type exceptedPage struct {
	Findings   []api.FindingView
	Exceptions []api.ExceptionView
}

func (d *Dashboard) excepted(w http.ResponseWriter, r *http.Request) {
	pg, err := d.svc.Findings(r.Context(), api.FindingQuery{States: []model.FindingState{model.StateExcepted}, Limit: 1000})
	if err != nil {
		d.fail(w, err)
		return
	}
	es, err := d.svc.Exceptions(r.Context())
	if err != nil {
		d.fail(w, err)
		return
	}
	d.render(w, http.StatusOK, "excepted", "Excepted", exceptedPage{Findings: pg.Items, Exceptions: es})
}

type feedsPage struct {
	Feeds   []api.FeedView
	Sources []api.Source
}

func (d *Dashboard) feeds(w http.ResponseWriter, r *http.Request) {
	fs, err := d.svc.Feeds(r.Context())
	if err != nil {
		d.fail(w, err)
		return
	}
	d.render(w, http.StatusOK, "feeds", "Feeds", feedsPage{Feeds: fs, Sources: api.Sources})
}

func (d *Dashboard) search(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	res := api.SearchResult{Query: q}
	if q != "" {
		var err error
		if res, err = d.svc.Search(r.Context(), q, ""); err != nil {
			d.fail(w, err)
			return
		}
	}
	d.render(w, http.StatusOK, "search", "Search", res)
}
