// Package api serves the read-only JSON API: queries over the store, shaped into stable view types.
package api

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/the-it-dept/ffs/api/v1alpha1"
	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/eol"
	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/match/upstream"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/upgrade"
)

const (
	defaultLimit = 100
	maxLimit     = 1000
	searchLimit  = 50
	// searchFetchAll is the per-kind store limit used when a post-filter must run before capping.
	searchFetchAll = 1_000_000

	dateFmt = "2006-01-02"
)

// FeedInfo names a registered feed and how long its last success may age before it is stale.
type FeedInfo struct {
	Name       string
	StaleAfter time.Duration
}

// Options are the Service's dependencies. Kube may be nil, which lists no exceptions, and so may EOL.
type Options struct {
	Store  *store.Store
	Config config.Config
	Feeds  []FeedInfo
	EOL    *eol.Evaluator
	Kube   client.Reader
	Now    func() time.Time
	Log    logr.Logger
}

// Service answers the API's queries. It never writes.
type Service struct{ o Options }

// NewService returns a Service over o. A nil Now means time.Now.
func NewService(o Options) *Service {
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{o: o}
}

// ClusterName is the cluster every response names.
func (s *Service) ClusterName() string { return s.o.Config.ClusterName }

// Page is a list response. Unpaged lists carry Total = len(Items) and zero Limit and Offset.
type Page[T any] struct {
	Cluster string `json:"cluster"`
	Items   []T    `json:"items"`
	Total   int    `json:"total"`
	Limit   int    `json:"limit"`
	Offset  int    `json:"offset"`
}

// FindingQuery filters Findings. Empty States means every state.
type FindingQuery struct {
	MinPriority model.Priority
	Namespace   string
	Owner       string // owner key "Kind/Namespace/Name", or path form with "-" for no namespace
	Advisory    string // canonical id or any alias
	States      []model.FindingState
	Limit       int // default 100, at most 1000
	Offset      int
}

// ---- view types ----

type FindingPackageView struct {
	Name      string   `json:"name"`
	Ecosystem string   `json:"ecosystem"`
	Installed string   `json:"installed"`
	Path      string   `json:"path,omitempty"`
	Fixed     []string `json:"fixed"`
}

type FindingView struct {
	ID             string               `json:"id"`
	Owner          string               `json:"owner"`
	OwnerPath      string               `json:"ownerPath"`
	Repo           string               `json:"repo"`
	Advisory       string               `json:"advisory"`
	Title          string               `json:"title"`
	Severity       model.Severity       `json:"severity"`
	SeveritySource string               `json:"severitySource"`
	Priority       model.Priority       `json:"priority"`
	Reasons        []string             `json:"reasons"`
	State          model.FindingState   `json:"state"`
	ExceptedBy     string               `json:"exceptedBy,omitempty"`
	FixState       model.FixState       `json:"fixState"`
	FixAvailable   bool                 `json:"fixAvailable"`
	Provisional    bool                 `json:"provisional"`
	KEV            bool                 `json:"kev"`
	KEVAdded       string               `json:"kevAdded,omitempty"`
	Packages       []FindingPackageView `json:"packages"`
	Digests        []string             `json:"digests"`
	Published      *time.Time           `json:"published,omitempty"`
	Observed       *time.Time           `json:"observed,omitempty"`
	Matched        *time.Time           `json:"matched,omitempty"`
	LastSeen       *time.Time           `json:"lastSeen,omitempty"`
	ResolvedAt     *time.Time           `json:"resolvedAt,omitempty"`
	Suggestion     *SuggestionView      `json:"suggestion,omitempty"`
}

type VulnerabilityView struct {
	ID              string         `json:"id"`
	Aliases         []string       `json:"aliases"`
	Title           string         `json:"title"`
	Severity        model.Severity `json:"severity"`
	HighestPriority model.Priority `json:"highestPriority"`
	KEV             bool           `json:"kev"`
	KEVAdded        string         `json:"kevAdded,omitempty"`
	EPSS            float64        `json:"epss"`
	EPSSPercentile  float64        `json:"epssPercentile"`
	Owners          int            `json:"owners"`
	FindingCount    int            `json:"findingCount"`
	FixAvailable    bool           `json:"fixAvailable"`
	Malicious       bool           `json:"malicious"`
	Withdrawn       bool           `json:"withdrawn"`
	Published       *time.Time     `json:"published,omitempty"`
}

type VulnerabilityDetail struct {
	VulnerabilityView
	Links    []string      `json:"links"`
	Findings []FindingView `json:"findings"`
	// Uncatalogued counts the in-use images with no catalogue, which no finding can cover.
	Uncatalogued int `json:"uncatalogued"`
}

// HealthView is what limits ffs's view: feeds past their staleness threshold (or never synced) and
// the in-use container images it has not catalogued.
type HealthView struct {
	StaleFeeds         []FeedView `json:"staleFeeds"`
	ImagesCatalogued   int        `json:"imagesCatalogued"`
	ImagesUncatalogued int        `json:"imagesUncatalogued"`
}

type ManagedByView struct {
	Tool      string `json:"tool"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type ContainerView struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Image    string `json:"image"`
	Repo     string `json:"repo"`
	Digest   string `json:"digest,omitempty"`
	Platform string `json:"platform,omitempty"`
}

// OwnerView deliberately has no pull-secret field.
type OwnerView struct {
	ID                    string                 `json:"id"`
	Path                  string                 `json:"path"`
	Kind                  string                 `json:"kind"`
	Namespace             string                 `json:"namespace"`
	Name                  string                 `json:"name"`
	ManagedBy             *ManagedByView         `json:"managedBy,omitempty"`
	NotRunning            bool                   `json:"notRunning"`
	ServiceAccount        string                 `json:"serviceAccount,omitempty"`
	Exposed               bool                   `json:"exposed"`
	ExposurePaths         []string               `json:"exposurePaths"`
	Privileged            bool                   `json:"privileged"`
	PrivilegeReasons      []string               `json:"privilegeReasons"`
	PowerfulServiceAcct   bool                   `json:"powerfulServiceAccount"`
	ServiceAccountReasons []string               `json:"serviceAccountReasons"`
	Arch                  []string               `json:"arch"`
	Containers            []ContainerView        `json:"containers"`
	Counts                map[model.Priority]int `json:"counts"` // open findings by priority
	// Images counts the owner's container images; ImagesCatalogued those catalogued. Counts cover
	// only the catalogued ones.
	Images           int        `json:"images"`
	ImagesCatalogued int        `json:"imagesCatalogued"`
	UpdatedAt        *time.Time `json:"updatedAt,omitempty"`
}

type OwnerDetail struct {
	OwnerView
	CoverageNotes []string         `json:"coverageNotes"`
	Findings      []FindingView    `json:"findings"` // open and excepted
	Suggestions   []SuggestionView `json:"suggestions"`
}

type CoverageView struct {
	UnattributedElf      int      `json:"unattributedElf"`
	RustWithoutAuditable int      `json:"rustWithoutAuditable"`
	Notes                []string `json:"notes"`
}

// ImageView has exactly these keys.
type ImageView struct {
	ID                string       `json:"id"`
	Repo              string       `json:"repo"`
	Platform          string       `json:"platform"`
	IndexDigest       string       `json:"indexDigest"`
	Status            string       `json:"status"`
	StatusReason      string       `json:"statusReason"`
	Source            string       `json:"source"`
	VersionAnnotation string       `json:"versionAnnotation"`
	PartialCoverage   bool         `json:"partialCoverage"`
	Coverage          CoverageView `json:"coverage"`
	CataloguedAt      *time.Time   `json:"cataloguedAt"`
	Owners            []string     `json:"owners"` // owner keys
}

type PackageView struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Ecosystem  string `json:"ecosystem"`
	Classifier string `json:"classifier,omitempty"`
	Path       string `json:"path,omitempty"`
}

type ImageDetail struct {
	ImageView
	Packages []PackageView `json:"packages"`
	EOL      []EOLView     `json:"eol"`
}

// EOLView is the end-of-life position of a product version.
type EOLView struct {
	Product string `json:"product"`
	Cycle   string `json:"cycle"`
	EOLDate string `json:"eolDate"`
	IsEOL   bool   `json:"isEol"`
	Latest  string `json:"latest"`
	Note    string `json:"note"`
	Text    string `json:"text"`
}

type NodeView struct {
	Name                    string     `json:"name"`
	OS                      string     `json:"os"`
	Arch                    string     `json:"arch"`
	OSImage                 string     `json:"osImage"`
	OSEOL                   *EOLView   `json:"osEol,omitempty"`
	KernelVersion           string     `json:"kernelVersion"`
	KubeletVersion          string     `json:"kubeletVersion"`
	ContainerRuntimeVersion string     `json:"containerRuntimeVersion"`
	Ready                   bool       `json:"ready"`
	UpdatedAt               *time.Time `json:"updatedAt,omitempty"`
}

type KubernetesVersionView struct {
	Version string   `json:"version"`
	Nodes   int      `json:"nodes"`
	EOL     *EOLView `json:"eol,omitempty"`
}

type RuntimeView struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Nodes   int      `json:"nodes"`
	EOL     *EOLView `json:"eol,omitempty"`
}

type NodeOSView struct {
	OSImage string   `json:"osImage"`
	Nodes   int      `json:"nodes"`
	EOL     *EOLView `json:"eol,omitempty"`
}

type ClusterView struct {
	Name          string                  `json:"name"`
	Distribution  string                  `json:"distribution"`
	Version       string                  `json:"version"`
	GitVersion    string                  `json:"gitVersion"`
	LowConfidence bool                    `json:"lowConfidence"`
	Kubernetes    []KubernetesVersionView `json:"kubernetes"`
	Runtimes      []RuntimeView           `json:"runtimes"`
	NodeOS        []NodeOSView            `json:"nodeOs"`
	Suggestions   []SuggestionView        `json:"suggestions"`
	CoverageNotes []string                `json:"coverageNotes"`
}

// SuggestionView is keyed by Owner (an owner key) and Repo.
type SuggestionView struct {
	Owner        string                 `json:"owner,omitempty"`
	Repo         string                 `json:"repo"`
	FromTag      string                 `json:"fromTag"`
	ToTag        string                 `json:"toTag"`
	ToDigest     string                 `json:"toDigest,omitempty"`
	Tier         model.Tier             `json:"tier"`
	Target       string                 `json:"target"`
	NetChange    string                 `json:"netChange"`
	Fixes        map[model.Priority]int `json:"fixes"`
	Remaining    map[model.Priority]int `json:"remaining"`
	Introduces   map[model.Priority]int `json:"introduces"`
	FixedIDs     []string               `json:"fixedIds"`
	Alternatives []SuggestionView       `json:"alternatives"`
	EOL          string                 `json:"eol,omitempty"`
	Notes        []string               `json:"notes"`
	ComputedAt   *time.Time             `json:"computedAt,omitempty"`
}

type ExceptionView struct {
	ID                string    `json:"id"` // namespace/name
	Namespace         string    `json:"namespace"`
	Name              string    `json:"name"`
	Reason            string    `json:"reason"`
	Expires           time.Time `json:"expires"`
	Advisories        []string  `json:"advisories"`
	Packages          []string  `json:"packages"`
	ImageRepositories []string  `json:"imageRepositories"`
	Owners            []string  `json:"owners"`
	VEXStatus         string    `json:"vexStatus,omitempty"`
	Justification     string    `json:"justification,omitempty"`
	MatchedFindings   int       `json:"matchedFindings"`
	UrgentNotExcepted int       `json:"urgentNotExcepted"`
	Expired           bool      `json:"expired"`
}

type FeedView struct {
	Name        string     `json:"name"`
	LastSuccess *time.Time `json:"lastSuccess"`
	LastAttempt *time.Time `json:"lastAttempt"`
	LastError   string     `json:"lastError"`
	StaleAfter  string     `json:"staleAfter"` // Go duration
	Stale       bool       `json:"stale"`
}

type PackageHit struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Ecosystem string   `json:"ecosystem"`
	Owners    []string `json:"owners"`
}

type AdvisoryHit struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type ImageHit struct {
	ID     string   `json:"id"`
	Repo   string   `json:"repo"`
	Owners []string `json:"owners"`
}

// SearchResult holds the hits of each kind. Uncatalogued counts the in-use images with no
// catalogue, whose packages no search can find.
type SearchResult struct {
	Query        string        `json:"query"`
	Packages     []PackageHit  `json:"packages"`
	Advisories   []AdvisoryHit `json:"advisories"`
	Images       []ImageHit    `json:"images"`
	Uncatalogued int           `json:"uncatalogued"`
	// Truncated is true when any kind had more than searchLimit matches and was cut short.
	Truncated bool `json:"truncated"`
}

// ---- helpers ----

func nz[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func utc(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func countMap(m map[model.Priority]int) map[model.Priority]int {
	out := map[model.Priority]int{}
	for p, n := range m {
		if n > 0 {
			out[p] = n
		}
	}
	return out
}

func ownerKey(q string) string {
	if parts := strings.SplitN(q, "/", 3); len(parts) == 3 {
		return ParseOwnerPath(parts[0], parts[1], parts[2]).Key()
	}
	return q
}

func (s *Service) eolView(pv eol.ProductVersion) *EOLView {
	if s.o.EOL == nil {
		return nil
	}
	st, ok := s.o.EOL.Evaluate(pv.Product, pv.Version)
	if !ok {
		return nil
	}
	v := s.statusView(st)
	return &v
}

func (s *Service) statusView(st eol.Status) EOLView {
	v := EOLView{Product: st.Product, Cycle: st.Cycle, IsEOL: st.IsEOL, Latest: st.Latest, Note: st.Note,
		Text: eol.Text(st, s.o.Now())}
	if st.EOLDate != nil {
		v.EOLDate = st.EOLDate.UTC().Format(dateFmt)
	}
	return v
}

// ---- findings ----

func (s *Service) findingViews(ctx context.Context, fs []model.Finding) ([]FindingView, error) {
	ids := make([]string, 0, len(fs))
	for _, f := range fs {
		ids = append(ids, f.AdvisoryID)
	}
	advs, err := s.o.Store.Advisories(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]FindingView, 0, len(fs))
	for _, f := range fs {
		v := FindingView{
			ID: f.Fingerprint, Owner: f.Owner.Key(), OwnerPath: OwnerPath(f.Owner), Repo: f.ImageRepo, Advisory: f.AdvisoryID,
			Severity: f.Severity, SeveritySource: f.SeveritySource, Priority: f.Priority, Reasons: nz(f.Reasons), State: f.State,
			ExceptedBy: f.ExceptedBy, FixState: f.FixState, FixAvailable: f.FixAvailable, Provisional: f.Provisional,
			Digests: nz(f.Digests), Published: utc(f.Published), Observed: utc(f.Observed), Matched: utc(f.Matched),
			LastSeen: utc(f.LastSeen), Packages: []FindingPackageView{},
		}
		if f.ResolvedAt != nil {
			v.ResolvedAt = utc(*f.ResolvedAt)
		}
		if a, ok := advs[f.AdvisoryID]; ok {
			v.Title = a.Title
			if a.KEVAdded != nil {
				v.KEV, v.KEVAdded = true, a.KEVAdded.UTC().Format(dateFmt)
			}
		}
		for _, p := range f.Packages {
			v.Packages = append(v.Packages, FindingPackageView{Name: p.Name, Ecosystem: p.Ecosystem, Installed: p.Installed,
				Path: p.Path, Fixed: nz(p.Fixed)})
		}
		if f.Suggestion != nil {
			sv := suggestionView(f.Owner.Key(), *f.Suggestion)
			v.Suggestion = &sv
		}
		out = append(out, v)
	}
	return out, nil
}

// Findings lists findings, newest priority first, with the total before paging.
func (s *Service) Findings(ctx context.Context, q FindingQuery) (Page[FindingView], error) {
	limit := q.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	limit = min(limit, maxLimit)
	offset := max(q.Offset, 0)
	f := store.FindingFilter{States: q.States, MinPriority: q.MinPriority, Namespace: q.Namespace}
	if q.Owner != "" {
		f.OwnerKey = ownerKey(q.Owner)
	}
	if q.Advisory != "" {
		canon, err := s.o.Store.Canonical(ctx, q.Advisory)
		if err != nil {
			return Page[FindingView]{}, err
		}
		f.AdvisoryIDs = []string{canon}
	}
	total, err := s.o.Store.CountFindings(ctx, f)
	if err != nil {
		return Page[FindingView]{}, err
	}
	f.Limit, f.Offset = limit, offset
	fs, err := s.o.Store.ListFindings(ctx, f)
	if err != nil {
		return Page[FindingView]{}, err
	}
	items, err := s.findingViews(ctx, fs)
	if err != nil {
		return Page[FindingView]{}, err
	}
	return Page[FindingView]{Cluster: s.ClusterName(), Items: items, Total: total, Limit: limit, Offset: offset}, nil
}

// Finding returns the finding with the given fingerprint.
func (s *Service) Finding(ctx context.Context, id string) (FindingView, bool, error) {
	f, ok, err := s.o.Store.GetFinding(ctx, id)
	if err != nil || !ok {
		return FindingView{}, false, err
	}
	vs, err := s.findingViews(ctx, []model.Finding{f})
	if err != nil {
		return FindingView{}, false, err
	}
	return vs[0], true, nil
}

// ---- vulnerabilities ----

var openOnly = []model.FindingState{model.StateOpen}

func vulnerabilityView(a model.Advisory, haveAdvisory bool, r store.AdvisoryRollup) VulnerabilityView {
	v := VulnerabilityView{ID: r.AdvisoryID, Aliases: []string{}, HighestPriority: r.HighestPriority, Severity: r.Severity,
		Owners: r.Owners, FindingCount: r.Findings, FixAvailable: r.FixAvailable}
	if haveAdvisory {
		v.Aliases, v.Title = nz(a.Aliases), a.Title
		v.EPSS, v.EPSSPercentile = a.EPSS, a.EPSSPercentile
		v.Malicious, v.Withdrawn = a.Malicious, a.Withdrawn
		v.Published = utc(a.Published)
		if a.KEVAdded != nil {
			v.KEV, v.KEVAdded = true, a.KEVAdded.UTC().Format(dateFmt)
		}
	}
	return v
}

// rollup summarises the open findings fs of advisory id, as store.OpenAdvisoryRollups does.
func rollup(id string, fs []model.Finding) store.AdvisoryRollup {
	r := store.AdvisoryRollup{AdvisoryID: id, Findings: len(fs)}
	owners := map[string]bool{}
	for _, f := range fs {
		owners[f.Owner.Key()] = true
		r.HighestPriority = max(r.HighestPriority, f.Priority)
		r.Severity = max(r.Severity, f.Severity)
		r.FixAvailable = r.FixAvailable || f.FixAvailable
	}
	r.Owners = len(owners)
	return r
}

// Vulnerabilities aggregates open findings by advisory: highest priority first, then most owners.
// The counts come from a SQL rollup, so no finding is decoded.
func (s *Service) Vulnerabilities(ctx context.Context) ([]VulnerabilityView, error) {
	rs, err := s.o.Store.OpenAdvisoryRollups(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(rs))
	for _, r := range rs {
		ids = append(ids, r.AdvisoryID)
	}
	advs, err := s.o.Store.Advisories(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]VulnerabilityView, 0, len(rs))
	for _, r := range rs {
		a, ok := advs[r.AdvisoryID]
		out = append(out, vulnerabilityView(a, ok, r))
	}
	slices.SortFunc(out, func(a, b VulnerabilityView) int {
		return cmp.Or(cmp.Compare(b.HighestPriority, a.HighestPriority), cmp.Compare(b.Owners, a.Owners), cmp.Compare(a.ID, b.ID))
	})
	return out, nil
}

// Vulnerability returns an advisory by canonical id or alias, with its open findings.
func (s *Service) Vulnerability(ctx context.Context, id string) (VulnerabilityDetail, bool, error) {
	a, ok, err := s.o.Store.GetAdvisory(ctx, id)
	if err != nil {
		return VulnerabilityDetail{}, false, err
	}
	canon := a.ID
	if !ok {
		if canon, err = s.o.Store.Canonical(ctx, id); err != nil {
			return VulnerabilityDetail{}, false, err
		}
	}
	fs, err := s.o.Store.ListFindings(ctx, store.FindingFilter{States: openOnly, AdvisoryIDs: []string{canon}})
	if err != nil {
		return VulnerabilityDetail{}, false, err
	}
	if !ok && len(fs) == 0 {
		return VulnerabilityDetail{}, false, nil
	}
	fvs, err := s.findingViews(ctx, fs)
	if err != nil {
		return VulnerabilityDetail{}, false, err
	}
	_, uncatalogued, err := s.o.Store.InUseImageCoverage(ctx)
	if err != nil {
		return VulnerabilityDetail{}, false, err
	}
	return VulnerabilityDetail{VulnerabilityView: vulnerabilityView(a, ok, rollup(canon, fs)), Links: nz(a.Links), Findings: fvs,
		Uncatalogued: uncatalogued}, true, nil
}

// ---- images ----

const (
	noteCPE           = "daily, CPE-based coverage only: "
	noteNotCatalogued = "image not catalogued yet: "
	noteNotResolved   = "image not resolved yet: "
)

// imageView shapes img. pkgs are its packages, or only the classified ones (store.ClassifiedPackages):
// the read-time coverage note looks at nothing else.
func imageView(img model.Image, owners []string, pkgs []model.Package) ImageView {
	notes := slices.Clone(img.Coverage.Notes)
	if names := upstream.UncoveredClassified(pkgs); len(names) > 0 {
		notes = append(notes, noteCPE+strings.Join(names, ", "))
	}
	return ImageView{
		ID: img.Digest, Repo: img.Repo, Platform: img.Platform, IndexDigest: img.IndexDigest, Status: string(img.Status),
		StatusReason: img.StatusReason, Source: img.Source, VersionAnnotation: img.VersionAnnotation,
		PartialCoverage: img.Coverage.UnattributedELF > 0 || img.Coverage.RustWithoutAuditable > 0 || len(notes) > 0,
		Coverage: CoverageView{UnattributedElf: img.Coverage.UnattributedELF, RustWithoutAuditable: img.Coverage.RustWithoutAuditable,
			Notes: nz(notes)},
		CataloguedAt: utc(img.CataloguedAt), Owners: nz(owners),
	}
}

// digestOwners maps each digest an owner runs to the sorted keys of the owners running it.
func digestOwners(owners []model.Owner) map[string][]string {
	m := map[string][]string{}
	for _, o := range owners {
		for _, c := range o.Containers {
			if c.Digest != "" && !slices.Contains(m[c.Digest], o.Ref.Key()) {
				m[c.Digest] = append(m[c.Digest], o.Ref.Key())
			}
		}
	}
	return m
}

// Images lists the images an owner runs, including the synthetic cluster and runtime ones.
func (s *Service) Images(ctx context.Context) ([]ImageView, error) {
	owners, err := s.o.Store.ListOwners(ctx)
	if err != nil {
		return nil, err
	}
	running := digestOwners(owners)
	imgs, err := s.o.Store.ListImages(ctx, store.ImageFilter{})
	if err != nil {
		return nil, err
	}
	classified, err := s.o.Store.ClassifiedPackages(ctx, slices.Collect(maps.Keys(running)))
	if err != nil {
		return nil, err
	}
	out := []ImageView{}
	for _, img := range imgs {
		if _, ok := running[img.Digest]; !ok {
			continue
		}
		out = append(out, imageView(img, running[img.Digest], classified[img.Digest]))
	}
	return out, nil
}

// Image returns one image with its packages and the lifecycle of its distro and runtimes.
func (s *Service) Image(ctx context.Context, digest string) (ImageDetail, bool, error) {
	img, ok, err := s.o.Store.GetImage(ctx, digest)
	if err != nil || !ok {
		return ImageDetail{}, false, err
	}
	owners, err := s.o.Store.OwnersForDigests(ctx, []string{digest})
	if err != nil {
		return ImageDetail{}, false, err
	}
	pkgs, err := s.o.Store.PackagesForImage(ctx, digest)
	if err != nil {
		return ImageDetail{}, false, err
	}
	d := ImageDetail{ImageView: imageView(img, owners, pkgs), Packages: []PackageView{}, EOL: []EOLView{}}
	for _, p := range pkgs {
		d.Packages = append(d.Packages, PackageView{Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem,
			Classifier: p.Classifier, Path: p.Path})
	}
	if s.o.EOL != nil {
		for _, st := range s.o.EOL.ImageEOL(img.Repo, pkgs) {
			d.EOL = append(d.EOL, s.statusView(st))
		}
	}
	return d, true, nil
}

// ---- owners ----

// containerDigests lists the distinct digests the owners' containers run.
func containerDigests(owners ...model.Owner) []string {
	var out []string
	for _, o := range owners {
		for _, c := range o.Containers {
			if c.Digest != "" && !slices.Contains(out, c.Digest) {
				out = append(out, c.Digest)
			}
		}
	}
	return out
}

// imageCounts counts o's container images, one per distinct digest and one per container with no
// digest yet, and how many of them statuses has as catalogued.
func imageCounts(o model.Owner, statuses map[string]model.ImageStatus) (images, catalogued int) {
	seen := map[string]bool{}
	for _, c := range o.Containers {
		if c.Digest != "" && seen[c.Digest] {
			continue
		}
		seen[c.Digest] = true
		images++
		if c.Digest != "" && statuses[c.Digest] == model.ImageCatalogued {
			catalogued++
		}
	}
	return images, catalogued
}

func ownerView(o model.Owner, counts map[model.Priority]int, statuses map[string]model.ImageStatus) OwnerView {
	v := OwnerView{
		ID: o.Ref.Key(), Path: OwnerPath(o.Ref), Kind: o.Ref.Kind, Namespace: o.Ref.Namespace, Name: o.Ref.Name,
		NotRunning: o.NotRunning, ServiceAccount: o.ServiceAccount, Exposed: o.Context.Exposed,
		ExposurePaths: nz(o.Context.ExposurePaths), Privileged: o.Context.Privileged,
		PrivilegeReasons: nz(o.Context.PrivilegeReasons), PowerfulServiceAcct: o.Context.PowerfulSA,
		ServiceAccountReasons: nz(o.Context.SAReasons), Arch: nz(o.Arch), Containers: []ContainerView{},
		Counts: countMap(counts), UpdatedAt: utc(o.UpdatedAt),
	}
	v.Images, v.ImagesCatalogued = imageCounts(o, statuses)
	if m := o.ManagedBy; m != nil {
		v.ManagedBy = &ManagedByView{Tool: m.Tool, Name: m.Name, Namespace: m.Namespace}
	}
	for _, c := range o.Containers {
		v.Containers = append(v.Containers, ContainerView{Name: c.Name, Kind: string(c.Kind), Image: c.ImageRef, Repo: c.Repo,
			Digest: c.Digest, Platform: c.Platform})
	}
	return v
}

// Owners lists every owner with its open finding counts, which come from a SQL rollup.
func (s *Service) Owners(ctx context.Context) ([]OwnerView, error) {
	owners, err := s.o.Store.ListOwners(ctx)
	if err != nil {
		return nil, err
	}
	counts, err := s.o.Store.OpenCountsByOwner(ctx)
	if err != nil {
		return nil, err
	}
	statuses, err := s.o.Store.ImageStatuses(ctx, containerDigests(owners...))
	if err != nil {
		return nil, err
	}
	out := make([]OwnerView, 0, len(owners))
	for _, o := range owners {
		out = append(out, ownerView(o, counts[o.Ref.Key()], statuses))
	}
	return out, nil
}

// OwnerViews returns the views of the owners stored under keys, by key; keys with no owner are
// left out. It reads only those owners, for pages that show a few of them.
func (s *Service) OwnerViews(ctx context.Context, keys []string) (map[string]OwnerView, error) {
	counts, err := s.o.Store.OpenCountsByOwner(ctx)
	if err != nil {
		return nil, err
	}
	var owners []model.Owner
	for _, k := range keys {
		o, ok, err := s.o.Store.GetOwner(ctx, k)
		if err != nil {
			return nil, err
		}
		if ok {
			owners = append(owners, o)
		}
	}
	statuses, err := s.o.Store.ImageStatuses(ctx, containerDigests(owners...))
	if err != nil {
		return nil, err
	}
	out := make(map[string]OwnerView, len(owners))
	for _, o := range owners {
		out[o.Ref.Key()] = ownerView(o, counts[o.Ref.Key()], statuses)
	}
	return out, nil
}

// Owner returns one owner with its findings, suggestions and the notes on how completely its
// images were covered.
func (s *Service) Owner(ctx context.Context, ref model.OwnerRef) (OwnerDetail, bool, error) {
	key := ref.Key()
	o, ok, err := s.o.Store.GetOwner(ctx, key)
	if err != nil || !ok {
		return OwnerDetail{}, false, err
	}
	fs, err := s.o.Store.ListFindings(ctx, store.FindingFilter{OwnerKey: key,
		States: []model.FindingState{model.StateOpen, model.StateExcepted}})
	if err != nil {
		return OwnerDetail{}, false, err
	}
	counts := map[model.Priority]int{}
	for _, f := range fs {
		if f.State == model.StateOpen {
			counts[f.Priority]++
		}
	}
	fvs, err := s.findingViews(ctx, fs)
	if err != nil {
		return OwnerDetail{}, false, err
	}
	notes, err := s.ownerCoverageNotes(ctx, o)
	if err != nil {
		return OwnerDetail{}, false, err
	}
	sugs, err := s.suggestionViews(ctx, func(k string) bool { return k == key })
	if err != nil {
		return OwnerDetail{}, false, err
	}
	statuses, err := s.o.Store.ImageStatuses(ctx, containerDigests(o))
	if err != nil {
		return OwnerDetail{}, false, err
	}
	return OwnerDetail{OwnerView: ownerView(o, counts, statuses), CoverageNotes: notes, Findings: fvs, Suggestions: sugs}, true, nil
}

// ownerCoverageNotes is the de-duplicated union of its images' coverage notes, plus why any of
// them has no catalogue (not resolved yet, not catalogued yet, unresolvable or failed), so an owner
// whose images were never catalogued does not read as one with no findings.
func (s *Service) ownerCoverageNotes(ctx context.Context, o model.Owner) ([]string, error) {
	var notes []string
	add := func(n string) {
		if n != "" && !slices.Contains(notes, n) {
			notes = append(notes, n)
		}
	}
	var digests []string
	for _, c := range o.Containers {
		if c.Digest != "" {
			digests = append(digests, c.Digest)
		}
	}
	classified, err := s.o.Store.ClassifiedPackages(ctx, digests)
	if err != nil {
		return nil, err
	}
	for _, c := range o.Containers {
		if c.Digest == "" {
			add(noteNotResolved + cmp.Or(c.ImageRef, c.Repo, c.Name))
			continue
		}
		img, ok, err := s.o.Store.GetImage(ctx, c.Digest)
		if err != nil {
			return nil, err
		}
		if !ok {
			add(noteNotCatalogued + cmp.Or(c.Repo, c.ImageRef, c.Digest))
			continue
		}
		for _, n := range imageView(img, nil, classified[c.Digest]).Coverage.Notes {
			add(n)
		}
		switch img.Status {
		case model.ImagePending:
			add(noteNotCatalogued + cmp.Or(img.Repo, c.Repo, c.Digest))
		case model.ImageUnresolvable:
			add(cmp.Or(img.StatusReason, "image could not be resolved"))
		case model.ImageCatalogFailed:
			add(cmp.Or(img.StatusReason, "image could not be catalogued"))
		}
	}
	return nz(notes), nil
}

// ---- nodes and cluster ----

func (s *Service) nodeView(n model.Node) NodeView {
	v := NodeView{Name: n.Name, OS: n.OS, Arch: n.Arch, OSImage: n.OSImage, KernelVersion: n.KernelVersion,
		KubeletVersion: n.KubeletVersion, ContainerRuntimeVersion: n.ContainerRuntimeVersion, Ready: n.Ready, UpdatedAt: utc(n.UpdatedAt)}
	if pv, ok := eol.NodeOSProduct(n.OSImage); ok {
		v.OSEOL = s.eolView(pv)
	}
	return v
}

// Nodes lists the nodes, by name.
func (s *Service) Nodes(ctx context.Context) ([]NodeView, error) {
	nodes, err := s.o.Store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]NodeView, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, s.nodeView(n))
	}
	return out, nil
}

// Node returns one node by name.
func (s *Service) Node(ctx context.Context, name string) (NodeView, bool, error) {
	nodes, err := s.o.Store.ListNodes(ctx)
	if err != nil {
		return NodeView{}, false, err
	}
	for _, n := range nodes {
		if n.Name == name {
			return s.nodeView(n), true, nil
		}
	}
	return NodeView{}, false, nil
}

// Cluster summarises the control plane, the Kubernetes versions and container runtimes in use, and
// their lifecycle.
func (s *Service) Cluster(ctx context.Context) (ClusterView, error) {
	ci, _, err := s.o.Store.GetClusterInfo(ctx)
	if err != nil {
		return ClusterView{}, err
	}
	nodes, err := s.o.Store.ListNodes(ctx)
	if err != nil {
		return ClusterView{}, err
	}
	owners, err := s.o.Store.ListOwners(ctx)
	if err != nil {
		return ClusterView{}, err
	}
	v := ClusterView{Name: s.ClusterName(), Distribution: ci.Distribution, Version: ci.Version, GitVersion: ci.GitVersion,
		LowConfidence: ci.LowConfidence, Kubernetes: []KubernetesVersionView{}, Runtimes: []RuntimeView{}, NodeOS: []NodeOSView{}}

	kubelets := map[string]int{}
	type rt struct{ name, version string }
	runtimes := map[rt]int{}
	osImages := map[string]int{}
	for _, n := range nodes {
		if ver, _, _, err := inventory.NormalizeK8sVersion(n.KubeletVersion); err == nil {
			kubelets[ver]++
		}
		if name, ver, ok := inventory.ParseRuntimeVersion(n.ContainerRuntimeVersion); ok {
			runtimes[rt{name, ver}]++
		}
		osImages[n.OSImage]++
	}
	var versions []string
	for _, o := range owners {
		if o.Ref.Kind != "Cluster" {
			continue
		}
		for _, c := range o.Containers {
			if ver, ok := strings.CutPrefix(c.Digest, "k8s:"); ok && !slices.Contains(versions, ver) {
				versions = append(versions, ver)
			}
		}
	}
	slices.Sort(versions)
	for _, ver := range versions {
		v.Kubernetes = append(v.Kubernetes, KubernetesVersionView{Version: ver, Nodes: kubelets[ver],
			EOL: s.eolView(eol.ClusterProduct(ci.Distribution, ver))})
	}
	rts := make([]rt, 0, len(runtimes))
	for k := range runtimes {
		rts = append(rts, k)
	}
	slices.SortFunc(rts, func(a, b rt) int { return cmp.Or(cmp.Compare(a.name, b.name), cmp.Compare(a.version, b.version)) })
	for _, k := range rts {
		rv := RuntimeView{Name: k.name, Version: k.version, Nodes: runtimes[k]}
		if pv, ok := eol.ContainerRuntimeProduct(k.name, k.version); ok {
			rv.EOL = s.eolView(pv)
		}
		v.Runtimes = append(v.Runtimes, rv)
	}
	names := make([]string, 0, len(osImages))
	for k := range osImages {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, img := range names {
		ov := NodeOSView{OSImage: img, Nodes: osImages[img]}
		if pv, ok := eol.NodeOSProduct(img); ok {
			ov.EOL = s.eolView(pv)
		}
		v.NodeOS = append(v.NodeOS, ov)
	}

	v.Suggestions, err = s.suggestionViews(ctx, func(k string) bool {
		return strings.HasPrefix(k, "Cluster/") || strings.HasPrefix(k, "ContainerRuntime/")
	})
	if err != nil {
		return ClusterView{}, err
	}
	imgs, err := s.o.Store.ListImages(ctx, store.ImageFilter{})
	if err != nil {
		return ClusterView{}, err
	}
	var notes []string
	for _, img := range imgs {
		if !strings.HasPrefix(img.Digest, "k8s:") && !strings.HasPrefix(img.Digest, "runtime:") {
			continue
		}
		for _, n := range img.Coverage.Notes {
			if !slices.Contains(notes, n) {
				notes = append(notes, n)
			}
		}
	}
	v.CoverageNotes = nz(notes)
	return v, nil
}

// ---- suggestions, exceptions, feeds ----

func suggestionView(owner string, sg model.Suggestion) SuggestionView {
	v := SuggestionView{
		Owner: owner, Repo: sg.Repo, FromTag: sg.FromTag, ToTag: sg.ToTag, ToDigest: sg.ToDigest, Tier: sg.Tier,
		Target: upgrade.Target(sg), NetChange: upgrade.NetChange(sg),
		Fixes: countMap(sg.Fixes), Remaining: countMap(sg.Remaining), Introduces: countMap(sg.Introduces),
		FixedIDs: nz(sg.FixedIDs), Alternatives: []SuggestionView{}, EOL: sg.EOL, Notes: nz(sg.Notes), ComputedAt: utc(sg.ComputedAt),
	}
	for _, alt := range sg.Alternatives {
		v.Alternatives = append(v.Alternatives, suggestionView("", alt))
	}
	return v
}

func (s *Service) suggestionViews(ctx context.Context, keep func(ownerKey string) bool) ([]SuggestionView, error) {
	list, err := s.o.Store.ListSuggestions(ctx)
	if err != nil {
		return nil, err
	}
	out := []SuggestionView{}
	for _, os := range list {
		if keep(os.OwnerKey) {
			out = append(out, suggestionView(os.OwnerKey, os.Suggestion))
		}
	}
	return out, nil
}

// Suggestions lists every upgrade suggestion, by owner and repository.
func (s *Service) Suggestions(ctx context.Context) ([]SuggestionView, error) {
	return s.suggestionViews(ctx, func(string) bool { return true })
}

// Exceptions lists the Exception resources, by namespace and name.
func (s *Service) Exceptions(ctx context.Context) ([]ExceptionView, error) {
	out := []ExceptionView{}
	if s.o.Kube == nil {
		return out, nil
	}
	var list v1alpha1.ExceptionList
	if err := s.o.Kube.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list exceptions: %w", err)
	}
	for _, e := range list.Items {
		out = append(out, ExceptionView{
			ID: e.Namespace + "/" + e.Name, Namespace: e.Namespace, Name: e.Name, Reason: e.Spec.Reason,
			Expires: e.Spec.Expires.UTC(), Advisories: nz(e.Spec.Advisories), Packages: nz(e.Spec.Packages),
			ImageRepositories: nz(e.Spec.ImageRepositories), Owners: nz(e.Spec.Owners), VEXStatus: e.Spec.VEXStatus,
			Justification: e.Spec.Justification, MatchedFindings: int(e.Status.MatchedFindings),
			UrgentNotExcepted: int(e.Status.UrgentNotExcepted), Expired: e.Status.Expired,
		})
	}
	slices.SortFunc(out, func(a, b ExceptionView) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}

// Feeds lists the registered feeds with their last sync and whether it is stale.
func (s *Service) Feeds(ctx context.Context) ([]FeedView, error) {
	now := s.o.Now()
	out := make([]FeedView, 0, len(s.o.Feeds))
	for _, f := range s.o.Feeds {
		st, err := s.o.Store.FeedState(ctx, f.Name)
		if err != nil {
			return nil, err
		}
		out = append(out, FeedView{
			Name: f.Name, LastSuccess: utc(st.LastSuccess), LastAttempt: utc(st.LastAttempt), LastError: st.LastError,
			StaleAfter: f.StaleAfter.String(), Stale: st.LastSuccess.IsZero() || now.Sub(st.LastSuccess) > f.StaleAfter,
		})
	}
	return out, nil
}

// Health reports what limits ffs's view: the stale or never-synced feeds, and how many of the
// in-use container images are catalogued. A page that reports no findings shows it first.
func (s *Service) Health(ctx context.Context) (HealthView, error) {
	feeds, err := s.Feeds(ctx)
	if err != nil {
		return HealthView{}, err
	}
	h := HealthView{StaleFeeds: []FeedView{}}
	for _, f := range feeds {
		if f.Stale {
			h.StaleFeeds = append(h.StaleFeeds, f)
		}
	}
	h.ImagesCatalogued, h.ImagesUncatalogued, err = s.o.Store.InUseImageCoverage(ctx)
	return h, err
}

// ---- search ----

// Search finds packages, advisories and images matching q. A non-empty lt keeps only package hits
// whose version is below it.
func (s *Service) Search(ctx context.Context, q, lt string) (SearchResult, error) {
	// Fetch one past the cap so truncation is detectable. With lt the version filter runs after
	// the store's per-kind LIMIT, so pull everything and cap once the filter has been applied.
	fetch := searchLimit + 1
	if lt != "" {
		fetch = searchFetchAll
	}
	hits, err := s.o.Store.Search(ctx, q, fetch)
	if err != nil {
		return SearchResult{}, err
	}
	res := SearchResult{Query: q, Packages: []PackageHit{}, Advisories: []AdvisoryHit{}, Images: []ImageHit{}}
	kept := map[string]int{}
	for _, h := range hits {
		if h.Kind == "package" && lt != "" && upstream.CompareVersions(h.Version, lt) >= 0 {
			continue
		}
		if kept[h.Kind] >= searchLimit {
			res.Truncated = true
			continue
		}
		kept[h.Kind]++
		if h.Kind == "advisory" {
			res.Advisories = append(res.Advisories, AdvisoryHit{ID: h.ID, Title: h.Label})
			continue
		}
		owners, err := s.o.Store.OwnersForDigests(ctx, h.Digests)
		if err != nil {
			return SearchResult{}, err
		}
		if h.Kind == "package" {
			res.Packages = append(res.Packages, PackageHit{Name: h.ID, Version: h.Version, Ecosystem: h.Ecosystem, Owners: nz(owners)})
		} else {
			res.Images = append(res.Images, ImageHit{ID: h.ID, Repo: h.Label, Owners: nz(owners)})
		}
	}
	if _, res.Uncatalogued, err = s.o.Store.InUseImageCoverage(ctx); err != nil {
		return SearchResult{}, err
	}
	return res, nil
}
