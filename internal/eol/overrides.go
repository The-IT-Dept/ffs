package eol

// override redirects or annotates a product endoflife.date does not track in the form ffs sees it.
type override struct {
	use     string // evaluate against this product's cycles instead
	note    string // no dated lifecycle: report the note instead
	rolling bool   // the cycle is "rolling" rather than a version prefix
}

var overrides = map[string]override{
	"k3s":          {use: "kubernetes"},
	"rke2":         {use: "kubernetes"},
	"distroless":   {use: "debian"},
	"wolfi":        {note: "rolling release", rolling: true},
	"chainguard":   {note: "rolling release", rolling: true},
	"flatcar":      {note: "rolling release", rolling: true},
	"bottlerocket": {note: "lifecycle follows the variant's Kubernetes version"},
	"talos":        {note: "security updates for the two latest minor releases"},
}
