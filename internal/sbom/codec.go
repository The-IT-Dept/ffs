package sbom

import (
	"bytes"
	"errors"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	syftsbom "github.com/anchore/syft/syft/sbom"
)

// errNoSBOM is EncodeSyftJSON's error for a nil SBOM.
var errNoSBOM = errors.New("sbom: no SBOM to encode")

// EncodeSyftJSON serialises s as syft-json, the format ffs stores. A nil s is an error.
func EncodeSyftJSON(s *syftsbom.SBOM) ([]byte, error) {
	if s == nil {
		return nil, errNoSBOM
	}
	return format.Encode(*s, syftjson.NewFormatEncoder())
}

// DecodeSyftJSON parses a stored syft-json document.
func DecodeSyftJSON(b []byte) (*syftsbom.SBOM, error) {
	s, _, _, err := syftjson.NewFormatDecoder().Decode(bytes.NewReader(b))
	return s, err
}
