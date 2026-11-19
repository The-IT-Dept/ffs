package sbom

import (
	"bytes"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	syftsbom "github.com/anchore/syft/syft/sbom"
)

// EncodeSyftJSON serialises s as syft-json, the format ffs stores.
func EncodeSyftJSON(s *syftsbom.SBOM) ([]byte, error) {
	return format.Encode(*s, syftjson.NewFormatEncoder())
}

// DecodeSyftJSON parses a stored syft-json document.
func DecodeSyftJSON(b []byte) (*syftsbom.SBOM, error) {
	s, _, _, err := syftjson.NewFormatDecoder().Decode(bytes.NewReader(b))
	return s, err
}
