package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEncodeSyftJSON_Nil (F53): a nil SBOM is an error, not a panic.
func TestEncodeSyftJSON_Nil(t *testing.T) {
	b, err := EncodeSyftJSON(nil)
	require.ErrorIs(t, err, errNoSBOM)
	require.Nil(t, b)
}
