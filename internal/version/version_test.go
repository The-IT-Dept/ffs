package version

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUserAgent(t *testing.T) {
	require.Equal(t, "ffs/dev (+https://github.com/The-IT-Dept/ffs)", UserAgent())
}
