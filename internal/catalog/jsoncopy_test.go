package catalog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// copyAll runs the copier over in and returns what it wrote.
func copyAll(in string) (string, error) {
	var out bytes.Buffer
	w := bufio.NewWriter(&out)
	c := &jsonCopier{r: bufio.NewReader(strings.NewReader(in))}
	err := c.copyValue(w)
	_ = w.Flush()
	return out.String(), err
}

func TestJSONCopier_CopiesValidDocumentsVerbatim(t *testing.T) {
	for _, doc := range []string{
		`{}`, `[]`, `""`, `0`, `-0`, `1.5`, `-12.25e-3`, `3E+10`, `true`, `false`, `null`,
		`{"a":1,"b":[true,false,null],"c":{"d":"e"}}`,
		`{ "spaced" : [ 1 , 2 ] , "x" : { } }`,
		`"escapes \" \\ \/ \b \f \n \r \t é 😀"`,
		`"unicode é and raw bytes"`,
		`[[[[[[[[[[1]]]]]]]]]]`,
	} {
		got, err := copyAll(doc)
		require.NoError(t, err, doc)
		require.Equal(t, doc, got, "a value is copied byte for byte")
		require.True(t, json.Valid([]byte(doc)), doc)
	}
	got, err := copyAll("  \n\t{\"a\":1}  trailing")
	require.NoError(t, err)
	require.Equal(t, `{"a":1}`, got, "leading space is skipped and nothing after the value is read into it")
}

func TestJSONCopier_RejectsWhatEncodingJSONRejects(t *testing.T) {
	for _, doc := range []string{
		`{"a" 1}`, `{"a":1,}`, `[1,]`, `[1 2]`, `{a:1}`, `{"a":1`, `[`, `"open`, `"\x"`, `"\u12g4"`, "\"a\x01b\"",
		`-`, `1.`, `1e`, `1e+`, `.5`, `+1`, `tru`, `nul`, `fals`, `}`, ``, `{"a":}`,
	} {
		_, err := copyAll(doc)
		require.Error(t, err, doc)
		require.False(t, json.Valid([]byte(doc)), doc)
		require.True(t, errors.Is(err, errJSONSyntax) || errors.Is(err, io.ErrUnexpectedEOF), "%q: %v", doc, err)
	}
	// "01" is a valid 0 followed by a stray 1; the copier stops after the 0 and the caller sees the 1.
	got, err := copyAll(`01`)
	require.NoError(t, err)
	require.Equal(t, "0", got)

	_, err = copyAll(strings.Repeat("[", maxJSONDepth+1) + strings.Repeat("]", maxJSONDepth+1))
	require.ErrorIs(t, err, errJSONSyntax, "nesting is bounded")
}

// failingWriter fails every write.
type failingWriter struct{}

func (failingWriter) WriteByte(byte) error { return errors.New("disk full") }

func TestJSONCopier_StopsAtWriteError(t *testing.T) {
	c := &jsonCopier{r: bufio.NewReader(strings.NewReader(`{"a":[1,2,3]}`))}
	err := c.copyValue(failingWriter{})
	require.EqualError(t, err, "disk full")
	require.EqualError(t, c.werr, "disk full")
}
