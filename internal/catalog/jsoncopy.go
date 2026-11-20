package catalog

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// maxJSONDepth bounds the nesting the copier follows, as encoding/json does.
const maxJSONDepth = 10000

// errJSONSyntax is a document that is not JSON.
var errJSONSyntax = errors.New("invalid JSON")

// jsonCopier reads JSON values from r and copies them to w byte for byte, checking their syntax as it goes, so a
// document of any size passes through a fixed amount of memory. With a nil w the values are only checked.
type jsonCopier struct {
	r     *bufio.Reader
	w     io.ByteWriter
	depth int
	werr  error // the first write error; reading stops at it
}

// next reads one byte; the end of the input inside a value is io.ErrUnexpectedEOF.
func (c *jsonCopier) next() (byte, error) {
	b, err := c.r.ReadByte()
	if errors.Is(err, io.EOF) {
		return 0, io.ErrUnexpectedEOF
	}
	return b, err
}

// put copies b to the writer.
func (c *jsonCopier) put(b byte) error {
	if c.w == nil || c.werr != nil {
		return c.werr
	}
	c.werr = c.w.WriteByte(b)
	return c.werr
}

// skipSpace reads past whitespace and returns the next byte, which is not copied. The whitespace is not copied
// either: it is outside any value.
func (c *jsonCopier) skipSpace() (byte, error) {
	for {
		b, err := c.next()
		if err != nil {
			return 0, err
		}
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		}
		return b, nil
	}
}

// space copies whitespace inside a value and returns the next byte, which is not copied.
func (c *jsonCopier) space() (byte, error) {
	for {
		b, err := c.next()
		if err != nil {
			return 0, err
		}
		switch b {
		case ' ', '\t', '\n', '\r':
			if err := c.put(b); err != nil {
				return 0, err
			}
			continue
		}
		return b, nil
	}
}

// expect reads past whitespace and fails unless the next byte is want.
func (c *jsonCopier) expect(want byte) error {
	b, err := c.skipSpace()
	if err != nil {
		return err
	}
	if b != want {
		return fmt.Errorf("%w: found %q, want %q", errJSONSyntax, b, want)
	}
	return nil
}

// value copies one value, skipping the whitespace before it. Whitespace inside the value is copied.
func (c *jsonCopier) value() error {
	b, err := c.skipSpace()
	if err != nil {
		return err
	}
	return c.valueFrom(b)
}

// valueFrom copies one value whose first byte, b, was already read.
func (c *jsonCopier) valueFrom(b byte) error {
	switch {
	case b == '{':
		return c.object()
	case b == '[':
		return c.array()
	case b == '"':
		if err := c.put(b); err != nil {
			return err
		}
		return c.str()
	case b == '-' || isDigit(b):
		return c.number(b)
	case b == 't':
		return c.literal("true")
	case b == 'f':
		return c.literal("false")
	case b == 'n':
		return c.literal("null")
	}
	return fmt.Errorf("%w: unexpected %q", errJSONSyntax, b)
}

func (c *jsonCopier) enter() error {
	c.depth++
	if c.depth > maxJSONDepth {
		return fmt.Errorf("%w: nested deeper than %d", errJSONSyntax, maxJSONDepth)
	}
	return nil
}

func (c *jsonCopier) object() error {
	if err := c.enter(); err != nil {
		return err
	}
	if err := c.put('{'); err != nil {
		return err
	}
	b, err := c.space()
	if err != nil {
		return err
	}
	if b == '}' {
		c.depth--
		return c.put('}')
	}
	for {
		if b != '"' {
			return fmt.Errorf("%w: object key must be a string", errJSONSyntax)
		}
		if err := c.put('"'); err != nil {
			return err
		}
		if err := c.str(); err != nil {
			return err
		}
		if b, err = c.space(); err != nil {
			return err
		}
		if b != ':' {
			return fmt.Errorf("%w: found %q after an object key", errJSONSyntax, b)
		}
		if err := c.put(':'); err != nil {
			return err
		}
		if b, err = c.space(); err != nil {
			return err
		}
		if err := c.valueFrom(b); err != nil {
			return err
		}
		if b, err = c.space(); err != nil {
			return err
		}
		switch b {
		case '}':
			c.depth--
			return c.put('}')
		case ',':
			if err := c.put(','); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: found %q after an object member", errJSONSyntax, b)
		}
		if b, err = c.space(); err != nil {
			return err
		}
	}
}

func (c *jsonCopier) array() error {
	if err := c.enter(); err != nil {
		return err
	}
	if err := c.put('['); err != nil {
		return err
	}
	b, err := c.space()
	if err != nil {
		return err
	}
	if b == ']' {
		c.depth--
		return c.put(']')
	}
	for {
		if err := c.valueFrom(b); err != nil {
			return err
		}
		if b, err = c.space(); err != nil {
			return err
		}
		switch b {
		case ']':
			c.depth--
			return c.put(']')
		case ',':
			if err := c.put(','); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: found %q after an array element", errJSONSyntax, b)
		}
		if b, err = c.space(); err != nil {
			return err
		}
	}
}

// str copies the rest of a string after its opening quote, through the closing quote.
func (c *jsonCopier) str() error {
	for {
		b, err := c.next()
		if err != nil {
			return err
		}
		if b < 0x20 {
			return fmt.Errorf("%w: control character in a string", errJSONSyntax)
		}
		if err := c.put(b); err != nil {
			return err
		}
		switch b {
		case '"':
			return nil
		case '\\':
			if err := c.escape(); err != nil {
				return err
			}
		}
	}
}

// escape copies the rest of an escape sequence after its backslash.
func (c *jsonCopier) escape() error {
	e, err := c.next()
	if err != nil {
		return err
	}
	if err := c.put(e); err != nil {
		return err
	}
	switch e {
	case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
		return nil
	case 'u':
		for range 4 {
			h, err := c.next()
			if err != nil {
				return err
			}
			if !isHexDigit(h) {
				return fmt.Errorf("%w: bad \\u escape", errJSONSyntax)
			}
			if err := c.put(h); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("%w: bad escape \\%c", errJSONSyntax, e)
}

// number copies a number whose first byte, b, was already read. The byte after it is left unread.
func (c *jsonCopier) number(b byte) error {
	if err := c.put(b); err != nil {
		return err
	}
	if b == '-' {
		var err error
		if b, err = c.next(); err != nil {
			return err
		}
		if !isDigit(b) {
			return fmt.Errorf("%w: '-' not followed by a digit", errJSONSyntax)
		}
		if err := c.put(b); err != nil {
			return err
		}
	}
	if b != '0' {
		if err := c.digits(false); err != nil {
			return err
		}
	}
	if p, ok := c.peek(); ok && p == '.' {
		_, _ = c.r.ReadByte()
		if err := c.put('.'); err != nil {
			return err
		}
		if err := c.digits(true); err != nil {
			return err
		}
	}
	if p, ok := c.peek(); ok && (p == 'e' || p == 'E') {
		_, _ = c.r.ReadByte()
		if err := c.put(p); err != nil {
			return err
		}
		if s, ok := c.peek(); ok && (s == '+' || s == '-') {
			_, _ = c.r.ReadByte()
			if err := c.put(s); err != nil {
				return err
			}
		}
		if err := c.digits(true); err != nil {
			return err
		}
	}
	return nil
}

// digits copies a run of digits; one is required when need is true.
func (c *jsonCopier) digits(need bool) error {
	for {
		p, ok := c.peek()
		if !ok || !isDigit(p) {
			if need {
				return fmt.Errorf("%w: digit expected in a number", errJSONSyntax)
			}
			return nil
		}
		_, _ = c.r.ReadByte()
		if err := c.put(p); err != nil {
			return err
		}
		need = false
	}
}

// peek returns the next byte without reading it; ok is false at the end of the input or on a read error, which
// the next read reports.
func (c *jsonCopier) peek() (byte, bool) {
	p, err := c.r.Peek(1)
	if err != nil {
		return 0, false
	}
	return p[0], true
}

// literal copies true, false or null, whose first byte was already read.
func (c *jsonCopier) literal(word string) error {
	if err := c.put(word[0]); err != nil {
		return err
	}
	for i := 1; i < len(word); i++ {
		b, err := c.next()
		if err != nil {
			return err
		}
		if b != word[i] {
			return fmt.Errorf("%w: bad literal, want %s", errJSONSyntax, word)
		}
		if err := c.put(b); err != nil {
			return err
		}
	}
	return nil
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func isHexDigit(b byte) bool { return isDigit(b) || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F') }
