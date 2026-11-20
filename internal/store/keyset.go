package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Keyset paging. A page is ordered by a tuple of columns whose last element is unique; its cursor
// is the tuple of the page's last row, so the next page starts strictly after that row however the
// rows before it changed. A cursor is base64url (unpadded) of the JSON array [tag, tuple...], where
// tag names the sort or grouping it belongs to.

// valueKind is the Go type a tuple column scans to and decodes from: int64, float64 or string.
type valueKind int

const (
	kindInt valueKind = iota
	kindFloat
	kindString
)

// keyCol is one column of a sort tuple.
type keyCol struct {
	expr string
	desc bool
	kind valueKind
}

const (
	defaultPageLimit = 50
	maxPageLimit     = 200
)

// clampLimit clamps a page size to 1..200, with 0 meaning 50.
func clampLimit(n int) int {
	switch {
	case n == 0:
		return defaultPageLimit
	case n < 0:
		return 1
	case n > maxPageLimit:
		return maxPageLimit
	}
	return n
}

// encodeCursor returns the cursor of the row whose tuple is vals, under tag.
func encodeCursor(tag string, vals []any) string {
	arr := make([]any, 0, len(vals)+1)
	arr = append(arr, tag)
	arr = append(arr, vals...)
	b, err := json.Marshal(arr)
	if err != nil { // tuples hold int64, float64 and string only
		panic(fmt.Sprintf("store: encode cursor: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeCursor returns the tuple held by cursor s, which must carry tag and one value of the right
// kind per column; anything else is ErrBadCursor. An empty cursor is the first page: nil.
func decodeCursor(s, tag string, cols []keyCol) ([]any, error) {
	if s == "" {
		return nil, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w", ErrBadCursor)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var arr []any
	if err := dec.Decode(&arr); err != nil || dec.More() || len(arr) != len(cols)+1 {
		return nil, fmt.Errorf("%w", ErrBadCursor)
	}
	if t, ok := arr[0].(string); !ok || t != tag {
		return nil, fmt.Errorf("%w", ErrBadCursor)
	}
	vals := make([]any, len(cols))
	for i, c := range cols {
		v, ok := decodeValue(arr[i+1], c.kind)
		if !ok {
			return nil, fmt.Errorf("%w", ErrBadCursor)
		}
		vals[i] = v
	}
	return vals, nil
}

func decodeValue(v any, kind valueKind) (any, bool) {
	if kind == kindString {
		s, ok := v.(string)
		return s, ok
	}
	n, ok := v.(json.Number)
	if !ok {
		return nil, false
	}
	if kind == kindInt {
		i, err := n.Int64()
		return i, err == nil
	}
	f, err := n.Float64()
	return f, err == nil
}

// keysetAfter is the predicate selecting the rows strictly after the tuple vals in the order of
// cols: (c1 OP1 ? OR (c1 = ? AND (c2 OP2 ? OR (… cN OPN ?)))), where OP is < for a descending
// column and > for an ascending one, with the values bound in order of appearance.
func keysetAfter(cols []keyCol, vals []any) (string, []any) {
	last := len(cols) - 1
	cond := cols[last].expr + " " + afterOp(cols[last]) + " ?"
	args := []any{vals[last]}
	for i := last - 1; i >= 0; i-- {
		c := cols[i]
		cond = "(" + c.expr + " " + afterOp(c) + " ? OR (" + c.expr + " = ? AND " + cond + "))"
		args = append([]any{vals[i], vals[i]}, args...)
	}
	return cond, args
}

func afterOp(c keyCol) string {
	if c.desc {
		return "<"
	}
	return ">"
}

// orderBy is the ORDER BY clause of cols.
func orderBy(cols []keyCol) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = c.expr
		if c.desc {
			parts[i] += " DESC"
		}
	}
	return " ORDER BY " + strings.Join(parts, ", ")
}

// tupleDest returns scan destinations for a row's tuple, and a function reading them back as the
// values a cursor holds.
func tupleDest(cols []keyCol) ([]any, func() []any) {
	dest := make([]any, len(cols))
	for i, c := range cols {
		switch c.kind {
		case kindInt:
			dest[i] = new(int64)
		case kindFloat:
			dest[i] = new(float64)
		default:
			dest[i] = new(string)
		}
	}
	return dest, func() []any {
		vals := make([]any, len(dest))
		for i, d := range dest {
			switch p := d.(type) {
			case *int64:
				vals[i] = *p
			case *float64:
				vals[i] = *p
			case *string:
				vals[i] = *p
			}
		}
		return vals
	}
}

// tupleExprs is the select list of cols' expressions.
func tupleExprs(cols []keyCol) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = c.expr
	}
	return strings.Join(parts, ", ")
}
