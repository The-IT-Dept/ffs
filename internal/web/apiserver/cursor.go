package apiserver

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"strings"

	"github.com/the-it-dept/ffs/internal/web/apigen"
)

// An API cursor is base64url(JSON {"q": fingerprint, "k": store cursor}). The fingerprint ties it to
// the operation and the query it was issued for, so a cursor pasted into another query is refused
// instead of paging through the wrong rows.
type apiCursor struct {
	Q string `json:"q"`
	K string `json:"k"`
}

// encodeCursor wraps a store cursor for op and params; nil when storeCursor is "" (the last page).
func encodeCursor(op string, params any, storeCursor string) *string {
	if storeCursor == "" {
		return nil
	}
	data, err := json.Marshal(apiCursor{Q: paramsFingerprint(op, params), K: storeCursor})
	if err != nil {
		// A struct of two strings always marshals.
		panic(err)
	}
	s := base64.RawURLEncoding.EncodeToString(data)
	return &s
}

// decodeCursor returns the store cursor inside cursor: "" when it is absent or empty. A cursor
// that does not decode, or was issued for another operation or query, is 400 invalid_cursor.
func decodeCursor(op string, params any, cursor *string) (string, error) {
	if cursor == nil || *cursor == "" {
		return "", nil
	}
	invalid := &Problem{Status: http.StatusBadRequest, Code: apigen.ProblemCodeInvalidCursor}
	data, err := base64.RawURLEncoding.DecodeString(*cursor)
	if err != nil {
		return "", invalid
	}
	var c apiCursor
	if err := json.Unmarshal(data, &c); err != nil || c.K == "" || c.Q != paramsFingerprint(op, params) {
		return "", invalid
	}
	return c.K, nil
}

// paramsFingerprint is the first 12 hex digits of sha256(op, NUL, the JSON of params as a map). The
// map holds every exported field by its JSON name, except Cursor and Facets (they do not change
// which rows a page holds) and nil pointers; pointers are dereferenced, and slices of string kind
// are sorted, so the order of values in a parameter does not matter.
func paramsFingerprint(op string, params any) string {
	m := map[string]any{}
	v := reflect.ValueOf(params)
	for v.Kind() == reflect.Pointer && !v.IsNil() {
		v = v.Elem()
	}
	if v.Kind() == reflect.Struct {
		t := v.Type()
		for i := range t.NumField() {
			f := t.Field(i)
			if !f.IsExported() || f.Name == "Cursor" || f.Name == "Facets" {
				continue
			}
			fv := v.Field(i)
			if fv.Kind() == reflect.Pointer {
				if fv.IsNil() {
					continue
				}
				fv = fv.Elem()
			}
			m[jsonName(f)] = canonical(fv)
		}
	}
	data, err := json.Marshal(m)
	if err != nil {
		// Parameter structs hold only strings, numbers and slices of them.
		panic(err)
	}
	sum := sha256.Sum256(append([]byte(op+"\x00"), data...))
	return hex.EncodeToString(sum[:])[:12]
}

// canonical returns v as a JSON-ready value, with a slice of string kind sorted.
func canonical(v reflect.Value) any {
	if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.String {
		out := make([]string, v.Len())
		for i := range out {
			out[i] = v.Index(i).String()
		}
		slices.Sort(out)
		return out
	}
	return v.Interface()
}

func jsonName(f reflect.StructField) string {
	name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
	if name == "" {
		return f.Name
	}
	return name
}
