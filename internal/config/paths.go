package config

import (
	"reflect"
	"sort"
	"strings"
)

// FieldPaths returns the sorted, dotted YAML key path of every leaf field of Config,
// using the tag key Load decodes with. Maps, slices and durations (an int64 kind) are leaves.
func FieldPaths() []string {
	var out []string
	walkPaths(reflect.TypeOf(Config{}), "", &out)
	sort.Strings(out)
	return out
}

func walkPaths(t reflect.Type, prefix string, out *[]string) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		key, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if key == "-" {
			continue
		}
		if key == "" {
			key = f.Name
		}
		path := prefix + key
		if f.Type.Kind() == reflect.Struct {
			walkPaths(f.Type, path+".", out)
			continue
		}
		*out = append(*out, path)
	}
}
