package api_test

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/the-it-dept/ffs/api"
)

var operations = []string{"getSummary", "getScope", "getExposure", "listFindings", "listTransitions", "getAdvisory", "listWorkloads",
	"getWorkload", "listImages", "getImage", "listImagePackages", "listPackages", "listNodeGroups", "getNodeGroup", "getNode",
	"getCoverage", "listFeeds", "listExceptions", "getSettings", "search", "streamChanges"}

func loadDoc(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("openapi.yaml")
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal(data, &doc))
	return doc
}

// resolve follows a local $ref ("#/a/b") to its target; any other value is returned unchanged.
func resolve(t *testing.T, doc map[string]any, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	require.True(t, ok, "%v is not an object", v)
	ref, ok := m["$ref"].(string)
	if !ok {
		return m
	}
	require.True(t, strings.HasPrefix(ref, "#/"), ref)
	var cur any = doc
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		obj, ok := cur.(map[string]any)
		require.True(t, ok, ref)
		cur, ok = obj[part]
		require.True(t, ok, "%s does not resolve", ref)
	}
	return resolve(t, doc, cur)
}

func isType(schema map[string]any, want string) bool {
	switch typ := schema["type"].(type) {
	case string:
		return typ == want
	case []any:
		return slices.Contains(typ, any(want))
	}
	return false
}

func TestOpenAPI_EveryOperationHasProblemDefault(t *testing.T) {
	doc := loadDoc(t)
	require.Equal(t, "3.1.0", doc["openapi"])
	servers, ok := doc["servers"].([]any)
	require.True(t, ok)
	require.Equal(t, "/api/v1", servers[0].(map[string]any)["url"])
	security, ok := doc["security"].([]any)
	require.True(t, ok, "security is a list")
	require.Empty(t, security)

	paths, ok := doc["paths"].(map[string]any)
	require.True(t, ok)
	var ids []string
	for path, item := range paths {
		pi, ok := item.(map[string]any)
		require.True(t, ok, path)
		for key := range pi {
			require.Contains(t, []string{"get", "parameters"}, key, "%s has %s", path, key)
		}
		op, ok := pi["get"].(map[string]any)
		require.True(t, ok, "%s has a get", path)
		id, ok := op["operationId"].(string)
		require.True(t, ok, path)
		ids = append(ids, id)

		responses, ok := op["responses"].(map[string]any)
		require.True(t, ok, path)
		def := resolve(t, doc, responses["default"])
		content, ok := def["content"].(map[string]any)
		require.True(t, ok, path)
		require.Len(t, content, 1, path)
		media, ok := content["application/problem+json"].(map[string]any)
		require.True(t, ok, "%s default is application/problem+json", path)
		schema, ok := media["schema"].(map[string]any)
		require.True(t, ok, path)
		require.Equal(t, "#/components/schemas/Problem", schema["$ref"], path)

		params, _ := op["parameters"].([]any)
		for _, p := range params {
			param := resolve(t, doc, p)
			if param["in"] != "query" {
				continue
			}
			ps, ok := param["schema"].(map[string]any)
			require.True(t, ok, "%s %v", path, param["name"])
			if isType(ps, "array") {
				require.Equal(t, "form", param["style"], "%s %v", path, param["name"])
				require.Equal(t, false, param["explode"], "%s %v", path, param["name"])
			}
		}
	}
	require.ElementsMatch(t, operations, ids)

	var walk func(at string, v any)
	walk = func(at string, v any) {
		switch x := v.(type) {
		case map[string]any:
			if isType(x, "number") {
				require.Equal(t, "double", x["format"], at)
			}
			for k, child := range x {
				walk(at+"/"+k, child)
			}
		case []any:
			for _, child := range x {
				walk(at, child)
			}
		}
	}
	walk("#", doc)
}

func TestOpenAPI_ServedDocumentIsEmbedded(t *testing.T) {
	disk, err := os.ReadFile("openapi.yaml")
	require.NoError(t, err)
	require.NotEmpty(t, api.OpenAPI)
	require.True(t, bytes.Equal(disk, api.OpenAPI))
}
