// Package api holds the ffs HTTP API contract.
package api

import _ "embed"

// OpenAPI is the OpenAPI 3.1 document of the ffs HTTP API, served unchanged at
// /api/v1/openapi.yaml. The Go server types and the UI's TypeScript types are generated from it.
//
//go:embed openapi.yaml
var OpenAPI []byte
