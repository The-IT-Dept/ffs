// Package nodegroup holds the pure node-grouping rules: host fingerprints, group names and labels,
// fallback groups built from node.status.nodeInfo, the running-kernel split, drift between two
// groups, and the Go module tables used to de-duplicate host binary findings.
//
// It imports only the standard library, internal/model and osv-scalibr's semantic package, so the
// store and the controller can both use it.
package nodegroup
