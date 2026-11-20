// Package memharness measures the controller's memory over a cluster's first node-agent ingest (issue #5),
// locally, with real advisory data and synthetic hosts. Its tests build only with the memharness tag, so CI never
// runs them, and it needs the network and docker. Everything it downloads or writes goes under the work directory,
// FFS_MEMHARNESS_DIR (default /tmp/ffs-memharness); none of it is committed. Delete the directory when done.
//
// TestPrepare builds the inputs once: a store holding the latest Grype DB and the OSV records the feed caches
// for Ubuntu and Debian hosts, both synced with the feeds' own code from the public sources, and five Ubuntu
// 26.04 host SBOMs (see prepareHosts). TestFirstIngest then replays a first ingest on a copy of that store:
// eight nodes in five groups send their first full reports together, through the agent API handler, the
// ingester, the acquirer, the engine and every matcher, wired and limited as in production, with the node-group
// reconciler and the engine's recompute worker running. It samples the runtime's heap metrics until every group
// is matched and its findings are written, writes a heap profile at the peak, and prints the top allocators.
//
//	export GOFLAGS=-p=4
//	go test -tags memharness -run TestPrepare -timeout 3h -v ./hack/memharness
//	GOMEMLIMIT=1932735283 FFS_MEMHARNESS_LABEL=before \
//	  go test -tags memharness -run TestFirstIngest -timeout 3h -v ./hack/memharness
//	GOMEMLIMIT=966367641 FFS_MEMHARNESS_LABEL=after FFS_MEMHARNESS_COMPARE=before \
//	  go test -tags memharness -run TestFirstIngest -timeout 3h -v ./hack/memharness
//
// GOMEMLIMIT is the chart's: 90% of the controller's memory limit (1932735283 for 2Gi, 966367641 for 1Gi).
// Each run writes <dir>/<label>/: summary.txt, timeline.tsv, heap-peak.pb.gz, top.txt and results.json, the
// stored matches and findings without their timestamps. FFS_MEMHARNESS_COMPARE=<label> fails the run when its
// results differ from that run's. FFS_MEMHARNESS_OSV_WINDOW (default 336h, the feed's retention) is how far
// back TestPrepare syncs the Ubuntu and Debian buckets; 0 keeps the feed's own first window of 72 hours.
package memharness
