//go:build bench

package apiserver_test

import "testing"

// BenchmarkAPI runs each operation of the latency table on the DefaultScale fixture, cycling
// through its variants, for profiling: go test -tags bench -run x -bench 'BenchmarkAPI/<op>'
// -cpuprofile cpu.out ./internal/web/apiserver/.
func BenchmarkAPI(b *testing.B) {
	h := scaleAPI(b, b.TempDir())
	for _, op := range latencyOps(b, h) {
		b.Run(op.name, func(b *testing.B) {
			i := 0
			for b.Loop() {
				serve(b, h, op.variants[i%len(op.variants)])
				i++
			}
		})
	}
}
