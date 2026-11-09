package scanner

import (
	"testing"

	"github.com/KrauzX/vibeguard/pkg/config"
)

func BenchmarkScan(b *testing.B) {
	cfg := config.DefaultConfig()
	s := New(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Scan(".")
	}
}

func BenchmarkScanParallel(b *testing.B) {
	cfg := config.DefaultConfig()
	s := New(cfg)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Scan(".")
		}
	})
}
