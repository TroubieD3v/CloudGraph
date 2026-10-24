package analyze_test

import (
	"math/rand"
	"testing"
	"time"

	"github.com/TroubieD3v/cloudgraph/examples"
	"github.com/TroubieD3v/cloudgraph/internal/analyze"
	"github.com/TroubieD3v/cloudgraph/internal/parse"
)

// TestMutatedInputsStayFast is a deterministic mutation test complementing
// FuzzAnalyze: corrupted configuration must never panic or take long.
func TestMutatedInputsStayFast(t *testing.T) {
	iterations := 3000
	if testing.Short() {
		iterations = 300
	}
	var seeds []parse.File
	for _, d := range []string{"insecure-kubernetes", "vulnerable-ecommerce", "hardened-infrastructure"} {
		fs, err := examples.Files(d)
		if err != nil {
			t.Fatal(err)
		}
		seeds = append(seeds, fs...)
	}
	rng := rand.New(rand.NewSource(42))
	var slowest time.Duration
	for i := 0; i < iterations; i++ {
		src := seeds[rng.Intn(len(seeds))]
		data := append([]byte(nil), src.Data...)
		for m := 0; m < 1+rng.Intn(8); m++ {
			if len(data) == 0 {
				break
			}
			p := rng.Intn(len(data))
			switch rng.Intn(4) {
			case 0: // flip a byte
				data[p] = byte(rng.Intn(128))
			case 1: // delete a chunk
				end := min(len(data), p+rng.Intn(64))
				data = append(data[:p], data[end:]...)
			case 2: // duplicate a chunk
				end := min(len(data), p+rng.Intn(256))
				chunk := append([]byte(nil), data[p:end]...)
				data = append(data[:p], append(chunk, data[p:]...)...)
			case 3: // insert YAML punctuation
				data = append(data[:p], append([]byte([]string{"\n- ", ": ", "&a ", "*a", "{", "[", "\n---\n"}[rng.Intn(7)]), data[p:]...)...)
			}
		}
		start := time.Now()
		a, _, err := analyze.Run("mutant", []parse.File{{Name: src.Name, Data: data}})
		if err == nil {
			var ids []string
			for _, f := range a.Fixes {
				ids = append(ids, f.ID)
			}
			if _, err := analyze.Simulate(a, ids); err != nil {
				t.Fatalf("simulate failed on mutant of %s: %v", src.Name, err)
			}
		}
		if d := time.Since(start); d > slowest {
			slowest = d
		}
		if time.Since(start) > 2*time.Second {
			t.Fatalf("mutant of %s took %s", src.Name, time.Since(start))
		}
	}
	t.Logf("%d mutants, slowest %s", iterations, slowest)
}
