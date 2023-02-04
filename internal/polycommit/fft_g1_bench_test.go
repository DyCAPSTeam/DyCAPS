//go:build !bignum_pure && !bignum_hol256
// +build !bignum_pure,!bignum_hol256

package polycommit

import (
	"fmt"
	"github.com/DyCAPSTeam/DyCAPS/internal/bls"
	"testing"
)

func benchFFTG1(scale uint8, b *testing.B) {
	fs := NewFFTSettings(scale)
	data := make([]bls.G1Point, fs.MaxWidth, fs.MaxWidth)
	for i := uint64(0); i < fs.MaxWidth; i++ {
		var tmpG1 bls.G1Point
		bls.CopyG1(&tmpG1, &bls.GenG1)
		bls.MulG1(&data[i], &tmpG1, bls.RandomFr())
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := fs.FFTG1(data, false)
		if err != nil {
			b.Fatal(err)
		}
		if len(out) != len(data) {
			panic("output len doesn't match input")
		}
	}
}

func BenchmarkFFTSettings_FFTG1(b *testing.B) {
	for scale := uint8(4); scale < 16; scale++ {
		b.Run(fmt.Sprintf("scale_%d", scale), func(b *testing.B) {
			benchFFTG1(scale, b)
		})
	}
}
