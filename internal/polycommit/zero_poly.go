/*
forked from https://github.com/protolambda/go-kzg at Feb 2,2023
*/

// Original: https://github.com/ethereum/research/blob/master/polynomial_reconstruction/polynomial_reconstruction.py
// Changes:
// - flattened leaf construction,
// - no aggressive poly truncation
// - simplified merges
// - no heap allocations during reduction

package polycommit

import (
	"fmt"
	"github.com/DyCAPSTeam/DyCAPS/internal/bls"
)

type ZeroPolyFn func(missingIndices []uint64, length uint64) ([]bls.Fr, []bls.Fr)

func (fs *FFTSettings) makeZeroPolyMulLeaf(dst []bls.Fr, indices []uint64, domainStride uint64) {
	if len(dst) < len(indices)+1 {
		panic(fmt.Sprintf("expected bigger destination length: %d, got: %d", len(indices)+1, len(dst)))
	}
	// zero out the unused slots
	for i := len(indices) + 1; i < len(dst); i++ {
		bls.CopyFr(&dst[i], &bls.ZERO)
	}
	bls.CopyFr(&dst[len(indices)], &bls.ONE)
	var negDi bls.Fr
	for i, v := range indices {
		bls.SubModFr(&negDi, &bls.ZERO, &fs.ExpandedRootsOfUnity[v*domainStride])
		bls.CopyFr(&dst[i], &negDi)
		if i > 0 {
			bls.AddModFr(&dst[i], &dst[i], &dst[i-1])
			for j := i - 1; j > 0; j-- {
				bls.MulModFr(&dst[j], &dst[j], &negDi)
				bls.AddModFr(&dst[j], &dst[j], &dst[j-1])
			}
			bls.MulModFr(&dst[0], &dst[0], &negDi)
		}
	}
}

// Copy all of the values of poly into out, and fill the remainder of out with zeroes.
func padPoly(out []bls.Fr, poly []bls.Fr) {
	for i := 0; i < len(poly); i++ {
		bls.CopyFr(&out[i], &poly[i])
	}
	for i := len(poly); i < len(out); i++ {
		bls.CopyFr(&out[i], &bls.ZERO)
	}
}

// Calculate the product of the input polynomials via convolution.
// Pad the polynomials in ps, perform FFTs, point-wise multiply the results together,
// and apply an inverse FFT to the result.
//
// The scratch space must be at least 3 times the output space.
// The output must have a power of 2 length.
// The input polynomials must not be empty, and sum to no larger than the output.
func (fs *FFTSettings) reduceLeaves(scratch []bls.Fr, dst []bls.Fr, ps [][]bls.Fr) []bls.Fr {
	n := uint64(len(dst))
	if !bls.IsPowerOfTwo(n) {
		panic("destination must be a power of two")
	}
	if len(ps) == 0 {
		panic("empty leaves")
	}
	// The degree of the output polynomial is the sum of the degrees of the input polynomials.
	outDegree := uint64(0)
	for _, p := range ps {
		if len(p) == 0 {
			panic("empty input poly")
		}
		outDegree += uint64(len(p)) - 1
	}
	if min := outDegree + 1; min > n {
		panic(fmt.Sprintf("expected larger destination length: %d, got: %d", min, n))
	}
	if uint64(len(scratch)) < 3*n {
		panic("not enough scratch space")
	}
	// Split `scratch` up into three equally sized working arrays
	pPadded := scratch[:n]
	mulEvalPs := scratch[n : 2*n]
	pEval := scratch[2*n : 3*n]

	// Do the last partial first: it is no longer than the others and the padding can remain in place for the rest.
	last := uint64(len(ps) - 1)
	padPoly(pPadded, ps[last])
	if err := fs.InplaceFFT(pPadded, mulEvalPs, false); err != nil {
		panic(err)
	}
	for i := uint64(0); i < last; i++ {
		p := ps[i]
		for j := 0; j < len(p); j++ {
			bls.CopyFr(&pPadded[j], &p[j])
		}
		if err := fs.InplaceFFT(pPadded, pEval, false); err != nil {
			panic(err)
		}
		for j := uint64(0); j < n; j++ {
			bls.MulModFr(&mulEvalPs[j], &mulEvalPs[j], &pEval[j])
		}
	}
	if err := fs.InplaceFFT(mulEvalPs, dst, true); err != nil {
		panic(err)
	}
	return dst[:outDegree+1]
}

// Calculate the minimal polynomial that evaluates to zero for powers of roots of unity that correspond to missing
// indices.
//
// This is done simply by multiplying together `(x - r^i)` for all the `i` that are missing indices, using a combination
// of direct multiplication (makeZeroPolyMulLeaf) and iterated multiplication via convolution (reduceLeaves)
//
// Also calculates the FFT (the "evaluation polynomial").
func (fs *FFTSettings) ZeroPolyViaMultiplication(missingIndices []uint64, length uint64) ([]bls.Fr, []bls.Fr) {
	if len(missingIndices) == 0 {
		return make([]bls.Fr, length, length), make([]bls.Fr, length, length)
	}
	if length > fs.MaxWidth {
		panic("domain too small for requested length")
	}
	if !bls.IsPowerOfTwo(length) {
		panic("length not a power of two")
	}
	domainStride := fs.MaxWidth / length
	perLeafPoly := uint64(64)
	// just under a power of two, since the leaf gets 1 bigger after building a poly for it
	perLeaf := perLeafPoly - 1

	// If the work is as small as a single leaf, don't bother with tree reduction
	if uint64(len(missingIndices)) <= perLeaf {
		zeroPoly := make([]bls.Fr, len(missingIndices)+1, length)
		fs.makeZeroPolyMulLeaf(zeroPoly, missingIndices, domainStride)
		// pad with zeroes (capacity is already there)
		zeroPoly = zeroPoly[:length]
		zeroEval, err := fs.FFT(zeroPoly, false)
		if err != nil {
			panic(err)
		}
		return zeroEval, zeroPoly
	}

	leafCount := (uint64(len(missingIndices)) + perLeaf - 1) / perLeaf
	n := nextPowOf2(leafCount * perLeafPoly)

	// The assumption here is that if the output is a power of two length, matching the sum of child leaf lengths,
	// then the space can be reused.
	out := make([]bls.Fr, n, n)

	// Build the leaves.

	// Just the headers, a leaf re-uses the output space.
	// Combining leaves can be done mostly in-place, using a scratchpad.
	leaves := make([][]bls.Fr, leafCount, leafCount)

	offset := uint64(0)
	outOffset := uint64(0)
	max := uint64(len(missingIndices))
	for i := uint64(0); i < leafCount; i++ {
		end := offset + perLeaf
		if end > max {
			end = max
		}
		leaves[i] = out[outOffset : outOffset+perLeafPoly]
		fs.makeZeroPolyMulLeaf(leaves[i], missingIndices[offset:end], domainStride)
		offset += perLeaf
		outOffset += perLeafPoly
	}

	// Now reduce all the leaves to a single poly

	// must be a power of 2
	reductionFactor := uint64(4)
	scratch := make([]bls.Fr, n*3, n*3)

	// from bottom to top, start reducing leaves.
	for len(leaves) > 1 {
		reducedCount := (uint64(len(leaves)) + reductionFactor - 1) / reductionFactor
		// all the leaves are the same. Except possibly the last leaf, but that's ok.
		leafSize := nextPowOf2(uint64(len(leaves[0])))
		for i := uint64(0); i < reducedCount; i++ {
			start := i * reductionFactor
			end := start + reductionFactor
			// E.g. if we *started* with 2 leaves, we won't have more than that since it is already a power of 2.
			// If we had 3, it would have been rounded up anyway. So just pick the end
			outEnd := end * leafSize
			if outEnd > uint64(len(out)) {
				outEnd = uint64(len(out))
			}
			reduced := out[start*leafSize : outEnd]
			// unlike reduced output, input may be smaller than the amount that aligns with powers of two
			if end > uint64(len(leaves)) {
				end = uint64(len(leaves))
			}
			leavesSlice := leaves[start:end]
			if end > start+1 {
				reduced = fs.reduceLeaves(scratch, reduced, leavesSlice)
			}
			leaves[i] = reduced
		}
		leaves = leaves[:reducedCount]
	}
	zeroPoly := leaves[0]
	if zl := uint64(len(zeroPoly)); zl < length {
		zeroPoly = append(zeroPoly, make([]bls.Fr, length-zl, length-zl)...)
	} else if zl > length {
		panic("expected output smaller or equal to input length")
	}

	zeroEval, err := fs.FFT(zeroPoly, false)
	if err != nil {
		panic(err)
	}

	return zeroEval, zeroPoly
}
