//go:build !bignum_pure && !bignum_hol256 && !bignum_hbls
// +build !bignum_pure,!bignum_hol256,!bignum_hbls

package bls

import (
	"fmt"
	kbls "github.com/kilic/bls12-381"
	"math/big"
	"strings"
)

var ZERO_G1 G1Point

var GenG1 G1Point
var GenG2 G2Point

var ZeroG1 G1Point
var ZeroG2 G2Point

// Herumi BLS doesn't offer these points to us, so we have to work around it by declaring them ourselves.
func initG1G2() {
	GenG1 = G1Point(*kbls.NewG1().One())
	GenG2 = G2Point(*kbls.NewG2().One())
	ZeroG1 = G1Point(*kbls.NewG1().Zero())
	ZeroG2 = G2Point(*kbls.NewG2().Zero())
}

// TODO types file, swap BLS with build args
type G1Point kbls.PointG1

// zeroes the point (like herumi BLS does with theirs). This is not co-factor clearing.
func ClearG1(x *G1Point) {
	(*kbls.PointG1)(x).Zero()
}

func CopyG1(dst *G1Point, v *G1Point) {
	*dst = *v
}

func MulG1(dst *G1Point, a *G1Point, b *Fr) {
	tmp := (kbls.Fr)(*b) // copy, we want to leave the original in mont-red form
	(&tmp).FromRed()
	kbls.NewG1().MulScalar((*kbls.PointG1)(dst), (*kbls.PointG1)(a), &tmp)
}

func AddG1(dst *G1Point, a *G1Point, b *G1Point) {
	kbls.NewG1().Add((*kbls.PointG1)(dst), (*kbls.PointG1)(a), (*kbls.PointG1)(b))
}

func SubG1(dst *G1Point, a *G1Point, b *G1Point) {
	kbls.NewG1().Sub((*kbls.PointG1)(dst), (*kbls.PointG1)(a), (*kbls.PointG1)(b))
}

func StrG1(v *G1Point) string {
	data := kbls.NewG1().ToUncompressed((*kbls.PointG1)(v))
	var a, b big.Int
	a.SetBytes(data[:48])
	b.SetBytes(data[48:])
	return a.String() + "\n" + b.String()
}

func NegG1(dst *G1Point) {
	// in-place should be safe here (TODO double check)
	kbls.NewG1().Neg((*kbls.PointG1)(dst), (*kbls.PointG1)(dst))
}

type G2Point kbls.PointG2

// zeroes the point (like herumi BLS does with theirs). This is not co-factor clearing.
func ClearG2(x *G2Point) {
	(*kbls.PointG2)(x).Zero()
}

func CopyG2(dst *G2Point, v *G2Point) {
	*dst = *v
}

func MulG2(dst *G2Point, a *G2Point, b *Fr) {
	tmp := (kbls.Fr)(*b) // copy, we want to leave the original in mont-red form
	(&tmp).FromRed()
	kbls.NewG2().MulScalar((*kbls.PointG2)(dst), (*kbls.PointG2)(a), &tmp)
}

func AddG2(dst *G2Point, a *G2Point, b *G2Point) {
	kbls.NewG2().Add((*kbls.PointG2)(dst), (*kbls.PointG2)(a), (*kbls.PointG2)(b))
}

func SubG2(dst *G2Point, a *G2Point, b *G2Point) {
	kbls.NewG2().Sub((*kbls.PointG2)(dst), (*kbls.PointG2)(a), (*kbls.PointG2)(b))
}

func NegG2(dst *G2Point) {
	// in-place should be safe here (TODO double check)
	kbls.NewG2().Neg((*kbls.PointG2)(dst), (*kbls.PointG2)(dst))
}

func StrG2(v *G2Point) string {
	data := kbls.NewG2().ToUncompressed((*kbls.PointG2)(v))
	var a, b big.Int
	a.SetBytes(data[:96])
	b.SetBytes(data[96:])
	return a.String() + "\n" + b.String()
}

func EqualG1(a *G1Point, b *G1Point) bool {
	return kbls.NewG1().Equal((*kbls.PointG1)(a), (*kbls.PointG1)(b))
}

func EqualG2(a *G2Point, b *G2Point) bool {
	return kbls.NewG2().Equal((*kbls.PointG2)(a), (*kbls.PointG2)(b))
}

func ToCompressedG1(p *G1Point) []byte {
	return kbls.NewG1().ToCompressed((*kbls.PointG1)(p))
}

func FromCompressedG1(v []byte) (*G1Point, error) {
	p, err := kbls.NewG1().FromCompressed(v)
	return (*G1Point)(p), err
}

func ToCompressedG2(p *G2Point) []byte {
	return kbls.NewG2().ToCompressed((*kbls.PointG2)(p))
}

func FromCompressedG2(v []byte) (*G2Point, error) {
	p, err := kbls.NewG2().FromCompressed(v)
	return (*G2Point)(p), err
}

func LinCombG1(numbers []G1Point, factors []Fr) *G1Point {
	if len(numbers) != len(factors) {
		panic("got LinCombG1 numbers/factors length mismatch")
	}
	var out G1Point
	tmpG1s := make([]*kbls.PointG1, len(numbers), len(numbers))
	for i := 0; i < len(numbers); i++ {
		tmpG1s[i] = (*kbls.PointG1)(&numbers[i])
	}
	tmpFrs := make([]*kbls.Fr, len(factors), len(factors))
	for i := 0; i < len(factors); i++ {
		// copy, since we have to change from mont-red form to regular again, and don't want to mutate the input.
		v := *(*kbls.Fr)(&factors[i])
		v.FromRed()
		tmpFrs[i] = &v
	}
	_, _ = kbls.NewG1().MultiExp((*kbls.PointG1)(&out), tmpG1s, tmpFrs)
	return &out
}

// e(a1^(-1), a2) * e(b1,  b2) = 1_T
func PairingsVerify(a1 *G1Point, a2 *G2Point, b1 *G1Point, b2 *G2Point) bool {
	pairingEngine := kbls.NewEngine()
	pairingEngine.AddPairInv((*kbls.PointG1)(a1), (*kbls.PointG2)(a2))
	pairingEngine.AddPair((*kbls.PointG1)(b1), (*kbls.PointG2)(b2))
	return pairingEngine.Check()
}

func DebugG1s(msg string, values []G1Point) {
	var out strings.Builder
	for i := range values {
		out.WriteString(fmt.Sprintf("%s %d: %s\n", msg, i, StrG1(&values[i])))
	}
	fmt.Println(out.String())
}
