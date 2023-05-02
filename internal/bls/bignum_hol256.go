//go:build bignum_hol256
// +build bignum_hol256

/*
forked from https://github.com/protolambda/go-kzg at Feb 2,2023
*/
package bls

import (
	"crypto/rand"
	"math/big"

	u256 "github.com/holiman/uint256"
)

var _modulus u256.Int

type Fr u256.Int

func init() {
	SetFr((*Fr)(&_modulus), ModulusStr)
	initGlobals()
}

func SetFr(dst *Fr, v string) {
	var b big.Int
	if err := b.UnmarshalText([]byte(v)); err != nil {
		panic(err)
	}
	if overflow := (*u256.Int)(dst).SetFromBig(&b); overflow {
		panic("overflow")
	}
}

// FrFrom32 mutates the fr num. The value v is little-endian 32-bytes.
// Returns false, without modifying dst, if the value is out of range.
func FrFrom32(dst *Fr, v [32]byte) (ok bool) {
	if !ValidFr(v) {
		return false
	}
	// reverse endianness, u256.Int takes big-endian bytes
	for i := 0; i < 16; i++ {
		v[i], v[31-i] = v[31-i], v[i]
	}
	(*u256.Int)(dst).SetBytes(v[:])
	return true
}

// FrTo32 serializes a fr number to 32 bytes. Encoded little-endian.
func FrTo32(src *Fr) (v [32]byte) {
	b := (*u256.Int)(src).Bytes()
	last := len(b) - 1
	// reverse endianness, u256.Int outputs big-endian bytes
	for i := 0; i < 16; i++ {
		b[i], b[last-i] = b[last-i], b[i]
	}
	copy(v[:], b)
	return
}

func CopyFr(dst *Fr, v *Fr) {
	*dst = *v
}

func AsFr(dst *Fr, i uint64) {
	(*u256.Int)(dst).SetUint64(i)
}

func FrStr(b *Fr) string {
	if b == nil {
		return "<nil>"
	}
	return (*u256.Int)(b).ToBig().String()
}

func EqualOne(v *Fr) bool {
	return *(v) == [4]uint64{0: 1}
}

func EqualZero(v *Fr) bool {
	return (*u256.Int)(v).IsZero()
}

func EqualFr(a *Fr, b *Fr) bool {
	return (*u256.Int)(a).Eq((*u256.Int)(b))
}

func RandomFr() *Fr {
	v, err := rand.Int(rand.Reader, _modulus.ToBig())
	if err != nil {
		panic(err)
	}
	var out u256.Int
	out.SetFromBig(v)
	return (*Fr)(&out)
}

func SubModFr(dst *Fr, a, b *Fr) {
	if _, underflow := (*u256.Int)(dst).SubOverflow((*u256.Int)(a), (*u256.Int)(b)); underflow {
		var tmp u256.Int // hacky
		tmp.Sub(new(u256.Int), (*u256.Int)(dst))
		(*u256.Int)(dst).Sub(&_modulus, &tmp)
	}
}

func AddModFr(dst *Fr, a, b *Fr) {
	(*u256.Int)(dst).AddMod((*u256.Int)(a), (*u256.Int)(b), &_modulus)
}

func DivModFr(dst *Fr, a, b *Fr) {
	var tmp Fr
	InvModFr(&tmp, b)
	MulModFr(dst, a, &tmp)
}

func MulModFr(dst *Fr, a, b *Fr) {
	(*u256.Int)(dst).MulMod((*u256.Int)(a), (*u256.Int)(b), &_modulus)
}

// TODO not optimized, but also not used as much
func InvModFr(dst *Fr, v *Fr) {
	// pow(x, n - 2, n)
	var tmp big.Int
	tmp.ModInverse((*u256.Int)(v).ToBig(), (&_modulus).ToBig())
	(*u256.Int)(dst).SetFromBig(&tmp)
}

// BatchInvModFr computes the inverse for each input.
// Warning: this does not actually batch, this is just here for compatibility with other BLS backends that do.
func BatchInvModFr(f []Fr) {
	for i := 0; i < len(f); i++ {
		InvModFr(&f[i], &f[i])
	}
}

//func SqrModFr(dst *Fr, v *Fr) {
//
//}

func EvalPolyAt(dst *Fr, p []Fr, x *Fr) {
	EvalPolyAtUnoptimized(dst, p, x)
}

// ExpModFr computes v**e in Fr. Warning: this is a fallback on big int math.
func ExpModFr(dst *Fr, v *Fr, e *big.Int) {
	(*u256.Int)(dst).SetFromBig(new(big.Int).Exp((*u256.Int)(v).ToBig(), e, (&_modulus).ToBig()))
}
