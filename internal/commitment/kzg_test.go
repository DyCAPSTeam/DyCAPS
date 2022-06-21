package commitment

/*
forked from https://github.com/CHURPTeam/CHURP
*/

import (
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	. "github.com/ncw/gmp"
	"github.com/stretchr/testify/assert"
)

func TestDLCommit_Commit(test *testing.T) {
	c := new(DLPolyCommit)
	const t = 5
	p := new(Int)
	p.SetString("11", 10)
	rnd := rand.New(rand.NewSource(99))

	// Test Setup
	c.SetupFix(t)
	//c.printPublicKey()

	// Sample a Poly and an x
	poly, err := polyring.NewRand(t, rnd, p)
	assert.Nil(test, err, "NewRand")

	// x is a random point
	x := new(Int)
	x.Rand(rnd, p)
	polyOfX := new(Int)

	C := c.pairing.NewG1()
	w := c.pairing.NewG1()

	// Test PolyCommit
	c.Commit(C, poly)

	assert.True(test, c.VerifyPoly(C, poly), "VerifyPoly")

	// Test EvalCommit
	c.polyEval(polyOfX, poly, x)
	c.CreateWitness(w, poly, x)
	assert.True(test, c.VerifyEval(C, x, polyOfX, w), "VerifyEval")

	// Test homomorphism
	rnd2 := rand.New(rand.NewSource(199))

	poly2, err2 := polyring.NewRand(t, rnd2, p)
	assert.Nil(test, err2, "NewRand")

	C2 := c.pairing.NewG1()
	w2 := c.pairing.NewG1()

	C3 := c.pairing.NewG1()
	w3 := c.pairing.NewG1()

	polyOfX2 := new(Int)
	polyOfX3 := new(Int)

	c.Commit(C2, poly2)
	assert.True(test, c.VerifyPoly(C2, poly2), "VerifyPoly")

	// G1 is an elliptic curve (additive)
	C3 = C3.Add(C, C2)
	poly3 := polyring.NewEmpty()
	poly3.Add(poly, poly2)
	assert.True(test, c.VerifyPoly(C3, poly3), "VerifyPoly")
	c.Commit(C3, poly3)
	assert.True(test, c.VerifyPoly(C3, poly3), "VerifyPoly")

	C4 := c.pairing.NewG1()
	C4 = C4.MulBig(C, big.NewInt(2))
	poly4 := polyring.NewEmpty()
	poly4.Add(poly, poly)
	assert.True(test, c.VerifyPoly(C4, poly4), "VerifyPoly")

	c.polyEval(polyOfX2, poly2, x)
	c.CreateWitness(w2, poly2, x)
	assert.True(test, c.VerifyEval(C2, x, polyOfX2, w2), "VerifyEval")

	c.polyEval(polyOfX3, poly3, x)
	c.CreateWitness(w3, poly3, x)
	assert.True(test, c.VerifyEval(C3, x, polyOfX3, w3), "VerifyEval")
	w3.Add(w, w2)
	assert.True(test, c.VerifyEval(C3, x, polyOfX3, w3), "VerifyEval")

}

func TestDLCommit_Large(test *testing.T) {
	c := new(DLPolyCommit)
	const t = 5
	p := new(Int)
	p.SetString("3932072858627806935726538339277743355414825585881591575522777707551535001573144400655144117202165255655144740729157349730442866695802580292372730337639931", 10)
	rnd := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))

	// Test Setup
	c.SetupFix(t)
	//c.printPublicKey()

	// Sample a Poly and an x
	poly, err := polyring.NewRand(t, rnd, p)
	assert.Nil(test, err, "NewRand")

	// x is a random point
	x := new(Int)
	x.Rand(rnd, p)
	polyOfX := new(Int)

	C := c.pairing.NewG1()
	w := c.pairing.NewG1()

	// Test PolyCommit
	c.Commit(C, poly)

	assert.True(test, c.VerifyPoly(C, poly), "VerifyPoly")

	// Test EvalCommit
	c.polyEval(polyOfX, poly, x)
	c.CreateWitness(w, poly, x)
	assert.True(test, c.VerifyEval(C, x, polyOfX, w), "VerifyEval")
}

const bigPolyDegree = 100

var rnd = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))

func BenchmarkDLPolyCommit_VerifyEval(b *testing.B) {
	c := new(DLPolyCommit)

	c.SetupFix(bigPolyDegree)

	poly100, err := polyring.NewRand(bigPolyDegree, rnd, c.p)
	assert.Nil(b, err)

	// x is a random point
	x := new(Int)
	x.Rand(rnd, c.p)
	polyOfX := new(Int)

	C := c.pairing.NewG1()
	w := c.pairing.NewG1()

	// Test PolyCommit
	c.Commit(C, poly100)

	// Test EvalCommit
	c.polyEval(polyOfX, poly100, x)
	c.CreateWitness(w, poly100, x)

	b.Run("VerifyEval", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			assert.True(b, c.VerifyEval(C, x, polyOfX, w), "VerifyEval")
		}
	})
}
