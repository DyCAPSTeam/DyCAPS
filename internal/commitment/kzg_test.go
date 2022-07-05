package commitment

/*
forked from https://github.com/CHURPTeam/CHURP
*/

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/ncw/gmp"
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
	w4 := c.pairing.NewG1()
	w4.Mul(w, w2)
	assert.True(test, c.VerifyEval(C3, x, polyOfX3, w4), "VerifyEval")

	C_tmp := c.pairing.NewG1()
	w_tmp := c.pairing.NewG1()
	v_tmp := new(gmp.Int)
	C_tmp.SetString("[3070377657691495978382169327594644386627953864868832088602924371310674903573044669475715046238887717177279510899530075117548939826122070300000979618752344, 5111457761625134081486160483460046901426824975007809982827707370026751649519240227048881822686950175942045337225549596174628296384772875996946639537500611]", 10)
	v_tmp.SetString("21734634643869398316733138289994802626472755850908305481494395555803185165550", 10)
	w_tmp.SetString("[5488476458189244046737364555525639578492430818082558289999558136899669643486004889019965186189875924756118442455106780663336911918487444239403042416675501, 4397491509361414647633418571444446006639413754945086239395409353531980883241170242457601739595839607580653657552576963698212163894151443406547713526766547]", 10)
	fmt.Printf("c.VerifyEval: %v\n", c.VerifyEval(C_tmp, gmp.NewInt(7), v_tmp, w_tmp))
	assert.True(test, c.VerifyEval(C_tmp, gmp.NewInt(7), v_tmp, w_tmp), "VerifyEval")

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
