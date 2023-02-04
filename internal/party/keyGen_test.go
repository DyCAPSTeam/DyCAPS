package party

import (
	"fmt"
	"testing"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
)

func TestSuite(t *testing.T) {
	f := 3
	n := 4
	suit := pairing.NewSuiteBn256()
	random := suit.RandomStream()

	x := suit.G1().Scalar().Pick(random)

	// priploy
	priploy := share.NewPriPoly(suit.G2(), f, x, suit.RandomStream())
	// n points in ploy
	npoints := priploy.Shares(int(n))
	//pub ploy
	pubploy := priploy.Commit(suit.G2().Point().Base())
	for i := 0; i < n; i++ {
		fmt.Println(npoints[i].V)
	}
	fmt.Println(pubploy.Info())

	coefficients := priploy.Coefficients()
	fmt.Println()
	fmt.Println(coefficients[0])
	data, _ := coefficients[0].MarshalBinary()
	fmt.Println(data)
	var a kyber.Scalar = suit.Scalar().One()
	a.SetBytes(data)
	fmt.Println(coefficients[0])
	fmt.Println()
	suit2 := pairing.NewSuiteBn256()
	priploy2 := share.CoefficientsToPriPoly(suit2.G2(), coefficients)
	npoints2 := priploy2.Shares(n)
	for i := 0; i < n; i++ {
		fmt.Println(npoints2[i].V)
	}
}
