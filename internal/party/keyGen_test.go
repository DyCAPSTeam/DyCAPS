package party

import (
	"fmt"
	"github.com/drand/kyber"
	kyberbls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/share"
	"testing"
)

func TestSuite(t *testing.T) {
	f := 3
	n := 4
	suit := kyberbls.NewBLS12381Suite()
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
	var a kyber.Scalar = suit.G1().Scalar().One()
	a.SetBytes(data)
	fmt.Println(coefficients[0])
	fmt.Println()
	suit2 := kyberbls.NewBLS12381Suite()
	priploy2 := share.CoefficientsToPriPoly(suit2.G2(), coefficients)
	npoints2 := priploy2.Shares(n)
	for i := 0; i < n; i++ {
		fmt.Println(npoints2[i].V)
	}
}
