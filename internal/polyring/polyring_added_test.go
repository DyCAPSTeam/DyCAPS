package polyring

import (
	"fmt"
	"github.com/ncw/gmp"
	"testing"
)

func TestGetLagrangeCoefficients(t *testing.T) {

	deg := 2
	p := gmp.NewInt(5)
	knownIndexes := make([]*gmp.Int, 3)
	knownIndexes[0] = gmp.NewInt(1)
	knownIndexes[1] = gmp.NewInt(2)
	knownIndexes[2] = gmp.NewInt(4)
	lambda := make([]*gmp.Int, 3)
	for i := 0; i < 3; i++ {
		lambda[i] = gmp.NewInt(0)
	}
	GetLagrangeCoefficients(deg, knownIndexes, p, gmp.NewInt(3), lambda)
	fmt.Println(lambda)

}
