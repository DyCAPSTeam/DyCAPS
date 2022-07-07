package polyring

import (
	"fmt"
	"testing"

	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/ncw/gmp"
)

func TestGetLagrangeCoefficients(t *testing.T) {

	deg := uint32(2)
	p := ecparam.PBC256.Ngmp
	knownIndexes := make([]*gmp.Int, 3)
	knownIndexes[0] = gmp.NewInt(1)
	knownIndexes[1] = gmp.NewInt(2)
	knownIndexes[2] = gmp.NewInt(4)
	lambda := make([]*gmp.Int, 3)
	for i := 0; i < 3; i++ {
		lambda[i] = gmp.NewInt(0)
	}
	GetLagrangeCoefficients(deg, knownIndexes, p, gmp.NewInt(8756), lambda)
	fmt.Println(lambda)

}
