package polyring

import "github.com/DyCAPSTeam/DyCAPS/internal/bls"

type PolyPoint struct {
	X       int
	Y       bls.Fr
	PolyWit bls.G1Point
}

func NewRandPoly(deg int) []bls.Fr {
	ans := make([]bls.Fr, deg+1)
	for i := 0; i <= deg; i++ {
		ans[i] = *bls.RandomFr()
	}
	return ans
}
