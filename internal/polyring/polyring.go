package polyring

import "github.com/DyCAPSTeam/DyCAPS/internal/bls"

type PolyPoint struct {
	X       int
	Y       bls.Fr
	PolyWit bls.G1Point
}
