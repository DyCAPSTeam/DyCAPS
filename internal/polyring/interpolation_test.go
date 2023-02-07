package polyring

import (
	"github.com/DyCAPSTeam/DyCAPS/internal/bls"
	"log"
	"math/rand"
	"testing"
	"time"
)

func TestInterpolation(t *testing.T) {
	repeat := 100

	indexrange := 1000

	for deg := 0; deg <= 64; deg++ {

		randPoly := make([]bls.Fr, deg+1)
		for i := 0; i < len(randPoly); i++ {
			randPoly[i] = *bls.RandomFr()
			//bls.AsFr(&randPoly[i], uint64(i+1))
		}

		subset := rand.Perm(indexrange)[:deg+1]

		KnownIndices := make([]bls.Fr, deg+1)

		for i := 0; i < deg+1; i++ {
			bls.AsFr(&KnownIndices[i], uint64(subset[i]))
			//bls.AsFr(&KnownIndices[i], uint64(i+1))
		}

		KnownValues := make([]bls.Fr, deg+1)
		for i := 0; i < deg+1; i++ {
			var value bls.Fr
			bls.EvalPolyAt(&value, randPoly, &KnownIndices[i])
			bls.CopyFr(&KnownValues[i], &value)
		}

		polyRecoverd := make([]bls.Fr, deg+1)

		time1 := time.Now()
		for i := 0; i < repeat; i++ {
			polyRecoverd = LagrangeInterpolate(deg, KnownIndices, KnownValues)
		}
		time2 := time.Now()
		log.Println("repeat=", repeat, "deg=", deg, "time=", time2.Sub(time1).Nanoseconds())

		for i := 0; i < deg+1; i++ {
			if !bls.EqualFr(&polyRecoverd[i], &randPoly[i]) {
				panic("fail")
			}
		}

	}
}
