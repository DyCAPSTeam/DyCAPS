package polyring

import (
	"github.com/DyCAPSTeam/DyCAPS/internal/bls"
	"log"
)

// LagrangeInterpolate returns a polynomial of specified degree that pass through all points in x and y
func LagrangeInterpolate(degree int, x []bls.Fr, y []bls.Fr) []bls.Fr {
	// initialize variables
	tmp := make([]bls.Fr, 2)

	inter := make([]bls.Fr, degree+1)

	product := make([]bls.Fr, 1)
	bls.AsFr(&product[0], 1)

	resultPoly := make([]bls.Fr, degree+1)

	denominator := bls.ZERO

	// tmp(x) = x - x[i]
	bls.AsFr(&tmp[1], 1)
	// note only the first degree points are used
	for i := 0; i <= degree; i++ {
		var negXi bls.Fr
		bls.SubModFr(&negXi, &bls.ZERO, &x[i])
		bls.CopyFr(&tmp[0], &negXi)
		product = mulPolyDegreeOne(product, tmp)
	}
	for i := 0; i <= degree; i++ {
		bls.CopyFr(&denominator, &bls.ONE)
		// compute denominator and numerator

		// tmp = x - x[i]
		var negXi bls.Fr
		bls.SubModFr(&negXi, &bls.ZERO, &x[i])
		bls.CopyFr(&tmp[0], &negXi)

		// inner(x) = (x-1)(x_2)...(x-n) except for (x-i)
		inter = divPolyDegreeOne(product, tmp)
		// lambda_i(x) = inner(x) * y[i] / inner(x[i])
		bls.EvalPolyAt(&denominator, inter, &x[i])

		// panic if denominator == 0
		if bls.EqualZero(&denominator) {
			log.Fatalln("internal error: check duplication in x[]")
		}

		var tmp2 bls.Fr

		bls.InvModFr(&tmp2, &denominator)
		bls.MulModFr(&denominator, &tmp2, &y[i])
		for j := 0; j < len(inter); j++ {
			var tmp3 bls.Fr
			bls.MulModFr(&tmp3, &inter[j], &denominator)
			bls.AddModFr(&resultPoly[j], &resultPoly[j], &tmp3)
		}
	}
	return resultPoly
}

func mulPolyDegreeOne(poly []bls.Fr, factor []bls.Fr) []bls.Fr {
	if len(factor) != 2 {
		log.Fatalln("len(factor) != 2 in function mulPolyDegreeOne")
	}

	ans := make([]bls.Fr, len(poly)+1)

	for i := 0; i < len(poly); i++ {
		bls.MulModFr(&ans[i], &poly[i], &factor[0])
	}
	for i := 0; i < len(poly); i++ {
		var tmp bls.Fr
		bls.MulModFr(&tmp, &poly[i], &factor[1])
		bls.AddModFr(&ans[i+1], &ans[i+1], &tmp)
	}
	return ans
}

func divPolyDegreeOne(op1 []bls.Fr, op2 []bls.Fr) []bls.Fr {
	deg1 := len(op1) - 1
	deg2 := len(op2) - 1
	if deg2 != 1 {
		log.Fatalln("op2 must be of format x-a")
	}
	if !bls.EqualFr(&bls.ONE, &op2[1]) {
		log.Fatalln("op2 must be of format x-a")
	}

	ans := make([]bls.Fr, deg1-1+1)

	tmp := bls.ZERO

	inter := make([]bls.Fr, deg1+1)
	for i := 0; i <= deg1; i++ {
		bls.CopyFr(&inter[i], &op1[i])
	}

	for i := deg1; i > 0; i-- {
		bls.CopyFr(&ans[i-1], &inter[i])
		bls.MulModFr(&tmp, &ans[i-1], &op2[0])
		bls.SubModFr(&inter[i-1], &inter[i-1], &tmp)
	}

	return ans
}
