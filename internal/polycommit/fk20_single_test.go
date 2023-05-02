//go:build !bignum_pure && !bignum_hol256
// +build !bignum_pure,!bignum_hol256

/*
forked from https://github.com/protolambda/go-kzg at Feb 2,2023
*/
package polycommit

import (
	"github.com/DyCAPSTeam/DyCAPS/internal/bls"
	"log"
	"testing"
	"time"
)

func TestKZGSettings_DAUsingFK20(t *testing.T) {
	fs := NewFFTSettings(5)
	s1, s2 := GenerateTestingSetup("1927409816240961209460912649124", 32+1)
	ks := NewKZGSettings(fs, s1, s2)
	fk := NewFK20SingleSettings(ks, 32)

	polynomial := testPoly(1, 2, 3, 4, 7, 7, 7, 7, 13, 13, 13, 13, 13, 13, 13, 13)

	commitment := ks.CommitToPoly(polynomial)
	t.Log("commitment\n", bls.StrG1(commitment))

	allProofs := fk.DAUsingFK20(polynomial)
	t.Log("All KZG proofs computed")
	for i := 0; i < len(allProofs); i++ {
		t.Logf("%d: %s", i, bls.StrG1(&allProofs[i]))
	}

	// Now check a random position
	pos := uint64(9)
	var posFr bls.Fr
	bls.AsFr(&posFr, pos)
	var x bls.Fr
	bls.CopyFr(&x, &ks.ExpandedRootsOfUnity[pos])
	t.Log("x:\n", bls.FrStr(&x))
	var y bls.Fr
	bls.EvalPolyAt(&y, polynomial, &x)
	t.Log("y:\n", bls.FrStr(&y))

	proof := &allProofs[reverseBitsLimited(uint32(2*16), uint32(pos))]

	if !ks.CheckProofSingle(commitment, proof, &x, &y) {
		t.Fatal("could not verify proof")
	}
}

func TestFK20Correctness(t *testing.T) {

	//repeat := 100

	for deg := 1; deg <= 21; deg++ {

		//setup FFT and normal KZG
		scale := GetScaleByCommitteeSize(3*deg + 1)
		fs := NewFFTSettings(scale)
		secret := bls.RandomFr().String()
		secretG1, secretG2 := GenerateTestingSetup(secret, fs.MaxWidth)
		KZG := NewKZGSettings(fs, secretG1, secretG2)

		//setup FK20
		fs_fk20 := NewFFTSettings(scale + 1)
		secretG1_fk20, secretG2_fk20 := GenerateTestingSetup(secret, fs_fk20.MaxWidth)
		fk20_kernel := NewKZGSettings(fs_fk20, secretG1_fk20, secretG2_fk20)
		KZG_fk20 := NewFK20SingleSettings(fk20_kernel, fs_fk20.MaxWidth)

		//generate random polynomial
		poly_CoeffForm := make([]bls.Fr, deg+1)
		for i := 0; i < deg+1; i++ {
			poly_CoeffForm[i] = *bls.RandomFr()
			//log.Println(poly_CoffForm[i].String())
		}

		poly_CoeffForm_Append := AppendCoeff(poly_CoeffForm, fs.MaxWidth)
		//get evaluation form

		poly_EvalForm, err := fs.FFT(poly_CoeffForm_Append, false)
		//log.Println(len(poly_EvalForm))
		if err != nil {
			log.Panicln(err)
		}

		//generate commitment
		Com := KZG.CommitToPoly(poly_CoeffForm)

		//generate witnesses in the normal way
		witnesses_normal := make([]bls.G1Point, 3*deg+2) //indices start from 1

		time1 := time.Now()
		for i := 0; i <= 3*deg+1; i++ {
			witnesses_normal[i] = *KZG.ComputeProofSingle(poly_CoeffForm, fs.ExpandedRootsOfUnity[i])
		}
		time2 := time.Now()

		log.Println(" deg=", deg, "Simple_CreateWitness_TotalTime=", time2.Sub(time1).Nanoseconds())
		//generate witnesses by fk20

		time3 := time.Now()
		witnesses_by_fk20 := KZG_fk20.FK20Single(poly_CoeffForm_Append)
		time4 := time.Now()

		log.Println(" deg=", deg, "FK20_CreateWitness_TotalTime=", time4.Sub(time3).Nanoseconds())

		//fmt.Println(len(witnesses_by_fk20))
		//compare
		for i := 0; i <= 3*deg+1; i++ {
			if bls.EqualG1(&witnesses_by_fk20[i], &witnesses_normal[i]) == false {
				log.Panicln("")
			}
		}

		//verify
		for i := 0; i <= 3*deg+1; i++ {
			if KZG.CheckProofSingle(Com, &witnesses_normal[i], &fs.ExpandedRootsOfUnity[i], &poly_EvalForm[i]) == false {
				log.Panicln()
			}
			if KZG.CheckProofSingle(Com, &witnesses_by_fk20[i], &fs.ExpandedRootsOfUnity[i], &poly_EvalForm[i]) == false {
				log.Panicln()
			}
		}
	}
}

func GetScaleByCommitteeSize(size int) uint8 {
	if size+1 > 1 && size+1 <= 2 {
		return 1
	}
	if size+1 > 2 && size+1 <= 4 {
		return 2
	}
	if size+1 > 4 && size+1 <= 8 {
		return 3
	}
	if size+1 > 8 && size+1 <= 16 {
		return 4
	}
	if size+1 > 16 && size+1 <= 32 {
		return 5
	}
	if size+1 > 32 && size+1 <= 64 {
		return 6
	}
	if size+1 > 64 && size+1 <= 128 {
		return 7
	}
	log.Panicln("invalid input at function GetScaleByCommitteeSize. size should be in [1,127].")
	return 0
}

func AppendCoeff(coeff []bls.Fr, length uint64) []bls.Fr {
	n := len(coeff)
	if uint64(n) > length {
		log.Fatalln("len(coeff) > targetLength in function AppendCoeff().len(coeff)=", n, "targetLength=", length)
	}

	ans := make([]bls.Fr, length)
	for j := 0; j < n; j++ {
		bls.CopyFr(&ans[j], &coeff[j])
	}
	for j := n; uint64(j) < length; j++ {
		bls.CopyFr(&ans[j], &bls.ZERO)
	}
	return ans
}
