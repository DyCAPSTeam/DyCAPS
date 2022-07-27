package party

import (
	"bytes"
	"encoding/gob"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"io/ioutil"
)

//SigKeyGen return pk and sks for threshold signature
//n is the number of parties, t is the threshold of combining signature
func SigKeyGen(n uint32, t uint32) ([]*share.PriShare, *share.PubPoly) {
	suit := pairing.NewSuiteBn256()
	random := suit.RandomStream()

	x := suit.G1().Scalar().Pick(random)

	// priploy
	priploy := share.NewPriPoly(suit.G2(), int(t), x, suit.RandomStream())
	// n points in ploy
	npoints := priploy.Shares(int(n))
	//pub ploy
	pubploy := priploy.Commit(suit.G2().Point().Base())
	return npoints, pubploy
}

//here t = 2f + 1
func SigKeyGenFix(n uint32, t uint32) ([]*share.PriShare, *share.PubPoly) {
	suit := pairing.NewSuiteBn256()

	coeff := make([]kyber.Scalar, t)
	coeff_bytes := make([][]byte, t)
	ReadFromFile(&coeff_bytes, "coefficients")
	for i := 0; uint32(i) < t; i++ {
		coeff[i] = suit.Scalar().One()
		coeff[i].SetBytes(coeff_bytes[i])
	}

	// pripoly
	pripoly := share.CoefficientsToPriPoly(suit.G2(), coeff)
	// n points in ploy
	npoints := pripoly.Shares(int(n))
	//pub poly
	pubpoly := pripoly.Commit(suit.G2().Point().Base())
	return npoints, pubpoly
}

func SigKeyGenFix_New(n uint32, t uint32) ([]*share.PriShare, *share.PubPoly) {
	suit := pairing.NewSuiteBn256()

	coeff := make([]kyber.Scalar, t)
	coeff_bytes := make([][]byte, t)
	ReadFromFile(&coeff_bytes, "coefficients_new")
	for i := 0; uint32(i) < t; i++ {
		coeff[i] = suit.Scalar().One()
		coeff[i].SetBytes(coeff_bytes[i])
	}

	// pripoly
	pripoly := share.CoefficientsToPriPoly(suit.G2(), coeff)
	// n points in ploy
	npoints := pripoly.Shares(int(n))
	//pub poly
	pubpoly := pripoly.Commit(suit.G2().Point().Base())
	return npoints, pubpoly
}

func ReadFromFile(data interface{}, filename string) {
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	buffer := bytes.NewBuffer(raw)
	dec := gob.NewDecoder(buffer)
	err = dec.Decode(data)
	if err != nil {
		panic(err)
	}
}
