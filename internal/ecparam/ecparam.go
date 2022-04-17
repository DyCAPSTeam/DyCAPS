package ecparam

/*
forked from https://github.com/CHURPTeam/CHURP
*/

import (
	"math/big"

	"github.com/Nik-U/pbc"
	"github.com/ncw/gmp"
)

var PBC256 = initializeParams()

const configString = "type a q 7551229346118097707657055192679868878245809937493679053434400908343538795134604198250280897597927293593086560738424067354362094283307245214081272453750739 h 130427378862502999532171986493880300490778513023419182702204867119101398441940 r 57896044618658097711785492504343953926634992332820282019728792006155588075521 exp2 255 exp1 41 sign1 1 sign0 1"

const order = "57896044618658097711785492504343953926634992332820282019728792006155588075521"

type ECParams struct {
	Params  *pbc.Params
	Pairing *pbc.Pairing
	Nbig    *big.Int
	Ngmp    *gmp.Int
	G       *pbc.Element
}

func initializeParams() ECParams {
	p, err := pbc.NewParamsFromString(configString)
	if err != nil {
		panic(err.Error())
	}

	var pp ECParams

	pp.Params = p
	pp.Pairing = p.NewPairing()
	pp.Nbig = big.NewInt(0)
	pp.Nbig.SetString(order, 10)
	pp.Ngmp = gmp.NewInt(0)
	pp.Ngmp.SetString(order, 10)
	pp.G = pp.Pairing.NewG1()
	pp.G.SetString("[4133724144590655254194602165057338253581374248311829415804358586850519521096709820505371851539736973052316311123290392470565023776459368655389261216524371, 3477043631151308457697380491861699444387375269849172071603708732050642928211953792333616861215138231339668243778249230704600690552449532564174180095431116]", 10)

	return pp
}