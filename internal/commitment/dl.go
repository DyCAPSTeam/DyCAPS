package commitment

/*
forked from https://github.com/CHURPTeam/CHURP
*/

import (
	"math/big"

	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/Nik-U/pbc"
	"github.com/ncw/gmp"
)

// DLCommit for x is g^x
type DLCommit struct {
	pairing *pbc.Pairing
	pk      *pbc.Element
}

// Setup initializes a DLCommit.
// group order is 2^rbits, finite field is F_q where q is ~2^qbits.
// suggested parameters are rbits = 160, qbits = 512
func (c *DLCommit) Setup(rbits, qbits uint32) {
	panic("unimplemented")
}

// Setup initializes a fixed DLCommit
func (c *DLCommit) SetupFix() {
	var Curve = ecparam.PBC256
	c.pairing = Curve.Pairing
	c.pk = Curve.G
}

func (c *DLCommit) NewG1() *pbc.Element {
	return c.pairing.NewG1()
}

func (c *DLCommit) NewGT() *pbc.Element {
	return c.pairing.NewGT()
}

// Commit sets res to g^x
func (c *DLCommit) Commit(res *pbc.Element, x *gmp.Int) {
	if c.pairing == nil || c.pk == nil {
		panic("not initialized")
	}
	exp := big.NewInt(0)
	exp.SetString(x.String(), 10)
	res.PowBig(c.pk, exp)
}

// Verify checks C == g^x
func (c *DLCommit) Verify(C *pbc.Element, x *gmp.Int) bool {
	if c.pairing == nil || c.pk == nil {
		panic("not initialized")
	}
	tmp := c.pairing.NewG1()
	exp := big.NewInt(0)
	exp.SetString(x.String(), 10)
	tmp.PowBig(c.pk, exp)
	return tmp.Equals(C)
}