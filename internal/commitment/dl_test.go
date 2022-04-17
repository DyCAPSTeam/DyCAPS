package commitment

/*
forked from https://github.com/CHURPTeam/CHURP
*/

import (
	"fmt"
	"testing"

	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/ncw/gmp"
	"github.com/stretchr/testify/assert"
)

func TestDLCommit(t *testing.T) {
	var Curve = ecparam.PBC256
	fmt.Println("Curve:", Curve)
	c := DLCommit{}
	c.SetupFix()

	// res = g^x
	res := c.pairing.NewG1()
	x := gmp.NewInt(100)
	c.Commit(res, x)

	assert.True(t, c.Verify(res, x), "dl_commit")
}
