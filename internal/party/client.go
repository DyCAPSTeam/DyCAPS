package party

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/DyCAPSTeam/DyCAPS/internal/commitment"
	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"github.com/Nik-U/pbc"
	"github.com/ncw/gmp"
	"go.dedis.ch/kyber/v3/pairing"
)

type Client struct {
	*HonestParty
	s *gmp.Int // the secret
}

var KZG = new(commitment.DLPolyCommit)
var Sys_Suite = pairing.NewSuiteBn256()

type Pi_Content struct {
	j    int
	CR_j *pbc.Element
	CZ_j *pbc.Element
	WZ_0 *pbc.Element
	g_Fj *pbc.Element
}

type Pi struct {
	G_s         *pbc.Element // g^s
	Pi_contents []Pi_Content
}

//Assuming KZG setup has done, and public parameters are available
//The secret to be shared is stored in client.s
func (client *Client) Share(ID []byte) {

	pi := new(Pi)
	pi.Init(client.F)
	pi.Pi_contents = make([]Pi_Content, 2*client.F+2) // here we do not use pi.Pi_contents[0]
	var p *gmp.Int                                    // the prime of Zp* (the type is *gmp.Int)
	p = ecparam.PBC256.Ngmp
	//pi <- g^s
	s_poly, _ := polyring.New(0)
	_ = s_poly.SetCoefficientBig(0, client.s)
	KZG.Commit(pi.G_s, s_poly)
	fmt.Printf("pi.G_s: %v\n", pi.G_s)

	//generate a 2t-degree random polynomial F, where F(0) = s
	var rnd = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	//TODO: use crypto/rand instead
	var F, _ = polyring.NewRand(int(2*client.F), rnd, p)
	var F_ValueAt = make([]*gmp.Int, 2*client.F+2) // here we do not use F_ValueAt[0]
	for i := 0; uint32(i) < 2*client.F+2; i++ {
		F_ValueAt[i] = gmp.NewInt(0)
	}
	F.SetCoefficientBig(0, client.s)

	//generate 2t+1 t-degree Rj(x)
	var R_list = make([]polyring.Polynomial, 2*client.F+2) // here we do not use R_list[0]
	var rnd2 = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	for j := 1; uint32(j) <= 2*client.F+1; j++ {
		F.EvalMod(gmp.NewInt(int64(j)), p, F_ValueAt[j])
		R_list[j], _ = polyring.NewRand(int(client.F), rnd2, p) //TODO: will rnd2 makes the coefficients duplicated?
		R_list[j].SetCoefficientBig(0, F_ValueAt[j])
	}

	//Commit
	var Z_list = make([]polyring.Polynomial, 2*client.F+2) // here we do not use Z_list[0]
	var C_R_list = make([]*pbc.Element, 2*client.F+2)      // here we do not use C_R_list[0]
	var C_Z_list = make([]*pbc.Element, 2*client.F+2)      // here we do not use C_Z_list[0]
	var W_Z0_list = make([]*pbc.Element, 2*client.F+2)
	for i := 0; uint32(i) <= 2*client.F+1; i++ {
		C_R_list[i] = KZG.NewG1()
		C_Z_list[i] = KZG.NewG1()
		W_Z0_list[i] = KZG.NewG1()
	}

	for i := 1; uint32(i) <= 2*client.F+1; i++ {
		Z_list[i] = polyring.NewEmpty()
		Z_list[i].ResetTo(R_list[i])
	}

	for i := 1; uint32(i) <= 2*client.F+1; i++ {
		//generate Z_list
		temp, _ := polyring.New(0) // temp means the 0-degree polynomial f(x) = F_ValueAt[i]
		temp.SetCoefficientBig(0, F_ValueAt[i])
		copyedZ := polyring.NewEmpty()
		copyedZ.ResetTo(Z_list[i])
		Z_list[i].Sub(copyedZ, temp)
		Z_list[i].Mod(p) // don't forget mod p!!!
		//commit R_list
		KZG.Commit(C_R_list[i], R_list[i])
		//commit Z_list
		KZG.Commit(C_Z_list[i], Z_list[i])
		//create witness of (Zj(x),0)
		KZG.CreateWitness(W_Z0_list[i], Z_list[i], gmp.NewInt(0))

		//add to pi
		var FjCommit *pbc.Element = KZG.NewG1()
		KZG.Commit(FjCommit, temp)
		pi.Pi_contents[i] = Pi_Content{j: i, CR_j: C_R_list[i], CZ_j: C_Z_list[i], WZ_0: W_Z0_list[i], g_Fj: FjCommit}
	}

	//Send
	W_Rji := make([][]*pbc.Element, client.N+1) // the first index is in range[1,N],and the second [1,2F+1]. start from 1
	Rji_list := make([][]*gmp.Int, client.N+1)

	for i := 1; uint32(i) <= client.N; i++ {
		W_Rji[i] = make([]*pbc.Element, 2*client.F+2) // start from 1
		Rji_list[i] = make([]*gmp.Int, 2*client.F+2)  // start from 1
		for j := 0; uint32(j) <= 2*client.F+1; j++ {
			Rji_list[i][j] = gmp.NewInt(0)
			W_Rji[i][j] = KZG.NewG1()
		}
		//set W_Rji
		for j := 1; uint32(j) <= 2*client.F+1; j++ {
			KZG.CreateWitness(W_Rji[i][j], R_list[j], gmp.NewInt(int64(i)))
			R_list[j].EvalMod(gmp.NewInt(int64(i)), p, Rji_list[i][j])
		}
		//encapsulate
		data := Encapsulate_VSSSend(pi, Rji_list[i], W_Rji[i], client.N, client.F)
		// fmt.Println("encapsulated data for ", i-1, " : ", data)
		// for j := 1; uint32(j) <= 2*client.F+1; j++ {
		// 	fmt.Println("i= ", i, " j= ", j, " Rj(i) = ", Rji_list[i][j], " W_Rji = ", W_Rji[i][j])
		// }
		client.Send(&protobuf.Message{
			Type:   "VSSSend",
			Id:     ID,
			Sender: 0x7fffffff, // 0x7fffffff denotes the dealer (this client) id
			Data:   data,
		}, uint32(i-1)) // pid = i - 1
		// fmt.Println("client send VSSSend message to ", i)
	}
}
