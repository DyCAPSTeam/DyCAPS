package party

import (
	"fmt"
	"math/rand"
	"sync"
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
var mutexKZG sync.Mutex
var SysSuite = pairing.NewSuiteBn256()

type PiContent struct {
	j    int
	CB_j *pbc.Element //In DyCAPS.Share, R_j(x)=B(j,x), R_j(0)=F(j)
	CZ_j *pbc.Element //Z_j(x)=R_j(x)-R_j(0)
	WZ_0 *pbc.Element //witness of Z_j(0)=0
	g_Fj *pbc.Element //g^F(j), F(j) is of t degree
}

type Pi struct {
	Gs         *pbc.Element // g^s
	PiContents []PiContent
}

//Assuming KZG setup has done, and public parameters are available
//The secret to be shared is stored in client.s
func (client *Client) Share(ID []byte) {

	pi := new(Pi)
	pi.Init(client.F)
	pi.PiContents = make([]PiContent, 2*client.F+2) // here we do not use pi.Pi_contents[0]
	var p *gmp.Int                                  // the prime of Zp* (the type is *gmp.Int)
	p = ecparam.PBC256.Ngmp
	//pi <- g^s
	sPoly, _ := polyring.New(0)
	_ = sPoly.SetCoefficientBig(0, client.s)
	KZG.Commit(pi.Gs, sPoly)
	fmt.Printf("pi.Gs: %v\n", pi.Gs)

	//generate a 2t-degree random polynomial F, where F(0) = s
	var rnd = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	//TODO: use crypto/rand instead
	var F, _ = polyring.NewRand(int(2*client.F), rnd, p)
	var FValueat = make([]*gmp.Int, 2*client.F+2) // here we do not use F_ValueAt[0]
	for i := 0; uint32(i) < 2*client.F+2; i++ {
		FValueat[i] = gmp.NewInt(0)
	}
	F.SetCoefficientBig(0, client.s)

	//generate 2t+1 t-degree Rj(x)
	var RList = make([]polyring.Polynomial, 2*client.F+2) // here we do not use R_list[0]
	var rnd2 = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	for j := 1; uint32(j) <= 2*client.F+1; j++ {
		F.EvalMod(gmp.NewInt(int64(j)), p, FValueat[j])
		RList[j], _ = polyring.NewRand(int(client.F), rnd2, p) //TODO: will rnd2 makes the coefficients duplicated?
		RList[j].SetCoefficientBig(0, FValueat[j])
	}

	//Commit
	var ZList = make([]polyring.Polynomial, 2*client.F+2) // here we do not use Z_list[0]
	var CBList = make([]*pbc.Element, 2*client.F+2)       // here we do not use C_R_list[0]
	var CZList = make([]*pbc.Element, 2*client.F+2)       // here we do not use C_Z_list[0]
	var WZ0List = make([]*pbc.Element, 2*client.F+2)
	for i := 0; uint32(i) <= 2*client.F+1; i++ {
		CBList[i] = KZG.NewG1()
		CZList[i] = KZG.NewG1()
		WZ0List[i] = KZG.NewG1()
	}

	for i := 1; uint32(i) <= 2*client.F+1; i++ {
		ZList[i] = polyring.NewEmpty()
		ZList[i].ResetTo(RList[i])
	}

	for i := 1; uint32(i) <= 2*client.F+1; i++ {
		//generate Z_list
		temp, _ := polyring.New(0) // temp means the 0-degree polynomial f(x) = F_ValueAt[i]
		err := temp.SetCoefficientBig(0, FValueat[i])
		if err != nil {
			fmt.Printf("Client SetCoefficientBig error at i=%v: %v", i, err)
		}
		copiedZ := polyring.NewEmpty()
		copiedZ.ResetTo(ZList[i])
		ZList[i].Sub(copiedZ, temp)
		ZList[i].Mod(p) // don't forget mod p!!!
		//commit R_list
		KZG.Commit(CBList[i], RList[i])
		//commit Z_list
		KZG.Commit(CZList[i], ZList[i])
		//create witness of (Zj(x),0)
		KZG.CreateWitness(WZ0List[i], ZList[i], gmp.NewInt(0))

		//add to pi
		var FjCommit *pbc.Element = KZG.NewG1()
		KZG.Commit(FjCommit, temp)
		pi.PiContents[i] = PiContent{j: i, CB_j: CBList[i], CZ_j: CZList[i], WZ_0: WZ0List[i], g_Fj: FjCommit}
	}

	//Send
	WRji := make([][]*pbc.Element, client.N+1) // the first index is in range[1,N],and the second [1,2F+1]. start from 1
	RjiList := make([][]*gmp.Int, client.N+1)

	for i := 1; uint32(i) <= client.N; i++ {
		WRji[i] = make([]*pbc.Element, 2*client.F+2) // start from 1
		RjiList[i] = make([]*gmp.Int, 2*client.F+2)  // start from 1
		for j := 0; uint32(j) <= 2*client.F+1; j++ {
			RjiList[i][j] = gmp.NewInt(0)
			WRji[i][j] = KZG.NewG1()
		}
		//set W_Rji
		for j := 1; uint32(j) <= 2*client.F+1; j++ {
			KZG.CreateWitness(WRji[i][j], RList[j], gmp.NewInt(int64(i)))
			RList[j].EvalMod(gmp.NewInt(int64(i)), p, RjiList[i][j])
		}
		//encapsulate
		data := EncapsulateVSSSend(pi, RjiList[i], WRji[i], client.N, client.F)
		// fmt.Println("encapsulated data for ", i-1, " : ", data)
		// for j := 1; uint32(j) <= 2*client.F+1; j++ {
		// 	fmt.Println("i= ", i, " j= ", j, " Rj(i) = ", Rji_list[i][j], " W_Rji = ", W_Rji[i][j])
		// }
		err := client.Send(&protobuf.Message{
			Type:   "VSSSend",
			Id:     ID,
			Sender: 0x7fffffff, // 0x7fffffff denotes the dealer (this client) id
			Data:   data,
		}, uint32(i-1))
		if err != nil {
			fmt.Printf("Client send VSSSend error: %v", err)
		} // pid = i - 1
		// fmt.Println("client send VSSSend message to ", i)
	}
}
