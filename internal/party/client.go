package party

import (
	"log"
	"math/rand"
	"time"

	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"github.com/Nik-U/pbc"
	"github.com/ncw/gmp"
)

type Client struct {
	*HonestParty
	s *gmp.Int // the secret
}

//Share shares a secret client.s to the other parties
//Assuming KZG setup has done, and public parameters are available
func (client *Client) Share(ID []byte) {
	pi := new(Pi)
	pi.Init(client.F, client.KZG)
	pi.PiContents = make([]PiContent, 2*client.F+2) // here we do not use pi.Pi_contents[0]
	var p = ecparam.PBC256.Ngmp                     // the prime of Zp* (the type is *gmp.Int)
	//pi <- g^s
	sPoly, _ := polyring.New(0)
	_ = sPoly.SetCoefficientBig(0, client.s)
	client.KZG.Commit(pi.Gs, sPoly)
	// log.Printf("[VSSSend] pi.Gs: %v\n", pi.Gs)

	//generate a 2t-degree random polynomial F, where F(0) = s
	var rnd = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	//TODO: use crypto/rand instead
	var F, _ = polyring.NewRand(int(2*client.F), rnd, p)

	var vF = make([]*gmp.Int, 2*client.F+2) // here we do not use F_ValueAt[0]
	for i := 0; uint32(i) < 2*client.F+2; i++ {
		vF[i] = gmp.NewInt(0)
	}
	F.SetCoefficientBig(0, client.s)

	//generate 2t+1 t-degree B(x,index)
	var BList = make([]polyring.Polynomial, 2*client.F+2) // here we do not use BList[0]
	var rnd2 = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	for j := 1; uint32(j) <= 2*client.F+1; j++ {
		F.EvalMod(gmp.NewInt(int64(j)), p, vF[j])
		BList[j], _ = polyring.NewRand(int(client.F), rnd2, p) //TODO: will rnd2 makes the coefficients duplicated?
		BList[j].SetCoefficientBig(0, vF[j])
	}

	//Commit
	var ZList = make([]polyring.Polynomial, 2*client.F+2) // here we do not use ZList[0]
	var CBList = make([]*pbc.Element, 2*client.F+2)       // here we do not use CBList[0]
	var CZList = make([]*pbc.Element, 2*client.F+2)       // here we do not use CZList[0]
	var WZ0List = make([]*pbc.Element, 2*client.F+2)
	for i := 0; uint32(i) <= 2*client.F+1; i++ {
		CBList[i] = client.KZG.NewG1()
		CZList[i] = client.KZG.NewG1()
		WZ0List[i] = client.KZG.NewG1()
	}

	for i := 1; uint32(i) <= 2*client.F+1; i++ {
		ZList[i] = polyring.NewEmpty()
		ZList[i].ResetTo(BList[i])
	}

	for i := uint32(1); i <= 2*client.F+1; i++ {
		//generate Z_list
		temp, _ := polyring.New(0) // temp means the 0-degree polynomial f(x) = F_ValueAt[i]
		err := temp.SetCoefficientBig(0, vF[i])
		if err != nil {
			log.Printf("[VSSSend] Client SetCoefficientBig error at i=%v: %v", i, err)
		}
		copiedZ := polyring.NewEmpty()
		copiedZ.ResetTo(ZList[i])
		ZList[i].Sub(copiedZ, temp)
		ZList[i].Mod(p) // don't forget mod p!!!
		//commit R_list
		client.KZG.Commit(CBList[i], BList[i])
		//commit Z_list
		client.KZG.Commit(CZList[i], ZList[i])
		//create witness of (Zj(x),0)
		client.KZG.CreateWitness(WZ0List[i], ZList[i], gmp.NewInt(0))

		//add to pi
		var FjCommit = client.KZG.NewG1()
		client.KZG.Commit(FjCommit, temp)
		pi.PiContents[i] = PiContent{j: i, CBj: CBList[i], CZj: CZList[i], WZ0: WZ0List[i], gFj: FjCommit}
	}

	//Send
	WBij := make([][]*pbc.Element, client.N+1) // the first index is in range[1,N],and the second [1,2F+1]. start from 1
	BijList := make([][]*gmp.Int, client.N+1)

	for i := 1; uint32(i) <= client.N; i++ {
		WBij[i] = make([]*pbc.Element, 2*client.F+2) // start from 1
		BijList[i] = make([]*gmp.Int, 2*client.F+2)  // start from 1
		for j := 0; uint32(j) <= 2*client.F+1; j++ {
			BijList[i][j] = gmp.NewInt(0)
			WBij[i][j] = client.KZG.NewG1()
		}
		//set W_Rji
		for j := 1; uint32(j) <= 2*client.F+1; j++ {
			client.KZG.CreateWitness(WBij[i][j], BList[j], gmp.NewInt(int64(i)))
			BList[j].EvalMod(gmp.NewInt(int64(i)), p, BijList[i][j])
		}
		//encapsulate
		data := EncapsulateVSSSend(pi, BijList[i], WBij[i], client.F)
		err := client.Send(&protobuf.Message{
			Type:   "VSSSend",
			Id:     ID,
			Sender: 0x7fffffff, // 0x7fffffff denotes the dealer (this client) id
			Data:   data,
		}, uint32(i-1)) // pid = i - 1
		if err != nil {
			log.Printf("[VSSSend] Client send VSSSend error: %v\n", err)
		} else {
			log.Printf("[VSSSend] Client has sent VSSSend to party %v\n", i-1)
		}
	}
}

func (client *Client) SetSecret(s *gmp.Int) {
	client.s = gmp.NewInt(0)
	client.s.Set(s)
}
