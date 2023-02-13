package party

import (
	"github.com/DyCAPSTeam/DyCAPS/internal/bls"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"log"
)

type Client struct {
	*HonestParty
	s bls.Fr // the secret
}

//Share shares a secret client.s to the other parties
//Assuming KZG setup has done, and public parameters are available
func (client *Client) Share(ID []byte) {
	pi := new(Pi)
	pi.Init(client.F)
	pi.PiContents = make([]PiContent, 2*client.F+2) // here we do not use pi.Pi_contents[0]

	//pi <- g^s
	client.mutexKZG.Lock()
	bls.MulG1(&(pi.Gs), &bls.GenG1, &client.s)
	client.mutexKZG.Unlock()

	log.Printf("[VSSSend] pi.Gs: %v\n", pi.Gs.String())

	//generate a 2t-degree random polynomial F, where F(0) = s

	polyF := make([]bls.Fr, 2*client.F+1) // 2t-degree polinomial F

	for i := 0; uint32(i) < 2*client.F+1; i++ {
		polyF[i] = *bls.RandomFr()
	}
	bls.CopyFr(&polyF[0], &client.s)

	F_Vals := make([]bls.Fr, 2*client.F+2) // here we do not use F_Vals[0]
	for j := 1; uint32(j) <= 2*client.F+1; j++ {
		var position bls.Fr
		bls.AsFr(&position, uint64(j))
		bls.EvalPolyAt(&F_Vals[j], polyF, &position)
	}

	//generate 2t+1 t-degree B(x,index) and Z(x,index) (Z(x,0)=0)
	var ZList = make([][]bls.Fr, 2*client.F+2) // here we do not use ZList[0];ZList[i][j] means the j-th coefficient of Z(x,i)(j starts from 0)

	for i := 1; uint32(i) <= 2*client.F+1; i++ {
		ZList[i] = make([]bls.Fr, client.F+1)
		for j := 0; uint32(j) < client.F+1; j++ {
			ZList[i][j] = *bls.RandomFr()
		}
		bls.CopyFr(&ZList[i][0], &bls.ZERO)
	}

	var BList = make([][]bls.Fr, 2*client.F+2) // here we do not use BList_CoeffForm[0]

	for i := 1; uint32(i) <= 2*client.F+1; i++ {
		BList[i] = make([]bls.Fr, client.F+1)
		copy(BList[i], ZList[i])
	}

	//calculate BList_CoeffForm
	for i := 1; uint32(i) <= 2*client.F+1; i++ {
		bls.CopyFr(&BList[i][0], &F_Vals[i])
	}

	//Commit
	var CBList = make([]bls.G1Point, 2*client.F+2) // here we do not use CBList[0]
	var CZList = make([]bls.G1Point, 2*client.F+2) // here we do not use CZList[0]
	var WZ0List = make([]bls.G1Point, 2*client.F+2)
	var gFjList = make([]bls.G1Point, 2*client.F+2)

	for i := uint32(1); i <= 2*client.F+1; i++ {
		client.mutexKZG.Lock()
		CBList[i] = *client.KZG.CommitToPoly(BList[i])
		CZList[i] = *client.KZG.CommitToPoly(ZList[i])
		WZ0List[i] = *client.KZG.ComputeProofSingle(ZList[i], bls.ZERO)

		bls.MulG1(&gFjList[i], &bls.GenG1, &F_Vals[i])
		client.mutexKZG.Unlock()
		//add to pi
		pi.PiContents[i] = PiContent{j: i, CBj: CBList[i], CZj: CZList[i], WZ0: WZ0List[i], gFj: gFjList[i]}
	}

	//Send
	WBij := make([][]bls.G1Point, client.N+1) // the first index is in range[1,N],and the second [1,2F+1]. start from 1
	BijList := make([][]bls.Fr, client.N+1)
	//calculate WBij[][]
	for i := 1; uint32(i) <= client.N; i++ {
		WBij[i] = make([]bls.G1Point, 2*client.F+2) // start from 1
		for j := 1; uint32(j) <= 2*client.F+1; j++ {
			var position bls.Fr
			bls.AsFr(&position, uint64(i))
			client.mutexKZG.Lock()
			WBij[i][j] = *client.KZG.ComputeProofSingle(BList[j], position)
			client.mutexKZG.Unlock()
		}

	}
	//calculate BijList[][].

	for i := 1; uint32(i) <= client.N; i++ {
		BijList[i] = make([]bls.Fr, 2*client.F+2)
		for j := 1; uint32(j) <= 2*client.F+1; j++ {
			var position bls.Fr
			bls.AsFr(&position, uint64(i))
			bls.EvalPolyAt(&BijList[i][j], BList[j], &position)
		}
	}

	for i := 1; uint32(i) <= client.N; i++ {
		//encapsulate
		data := EncapsulateVSSSend(pi, BijList[i], WBij[i], client.F)
		err3 := client.Send(&protobuf.Message{
			Type:   "VSSSend",
			Id:     ID,
			Sender: 0x7fffffff, // 0x7fffffff denotes the dealer (this client) id
			Data:   data,
		}, uint32(i-1)) // pid = i - 1
		if err3 != nil {
			log.Printf("[VSSSend] Client send VSSSend error: %v\n", err3)
		} else {
			log.Printf("[VSSSend] Client has sent VSSSend to party %v\n", i-1)
		}
	}
}

func (client *Client) SetSecret(s bls.Fr) {
	bls.CopyFr(&client.s, &s)
}
