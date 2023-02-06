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
	bls.MulG1(&(pi.Gs), &bls.GenG1, &client.s)

	log.Printf("[VSSSend] pi.Gs: %v\n", pi.Gs.String())

	//generate a 2t-degree random polynomial F, where F(w^0) = s

	F_CoeffForm := make([]bls.Fr, 2*client.F+1) // 2t-degree polinomial F

	for i := 0; uint32(i) < 2*client.F+1; i++ {
		F_CoeffForm[i] = *bls.RandomFr()
	}
	var FValAtZero bls.Fr
	bls.EvalPolyAt(&FValAtZero, F_CoeffForm, &client.FS.ExpandedRootsOfUnity[0])
	bls.SubModFr(&F_CoeffForm[0], &F_CoeffForm[0], &FValAtZero)
	bls.AddModFr(&F_CoeffForm[0], &F_CoeffForm[0], &client.s)
	F_EvalFrom, err := client.FS.FFT(PadCoeff(F_CoeffForm, client.FS.MaxWidth), false)
	if err != nil {
		log.Fatalln(err)
	}

	//generate 2t+1 t-degree B(x,w^index) and Z(x,w^index) (Z(x,w^0)=0)
	var ZList_CoeffForm = make([][]bls.Fr, 2*client.F+2) // here we do not use ZList_CoeffForm[0];ZList_CoeffForm[i][j] means the j-th coefficient of Z(x,w^i)(j starts from 0)

	for i := 1; uint32(i) <= 2*client.F+1; i++ {
		ZList_CoeffForm[i] = make([]bls.Fr, client.F+1)
		for j := 0; uint32(j) < client.F+1; j++ {
			ZList_CoeffForm[i][j] = *bls.RandomFr()
		}
		var ValAtZero bls.Fr
		bls.EvalPolyAt(&ValAtZero, ZList_CoeffForm[i], &client.FS.ExpandedRootsOfUnity[0])
		var tmp bls.Fr
		bls.SubModFr(&tmp, &ZList_CoeffForm[i][0], &ValAtZero)
		bls.CopyFr(&ZList_CoeffForm[i][0], &tmp)
	}

	var BList_CoeffForm = make([][]bls.Fr, 2*client.F+2) // here we do not use BList_CoeffForm[0]

	for i := 1; uint32(i) <= 2*client.F+1; i++ {
		BList_CoeffForm[i] = make([]bls.Fr, client.F+1)
		copy(BList_CoeffForm[i], ZList_CoeffForm[i])
	}

	//calculate BList_CoeffForm
	for i := 1; uint32(i) <= 2*client.F+1; i++ {
		var tmp bls.Fr
		bls.AddModFr(&tmp, &BList_CoeffForm[i][0], &F_EvalFrom[i])
		bls.CopyFr(&BList_CoeffForm[i][0], &tmp)
	}

	//Commit
	var CBList = make([]bls.G1Point, 2*client.F+2) // here we do not use CBList[0]
	var CZList = make([]bls.G1Point, 2*client.F+2) // here we do not use CZList[0]
	var WZ0List = make([]bls.G1Point, 2*client.F+2)
	var gFjList = make([]bls.G1Point, 2*client.F+2)

	for i := uint32(1); i <= 2*client.F+1; i++ {

		CBList[i] = *client.KZG.CommitToPoly(BList_CoeffForm[i])
		CZList[i] = *client.KZG.CommitToPoly(ZList_CoeffForm[i])
		WZ0List[i] = *client.KZG.ComputeProofSingle(ZList_CoeffForm[i], client.FS.ExpandedRootsOfUnity[0])

		bls.MulG1(&gFjList[i], &bls.GenG1, &F_EvalFrom[i])
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
			WBij[i][j] = *client.KZG.ComputeProofSingle(BList_CoeffForm[j], client.FS.ExpandedRootsOfUnity[i])
		}

	}
	//calculate BijList[][]. First calculate BList_EvalForm and then calculate BijList[][].
	var BList_EvalForm = make([][]bls.Fr, 2*client.F+2)
	for i := 1; uint32(i) <= 2*client.F+1; i++ {
		BList_EvalForm[i] = make([]bls.Fr, client.FS.MaxWidth)
		var err2 error
		BList_EvalForm[i], err2 = client.FS.FFT(PadCoeff(BList_CoeffForm[i], client.FS.MaxWidth), false)
		if err2 != nil {
			log.Fatalln(err2)
		}
	}

	for i := 1; uint32(i) <= client.N; i++ {
		BijList[i] = make([]bls.Fr, 2*client.F+2)
		for j := 1; uint32(j) <= 2*client.F+1; j++ {
			BijList[i][j] = BList_EvalForm[j][i]
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
