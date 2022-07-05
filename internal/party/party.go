package party

import (
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"time"

	"github.com/Nik-U/pbc"
	"github.com/ncw/gmp"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"google.golang.org/protobuf/proto"

	"github.com/DyCAPSTeam/DyCAPS/internal/conv"
	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/interpolation"
	"github.com/DyCAPSTeam/DyCAPS/internal/polypoint"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
)

//Party is an interface of committee members
type Party interface {
	send(m *protobuf.Message, des uint32) error
	broadcast(m *protobuf.Message) error
	getMessageWithType(messageType string) (*protobuf.Message, error)
}

//TODO: add epoch number into this struct
//HonestParty is a struct of honest committee members
type HonestParty struct {
	N            uint32   // committee size
	F            uint32   // number of corrupted parties
	PID          uint32   // id of this party
	ipList       []string // ip list of the current committee
	portList     []string // port list of the current committee
	sendChannels []chan *protobuf.Message

	ipListNext         []string // ip list of the new committee
	portListNext       []string // port list of the new committee
	sendToNextChannels []chan *protobuf.Message

	dispatchChannels *sync.Map

	SigPK *share.PubPoly  //tss pk
	SigSK *share.PriShare //tss sk

	Proof *Pi //pi

	fullShare    polyring.Polynomial // B(p.PID+1,y)
	reducedShare polyring.Polynomial // B(x,p.PID+1)

	witnessInit        []*pbc.Element
	witnessInitIndexes []*gmp.Int //TODO: change this name later. witnessInitIndexes[j] means the witness of Rj+1(p.PID+1)
}

// SRecElement is the set of elements for recover
type SRecElement struct {
	j int
	v *gmp.Int
}

// SSigElement is the set of signatures
type SSigElement struct {
	j   int
	Sig []byte
}

// SComElement is the set of commitments
type SComElement struct {
	j  int
	CB *pbc.Element
}

// SBElement is the set of elements for full shares
type SBElement struct {
	j  int
	CB *pbc.Element
	v  *gmp.Int
	w  *pbc.Element
}

//NewHonestParty returns a new honest party object
//FIXME: witnessInit may bring the problem of null pointers.
func NewHonestParty(N uint32, F uint32, pid uint32, ipList []string, portList []string, ipListNext []string, portListNext []string, sigPK *share.PubPoly, sigSK *share.PriShare) *HonestParty {
	piInit := new(Pi)
	piInit.Init(F)
	witnessInit := make([]*pbc.Element, 2*F+2)
	witnessInitIndexes := make([]*gmp.Int, 2*F+2)
	for i := 0; uint32(i) < 2*F+2; i++ {
		witnessInit[i] = KZG.NewG1()
		witnessInitIndexes[i] = gmp.NewInt(0)
	}
	p := HonestParty{
		N:                  N,
		F:                  F,
		PID:                pid,
		ipList:             ipList,
		portList:           portList,
		ipListNext:         ipListNext,
		portListNext:       portListNext,
		sendChannels:       make([]chan *protobuf.Message, N),
		sendToNextChannels: make([]chan *protobuf.Message, N),

		SigPK: sigPK,
		SigSK: sigSK,

		Proof: piInit,

		fullShare:          polyring.NewEmpty(),
		reducedShare:       polyring.NewEmpty(),
		witnessInit:        witnessInit,
		witnessInitIndexes: witnessInitIndexes,
	}
	return &p
}

func (p *HonestParty) ShareReduceSend(ID []byte) {
	ecparamN := ecparam.PBC256.Ngmp

	var tmpCB = make([]*pbc.Element, p.N+1) //B(x,j)=R_j(x), start from 1
	var tmpWB = make([]*pbc.Element, p.N+1) //start from 1
	for i := uint32(0); i < p.N+1; i++ {
		tmpCB[i] = KZG.NewG1()
		tmpWB[i] = KZG.NewG1()
	}

	for j := uint32(0); j < 2*p.F+2; j++ {
		tmpCB[j].Set(p.Proof.PiContents[j].CB_j)
		tmpWB[p.witnessInitIndexes[j].Int64()].Set(p.witnessInit[j])
	}

	//interpolate the commitments and witnesses
	mutexPolyring.Lock()
	for j := uint32(1); j < p.N+1; j++ {
		tmpCB[j] = InterpolateComOrWit(2*p.F, j, tmpCB[1:2*p.F+2])
		tmpWB[j] = InterpolateComOrWitbyKnownIndexes(2*p.F, j, p.witnessInitIndexes[1:], p.witnessInit[1:])
		// tmpWB[j] = InterpolateComOrWit(2*p.F, j, tmpWB[1:])
	}

	mutexPolyring.Unlock()

	if p.PID == 1 {
		fmt.Printf("Party %v, tmpWB: %v\n", p.PID, tmpWB)
		fmt.Printf("Party %v, tmpCB: %v\n", p.PID, tmpCB)
	}

	for j := uint32(0); j < p.N; j++ {
		polyValue := gmp.NewInt(0)
		p.fullShare.EvalMod(gmp.NewInt(int64(j+1)), ecparamN, polyValue)
		ShareReduceMessage := protobuf.ShareReduce{
			C: tmpCB[j+1].CompressedBytes(),
			V: polyValue.Bytes(),
			W: tmpWB[j+1].CompressedBytes(),
		}
		data, _ := proto.Marshal(&ShareReduceMessage)
		p.SendtoNext(&protobuf.Message{
			Type:   "ShareReduce",
			Id:     ID,
			Sender: p.PID,
			Data:   data,
		}, j)
	}
}

func (p *HonestParty) ShareReduceReceive(ID []byte) {
	ecparamN := ecparam.PBC256.Ngmp
	// var wgShareReduce sync.WaitGroup
	var ShareReduceMap = make(map[string][]polypoint.PolyPoint)
	var ComMap = make(map[string]uint32)
	// var mutexShareReduceMap sync.Mutex
	var MostCountedCom string

	var vJ *gmp.Int
	var C, wJ *pbc.Element
	var deg = 0
	var polyX, polyY []*gmp.Int
	vJ = gmp.NewInt(0)
	C = KZG.NewG1()
	wJ = KZG.NewG1()

	for {
		m := <-p.GetMessage("ShareReduce", ID)
		fmt.Printf("[ShareReduce] Party %v receives ShareReduce message from %v\n", p.PID, m.Sender)
		var ShareReduceData protobuf.ShareReduce
		proto.Unmarshal(m.Data, &ShareReduceData)
		C.SetCompressedBytes(ShareReduceData.C)
		wJ.SetCompressedBytes(ShareReduceData.W)
		vJ.SetBytes(ShareReduceData.V)

		verified := KZG.VerifyEval(C, gmp.NewInt(int64(m.Sender+1)), vJ, wJ)
		if verified {
			// mutexShareReduceMap.Lock()
			_, ok2 := ShareReduceMap[string(ShareReduceData.C)]
			if ok2 {
				ShareReduceMap[string(ShareReduceData.C)] = append(ShareReduceMap[string(ShareReduceData.C)], polypoint.PolyPoint{
					X:       0,
					Y:       gmp.NewInt(0),
					PolyWit: KZG.NewG1(),
				})
				count := ComMap[string(ShareReduceData.C)]

				ShareReduceMap[string(ShareReduceData.C)][count].X = int32(m.Sender + 1)
				ShareReduceMap[string(ShareReduceData.C)][count].Y.Set(vJ)
				ShareReduceMap[string(ShareReduceData.C)][count].PolyWit.Set(wJ)
				ComMap[string(ShareReduceData.C)] += 1
			} else {
				ShareReduceMap[string(ShareReduceData.C)] = make([]polypoint.PolyPoint, 0)
				ShareReduceMap[string(ShareReduceData.C)] = append(ShareReduceMap[string(ShareReduceData.C)], polypoint.PolyPoint{
					X:       0,
					Y:       gmp.NewInt(0),
					PolyWit: KZG.NewG1(),
				})
				ShareReduceMap[string(ShareReduceData.C)][0].X = int32(m.Sender + 1)
				ShareReduceMap[string(ShareReduceData.C)][0].Y.Set(vJ)
				ShareReduceMap[string(ShareReduceData.C)][0].PolyWit.Set(wJ)
				ComMap[string(ShareReduceData.C)] = 1
			}

			if ComMap[string(ShareReduceData.C)] >= p.F+1 {
				MostCountedCom = string(ShareReduceData.C)

				// mutexShareReduceMap.Unlock()
				fmt.Printf("[ShareReduce] Party %v has finished ShareReduce.\n", p.PID)
				break
			}
			// mutexShareReduceMap.Unlock()
		} else {
			fmt.Printf("[ShareReduce] Party %v verifies Reduce message from party %v FAIL. C: %s, v: %v, w: %s\n", p.PID, m.Sender, C.String(), vJ, wJ.String())
		}
	}

	// mutexShareReduceMap.Lock()
	polyX = make([]*gmp.Int, p.F+1)
	polyY = make([]*gmp.Int, p.F+1)
	for i := uint32(0); i <= p.F; i++ {

		polyX[deg] = gmp.NewInt(0)
		polyX[deg].Set(gmp.NewInt(int64(ShareReduceMap[MostCountedCom][i].X)))
		polyY[deg] = gmp.NewInt(0)
		polyY[deg].Set(ShareReduceMap[MostCountedCom][i].Y)
		deg++
	}

	// mutexShareReduceMap.Unlock()
	p.reducedShare, _ = interpolation.LagrangeInterpolate(int(p.F), polyX, polyY, ecparamN)
	fmt.Println("Party ", p.PID, " recover its reducedShare:")
	p.reducedShare.Print()
}

//FIXME: the secret after the Proactivize phase is not correct.
func (p *HonestParty) ProactivizeAndShareDist(ID []byte) {
	// Init
	ecparamN := ecparam.PBC256.Ngmp
	var flg_C = make([]uint32, p.N+1)
	var flg_Rec = make([]uint32, p.N+1)
	var sig []PiContent = make([]PiContent, 0)

	for i := 0; i <= int(p.N); i++ {
		flg_C[i] = 0
		flg_Rec[i] = 0
	}
	var rnd = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	var poly_F, _ = polyring.NewRand(int(2*p.F), rnd, ecparamN)
	poly_F.SetCoefficientBig(0, gmp.NewInt(0))

	var R = make([][]polyring.Polynomial, p.N+1) // i and j in R[][] start from 1

	for j := 0; j <= int(p.N); j++ {
		R[j] = make([]polyring.Polynomial, p.N+1)

		for k := 0; k <= int(p.N); k++ {
			R[j][k] = polyring.NewEmpty()
		}
	}

	for j := 1; j <= int(2*p.F+1); j++ {
		rnd = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
		R[p.PID+1][j], _ = polyring.NewRand(int(p.F), rnd, ecparamN)
	}

	//Commit
	var Z = make([]polyring.Polynomial, p.N+1)
	var Fj = gmp.NewInt(0)
	var Fj_C = KZG.NewG1()
	var CR = make([][]*pbc.Element, p.N+1)
	var CZ = make([]*pbc.Element, p.N+1)
	var wz = make([]*pbc.Element, p.N+1)
	var F_val = make([][][]*gmp.Int, p.N+1)
	var w_F_val = make([][][]*pbc.Element, p.N+1)

	for i := 0; i <= int(p.N); i++ {
		F_val[i] = make([][]*gmp.Int, p.N+1)
		w_F_val[i] = make([][]*pbc.Element, p.N+1)

		for j := 0; j <= int(p.N); j++ {
			F_val[i][j] = make([]*gmp.Int, p.N+1)
			w_F_val[i][j] = make([]*pbc.Element, p.N+1)

			for k := 0; k <= int(p.N); k++ {
				F_val[i][j][k] = gmp.NewInt(0)
				w_F_val[i][j][k] = KZG.NewG1()
			}
		}
	}

	for j := 0; j <= int(p.N); j++ {
		Z[j] = polyring.NewEmpty()
		CR[j] = make([]*pbc.Element, p.N+1)

		for k := 0; k <= int(p.N); k++ {
			CR[j][k] = KZG.NewG1()
		}
		CZ[j] = KZG.NewG1()
		wz[j] = KZG.NewG1()
	}

	for j := 1; j <= int(2*p.F+1); j++ {
		poly_F.EvalMod(gmp.NewInt(int64(j)), ecparamN, Fj)
		R[p.PID+1][j].SetCoefficientBig(0, Fj) // R_i,j(0)=F_i,j
		var tmp_poly = polyring.NewEmpty()
		tmp_poly.SetCoefficientBig(0, Fj)
		KZG.Commit(Fj_C, tmp_poly) // g^F_i(j)

		Z[j].Sub(R[p.PID+1][j], tmp_poly)
		KZG.Commit(CR[p.PID+1][j], R[p.PID+1][j])
		KZG.Commit(CZ[j], Z[j])
		KZG.CreateWitness(wz[j], Z[j], gmp.NewInt(0))
		// pi_i
		sig = append(sig, PiContent{j, KZG.NewG1(), KZG.NewG1(), KZG.NewG1(), KZG.NewG1()})
		sig[j-1].WZ_0.Set(wz[j])
		sig[j-1].CZ_j.Set(CZ[j])
		sig[j-1].CB_j.Set(CR[p.PID+1][j])
		sig[j-1].g_Fj.Set(Fj_C)
	}

	var Commit_Message = new(protobuf.Commit)
	Commit_Message.Sig = make([]*protobuf.PiContent, 2*p.F+1)
	for j := 0; j < int(2*p.F+1); j++ {
		Commit_Message.Sig[j] = new(protobuf.PiContent)
		Commit_Message.Sig[j].J = int32(sig[j].j)
		Commit_Message.Sig[j].WZ_0 = sig[j].WZ_0.CompressedBytes()
		Commit_Message.Sig[j].CBJ = sig[j].CB_j.CompressedBytes()
		Commit_Message.Sig[j].CZJ = sig[j].CZ_j.CompressedBytes()
		Commit_Message.Sig[j].G_Fj = sig[j].g_Fj.CompressedBytes()
	}
	//fmt.Println("Party ", p.PID, "Commit Message is", Commit_Message)
	Commit_Message_data, _ := proto.Marshal(Commit_Message)
	p.RBCSend(&protobuf.Message{Type: "Commit", Sender: p.PID, Id: ID, Data: Commit_Message_data}, []byte(string(ID)+strconv.Itoa(int(p.PID+1)))) // ID has been changed
	//Verify
	go func() {
		for j := 1; j <= int(p.N); j++ {
			go func(j int) {
				m := p.RBCReceive([]byte(string(ID) + strconv.Itoa(j))) // ID has been changed.
				fmt.Println("Party", p.PID, "receive RBC message from", m.Sender, "in ShareDist Phase,the ID is", string(ID))
				var Received_Data protobuf.Commit
				proto.Unmarshal(m.Data, &Received_Data)
				// var Verify_Flag = KZG.NewG1()
				// Verify_Flag = Verify_Flag.Set1()
				lambda := make([]*gmp.Int, 2*p.F+1)
				knownIndexes := make([]*gmp.Int, 2*p.F+1)
				for k := 0; uint32(k) < 2*p.F+1; k++ {
					lambda[k] = gmp.NewInt(int64(k + 1))
				}
				for k := 0; uint32(k) < 2*p.F+1; k++ {
					knownIndexes[k] = gmp.NewInt(int64(k + 1))
				}
				polyring.GetLagrangeCoefficients(int(2*p.F), knownIndexes, ecparamN, gmp.NewInt(0), lambda)
				var tmp = KZG.NewG1()
				var tmp2 = KZG.NewG1()
				var tmp3 = KZG.NewG1()
				var copy_tmp3 = KZG.NewG1()
				var tmp4 = KZG.NewG1()
				tmp3.Set1()
				tmp4.Set1()
				for k := 0; k < int(2*p.F+1); k++ {
					tmp.SetCompressedBytes(Received_Data.Sig[k].G_Fj) // change tmp = tmp.SetCompressedBytes(Received_Data.Sig[k].G_Fj)
					tmp2.PowBig(tmp, conv.GmpInt2BigInt(lambda[k]))
					copy_tmp3.Set(tmp3)
					tmp3.Mul(copy_tmp3, tmp2)
				}
				if !tmp3.Equals(tmp4) {
					return //possible bug
				}

				var revert_flag = false
				for k := 0; uint32(k) < 2*p.F+1; k++ {
					CR_k := KZG.NewG1()
					CZ_k := KZG.NewG1()
					wz_k := KZG.NewG1()
					Gj_k := KZG.NewG1()
					CR_k.SetCompressedBytes(Received_Data.Sig[k].CBJ)
					CR[m.Sender+1][k+1].Set(CR_k) //added by ch
					CZ_k.SetCompressedBytes(Received_Data.Sig[k].CZJ)
					wz_k.SetCompressedBytes(Received_Data.Sig[k].WZ_0)
					Gj_k.SetCompressedBytes(Received_Data.Sig[k].G_Fj)
					mul_res := KZG.NewG1()
					mul_res.Mul(CZ_k, Gj_k)
					if !KZG.VerifyEval(CZ_k, gmp.NewInt(0), gmp.NewInt(0), wz_k) || !CR_k.Equals(mul_res) {
						revert_flag = true
						break
					}
				}
				if revert_flag {
					return //possible bug
				}

				for l := 2*p.F + 2; l <= p.N; l++ {
					polyring.GetLagrangeCoefficients(int(2*p.F), knownIndexes, ecparamN, gmp.NewInt(int64(l)), lambda)
					CR[m.Sender+1][l].Set1()
					pow_res := KZG.NewG1()
					copy_CR := KZG.NewG1()
					for k := 1; uint32(k) <= 2*p.F+1; k++ {
						pow_res.PowBig(CR[m.Sender+1][k], conv.GmpInt2BigInt(lambda[k-1]))
						copy_CR.Set(CR[m.Sender+1][l])
						CR[m.Sender+1][l].Mul(copy_CR, pow_res)
					}
				}
				flg_C[m.Sender+1] = 1 //ch change j to m.Sender.
			}(j)
		}

	}()

	//Reshare
	var wf = make([][]*pbc.Element, p.N+1)
	for k := 1; k <= int(p.N); k++ {
		var reshare_message protobuf.Reshare
		reshare_message.Wk = make([][]byte, 2*p.F+1) //added
		reshare_message.Fk = make([][]byte, 2*p.F+1) //added
		wf[k] = make([]*pbc.Element, p.N+1)

		for j := 1; j <= int(2*p.F+1); j++ {

			wf[k][j] = KZG.NewG1()
			KZG.CreateWitness(wf[k][j], R[p.PID+1][j], gmp.NewInt(int64(k))) // changed.
			var Fkj = gmp.NewInt(0)

			//Denote Ri,j(k) as [Fi(j)]k
			R[p.PID+1][j].EvalMod(gmp.NewInt(int64(k)), ecparamN, Fkj)

			F_val[p.PID+1][j][k].Set(Fkj)
			w_F_val[p.PID+1][j][k].Set(wf[k][j])
			reshare_message.Wk[j-1] = wf[k][j].CompressedBytes()
			reshare_message.Fk[j-1] = Fkj.Bytes()
		}

		reshare_data, _ := proto.Marshal(&reshare_message)
		p.Send(&protobuf.Message{Type: "Reshare", Id: ID, Sender: p.PID, Data: reshare_data}, uint32(k-1))
		fmt.Println("Party ", p.PID, "send Reshare message to", k-1, "the content is", reshare_message)
	}

	//Vote
	var Reshare_Data_Map = make(map[int]protobuf.Reshare)
	var Reshare_Data_Map_Mutex sync.Mutex
	var Sig = make(map[int]map[int][]byte)
	for i := 1; i <= int(p.N); i++ {
		Sig[i] = make(map[int][]byte)
	}

	go func() {
		for {
			m := <-p.GetMessage("Reshare", ID) // this ID is not correct //ch thinks it is correct
			var Received_Reshare_Data protobuf.Reshare
			proto.Unmarshal(m.Data, &Received_Reshare_Data)

			//fmt.Println("Party", p.PID, "receive Reshare message from", m.Sender, "the content is", Received_Reshare_Data.Wk)
			Reshare_Data_Map_Mutex.Lock()
			_, ok := Reshare_Data_Map[int(m.Sender+1)]
			if !ok {
				Reshare_Data_Map[int(m.Sender+1)] = Received_Reshare_Data
			}
			Reshare_Data_Map_Mutex.Unlock()
		}
	}()
	go func() {
		for { //TODO: change busy waiting to block waiting later.
			Reshare_Data_Map_Mutex.Lock()
			for j := 1; j <= int(p.N); j++ {
				_, ok := Reshare_Data_Map[j]
				if ok == true && flg_C[j] == 1 {
					//if p.PID == uint32(5) && j == 7 {
					//	fmt.Println("enter 2")
					//}
					var w_j_k *pbc.Element
					var v_j_k_i *gmp.Int
					v_j_k_i = gmp.NewInt(0)
					w_j_k = KZG.NewG1()
					now_Data := Reshare_Data_Map[j]
					var Vote_Revert_Flag = false
					/*
						if p.PID == uint32(3) {
							fmt.Println("In vote phase,the C_Rist is:")
							for k := 1; uint32(k) <= p.N; k++ {
								fmt.Println("CR", j, k, "=", CR[j][k].String())
							}
						}
					*/
					for k := 1; k <= int(2*p.F+1); k++ {
						v_j_k_i.SetBytes(now_Data.Fk[k-1])
						w_j_k.SetCompressedBytes(now_Data.Wk[k-1])

						//if j == 3 {
						//	fmt.Println("Party", p.PID, "receive w", p.PID+1, k, "=", w_j_k.String(), "from Party", j-1)
						//}
						//fmt.Println("Party", p.PID, v_j_k_i, w_j_k.String())
						//fmt.Println("Party ", p.PID, "can enter here")
						//fmt.Println("Party ", p.PID, "Verify v ", j, k, "result = ", KZG.VerifyEval(CR[j][k], gmp.NewInt(int64(p.PID+1)), v_j_k_i, w_j_k))

						if KZG.VerifyEval(CR[j][k], gmp.NewInt(int64(p.PID+1)), v_j_k_i, w_j_k) == false {
							Vote_Revert_Flag = true
							break
						}
					}
					if Vote_Revert_Flag == true {
						delete(Reshare_Data_Map, j) // discard this message
						continue
					}
					//Sig_hash := sha256.Sum256([]byte(string(j)))
					//Sig[j][int(p.PID+1)] = bls.Sign(Sig_hash, p.SigSK)
					Sig[j][int(p.PID+1)], _ = tbls.Sign(SysSuite, p.SigSK, []byte((strconv.Itoa(j))))
					lambda := make([]*gmp.Int, 2*p.F+1)
					knownIndexes := make([]*gmp.Int, 2*p.F+1)
					for k := 0; uint32(k) < 2*p.F+1; k++ {
						knownIndexes[k] = gmp.NewInt(int64(k + 1))
						lambda[k] = gmp.NewInt(int64(k + 1))
					}
					for l := 1; l <= int(p.N); l++ {
						polyring.GetLagrangeCoefficients(int(2*p.F), knownIndexes, ecparamN, gmp.NewInt(int64(l)), lambda)
						F_val[j][l][p.PID+1].SetInt64(int64(0)) // might have a bug
						w_F_val[j][l][p.PID+1].Set1()           // might have a bug
						for k := 1; k <= int(2*p.F+1); k++ {
							v_j_k_i.SetBytes(now_Data.Fk[k-1])
							w_j_k.SetCompressedBytes(now_Data.Wk[k-1])
							var copy_Fijl *gmp.Int
							var copy_wijl *pbc.Element
							var tt1 *gmp.Int     // temp mul result
							var tt2 *pbc.Element // temp pow result
							tt1 = gmp.NewInt(0)
							tt2 = KZG.NewG1()
							copy_Fijl = gmp.NewInt(0)
							copy_wijl = KZG.NewG1()
							copy_Fijl.Set(F_val[j][l][p.PID+1])
							copy_wijl.Set(w_F_val[j][l][p.PID+1])
							tt1.Mul(lambda[k-1], v_j_k_i)
							F_val[j][l][p.PID+1].Add(copy_Fijl, tt1)
							tt2.PowBig(w_j_k, conv.GmpInt2BigInt(lambda[k-1]))
							w_F_val[j][l][p.PID+1].Mul(copy_wijl, tt2)
						}
						// send Recover
						var Recover_Message protobuf.Recover
						Recover_Message.J = int32(j)
						Recover_Message.V = F_val[j][l][p.PID+1].Bytes()
						Recover_Message.W = w_F_val[j][l][p.PID+1].CompressedBytes()
						Recover_Message.Sig = Sig[j][int(p.PID+1)]
						Recover_Message_data, _ := proto.Marshal(&Recover_Message)
						p.Send(&protobuf.Message{Type: "Recover", Id: ID, Sender: p.PID, Data: Recover_Message_data}, uint32(l-1))
					}
					delete(Reshare_Data_Map, j) //added
				}
			}
			Reshare_Data_Map_Mutex.Unlock()
		}
	}()

	//Recover
	var Recover_Data_Map = make(map[int]map[int]protobuf.Recover)
	for i := 1; i <= int(p.N); i++ {
		Recover_Data_Map[i] = make(map[int]protobuf.Recover)
	}
	var Recover_Data_Map_Mutex sync.Mutex
	var S_rec [][]SRecElement = make([][]SRecElement, p.N+1) // start from 1
	var S_sig [][]SSigElement = make([][]SSigElement, p.N+1) // start from 1
	for i := 0; i <= int(p.N); i++ {
		S_rec[i] = make([]SRecElement, 0)
		S_sig[i] = make([]SSigElement, 0)
	}
	var Interpolate_poly_x = make([]*gmp.Int, p.N+1)
	var Interpolate_poly_y = make([]*gmp.Int, p.N+1)
	var Combined_Sig = make([][]byte, p.N+1) // start from 1
	var Combined_flag = make([]bool, p.N+1)  //start from 1
	var MVBA_In *protobuf.MVBA_IN = new(protobuf.MVBA_IN)
	MVBA_In.J = make([]int32, 0)
	MVBA_In.Sig = make([][]byte, 0)
	var MVBA_In_Mutex sync.Mutex
	for i := 0; i <= int(p.N); i++ {
		Combined_flag[i] = false
	}
	var MVBA_Sent = false
	MVBA_res_chan := make(chan []byte, 1)

	go func() {
		for {
			m := <-p.GetMessage("Recover", ID)
			var Received_Recover_Data protobuf.Recover
			proto.Unmarshal(m.Data, &Received_Recover_Data)
			Recover_Data_Map_Mutex.Lock()
			_, ok := Recover_Data_Map[int(Received_Recover_Data.J)][int(m.Sender+1)]
			if !ok {
				Recover_Data_Map[int(Received_Recover_Data.J)][int(m.Sender+1)] = Received_Recover_Data
			}
			Recover_Data_Map_Mutex.Unlock()
		}
	}()

	go func() {
		for {
			Recover_Data_Map_Mutex.Lock()
			for k := 1; k <= int(p.N); k++ {
				for j := 1; j <= int(p.N); j++ {
					_, ok := Recover_Data_Map[k][j]
					if ok == true {
						now_Recover_Data := Recover_Data_Map[k][j]
						if flg_C[k] == 0 {
							continue //FIXME: wrong continue
						}

						var w_k_i_j *pbc.Element
						var v_k_i_j *gmp.Int
						v_k_i_j = gmp.NewInt(0)
						w_k_i_j = KZG.NewG1()
						v_k_i_j.SetBytes(now_Recover_Data.V)
						w_k_i_j.SetCompressedBytes(now_Recover_Data.W)

						Received_Sig := now_Recover_Data.Sig
						//Check_Sig_Hash := sha256.Sum256([]byte(string(j)))

						if KZG.VerifyEval(CR[k][p.PID+1], gmp.NewInt(int64(j)), v_k_i_j, w_k_i_j) == false || (tbls.Verify(SysSuite, p.SigPK, []byte(strconv.Itoa(k)), Received_Sig) != nil) {
							delete(Recover_Data_Map[k], j) // discard this message
							continue                       // ch change break to continue.
						}
						S_rec[k] = append(S_rec[k], SRecElement{j, v_k_i_j})
						if len(S_rec[k]) >= int(p.F+1) && flg_Rec[k] == 0 {
							for t := 0; t < len(S_rec[k]); t++ {
								Interpolate_poly_x[t] = gmp.NewInt(int64(S_rec[k][t].j))
								Interpolate_poly_y[t] = S_rec[k][t].v
							}

							R[k][int(p.PID+1)], _ = interpolation.LagrangeInterpolate(int(p.F), Interpolate_poly_x[:p.F+1], Interpolate_poly_y[:p.F+1], ecparamN) //ch add :p.F+1
							flg_Rec[k] = 1
						}
						S_sig[k] = append(S_sig[k], SSigElement{j, Received_Sig})
						if len(S_sig[k]) >= int(2*p.F+1) && Combined_flag[k] == false {
							var tmp_Sig = make([][]byte, len(S_sig))
							for t := 0; t < len(S_sig[k]); t++ {
								tmp_Sig[t] = S_sig[k][t].Sig
							}
							Combined_Sig[k], _ = tbls.Recover(SysSuite, p.SigPK, []byte(strconv.Itoa(k)), tmp_Sig, int(2*p.F), int(p.N))
							Combined_flag[k] = true
							MVBA_In_Mutex.Lock()
							MVBA_In.J = append(MVBA_In.J, int32(k))
							MVBA_In.Sig = append(MVBA_In.Sig, Combined_Sig[k])
							if len(MVBA_In.J) >= int(p.N-p.F) && MVBA_Sent == false {
								fmt.Println("Party", p.PID, "calls MVBA")
								MVBA_In_data, _ := proto.Marshal(MVBA_In)
								MVBA_res_chan <- MainProcess(p, ID, MVBA_In_data, []byte{}) //temporary solution (MainProcess means smvba.MainProcess)
								MVBA_Sent = true
							}
							MVBA_In_Mutex.Unlock()
						}
						delete(Recover_Data_Map[k], j) // added by ch
					}
				}
			}
			Recover_Data_Map_Mutex.Unlock()
		}
	}()

	//MVBA (MVBA verification hasn't been implemented)
	//TODO:implement MVBA's verification
	MVBA_res_data := <-MVBA_res_chan //question: do we need waitGroup to synchronize the MVBA instances?
	var MVBA_res protobuf.MVBA_IN
	proto.Unmarshal(MVBA_res_data, &MVBA_res)
	fmt.Println("Party", p.PID, " output MBVA result:", MVBA_res.J)

	//Refresh
	var CQ = make([]*pbc.Element, p.N+1)
	var Q = polyring.NewEmpty()

	for i := 0; i <= int(p.N); i++ {
		CQ[i] = KZG.NewG1()
	}
	for {

		for i := 0; uint32(i) < p.N-p.F; i++ {
			if flg_C[MVBA_res.J[i]] == 0 {
				continue //FIXME: wrong continue
			}
		}

		for i := 0; uint32(i) < p.N-p.F; i++ {
			copyed_Q := polyring.NewEmpty()
			copyed_Q.ResetTo(Q)
			//fmt.Println("Party ", p.PID, "R[MVBA_res.J[i]][p.PID+1] =")
			//R[MVBA_res.J[i]][p.PID+1].Print()
			Q.Add(copyed_Q, R[MVBA_res.J[i]][p.PID+1])
			Q.Mod(ecparamN)
		}
		//TODO: add CQ here later!!
		fmt.Println("Party", p.PID, "recover Q:")
		Q.Print()
		fmt.Println("Party", p.PID, "previous reducedShare:")
		p.reducedShare.Print()
		copyed_halfShare := polyring.NewEmpty()
		copyed_halfShare.ResetTo(p.reducedShare)
		p.reducedShare.Add(Q, copyed_halfShare)
		p.reducedShare.Mod(ecparamN)
		fmt.Println("Party ", p.PID, "get its new reducedShare:")
		p.reducedShare.Print()
		break
	}

	//-------------------------------------ShareDist-------------------------------------
	//Init
	var S_com = make(map[int]SComElement)
	var S_B []SBElement = make([]SBElement, 0)
	var S_com_Mutex sync.Mutex

	//Commit
	var C_B = make([]*pbc.Element, p.N+1)
	for i := 0; i <= int(p.N); i++ {
		C_B[i] = KZG.NewG1()
	}

	KZG.Commit(C_B[p.PID+1], p.reducedShare)
	var NewCommit_Message protobuf.NewCommit
	NewCommit_Message.CB = C_B[p.PID+1].CompressedBytes()
	NewCommit_Message_Data, _ := proto.Marshal(&NewCommit_Message)
	p.RBCSend(&protobuf.Message{Type: "NewCommit", Id: ID, Sender: p.PID, Data: NewCommit_Message_Data}, []byte(string(ID)+"Distribute"+strconv.Itoa(int(p.PID+1)))) // this ID is not correct

	//Distribute
	var w_B_i_j *pbc.Element
	var B_i_j *gmp.Int
	w_B_i_j = KZG.NewG1()
	B_i_j = gmp.NewInt(0)

	for j := 1; j <= int(p.N); j++ {
		p.reducedShare.EvalMod(gmp.NewInt(int64(j)), ecparamN, B_i_j)
		KZG.CreateWitness(w_B_i_j, p.reducedShare, gmp.NewInt(int64(j)))
		var ShareDist_Message protobuf.ShareDist
		ShareDist_Message.B = B_i_j.Bytes()
		ShareDist_Message.WB = w_B_i_j.CompressedBytes()
		ShareDist_Message_Data, _ := proto.Marshal(&ShareDist_Message)
		p.Send(&protobuf.Message{Type: "ShareDist", Id: ID, Sender: p.PID, Data: ShareDist_Message_Data}, uint32(j-1))
	}

	//Verify
	for j := 1; j <= int(p.N); j++ {
		go func(j int) {
			m := p.RBCReceive([]byte(string(ID) + "Distribute" + strconv.Itoa(j)))
			NewCommit_Data := m.Data
			var Received_CB *pbc.Element
			Received_CB = KZG.NewG1()
			Received_CB.SetCompressedBytes(NewCommit_Data)

			S_com_Mutex.Lock()
			S_com[int(m.Sender+1)] = SComElement{
				j:  int(m.Sender + 1),
				CB: KZG.NewG1(),
			}
			S_com[int(m.Sender+1)].CB.Set(Received_CB) //here add it without Verifying temporarily  //ch change j to m.sender+1
			//TODO: Add Verification here (CB'(x,j) == CB(x,j)CQ(x,j) ?)
			S_com_Mutex.Unlock()
		}(j)
	}

	//Interpolate
	var ShareDist_Map = make(map[int]protobuf.ShareDist)
	var ShareDist_Map_Mutex sync.Mutex
	var Received_ShareDist_Data protobuf.ShareDist
	var Success_Sent = false
	var Success_Sent_chan = make(chan bool, 1)

	go func() {
		for {
			m := <-p.GetMessage("ShareDist", ID) // this ID is not correct
			proto.Unmarshal(m.Data, &Received_ShareDist_Data)
			ShareDist_Map_Mutex.Lock()
			_, ok := ShareDist_Map[int(m.Sender+1)]
			if !ok {
				ShareDist_Map[int(m.Sender+1)] = Received_ShareDist_Data
			}
			ShareDist_Map_Mutex.Unlock()
		}
	}()
	go func() {
		for {
			for j := 1; j <= int(p.N); j++ {
				ShareDist_Map_Mutex.Lock()
				_, ok := ShareDist_Map[j]
				if ok == true {
					S_com_Mutex.Lock()
					_, ok2 := S_com[j]
					if ok2 == true {
						now_ShareDist_Data := ShareDist_Map[j]
						now_CB := S_com[j].CB
						var ShareDist_vj *gmp.Int
						var ShareDist_wj *pbc.Element
						ShareDist_vj = gmp.NewInt(0)
						ShareDist_wj = KZG.NewG1()
						ShareDist_vj.SetBytes(now_ShareDist_Data.B)
						ShareDist_wj.SetCompressedBytes(now_ShareDist_Data.WB)
						//fmt.Println(KZG.VerifyEval(now_CB, gmp.NewInt(int64(p.PID+1)), ShareDist_vj, ShareDist_wj))
						/*
							if KZG.VerifyEval(now_CB, gmp.NewInt(int64(p.PID+1)), ShareDist_vj, ShareDist_wj) == false {
								delete(ShareDist_Map, j)
								ShareDist_Map_Mutex.Unlock()
								S_com_Mutex.Unlock()
								continue
							}*/
						// debug for KZG Verification later.
						// TODO: complete the KZG verification here.
						S_B = append(S_B, SBElement{
							j:  0,
							CB: KZG.NewG1(),
							v:  gmp.NewInt(0),
							w:  KZG.NewG1(),
						})
						length := len(S_B)
						S_B[length-1].j = j
						S_B[length-1].CB.Set(now_CB)
						S_B[length-1].v.Set(ShareDist_vj)
						S_B[length-1].w.Set(ShareDist_wj)

						if len(S_B) >= int(2*p.F+1) && Success_Sent == false { //ch added "&&Success_Sent == false"
							var Dist_x []*gmp.Int = make([]*gmp.Int, 2*p.F+1)
							var Dist_y []*gmp.Int = make([]*gmp.Int, 2*p.F+1)
							for t := 0; t < int(2*p.F+1); t++ {
								Dist_x[t] = gmp.NewInt(int64(S_B[t].j))
								Dist_y[t] = gmp.NewInt(0)
								Dist_y[t].Set(S_B[t].v)
							}
							p.fullShare, _ = interpolation.LagrangeInterpolate(int(2*p.F), Dist_x, Dist_y, ecparamN)
							fmt.Println("Party ", p.PID, "recover full Share:")
							p.fullShare.Print()
							var Success_Message protobuf.Success
							Success_Message.Nothing = []byte("123") // doesn't matter. Send whatever you want
							Success_Data, _ := proto.Marshal(&Success_Message)
							p.Broadcast(&protobuf.Message{Type: "Success", Id: ID, Sender: p.PID, Data: Success_Data})
							Success_Sent = true       //added by ch
							Success_Sent_chan <- true //added by ch
						}
						delete(ShareDist_Map, j) // added by ch
					}
					S_com_Mutex.Unlock()

				}
				ShareDist_Map_Mutex.Unlock()
			}
		}

	}()

	// Receive Success Message
	var Success_Map = make(map[int]protobuf.Success)
	var Success_Map_Mutex sync.Mutex
	var Received_Success_Data protobuf.Success
	var Success_Count = 0

	go func() {
		<-Success_Sent_chan //added by ch
		for {
			m := <-p.GetMessage("Success", ID) // this ID is not correct //ch thinks it is correct
			proto.Unmarshal(m.Data, &Received_Success_Data)
			Success_Map_Mutex.Lock()
			_, ok := Success_Map[int(m.Sender+1)]
			if !ok {
				Success_Map[int(m.Sender+1)] = Received_Success_Data
				Success_Count++
			}
			if Success_Count >= int(2*p.F+1) {
				Success_Map_Mutex.Unlock()
				fmt.Println("Party ", p.PID, "Enter the normal state")
				break // Enter normal state
			}
			Success_Map_Mutex.Unlock()
		}

	}()
}
