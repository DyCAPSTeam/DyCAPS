package party

import (
	"crypto/sha256"
	"log"
	"time"

	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/interpolation"
	"github.com/DyCAPSTeam/DyCAPS/internal/polypoint"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"github.com/Nik-U/pbc"
	"github.com/ncw/gmp"
	"google.golang.org/protobuf/proto"
)

func (p *HonestParty) ShareReduceSend(ID []byte) {

	ecparamN := ecparam.PBC256.Ngmp

	var tmpCB = make([]*pbc.Element, p.N+1) //commitment of B(x,index), index start from 1
	var tmpWB = make([]*pbc.Element, p.N+1) //witness of B(i,index), index start from 1
	for i := uint32(0); i < p.N+1; i++ {
		tmpCB[i] = p.KZG.NewG1()
		tmpWB[i] = p.KZG.NewG1()
	}

	//get 2t+1 values from prior execution of DyCAPS.Handoff or DyCAPS.Share
	for j := uint32(0); j < 2*p.F+2; j++ {
		tmpCB[j].Set(p.Proof.PiContents[j].CBj)
		tmpWB[p.witnessIndexes[j].Int64()].Set(p.witness[j])
	}

	p.ShareReduceStart_old = time.Now()

	//interpolate the remaining commitments and witnesses
	p.mutexKZG.Lock()
	mutexPolyring.Lock()
	for j := uint32(1); j < p.N+1; j++ {
		tmpCB[j] = InterpolateComOrWit(2*p.F, j, tmpCB[1:2*p.F+2], p.KZG)
		tmpWB[j] = InterpolateComOrWitByKnownIndexes(2*p.F, j, p.witnessIndexes[1:], p.witness[1:], p.KZG)
	}
	mutexPolyring.Unlock()
	p.mutexKZG.Unlock()

	for j := uint32(0); j < p.N; j++ {
		polyValue := gmp.NewInt(0)
		p.fullShare.EvalMod(gmp.NewInt(int64(j+1)), ecparamN, polyValue)
		ShareReduceMessage := protobuf.ShareReduce{
			C: tmpCB[j+1].CompressedBytes(),
			V: polyValue.Bytes(),
			W: tmpWB[j+1].CompressedBytes(),
		}
		data, _ := proto.Marshal(&ShareReduceMessage)
		p.SendToNextCommittee(&protobuf.Message{
			Type:   "ShareReduce",
			Id:     ID,
			Sender: p.PID,
			Data:   data,
		}, j)
	}
	p.ShareReduceEnd_old = time.Now()
}

func (p *HonestParty) ShareReduceReceive(ID []byte) {
	ecparamN := ecparam.PBC256.Ngmp
	var ShareReduceMap = make(map[string][]polypoint.PolyPoint) //map a commitment string to a poly point set
	var ComMap = make(map[string]uint32)                        //count the number of C
	var MostCountedCom string                                   //C_B(x,i)

	var vJ = gmp.NewInt(0)
	var polyX, polyY []*gmp.Int
	C := p.KZG.NewG1()
	wJ := p.KZG.NewG1()

	var cnt = 0 //used to judge whether to execute p.ShareReduceStart_new = time.Now()

	for {
		m := <-p.GetMessage("ShareReduce", ID)
		if cnt == 0 {
			p.ShareReduceStart_new = time.Now()
		}
		//log.Printf("[ShareReduce][New party %v] Receive ShareReduce message from %v\n", p.PID, m.Sender)
		var ShareReduceData protobuf.ShareReduce
		proto.Unmarshal(m.Data, &ShareReduceData)
		C.SetCompressedBytes(ShareReduceData.C)
		wJ.SetCompressedBytes(ShareReduceData.W)
		vJ.SetBytes(ShareReduceData.V)

		p.mutexKZG.Lock()
		verified := p.KZG.VerifyEval(C, gmp.NewInt(int64(m.Sender+1)), vJ, wJ)
		p.mutexKZG.Unlock()
		if verified {
			cStr := string(ShareReduceData.C)
			_, ok2 := ShareReduceMap[cStr]
			if ok2 {
				ShareReduceMap[cStr] = append(ShareReduceMap[cStr], polypoint.PolyPoint{
					X:       int32(m.Sender + 1),
					Y:       gmp.NewInt(0).Set(vJ),
					PolyWit: p.KZG.NewG1().Set(wJ),
				})
				ComMap[cStr] += 1
			} else {
				ShareReduceMap[cStr] = make([]polypoint.PolyPoint, 0)
				ShareReduceMap[cStr] = append(ShareReduceMap[cStr], polypoint.PolyPoint{
					X:       int32(m.Sender + 1),
					Y:       gmp.NewInt(0).Set(vJ),
					PolyWit: p.KZG.NewG1().Set(wJ),
				})
				ComMap[cStr] = 1
			}

			if ComMap[cStr] >= p.F+1 {
				MostCountedCom = cStr

				log.Printf("[ShareReduce][New party %v]ShareReduce done\n", p.PID)
				break
			}
		} else {
			log.Printf("[ShareReduce][New party %v] Verify Reduce message from old party %v FAIL. C: %s, v: %v, w: %s\n", p.PID, m.Sender, C.String(), vJ, wJ.String())
		}
		cnt++
	}

	polyX = make([]*gmp.Int, p.F+1)
	polyY = make([]*gmp.Int, p.F+1)
	for i := uint32(0); i <= p.F; i++ {
		polyX[i] = gmp.NewInt(0)
		polyX[i].Set(gmp.NewInt(int64(ShareReduceMap[MostCountedCom][i].X)))
		polyY[i] = gmp.NewInt(0)
		polyY[i].Set(ShareReduceMap[MostCountedCom][i].Y)
	}

	p.reducedShare, _ = interpolation.LagrangeInterpolate(int(p.F), polyX, polyY, ecparamN)
	//log.Printf("[ShareReduce][New party %v] have recovered reducedShare B(x,i):\n", p.PID)
	//p.reducedShare.Print(fmt.Sprintf("B(x,%v)", p.PID+1))
	p.ShareReduceEnd_new = time.Now()
}

//PrepareSend sends p.Proof to the corresponding node in the next commitee.i.e.p[i].Proof -> pNext[i].Proof
func (p *HonestParty) PrepareSend(ID []byte) {
	p.PrepareStart_old = time.Now()
	//VSSEcho only contains Pi, so here we use EncapsulateVSSEcho().
	data := EncapsulateVSSEcho(p.Proof, p.F)
	/*
		p.SendToNextCommittee(&protobuf.Message{
			Type:   "Prepare",
			Id:     ID,
			Sender: p.PID,
			Data:   data,
		}, p.PID)*/
	p.BroadcastToNextCommittee(&protobuf.Message{
		Type:   "Prepare",
		Id:     ID,
		Sender: p.PID,
		Data:   data,
	})
	p.PrepareEnd_old = time.Now()
}

//PrepareReceive receives Prepare message which contains Pi from the previous commitee  and sets p.Proof.
func (p *HonestParty) PrepareReceive(ID []byte) {

	/*
		msg := <-p.GetMessage("Prepare", ID)
		ProofMsg := new(protobuf.VSSEcho) //VSSEcho only contains protobuf.Pi
		proto.Unmarshal(msg.Data, ProofMsg)
		p.Proof.SetFromVSSMessage(ProofMsg.Pi, p.F)
	*/
	ProofMap := make(map[string]int)

	var cnt = 0 //used to judge whether to execute p.PrepareStart_new = time.Now()

	for {
		msg := <-p.GetMessage("Prepare", ID)
		if cnt == 0 {
			p.PrepareStart_new = time.Now()
		}
		hash := sha256.New()
		hash.Write(msg.Data)
		hashToString := string(hash.Sum(nil))
		counter, ok := ProofMap[hashToString]
		if ok {
			ProofMap[hashToString] = counter + 1
		} else {
			ProofMap[hashToString] = 1
		}
		if uint32(counter+1) == p.F+1 {
			ProofMsg := new(protobuf.VSSEcho) //VSSEcho only contains protobuf.Pi
			proto.Unmarshal(msg.Data, ProofMsg)
			p.Proof.SetFromVSSMessage(ProofMsg.Pi, p.F)
			p.PrepareEnd_new = time.Now()
			break
		}
		cnt++
	}
}
