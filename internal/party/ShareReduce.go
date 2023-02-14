package party

import (
	"crypto/sha256"
	"github.com/DyCAPSTeam/DyCAPS/internal/bls"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"google.golang.org/protobuf/proto"
	"log"
	"strconv"
	"time"
)

func (p *HonestParty) ShareReduceSend(ID []byte) {

	var tmpCB = make([]bls.G1Point, p.N+1) //commitment of B(x,index), index start from 1
	var tmpWB = make([]bls.G1Point, p.N+1) //witness of B(i,index), index start from 1

	//get 2t+1 values from prior execution of DyCAPS.Handoff or DyCAPS.Share
	for j := uint32(1); j < 2*p.F+2; j++ {
		bls.CopyG1(&tmpCB[j], &p.Proof.PiContents[j].CBj)
		tmpInt, _ := strconv.Atoi(p.witnessIndexes[j-1].String())
		bls.CopyG1(&tmpWB[tmpInt], &p.witness[j-1])
	}

	p.ShareReduceStart_old = time.Now()

	//interpolate the remaining commitments and witnesses

	for j := uint32(1); j < p.N+1; j++ {
		p.mutexKZG.Lock()
		tmpCB[j] = p.InterpolateComOrWit(2*p.F, j, tmpCB[1:2*p.F+2])
		tmpWB[j] = p.InterpolateComOrWitByKnownIndexes(2*p.F, j, p.witnessIndexes, p.witness)
		p.mutexKZG.Unlock()
	}

	for j := uint32(0); j < p.N; j++ {
		var position, polyValue bls.Fr
		bls.AsFr(&position, uint64(j+1))
		bls.EvalPolyAt(&polyValue, p.fullShare, &position)

		tmpBytes := bls.FrTo32(&polyValue) //from array to slice
		polyValue_bytes := make([]byte, 32)
		copy(polyValue_bytes, tmpBytes[:])

		ShareReduceMessage := protobuf.ShareReduce{
			C: bls.ToCompressedG1(&tmpCB[j+1]),
			V: polyValue_bytes,
			W: bls.ToCompressedG1(&tmpWB[j+1]),
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
	var ShareReduceMap = make(map[string][]polyring.PolyPoint) //map a commitment string to a poly point set
	var ComMap = make(map[string]uint32)                       //count the number of C
	var MostCountedCom string                                  //C_B(x,i)

	var vJ = bls.ZERO
	var polyX, polyY []bls.Fr
	C := bls.ZeroG1
	wJ := bls.ZeroG1

	var cnt = 0 //used to judge whether to execute p.ShareReduceStart_new = time.Now()

	for {
		m := <-p.GetMessage("ShareReduce", ID)
		if cnt == 0 {
			p.ShareReduceStart_new = time.Now()
		}
		//log.Printf("[ShareReduce][New party %v] Receive ShareReduce message from %v\n", p.PID, m.Sender)
		var ShareReduceData protobuf.ShareReduce
		proto.Unmarshal(m.Data, &ShareReduceData)

		tmpC, _ := bls.FromCompressedG1(ShareReduceData.C)
		tmpwJ, _ := bls.FromCompressedG1(ShareReduceData.W)
		tmpvJ_bytes := [32]byte{}
		copy(tmpvJ_bytes[:], ShareReduceData.V)
		bls.CopyG1(&C, tmpC)
		bls.CopyG1(&wJ, tmpwJ)
		bls.FrFrom32(&vJ, tmpvJ_bytes)

		var tmpPosition bls.Fr
		bls.AsFr(&tmpPosition, uint64(m.Sender+1))

		p.mutexKZG.Lock()
		verified := p.KZG.CheckProofSingle(&C, &wJ, &tmpPosition, &vJ)
		p.mutexKZG.Unlock()

		if verified {
			cStr := string(ShareReduceData.C)
			_, ok2 := ShareReduceMap[cStr]
			if ok2 {
				ShareReduceMap[cStr] = append(ShareReduceMap[cStr], polyring.PolyPoint{
					X:       int(m.Sender + 1),
					Y:       vJ,
					PolyWit: wJ,
				})
				ComMap[cStr] += 1
			} else {
				ShareReduceMap[cStr] = make([]polyring.PolyPoint, 0)
				ShareReduceMap[cStr] = append(ShareReduceMap[cStr], polyring.PolyPoint{
					X:       int(m.Sender + 1),
					Y:       vJ,
					PolyWit: wJ,
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

	polyX = make([]bls.Fr, p.F+1)
	polyY = make([]bls.Fr, p.F+1)
	for i := uint32(0); i <= p.F; i++ {
		bls.AsFr(&polyX[i], uint64(ShareReduceMap[MostCountedCom][i].X))
		bls.CopyFr(&polyY[i], &ShareReduceMap[MostCountedCom][i].Y)
	}

	p.reducedShare = polyring.LagrangeInterpolate(int(p.F), polyX, polyY)
	//log.Printf("[ShareReduce][New party %v] have recovered reducedShare B(x,i):\n", p.PID)
	//p.reducedShare.Print(fmt.Sprintf("B(x,%v)", p.PID+1))
	p.ShareReduceEnd_new = time.Now()
}

//PrepareSend sends public parameters(commitments) to the corresponding node in the next commitee
func (p *HonestParty) PrepareSend(ID []byte) {
	p.PrepareStart_old = time.Now()
	//VSSEcho only contains Pi, so here we use EncapsulateVSSEcho().

	//Encapsulate
	var msg = new(protobuf.Prepare)
	msg.Commitments = make([][]byte, 2*p.F+2)

	for i := 1; uint32(i) < 2*p.F+2; i++ {
		msg.Commitments[i] = bls.ToCompressedG1(&p.Proof.PiContents[i].CBj)
	}

	data, err := proto.Marshal(msg)
	if err != nil {
		log.Fatalln(err)
	}

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
			ProofMsg := new(protobuf.Prepare)

			proto.Unmarshal(msg.Data, ProofMsg)

			for i := 1; uint32(i) < 2*p.F+2; i++ {
				tmp, _ := bls.FromCompressedG1(ProofMsg.Commitments[i])
				bls.CopyG1(&p.Proof.PiContents[i].CBj, tmp)
			}

			p.PrepareEnd_new = time.Now()
			break
		}
		cnt++
	}
}
