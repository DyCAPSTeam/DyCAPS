package party

import (
	"fmt"

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

	var tmpCB = make([]*pbc.Element, p.N+1) //commitment of B(x,j), j start from 1
	var tmpWB = make([]*pbc.Element, p.N+1) //witness of B(i,j), j start from 1
	for i := uint32(0); i < p.N+1; i++ {
		tmpCB[i] = KZG.NewG1()
		tmpWB[i] = KZG.NewG1()
	}

	//get 2t+1 values from prior execution of DyCAPS.Handoff or DyCAPS.Share
	for j := uint32(0); j < 2*p.F+2; j++ {
		tmpCB[j].Set(p.Proof.PiContents[j].CB_j)
		tmpWB[p.witnessIndexes[j].Int64()].Set(p.witness[j])
	}

	//interpolate the remaining commitments and witnesses
	mutexPolyring.Lock()
	for j := uint32(1); j < p.N+1; j++ {
		tmpCB[j] = InterpolateComOrWit(2*p.F, j, tmpCB[1:2*p.F+2])
		tmpWB[j] = InterpolateComOrWitbyKnownIndexes(2*p.F, j, p.witnessIndexes[1:], p.witness[1:])
	}
	mutexPolyring.Unlock()

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
	var ShareReduceMap = make(map[string][]polypoint.PolyPoint) //map a commitment string to a poly point set
	var ComMap = make(map[string]uint32)                        //count the number of C
	var MostCountedCom string                                   //C_B(x,i)

	var vJ *gmp.Int
	var C, wJ *pbc.Element
	var polyX, polyY []*gmp.Int
	vJ = gmp.NewInt(0)
	C = KZG.NewG1()
	wJ = KZG.NewG1()

	for {
		m := <-p.GetMessage("ShareReduce", ID)
		fmt.Printf("[ShareReduce] New party %v receives ShareReduce message from %v\n", p.PID, m.Sender)
		var ShareReduceData protobuf.ShareReduce
		proto.Unmarshal(m.Data, &ShareReduceData)
		C.SetCompressedBytes(ShareReduceData.C)
		wJ.SetCompressedBytes(ShareReduceData.W)
		vJ.SetBytes(ShareReduceData.V)

		mutexKZG.Lock()
		verified := KZG.VerifyEval(C, gmp.NewInt(int64(m.Sender+1)), vJ, wJ)
		mutexKZG.Unlock()
		if verified {
			cStr := string(ShareReduceData.C)
			_, ok2 := ShareReduceMap[cStr]
			if ok2 {
				ShareReduceMap[cStr] = append(ShareReduceMap[cStr], polypoint.PolyPoint{
					X:       int32(m.Sender + 1),
					Y:       gmp.NewInt(0).Set(vJ),
					PolyWit: KZG.NewG1().Set(wJ),
				})
				ComMap[cStr] += 1
			} else {
				ShareReduceMap[cStr] = make([]polypoint.PolyPoint, 0)
				ShareReduceMap[cStr] = append(ShareReduceMap[cStr], polypoint.PolyPoint{
					X:       int32(m.Sender + 1),
					Y:       gmp.NewInt(0).Set(vJ),
					PolyWit: KZG.NewG1().Set(wJ),
				})
				ComMap[cStr] = 1
			}

			if ComMap[cStr] >= p.F+1 {
				MostCountedCom = cStr

				fmt.Printf("[ShareReduce] New party %v has finished ShareReduce.\n", p.PID)
				break
			}
		} else {
			fmt.Printf("[ShareReduce] New party %v verifies Reduce message from old party %v FAIL. C: %s, v: %v, w: %s\n", p.PID, m.Sender, C.String(), vJ, wJ.String())
		}
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
	fmt.Printf("[ShareReduce] New party %v has recovered its reducedShare:\n", p.PID)
	p.reducedShare.Print()
}
