package party

import (
	"github.com/DyCAPSTeam/DyCAPS/internal/bls"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"google.golang.org/protobuf/proto"
	"log"
)

func (p *HonestParty) VSSShareReceive(ID []byte) {

	polyValueFromSend := make([]bls.Fr, 2*p.F+2)

	witnessFromSend := make([]bls.G1Point, 2*p.F+2)

	var piFromSend = new(Pi)
	piFromSend.Init(p.F)

	var verifyOK = false
	//We assume VSS sender only sends VSSSend message once (whether the sender is honest or not)
	//So there is no for-loop here: each party only processes VSSSend once
	m := <-p.GetMessage("VSSSend", ID)
	log.Printf("[VSSEcho][Party %v] Received VSSSend Message\n", p.PID)
	var payloadMessage protobuf.VSSSend
	err := proto.Unmarshal(m.Data, &payloadMessage)
	if err != nil {
		log.Printf("[VSSEcho][Party %v] Unmarshal err: %v\n", p.PID, err)
	}
	piFromSend.SetFromVSSMessage(payloadMessage.Pi, p.F)

	for j := uint32(1); j < 2*p.F+2; j++ {

		value_byte := [32]byte{}
		copy(value_byte[:], payloadMessage.BijList[j])
		bls.FrFrom32(&polyValueFromSend[j], value_byte)

		wit_raw, _ := bls.FromCompressedG1(payloadMessage.WBijList[j])
		bls.CopyG1(&witnessFromSend[j], wit_raw)
	}

	verifyOK = p.VerifyVSSSendReceived(polyValueFromSend, witnessFromSend, piFromSend)
	if !verifyOK {
		log.Printf("[VSSEcho][Party %v] Verify VSSSend FAIL\n", p.PID)
	} else {
		log.Printf("[VSSEcho][Party %v] Verify VSSSend SUCCESS\n", p.PID)
		p.Proof.Set(piFromSend, p.F)

		//prepare for polyring
		for j := uint32(1); j < 2*p.F+2; j++ {

			bls.CopyG1(&p.witness[j], &witnessFromSend[j])
			p.witnessIndexes[j] = int(j)
		}

		//interpolate 2t-degree polynomial B*(i,y)
		KnownIndexes := make([]bls.Fr, 2*p.F+1) //start from 0
		KnownValues := make([]bls.Fr, 2*p.F+1)
		for j := uint32(0); j < 2*p.F+1; j++ {
			bls.AsFr(&KnownIndexes[j], uint64(j+1))
			bls.CopyFr(&KnownValues[j], &polyValueFromSend[j+1])
		}

		fullShareFromSend := polyring.LagrangeInterpolate(int(2*p.F), KnownIndexes, KnownValues)

		//set the final reduceShare and witnesses, then break
		copy(p.fullShare, fullShareFromSend)
		log.Printf("[VSSRecover][Party %v] Get full share B(i,y):\n %s", p.PID, PolyToString(p.fullShare))
	}

	log.Printf("[VSS][Party %v] Exist VSS now\n", p.PID)

}

func (p *HonestParty) VerifyVSSSendReceived(polyValue []bls.Fr, witness []bls.G1Point, piReceived *Pi) bool {

	//Verify g^s == \prod((g^F_j)^lambda_j)

	gFjList := make([]bls.G1Point, 2*p.F+2)
	for j := uint32(1); j < 2*p.F+2; j++ {
		bls.CopyG1(&gFjList[j], &piReceived.PiContents[j].gFj)
	}

	tmpGs := *bls.LinCombG1(gFjList[1:], p.LagrangeCoefficients[0])
	if !bls.EqualG1(&piReceived.Gs, &tmpGs) {
		log.Printf("[VSSEcho][Party %v] VSSSend Verify FAIL, g_s=%v, but prod(g^F(index))=%v \n", p.PID, piReceived.Gs.String(), tmpGs.String())
	}

	//Verify KZG.VerifyEval(CZjk,0,0,WZjk0) == 1 && CBjk == CZjk * g^Fj(k) for k in [1,2t+1]
	for k := uint32(1); k < 2*p.F+2; k++ {

		verifyEval := p.KZG.CheckProofSingle(&piReceived.PiContents[k].CZj, &piReceived.PiContents[k].WZ0, &bls.ZERO, &bls.ZERO)

		var verifyCBj = false
		var tmp bls.G1Point
		bls.AddG1(&tmp, &piReceived.PiContents[k].CZj, &piReceived.PiContents[k].gFj)
		verifyCBj = bls.EqualG1(&tmp, &piReceived.PiContents[k].CBj)
		if !verifyEval || !verifyCBj {
			log.Printf("[VSSEcho][Party %v] VSSSend Verify FAIL, k=%v\n", p.PID, k)
			return false
		}
	}

	//Verify v'ji,w'ji w.r.t pi'
	for j := uint32(1); j < 2*p.F+2; j++ {
		//KZG Verify
		var position bls.Fr
		bls.AsFr(&position, uint64(p.PID+1))
		verifyPoint := p.KZG.CheckProofSingle(&piReceived.PiContents[j].CBj, &witness[j], &position, &polyValue[j])

		if !verifyPoint {
			log.Printf("[VSSEcho][Party %v] VSSSend KZGVerify FAIL when verify v'ji and w'ji, i=%v, CBj[%v]=%v, polyValue[%v]=%v, witness[%v]=%v\n", p.PID, p.PID+1, j, piReceived.PiContents[j].CBj, j, polyValue[j], j, witness[j])
			return false
		}
	}

	return true
}
