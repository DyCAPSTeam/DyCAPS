package party

import (
	"github.com/DyCAPSTeam/DyCAPS/internal/bls"
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

		//prepare for interpolation
		for j := uint32(1); j < 2*p.F+2; j++ {

			bls.CopyG1(&p.witness[j], &witnessFromSend[j])
			bls.CopyFr(&p.witnessIndexes[j], &p.FS.ExpandedRootsOfUnity[j])
		}

		//interpolate 2t-degree polynomial B*(i,y)
		KnownExpIndexes := make([]int, 2*p.F+1) //start from 0
		KnownValues := make([]bls.Fr, 2*p.F+1)
		for j := uint32(0); j < 2*p.F+1; j++ {
			KnownExpIndexes[j] = int(j + 1)
			bls.CopyFr(&KnownValues[j], &polyValueFromSend[j+1])
		}

		samples := GetSamples(KnownExpIndexes, KnownValues, p.FS.MaxWidth)

		fullShareFromSend_EvalForm, err2 := p.FS.RecoverPolyFromSamples(samples, p.FS.ZeroPolyViaMultiplication)
		if err2 != nil {
			log.Fatalln(err2)
		}

		fullShareFromSend_CoeffForm, err3 := p.FS.FFT(fullShareFromSend_EvalForm, true)
		fullShareFromSend_CoeffForm = fullShareFromSend_CoeffForm[:2*p.F+1]
		if err3 != nil {
			log.Fatalln(err3)
		}
		//set the final reduceShare and witnesses, then break
		copy(p.fullShare_CoeffForm, fullShareFromSend_CoeffForm)
		copy(p.fullShare_EvalForm, fullShareFromSend_EvalForm)
		log.Printf("[VSSRecover][Party %v] Get full share B(i,y):\n %s", p.PID, PolyToString(p.fullShare_CoeffForm))
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
		log.Printf("[VSSEcho][Party %v] VSSSend Verify FAIL, g_s=%v, but prod(g^F(w^index))=%v \n", p.PID, piReceived.Gs.String(), tmpGs.String())
	}

	//Verify KZG.VerifyEval(CZjk,0,0,WZjk0) == 1 && CBjk == CZjk * g^Fj(k) for k in [1,2t+1]
	for k := uint32(1); k < 2*p.F+2; k++ {

		verifyEval := p.KZG.CheckProofSingle(&piReceived.PiContents[k].CZj, &piReceived.PiContents[k].WZ0, &p.FS.ExpandedRootsOfUnity[0], &bls.ZERO)

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

		verifyPoint := p.KZG.CheckProofSingle(&piReceived.PiContents[j].CBj, &witness[j], &p.FS.ExpandedRootsOfUnity[p.PID+1], &polyValue[j])

		if !verifyPoint {
			log.Printf("[VSSEcho][Party %v] VSSSend KZGVerify FAIL when verify v'ji and w'ji, i=w^%v, CBj[%v]=%v, polyValue[%v]=%v, witness[%v]=%v\n", p.PID, p.PID+1, j, piReceived.PiContents[j].CBj, j, polyValue[j], j, witness[j])
			return false
		}
	}

	return true
}
