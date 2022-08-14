package party

import (
	"fmt"
	"github.com/DyCAPSTeam/DyCAPS/internal/conv"
	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/interpolation"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"github.com/Nik-U/pbc"
	"github.com/ncw/gmp"
	"google.golang.org/protobuf/proto"
	"log"
	"sync"
)

var mutexPolyring sync.Mutex

func (p *HonestParty) VSSShareReceive(ID []byte) {
	ecparamN := ecparam.PBC256.Ngmp

	var CB = make([]*pbc.Element, p.N+1) //CBj for index=1...n

	for i := uint32(0); i < p.N+1; i++ {
		CB[i] = p.KZG.NewG1()
	}

	witnessInterpolated := make([]*pbc.Element, p.N+1)
	for i := uint32(0); i < p.N+1; i++ {
		witnessInterpolated[i] = p.KZG.NewG1()
	}

	fullShareFromSend := polyring.NewEmpty() //B*(i,y)

	polyValueFromSend := make([]*gmp.Int, 2*p.F+2)

	witnessFromSend := make([]*pbc.Element, 2*p.F+2)

	for i := uint32(0); i < 2*p.F+2; i++ {
		polyValueFromSend[i] = gmp.NewInt(0)
		witnessFromSend[i] = p.KZG.NewG1()
	}

	var piFromSend = new(Pi)
	piFromSend.Init(p.F, p.KZG)

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
		polyValueFromSend[j].SetBytes(payloadMessage.BijList[j])
		witnessFromSend[j].SetCompressedBytes(payloadMessage.WBijList[j])
	}

	verifyOK = p.VerifyVSSSendReceived(polyValueFromSend, witnessFromSend, piFromSend)
	if !verifyOK {
		log.Printf("[VSSEcho][Party %v] Verify VSSSend FAIL\n", p.PID)
	} else {
		log.Printf("[VSSEcho][Party %v] Verify VSSSend SUCCESS\n", p.PID)
		p.Proof.Set(piFromSend, p.F)

		//prepare for interpolation
		for j := uint32(1); j < 2*p.F+2; j++ {
			CB[j].Set(piFromSend.PiContents[j].CBj)
			witnessInterpolated[j].Set(witnessFromSend[j])
		}

		for j := uint32(1); j < 2*p.F+2; j++ {
			p.witness[j].Set(witnessFromSend[j])
			p.witnessIndexes[j].Set(gmp.NewInt(int64(j)))
		}

		//interpolate 2t-degree polynomial B*(i,y)
		x := make([]*gmp.Int, 2*p.F+1) //start from 0
		y := make([]*gmp.Int, 2*p.F+1)
		for j := uint32(0); j < 2*p.F+1; j++ {
			x[j] = gmp.NewInt(0)
			x[j].Set(gmp.NewInt(int64(j + 1)))
			y[j] = gmp.NewInt(0)
			y[j].Set(polyValueFromSend[j+1])
		}
		tmpPoly, _ := interpolation.LagrangeInterpolate(int(2*p.F), x, y, ecparamN)
		fullShareFromSend.ResetTo(tmpPoly)
		log.Printf("[VSSEcho][Party %v] Interpolate B*(i,x) polynomial from VSSSend messages:\n", p.PID)
		fullShareFromSend.Print(fmt.Sprintf("B*(%v,x)", p.PID+1))

	}

	//set the final reduceShare and witnesses, then break
	p.fullShare.ResetTo(fullShareFromSend)
	log.Printf("[VSSRecover][Party %v] Get full share B(i,y):\n", p.PID)
	p.fullShare.Print(fmt.Sprintf("B(%v,y)", p.PID+1))
	log.Printf("[VSS][Party %v] Exist VSS now\n", p.PID)

}

func (p *HonestParty) VerifyVSSSendReceived(polyValue []*gmp.Int, witness []*pbc.Element, piReceived *Pi) bool {
	ecparamN := ecparam.PBC256.Ngmp

	//Verify g^s == \prod((g^F_j)^lambda_j)
	lambda := make([]*gmp.Int, 2*p.F+1)
	knownIndexes := make([]*gmp.Int, 2*p.F+1)
	for j := 0; uint32(j) < 2*p.F+1; j++ {
		lambda[j] = gmp.NewInt(0)
		knownIndexes[j] = gmp.NewInt(int64(j + 1))
	}

	mutexPolyring.Lock()
	polyring.GetLagrangeCoefficients(2*p.F, knownIndexes, ecparamN, gmp.NewInt(0), lambda)
	mutexPolyring.Unlock()

	tmp := p.KZG.NewG1()
	tmp.Set0()
	for j := uint32(1); j < 2*p.F+2; j++ {
		tmp2 := p.KZG.NewG1()
		// tmp2.Set1()
		tmp2.MulBig(piReceived.PiContents[j].gFj, conv.GmpInt2BigInt(lambda[j-1])) // the x value of index index-1 is index
		tmp.ThenAdd(tmp2)
		// tmp.ThenMul(tmp2)
	}
	if !tmp.Equals(piReceived.Gs) {
		log.Printf("[VSSEcho][Party %v] VSSSend Verify FAIL, g_s=%v, but prod(g^F(index))=%v \n", p.PID, piReceived.Gs.String(), tmp.String())
		return false
	}
	//Verify KZG.VerifyEval(CZjk,0,0,WZjk0) == 1 && CBjk == CZjk * g^Fj(k) for k in [1,2t+1]
	for k := uint32(1); k < 2*p.F+2; k++ {
		p.mutexKZG.Lock()
		verifyEval := p.KZG.VerifyEval(piReceived.PiContents[k].CZj, gmp.NewInt(0), gmp.NewInt(0), piReceived.PiContents[k].WZ0)
		p.mutexKZG.Unlock()

		var verifyCBj = false
		tmp3 := p.KZG.NewG1()
		tmp3.Set0()
		tmp3.Add(piReceived.PiContents[k].CZj, piReceived.PiContents[k].gFj)
		verifyCBj = tmp3.Equals(piReceived.PiContents[k].CBj)
		if !verifyEval || !verifyCBj {
			log.Printf("[VSSEcho][Party %v] VSSSend Verify FAIL, k=%v\n", p.PID, k)
			return false
		}
	}

	//Verify v'ji,w'ji w.r.t pi'
	for j := uint32(1); j < 2*p.F+2; j++ {
		//KZG Verify
		p.mutexKZG.Lock()
		verifyPoint := p.KZG.VerifyEval(piReceived.PiContents[j].CBj, gmp.NewInt(int64(p.PID+1)), polyValue[j], witness[j])
		p.mutexKZG.Unlock()

		if !verifyPoint {
			log.Printf("[VSSEcho][Party %v] VSSSend KZGVerify FAIL when verify v'ji and w'ji, i=%v, CBj[%v]=%v, polyValue[%v]=%v, witness[%v]=%v\n", p.PID, p.PID+1, j, piReceived.PiContents[j].CBj, j, polyValue[j], j, witness[j])
			return false
		}
	}

	return true
}
