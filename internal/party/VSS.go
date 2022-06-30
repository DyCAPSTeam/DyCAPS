package party

import (
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/DyCAPSTeam/DyCAPS/internal/conv"
	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/interpolation"
	"github.com/DyCAPSTeam/DyCAPS/internal/polypoint"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"github.com/Nik-U/pbc"
	"github.com/golang/protobuf/proto"
	"github.com/ncw/gmp"
)

var mutexPolyring sync.Mutex

//Receiving VSS Shares
func (p *HonestParty) VSSshareReceiver(ID []byte) {
	ecparamN := ecparam.PBC256.Ngmp

	var PiChecked bool = false //Once PiChecked, p will send VSSReady messages
	var mutexPi sync.Mutex

	var EchoMap = make(map[string]int)

	var ReadyMap = make(map[string]int)
	var mutexReadyMap sync.RWMutex

	var ReadyContent = make(map[string][]polypoint.PolyPoint)
	var mutexReadyContent sync.Mutex

	var InitDoneChannel chan bool = make(chan bool, 1)
	var InitDoneChannel2 chan bool = make(chan bool, 1)
	var InitDoneChannel3 chan bool = make(chan bool, 1)
	var PiCheckedChannel chan bool = make(chan bool, 1)
	var CBSetChannel chan bool = make(chan bool, 1)
	var CBResetChannel chan bool = make(chan bool)

	var DistSent bool = false
	var VSSShareFinished chan bool = make(chan bool, 1)

	var CB = make([]*pbc.Element, p.N+1, p.N+1) //CB_j for j=1...n
	var mutexCW sync.Mutex

	mutexCW.Lock()
	for i := uint32(0); i < p.N+1; i++ {
		CB[i] = KZG.NewG1()
	}
	mutexCW.Unlock()

	witnessInterpolated := make([]*pbc.Element, p.N+1, p.N+1)
	for i := uint32(0); i < p.N+1; i++ {
		witnessInterpolated[i] = KZG.NewG1()
	}

	var CBFromReady = make([]*pbc.Element, p.N+1, p.N+1) //l=1...n
	for i := uint32(0); i < p.N+1; i++ {
		CBFromReady[i] = KZG.NewG1()
		CBFromReady[i].Set1()
	}

	fullShareFromSend := polyring.NewEmpty() //B*(i,y)
	SFullIndexes := make([]*gmp.Int, 0, p.N) //init as empty set
	SFullPolyValue := make([]*gmp.Int, 0, p.N)

	InitDoneChannel <- true
	InitDoneChannel2 <- true
	InitDoneChannel3 <- true

	// go p.handleVSSSend()

	//handle VSSSend Message
	go func() {
		polyValueFromSend := make([]*gmp.Int, 2*p.F+2, p.N+1)
		witnessFromSend := make([]*pbc.Element, 2*p.F+2, p.N+1)
		for i := uint32(0); i < 2*p.F+2; i++ {
			polyValueFromSend[i] = gmp.NewInt(0)
			witnessFromSend[i] = KZG.NewG1()
		}

		var piFromSend = new(Pi)
		piFromSend.Init(p.F)

		<-InitDoneChannel
		var verifyOK = false
		//We assume VSS sender only sends VSSSend message once (whether the sender is honest or not)
		//So there is no for-loop here: each party only processes VSSSend once
		m := <-p.GetMessage("VSSSend", ID)
		fmt.Printf("Party %v receive VSSSend Message\n", p.PID)
		var payloadMessage protobuf.VSSSend
		err := proto.Unmarshal(m.Data, &payloadMessage)
		if err != nil {
			fmt.Printf("Party %v unmarshal err: %v\n", p.PID, err)
		}
		piFromSend.SetFromVSSMessage(payloadMessage.Pi, p.F)

		mutexPi.Lock()
		if PiChecked == false {
			for j := uint32(1); j < 2*p.F+2; j++ {
				polyValueFromSend[j].SetBytes(payloadMessage.RjiList[j])
				witnessFromSend[j].SetCompressedBytes(payloadMessage.WRjiList[j])
			}

			verifyOK = p.VerifyVSSSendReceived(polyValueFromSend, witnessFromSend, piFromSend)
			if !verifyOK {
				fmt.Printf("Party %v verifies VSSSend Failed\n", p.PID)
			} else {
				fmt.Printf("Party %v verifies VSSSend Success\n", p.PID)
				p.Proof.Set(piFromSend, p.F)

				//prepare for interpolation
				mutexCW.Lock()
				for j := uint32(1); j < 2*p.F+2; j++ {
					CB[j].Set(piFromSend.PiContents[j].CB_j)
					witnessInterpolated[j].Set(witnessFromSend[j])
				}
				CBSetChannel <- true

				mutexCW.Unlock()

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
				fmt.Printf("Party %v interpolate B*(i,x) polynomial when receive Send Message:\n", p.PID)
				fullShareFromSend.Print()

				//sendEcho
				EchoData := EncapsulateVSSEcho(piFromSend, p.N, p.F)
				EchoMessage := &protobuf.Message{
					Type:   "VSSEcho",
					Id:     ID,
					Sender: p.PID,
					Data:   EchoData,
				}
				err := p.Broadcast(EchoMessage)
				if err != nil {
					fmt.Printf("Party %v broadcast VSSEcho error:%v\n", p.PID, err)
				}
				fmt.Printf("Party %v broadcasts Echo Message, handle VSSSend done\n", p.PID)
			}
		}
		mutexPi.Unlock()
	}()

	//handle VSSEcho Message
	go func() {
		<-InitDoneChannel2
		for {
			m := <-p.GetMessage("VSSEcho", ID)
			var payloadMessage protobuf.VSSEcho
			err := proto.Unmarshal(m.Data, &payloadMessage)
			if err != nil {
				fmt.Printf("Party %v unmarshal err: %v\n", p.PID, err)
			}
			var piFromEcho = new(Pi)
			piFromEcho.Init(p.F)
			piFromEcho.SetFromVSSMessage(payloadMessage.Pi, p.F)
			piHash := sha256.New()
			piByte, _ := proto.Marshal(payloadMessage.Pi)
			piHash.Write(piByte)
			piHashStr := string(piHash.Sum(nil))

			counter, ok := EchoMap[piHashStr]
			if ok {
				counter = counter + 1
				EchoMap[piHashStr] = counter
			} else {
				counter = 1
				EchoMap[piHashStr] = 1
			}

			fmt.Printf("Party %v receives VSSEcho message from %v, has collected %v VSSEcho messages now\n", p.PID, m.Sender, counter)

			mutexPi.Lock()
			if !PiChecked && uint32(counter) >= p.N-p.F {
				fmt.Printf("Party %v has entered the case Echo >= n-t\n", p.PID)
				if p.Proof.Equals(piFromEcho, p.F) {
					//in this case (pi = pi'), this party must have received a valid VSSSend message

					w := KZG.NewG1()
					for l := uint32(0); l < p.N; l++ {
						v_l := gmp.NewInt(0) //value at l+1
						fullShareFromSend.EvalMod(gmp.NewInt(int64(l+1)), ecparamN, v_l)
						if l < 2*p.F+1 {
							w = witnessInterpolated[l+1]
						} else {
							mutexPolyring.Lock()
							w.Set(InterpolateComOrWit(2*p.F, l+1, witnessInterpolated[1:2*p.F+2]))
							mutexPolyring.Unlock()
						}
						ReadyData := EncapsulateVSSReady(piFromEcho, "SHARE", v_l, w, p.N, p.F)
						err := p.Send(&protobuf.Message{Type: "VSSReady", Id: ID, Sender: p.PID, Data: ReadyData}, l)
						if err != nil {
							fmt.Printf("Party %v send VSSReady err: %v\n", p.PID, err)
						}
					}
					fmt.Printf("Collected n-t=%v VSSEcho messages, VSSReady sent, PID: %v, ReadyType: SHARE\n", counter, p.PID)

					//PiChecked == true  <=> p has sent (or will send) VSSReady messages
					PiChecked = true
					PiCheckedChannel <- true
					fmt.Printf("Party %v Pichecked by n-t VSSEcho messages\n", p.PID)
					mutexPi.Unlock()

					//break after sending VSSReady message
					break
				} else {
					fmt.Println("Party", p.PID, "resets Pi <- Pi'")
					p.Proof.Set(piFromEcho, p.F)

					//discard full share
					fullShareFromSend.ResetTo(polyring.NewEmpty())

					//reset CBj
					mutexCW.Lock()
					for j := uint32(1); j < 2*p.F+2; j++ {
						CB[j].SetCompressedBytes(payloadMessage.Pi.PiContents[j].CBJ)
					}
					CBResetChannel <- true

					//reset witness
					for i := uint32(0); i < p.N+1; i++ {
						witnessInterpolated[i] = KZG.NewG1()
					}
					mutexCW.Unlock()

					//send VSSReady-NOSHARE
					ReadyData := EncapsulateVSSReady(piFromEcho, "NOSHARE", nil, nil, p.N, p.F)
					err := p.Broadcast(&protobuf.Message{Type: "VSSReady", Id: ID, Sender: p.PID, Data: ReadyData})
					if err != nil {
						fmt.Printf("Party %v broadcast VSSReady error: %v\n", p.PID, err)
					}
					fmt.Printf("Collected n-t=%v VSSEcho message, VSSReady sent, PID: %v, ReadyType: NOSHARE\n", counter, p.PID)

					//PiChecked == true  <=> p has sent (or will send) VSSReady messages
					PiChecked = true
					PiCheckedChannel <- true
					fmt.Printf("Party %v Pichecked by n-t VSSEcho messages\n", p.PID)

					mutexPi.Unlock()
					//break after sending VSSReady message
					break
				}
			} else {
				mutexPi.Unlock()
			}
		}
	}()

	//handle VSSReady Message
	go func() {
		<-InitDoneChannel3
		var piFromReady = new(Pi)
		piFromReady.Init(p.F)
		var payloadMessage protobuf.VSSReady
		for {
			m := <-p.GetMessage("VSSReady", ID)
			err := proto.Unmarshal(m.Data, &payloadMessage)
			if err != nil {
				fmt.Printf("Party %v unmarshal err: %v\n", p.PID, err)
			}
			fmt.Printf("Party %v has received VSSReady from %v, ReadyType: %v\n", p.PID, m.Sender, payloadMessage.ReadyType)
			piFromReady.SetFromVSSMessage(payloadMessage.Pi, p.F)
			piHash := sha256.New()
			piByte, _ := proto.Marshal(payloadMessage.Pi)
			piHash.Write(piByte)
			piHashStr := string(piHash.Sum(nil))
			mSender := m.Sender //senderID
			vL := gmp.NewInt(0) //l = senderID + 1
			wL := KZG.NewG1()
			wL.Set1()

			if payloadMessage.ReadyType == "SHARE" {
				//verify READY-SHARE messages
				vL.SetBytes(payloadMessage.BIl)
				wL.SetCompressedBytes(payloadMessage.WBIl)
				//start from 1
				for j := uint32(1); j < 2*p.F+2; j++ {
					CBFromReady[j].Set(piFromReady.PiContents[j].CB_j)
				}

				//P_s sends {VSSReady, B*(s,r)} to P_r, so P_r interpolates C_B(x,r) to verify the evaluation at x=s
				C := KZG.NewG1()
				if p.PID < 2*p.F+1 {
					C.Set(CBFromReady[p.PID+1])
				} else {
					mutexPolyring.Lock()
					C.Set(InterpolateComOrWit(2*p.F, p.PID+1, CBFromReady[1:2*p.F+2]))
					mutexPolyring.Unlock()
				}
				fmt.Printf("Party %v verifying, mSender+1: %v, C:%s, v_l: %s, w_l: %s\n", p.PID, gmp.NewInt(int64(mSender+1)), C.String(), vL.String(), wL.String())

				mutexKZG.Lock()
				verified := KZG.VerifyEval(C, gmp.NewInt(int64(mSender+1)), vL, wL)
				mutexKZG.Unlock()

				if verified {
					fmt.Printf("Party %v verified: %v, sender: %v\n", p.PID, verified, mSender)
					mutexReadyMap.Lock()
					counter, ok := ReadyMap[piHashStr]
					if ok {
						ReadyMap[piHashStr] = counter + 1
					} else {
						ReadyMap[piHashStr] = 1
					}
					fmt.Printf("ReadyMap[pi_hash_str]: %v, PID: %v\n", ReadyMap[piHashStr], p.PID)
					mutexReadyMap.Unlock()

					//record the value and witness
					mutexReadyContent.Lock()
					_, ok2 := ReadyContent[piHashStr]
					if ok2 {
						ReadyContent[piHashStr] = append(ReadyContent[piHashStr], polypoint.PolyPoint{
							X:       int32(mSender + 1),
							Y:       vL,
							PolyWit: wL,
						})
					} else {
						ReadyContent[piHashStr] = make([]polypoint.PolyPoint, 0)
						ReadyContent[piHashStr] = append(ReadyContent[piHashStr], polypoint.PolyPoint{
							X:       int32(mSender + 1),
							Y:       vL,
							PolyWit: wL,
						})
					}
					mutexReadyContent.Unlock()
				} else {
					fmt.Printf("Party %v not verified, mSender+1=%v, C=%s, v_l=%s, w_l=%s\n", p.PID, mSender+1, C.String(), vL.String(), wL.String())
				}
			} else if payloadMessage.ReadyType == "NOSHARE" {
				mutexReadyMap.Lock()
				_, ok := ReadyMap[piHashStr]
				if ok {
					ReadyMap[piHashStr] = ReadyMap[piHashStr] + 1
				} else {
					ReadyMap[piHashStr] = 1
				}
				mutexReadyMap.Unlock()
			}

			//send VSSReady message
			mutexPi.Lock()
			mutexReadyMap.RLock()
			if !PiChecked && uint32(ReadyMap[piHashStr]) >= p.F+1 {
				mutexReadyMap.RUnlock()
				fmt.Printf("Party %v has entered the case Ready >= t+1\n", p.PID)

				if p.Proof.Equals(piFromReady, p.F) {
					// in this case, p.Proof has been set by VSSSend message
					// send VSSReady-SHARE
					w := KZG.NewG1()
					for l := uint32(0); l < p.N; l++ {
						vLSend := gmp.NewInt(0) //value at l+1
						fullShareFromSend.EvalMod(gmp.NewInt(int64(l+1)), ecparamN, vLSend)
						if l < 2*p.F+1 {
							w = p.witnessInit[l+1]
						} else {
							mutexPolyring.Lock()
							w.Set(InterpolateComOrWit(2*p.F, l+1, witnessInterpolated[1:2*p.F+2]))
							mutexPolyring.Unlock()
						}
						ReadyData := EncapsulateVSSReady(piFromReady, "SHARE", vLSend, w, p.N, p.F)
						err := p.Send(&protobuf.Message{Type: "VSSReady", Id: ID, Sender: p.PID, Data: ReadyData}, uint32(l))
						if err != nil {
							fmt.Printf("Party %v send VSSReady err: %v\n", p.PID, err)
						}
					}
					fmt.Printf("Collected t+1 VSSReady message, VSSReady sent, PID: %v, ReadyType: SHARE\n", p.PID)

					PiChecked = true
					PiCheckedChannel <- true
					fmt.Printf("Party %v Pichecked by t+1 VSSReady messages\n", p.PID)

				} else {
					p.Proof.Set(piFromReady, p.F)

					mutexCW.Lock()
					//reset CBj
					for j := uint32(1); j < 2*p.F+2; j++ {
						CB[j].SetCompressedBytes(payloadMessage.Pi.PiContents[j].CBJ)
					}
					CBResetChannel <- true

					//reset witnesses
					for i := uint32(0); i < p.N+1; i++ {
						witnessInterpolated[i] = KZG.NewG1()
					}

					//discard the full share B*(i,y) interpolated from VSSSend message
					fullShareFromSend.ResetTo(polyring.NewEmpty())

					mutexCW.Unlock()

					//send Ready-NOSHARE
					ReadyData := EncapsulateVSSReady(piFromReady, "NOSHARE", nil, nil, p.N, p.F)
					err := p.Broadcast(&protobuf.Message{Type: "VSSReady", Id: ID, Sender: p.PID, Data: ReadyData})
					if err != nil {
						fmt.Printf("Party %v broadcast VSSReady err: %v\n", p.PID, err)
					}
					fmt.Printf("Collected t+1 VSSReady message, VSSReady sent, PID: %v, ReadyType: NOSHARE\n", p.PID)

					PiChecked = true
					PiCheckedChannel <- true
					fmt.Printf("Party %v Pichecked by t+1 VSSReady messages\n", p.PID)

				}
			} else {
				mutexReadyMap.RUnlock()

			}
			mutexPi.Unlock()

			mutexReadyMap.RLock()
			mutexReadyContent.Lock()
			//send Distribute Message
			if !DistSent && uint32(ReadyMap[piHashStr]) >= p.N-p.F && uint32(len(ReadyContent[piHashStr])) >= p.F+1 {
				fmt.Printf("Party %v has collected n-t=%v Ready messages, and there are %v >= t+1 valid contents\n", p.PID, ReadyMap[piHashStr], len(ReadyContent[piHashStr]))
				var witnessFromReady []*pbc.Element = make([]*pbc.Element, p.F+1)
				var reducedShareX []*gmp.Int = make([]*gmp.Int, p.F+1)
				var reducedShareY []*gmp.Int = make([]*gmp.Int, p.F+1)
				for k := 0; uint32(k) < p.F+1; k++ {
					reducedShareX[k] = gmp.NewInt(0)
					reducedShareX[k].Set(gmp.NewInt(int64(ReadyContent[piHashStr][k].X)))
					reducedShareY[k] = gmp.NewInt(0)
					reducedShareY[k].Set(ReadyContent[piHashStr][k].Y)
					witnessFromReady[k] = KZG.NewG1()
					witnessFromReady[k].Set(ReadyContent[piHashStr][k].PolyWit)
				}
				reducedShare, err := interpolation.LagrangeInterpolate(int(p.F), reducedShareX, reducedShareY, ecparamN)
				if err != nil {
					fmt.Printf("Party %v incurrs an error when interpolates B(x,i): %v\n", p.PID, err)
				} else {
					fmt.Printf("Party %v has reconstructed reducedShare B(x,i) from t+1 Ready messages:\n", p.PID)
				}
				reducedShare.Print()

				//send VSSDistribute
				for l := uint32(0); l < p.N; l++ {
					polyvalueDist := gmp.NewInt(0)
					reducedShare.EvalMod(gmp.NewInt(int64(l+1)), ecparamN, polyvalueDist)
					witnessDist := KZG.NewG1()

					mutexKZG.Lock()
					KZG.CreateWitness(witnessDist, reducedShare, gmp.NewInt(int64(l+1)))
					mutexKZG.Unlock()

					DistData := EncapsulateVSSDistribute(polyvalueDist, witnessDist, p.N, p.F)
					err := p.Send(&protobuf.Message{
						Type:   "VSSDistribute",
						Id:     ID,
						Sender: p.PID,
						Data:   DistData,
					}, l)
					if err != nil {
						fmt.Printf("Party %v send VSSDistribute err: %v\n", p.PID, err)
					}
				}
				// fmt.Printf("Party %v has sent VSSDistribute message\n", p.PID)
				DistSent = true

			}
			mutexReadyContent.Unlock()
			mutexReadyMap.RUnlock()

			if DistSent {
				fmt.Printf("Party %v has sent VSSDistribute, breaking now\n", p.PID)
				break
			}
		}
	}()

	//handle VSSDistribute Message
	go func() {
		<-PiCheckedChannel // waiting for Pi checked
		var fullShareInterpolated = false

		select {
		case <-CBSetChannel:
			goto handleVSSDistribute
		case <-CBResetChannel:
			goto handleVSSDistribute
		}

	handleVSSDistribute:
		fmt.Printf("Party %v is ready to handle VSSDistribute Message\n", p.PID)
		for {
			msg := <-p.GetMessage("VSSDistribute", ID)
			var payloadMessage protobuf.VSSDistribute
			err := proto.Unmarshal(msg.Data, &payloadMessage)
			if err != nil {
				fmt.Printf("Party %v unmarshal err: %v\n", p.PID, err)
			}
			fmt.Printf("Party %v has received VSSDistribute from %v \n", p.PID, msg.Sender)

			valueFromDist := gmp.NewInt(0)
			valueFromDist.SetBytes(payloadMessage.BLi)
			witnessFromDist := KZG.NewG1()
			witnessFromDist.SetCompressedBytes(payloadMessage.WBLi)

			mutexCW.Lock()
			//interpolate the required CBj
			C := KZG.NewG1()
			if msg.Sender < 2*p.F+1 {
				C = CB[msg.Sender+1]
			} else {
				mutexPolyring.Lock()
				C.Set(InterpolateComOrWit(2*p.F, msg.Sender+1, CB[1:2*p.F+2]))
				mutexPolyring.Unlock()
			}

			mutexKZG.Lock()
			distVerifyOK := KZG.VerifyEval(C, gmp.NewInt(int64(p.PID+1)), valueFromDist, witnessFromDist)
			mutexKZG.Unlock()

			if distVerifyOK {
				fmt.Printf("Party %v verifies Distribute message from %v, ok\n", p.PID, msg.Sender)
				SFullPolyValue = append(SFullPolyValue, valueFromDist)
				SFullIndexes = append(SFullIndexes, gmp.NewInt(int64(msg.Sender+1)))
				length := len(SFullPolyValue)
				p.witnessInit[length-1].Set(witnessFromDist)
				p.witnessInitIndexes[length-1].Set(gmp.NewInt(int64(msg.Sender + 1))) //change this name later.
			} else {
				fmt.Printf("Party %v verifies Distribute message from %v, FAIL, C_B[%v]=%v, valueFromDist=%v, witnessFromDist=%v\n", p.PID, msg.Sender, msg.Sender+1, CB[msg.Sender+1], valueFromDist, witnessFromDist)
			}
			mutexCW.Unlock()

			if uint32(len(SFullPolyValue)) >= 2*p.F+1 && !fullShareInterpolated {
				// fmt.Println(p.PID, "starts to interpolate")
				fullShare, err := interpolation.LagrangeInterpolate(int(2*p.F), SFullIndexes, SFullPolyValue, ecparamN)
				if err != nil {
					fmt.Printf("Party %v interpolation error: %v\n", p.PID, err)
					// continue
				} else {
					//set the final reduceShare and witnesses, then break
					p.fullShare.ResetTo(fullShare)
					fmt.Printf("Party %v gets its full share B(i,y):\n", p.PID)
					p.fullShare.Print()
					fullShareInterpolated = true
					VSSShareFinished <- true
					break
				}
			}
		}
	}()

	<-VSSShareFinished
	fmt.Printf("Party %v exist VSS now\n", p.PID)
	return
}

// func (p *HonestParty) handleVSSSend(ID []byte) {

// }

//Verify pi' and v'ji ,w'ji received
func (p *HonestParty) VerifyVSSSendReceived(polyValue []*gmp.Int, witness []*pbc.Element, pi_received *Pi) bool {
	ecparamN := ecparam.PBC256.Ngmp

	//Verify g^s == sigma((g^F_j)^lambda_j)
	lambda := make([]*gmp.Int, 2*p.F+1)
	knownIndexes := make([]*gmp.Int, 2*p.F+1)
	for j := 0; uint32(j) < 2*p.F+1; j++ {
		lambda[j] = gmp.NewInt(0)
		knownIndexes[j] = gmp.NewInt(int64(j + 1))
	}

	mutexPolyring.Lock()
	polyring.GetLagrangeCoefficients(int(2*p.F), knownIndexes, ecparamN, gmp.NewInt(0), lambda)
	mutexPolyring.Unlock()

	tmp := KZG.NewG1()
	tmp.Set0()
	for j := uint32(1); j < 2*p.F+2; j++ {
		tmp2 := KZG.NewG1()
		// tmp2.Set1()
		tmp2.MulBig(pi_received.PiContents[j].g_Fj, conv.GmpInt2BigInt(lambda[j-1])) // the x value of index j-1 is j
		// tmp2.PowBig(p.Proof.Pi_contents[j].g_Fj, conv.GmpInt2BigInt(lambda[j-1])) // the x value of index j-1 is j
		tmp.ThenAdd(tmp2)
		// tmp.ThenMul(tmp2)
	}
	if !tmp.Equals(pi_received.Gs) {
		fmt.Printf("Party %v VSSSend Verify Failed, g_s=%v, but prod(g^F(j))=%v \n", p.PID, pi_received.Gs.String(), tmp.String())
		return false
	}
	//Verify KZG.VerifyEval(CZjk,0,0,WZjk0) == 1 && CBjk == CZjk * g^Fj(k) for k in [1,2t+1]
	for k := uint32(1); k < 2*p.F+2; k++ {
		mutexKZG.Lock()
		verifyEval := KZG.VerifyEval(pi_received.PiContents[k].CZ_j, gmp.NewInt(0), gmp.NewInt(0), pi_received.PiContents[k].WZ_0)
		mutexKZG.Unlock()

		var verifyRj bool = false
		tmp3 := KZG.NewG1()
		tmp3.Set0()
		tmp3.Add(pi_received.PiContents[k].CZ_j, pi_received.PiContents[k].g_Fj)
		verifyRj = tmp3.Equals(pi_received.PiContents[k].CB_j)
		if !verifyEval || !verifyRj {
			fmt.Printf("Party %v VSSSend Verify Failed at k=%v\n", p.PID, k)
			return false
		}
	}

	//Verify v'ji,w'ji w.r.t pi'
	for j := uint32(1); j < 2*p.F+2; j++ {
		//KZG Verify
		mutexKZG.Lock()
		verifyPoint := KZG.VerifyEval(pi_received.PiContents[j].CB_j, gmp.NewInt(int64((p.PID + 1))), polyValue[j], witness[j])
		mutexKZG.Unlock()

		if !verifyPoint {
			fmt.Printf("Party %v VSSSend KZGVerify Failed when verify v'ji and w'ji, i=%v, CB_j[%v]=%v, polyValue[%v]=%v, witness[%v]=%v\n", p.PID, p.PID+1, j, pi_received.PiContents[j].CB_j, j, polyValue[j], j, witness[j])
			return false
		}
	}

	return true
}
