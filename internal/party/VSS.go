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

//Receiving VSS Shares
func (p *HonestParty) VSSshareReceiver(ID []byte) {
	ecparamN := ecparam.PBC256.Ngmp

	var PiChecked bool = false //Once PiChecked, p will send VSSReady messages
	var mutexPi sync.Mutex
	//TODO: the problem should be related to the mutexes

	var EchoMap = make(map[string]int)

	var ReadyMap = make(map[string]int)
	var mutex_ReadyMap sync.RWMutex

	var ReadyContent = make(map[string][]polypoint.PolyPoint)
	var mutex_ReadyContent sync.Mutex

	var PiCheckedChannel chan bool = make(chan bool, 1)
	var InitDoneChannel chan bool = make(chan bool, 1)
	var InitDoneChannel2 chan bool = make(chan bool, 1)
	var InitDoneChannel3 chan bool = make(chan bool, 1)

	var DistSent bool = false
	var VSSshareFinished chan bool = make(chan bool, 1)

	var C_R = make([]*pbc.Element, p.N+1, p.N+1) //C_R_l for l=1...n
	var mutexCW sync.Mutex

	mutexCW.Lock()
	for i := uint32(0); i < p.N+1; i++ {
		C_R[i] = KZG.NewG1()
	}
	mutexCW.Unlock()

	witnessInterpolated := make([]*pbc.Element, p.N+1, p.N+1)
	for i := uint32(0); i < p.N+1; i++ {
		witnessInterpolated[i] = KZG.NewG1()
	}

	var CRFromReady = make([]*pbc.Element, p.N+1, p.N+1) //l=1...n
	for i := uint32(0); i < p.N+1; i++ {
		CRFromReady[i] = KZG.NewG1()
		CRFromReady[i].Set1()
	}

	fullShare_from_Send := polyring.NewEmpty() //B*(i,y)
	S_full_indexes := make([]*gmp.Int, 0, p.N) //init as empty set
	S_full_polyValue := make([]*gmp.Int, 0, p.N)

	InitDoneChannel <- true
	InitDoneChannel2 <- true
	InitDoneChannel3 <- true

	// go p.handleVSSSend()

	//handle VSSSend Message
	go func() {
		polyValueFromSend := make([]*gmp.Int, 2*p.F+2, p.N+1)
		witnessFromSend := make([]*pbc.Element, 2*p.F+2, p.N+1)
		CRFromSend := make([]*pbc.Element, 2*p.F+2, p.N+1)
		for i := uint32(0); i < 2*p.F+2; i++ {
			polyValueFromSend[i] = gmp.NewInt(0)
			witnessFromSend[i] = KZG.NewG1()
			CRFromSend[i] = KZG.NewG1()
		}

		var pi_from_Send = new(Pi)
		pi_from_Send.Init(p.F)

		<-InitDoneChannel
		var verifyOK = false
		//We assume VSS sender only sends VSSSend message once (whether the sender is honest or not)
		//So there is no for-loop here: each party only processes VSSSend once
		m := <-p.GetMessage("VSSSend", ID)
		fmt.Printf("Party %v receive VSSSend Message\n", p.PID)
		var payloadMessage protobuf.VSSSend
		err := proto.Unmarshal(m.Data, &payloadMessage)
		if err != nil {
			fmt.Printf("Party %v err: %v\n", p.PID, err)
		}
		pi_from_Send.SetFromVSSMessage(payloadMessage.Pi, p.F)

		mutexPi.Lock()
		if PiChecked == false {

			for j := uint32(1); j < 2*p.F+2; j++ {
				polyValueFromSend[j].SetBytes(payloadMessage.RjiList[j])
				witnessFromSend[j].SetCompressedBytes(payloadMessage.WRjiList[j])
			}

			verifyOK = p.VerifyVSSSendReceived(polyValueFromSend, witnessFromSend, pi_from_Send)
			if !verifyOK {
				fmt.Printf("Party %v verifies VSSSend Failed\n", p.PID)
			} else {
				fmt.Printf("Party %v verifies VSSSend Success\n", p.PID)
				// During the verification, PiChcked may become true.
				// So PiChecked == false is checked again here
				if PiChecked == false {
					// p.Proof.SetFromVSSMessage(payloadMessage.Pi, p.F)
					p.Proof.Set(pi_from_Send, p.F)

					//prepare for interpolation
					mutexCW.Lock()
					for j := uint32(1); j < 2*p.F+2; j++ {
						C_R[j].Set(pi_from_Send.Pi_contents[j].CR_j)
						CRFromSend[j].Set(pi_from_Send.Pi_contents[j].CR_j)
						witnessInterpolated[j].Set(witnessFromSend[j])
					}

					//interpolate the remaining w_B*(i,j)
					for j := 2*p.F + 2; j < p.N+1; j++ {
						witnessInterpolated[j].Set(InterpolateComOrWit(2*p.F, j, witnessFromSend[1:]))
					}
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
					tmp_poly, _ := interpolation.LagrangeInterpolate(int(2*p.F), x, y, ecparamN)
					fullShare_from_Send.ResetTo(tmp_poly)
					fmt.Printf("Party %v interpolate B*(i,x) polynomial when receive Send Message:\n", p.PID)
					fullShare_from_Send.Print()

					//sendEcho
					EchoData := Encapsulate_VSSEcho(pi_from_Send, p.N, p.F)
					EchoMessage := &protobuf.Message{
						Type:   "VSSEcho",
						Id:     ID,
						Sender: p.PID,
						Data:   EchoData,
					}
					p.Broadcast(EchoMessage)
					fmt.Printf("Party %v broadcasts Echo Message\n", p.PID)

				}

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
			proto.Unmarshal(m.Data, &payloadMessage)
			var pi_from_Echo = new(Pi)
			pi_from_Echo.Init(p.F)
			pi_from_Echo.SetFromVSSMessage(payloadMessage.Pi, p.F)
			pi_hash := sha256.New()
			pi_byte, _ := proto.Marshal(payloadMessage.Pi)
			pi_hash.Write(pi_byte)
			pi_hash_str := string(pi_hash.Sum(nil))

			counter, ok := EchoMap[pi_hash_str]
			if ok {
				counter = counter + 1
				EchoMap[pi_hash_str] = counter
			} else {
				counter = 1
				EchoMap[pi_hash_str] = 1
			}

			fmt.Printf("Party %v receives VSSEcho message from %v, has collected %v VSSEcho messages now\n", p.PID, m.Sender, counter)

			mutexPi.Lock()
			if !PiChecked && uint32(counter) >= p.N-p.F {
				fmt.Printf("Party %v has entered the case Echo >= n-t\n", p.PID)
				if p.Proof.Equals(pi_from_Echo, p.F) {
					//in this case (pi = pi'), this party must have received a valid VSSSend message

					for l := uint32(0); l < p.N; l++ {
						v_l := gmp.NewInt(0) //value at l+1
						fullShare_from_Send.EvalMod(gmp.NewInt(int64(l+1)), ecparamN, v_l)
						Readydata := Encapsulate_VSSReady(p.Proof, "SHARE", v_l, witnessInterpolated[l+1], p.N, p.F)
						p.Send(&protobuf.Message{Type: "VSSReady", Id: ID, Sender: p.PID, Data: Readydata}, l)
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
					p.Proof.Set(pi_from_Echo, p.F)

					//discard full share
					fullShare_from_Send.ResetTo(polyring.NewEmpty())

					//reset CRl
					mutexCW.Lock()
					for j := uint32(1); j < 2*p.F+2; j++ {
						C_R[j].SetCompressedBytes(payloadMessage.Pi.PiContents[j].CRJ)
					}

					//reset witness
					for i := uint32(0); i < p.N+1; i++ {
						witnessInterpolated[i] = KZG.NewG1()
					}
					mutexCW.Unlock()

					//send VSSReady-NOSHARE
					Readydata := Encapsulate_VSSReady(p.Proof, "NOSHARE", nil, nil, p.N, p.F)
					p.Broadcast(&protobuf.Message{Type: "VSSReady", Id: ID, Sender: p.PID, Data: Readydata})
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
		var pi_from_Ready = new(Pi)
		pi_from_Ready.Init(p.F)
		var payloadMessage protobuf.VSSReady
		for {
			m := <-p.GetMessage("VSSReady", ID)
			proto.Unmarshal(m.Data, &payloadMessage)
			fmt.Printf("Party %v has received VSSReady from %v, ReadyType: %v\n", p.PID, m.Sender, payloadMessage.ReadyType)
			pi_from_Ready.SetFromVSSMessage(payloadMessage.Pi, p.F)
			pi_hash := sha256.New()
			pi_byte, _ := proto.Marshal(payloadMessage.Pi)
			pi_hash.Write(pi_byte)
			pi_hash_str := string(pi_hash.Sum(nil))
			mSender := m.Sender  //senderID
			v_l := gmp.NewInt(0) //l = senderID + 1
			w_l := KZG.NewG1()
			w_l.Set1()

			if payloadMessage.ReadyType == "SHARE" {
				//verify READY-SHARE messages
				v_l.SetBytes(payloadMessage.BIl)
				w_l.SetCompressedBytes(payloadMessage.WBIl)
				//start from 1
				for j := uint32(1); j < 2*p.F+2; j++ {
					CRFromReady[j].Set(pi_from_Ready.Pi_contents[j].CR_j)
				}

				//P_s sends {VSSReady, B*(s,r)} to P_r, so P_r interpolates C_B(x,r) to verify the evaluation at x=s
				C := KZG.NewG1()
				if p.PID < 2*p.F+1 {
					C.Set(CRFromReady[p.PID+1])
				} else {
					C.Set(InterpolateComOrWit(2*p.F, p.PID+1, CRFromReady[1:]))
				}
				fmt.Printf("Party %v verifying, mSender+1: %v, C:%s, v_l: %s, w_l: %s\n", p.PID, gmp.NewInt(int64(mSender+1)), C.String(), v_l.String(), w_l.String())
				verified := KZG.VerifyEval(C, gmp.NewInt(int64(mSender+1)), v_l, w_l)

				if verified {
					fmt.Printf("Party %v verified: %v, sender: %v\n", p.PID, verified, mSender)
					mutex_ReadyMap.Lock()
					counter, ok := ReadyMap[pi_hash_str]
					if ok {
						ReadyMap[pi_hash_str] = counter + 1
					} else {
						ReadyMap[pi_hash_str] = 1
					}
					fmt.Printf("ReadyMap[pi_hash_str]: %v, PID: %v\n", ReadyMap[pi_hash_str], p.PID)
					mutex_ReadyMap.Unlock()

					//record the value and witness
					mutex_ReadyContent.Lock()
					_, ok2 := ReadyContent[pi_hash_str]
					if ok2 {
						ReadyContent[pi_hash_str] = append(ReadyContent[pi_hash_str], polypoint.PolyPoint{
							X:       int32(mSender + 1),
							Y:       v_l,
							PolyWit: w_l,
						})
					} else {
						ReadyContent[pi_hash_str] = make([]polypoint.PolyPoint, 0)
						ReadyContent[pi_hash_str] = append(ReadyContent[pi_hash_str], polypoint.PolyPoint{
							X:       int32(mSender + 1),
							Y:       v_l,
							PolyWit: w_l,
						})
					}
					mutex_ReadyContent.Unlock()
				} else {
					fmt.Printf("Party %v not verified: %v, sender: %v\n", p.PID, verified, mSender)
				}
			} else if payloadMessage.ReadyType == "NOSHARE" {
				mutex_ReadyMap.Lock()
				_, ok := ReadyMap[pi_hash_str]
				if ok {
					ReadyMap[pi_hash_str] = ReadyMap[pi_hash_str] + 1
				} else {
					ReadyMap[pi_hash_str] = 1
				}
				mutex_ReadyMap.Unlock()
			}

			//send VSSReady message
			mutexPi.Lock()
			mutex_ReadyMap.RLock()
			if !PiChecked && uint32(ReadyMap[pi_hash_str]) >= p.F+1 {
				mutex_ReadyMap.RUnlock()
				fmt.Printf("Party %v has entered the case Ready >= t+1\n", p.PID)

				if p.Proof.Equals(pi_from_Ready, p.F) {
					// in this case, p.Proof has been set by VSSSend message
					// send VSSReady-SHARE
					for l := uint32(0); l < p.N; l++ {
						v_l_Send := gmp.NewInt(0) //value at l+1
						fullShare_from_Send.EvalMod(gmp.NewInt(int64(l+1)), ecparamN, v_l_Send)
						Readydata := Encapsulate_VSSReady(p.Proof, "SHARE", v_l_Send, witnessInterpolated[l+1], p.N, p.F)
						p.Send(&protobuf.Message{Type: "VSSReady", Id: ID, Sender: p.PID, Data: Readydata}, uint32(l))
					}
					fmt.Printf("Collected t+1 VSSReady message, VSSReady sent, PID: %v, ReadyType: SHARE\n", p.PID)

					PiChecked = true
					PiCheckedChannel <- true
					fmt.Printf("Party %v Pichecked by t+1 VSSReady messages\n", p.PID)

				} else {
					p.Proof.Set(pi_from_Ready, p.F)

					mutexCW.Lock()
					//reset CRl
					for j := uint32(1); j < 2*p.F+2; j++ {
						C_R[j].SetCompressedBytes(payloadMessage.Pi.PiContents[j].CRJ)
					}

					//reset witnesses
					for i := uint32(0); i < p.N+1; i++ {
						witnessInterpolated[i] = KZG.NewG1()
					}

					//discard the full share B*(i,y) interpolated from VSSSend message
					fullShare_from_Send.ResetTo(polyring.NewEmpty())

					mutexCW.Unlock()

					//send Ready-NOSHARE
					Readydata := Encapsulate_VSSReady(p.Proof, "NOSHARE", nil, nil, p.N, p.F)
					p.Broadcast(&protobuf.Message{Type: "VSSReady", Id: ID, Sender: p.PID, Data: Readydata})
					fmt.Printf("Collected t+1 VSSReady message, VSSReady sent, PID: %v, ReadyType: NOSHARE\n", p.PID)

					PiChecked = true
					PiCheckedChannel <- true
					fmt.Printf("Party %v Pichecked by t+1 VSSReady messages\n", p.PID)

				}
			} else {
				mutex_ReadyMap.RUnlock()

			}
			mutexPi.Unlock()

			mutex_ReadyMap.RLock()
			mutex_ReadyContent.Lock()
			//send Distribute Message
			if !DistSent && uint32(ReadyMap[pi_hash_str]) >= p.N-p.F && uint32(len(ReadyContent[pi_hash_str])) >= p.F+1 {
				fmt.Printf("Party %v has collected n-t=%v Ready messages, and there are %v >= t+1 valid contents\n", p.PID, ReadyMap[pi_hash_str], len(ReadyContent[pi_hash_str]))
				// StartDist_str <- pi_hash_str
				var witnessFromReady []*pbc.Element = make([]*pbc.Element, p.F+1)
				var reducedShare_x []*gmp.Int = make([]*gmp.Int, p.F+1)
				var reducedShare_y []*gmp.Int = make([]*gmp.Int, p.F+1)
				for k := 0; uint32(k) < p.F+1; k++ {
					reducedShare_x[k] = gmp.NewInt(0)
					reducedShare_x[k].Set(gmp.NewInt(int64(ReadyContent[pi_hash_str][k].X)))
					reducedShare_y[k] = gmp.NewInt(0)
					reducedShare_y[k].Set(ReadyContent[pi_hash_str][k].Y)
					witnessFromReady[k] = KZG.NewG1()
					witnessFromReady[k].Set(ReadyContent[pi_hash_str][k].PolyWit)
				}
				reducedShare, err := interpolation.LagrangeInterpolate(int(p.F), reducedShare_x, reducedShare_y, ecparamN)
				if err != nil {
					fmt.Printf("Party %v incurrs an error when interpolates B(x,i): %v\n", p.PID, err)
				} else {
					fmt.Printf("Party %v has reconstructed reducedShare B(x,i) from t+1 Ready messages:\n", p.PID)
				}
				reducedShare.Print()

				//send VSSDistribute
				for l := uint32(0); l < p.N; l++ {
					polyValue_dist := gmp.NewInt(0)
					reducedShare.EvalMod(gmp.NewInt(int64(l+1)), ecparamN, polyValue_dist)
					witness_dist := KZG.NewG1()
					KZG.CreateWitness(witness_dist, reducedShare, gmp.NewInt(int64(l+1)))
					data_dist := Encapsulate_VSSDistribute(polyValue_dist, witness_dist, p.N, p.F)
					p.Send(&protobuf.Message{
						Type:   "VSSDistribute",
						Id:     ID,
						Sender: p.PID,
						Data:   data_dist,
					}, l)
				}
				// fmt.Printf("Party %v has sent VSSDistribute message\n", p.PID)
				DistSent = true

			}
			mutex_ReadyContent.Unlock()
			mutex_ReadyMap.RUnlock()

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

		for {
			msg := <-p.GetMessage("VSSDistribute", ID)
			var payloadMessage protobuf.VSSDistribute
			proto.Unmarshal(msg.Data, &payloadMessage)
			fmt.Printf("Party %v has received VSSDistribute from %v \n", p.PID, msg.Sender)

			valueFromDist := gmp.NewInt(0)
			valueFromDist.SetBytes(payloadMessage.BLi)
			witnessFromDist := KZG.NewG1()
			witnessFromDist.SetCompressedBytes(payloadMessage.WBLi)

			mutexCW.Lock()
			//interpolate the required CR
			C := KZG.NewG1()
			if msg.Sender < 2*p.F+1 {
				C = C_R[msg.Sender+1]
			} else {
				C = InterpolateComOrWit(2*p.F, msg.Sender+1, C_R[1:2*p.F+2])
			}
			distVerifyOK := KZG.VerifyEval(C, gmp.NewInt(int64(p.PID+1)), valueFromDist, witnessFromDist)
			if distVerifyOK {
				fmt.Printf("Party %v verifies Distribute message from %v, ok\n", p.PID, msg.Sender)
				S_full_polyValue = append(S_full_polyValue, valueFromDist)
				S_full_indexes = append(S_full_indexes, gmp.NewInt(int64(msg.Sender+1)))
				length := len(S_full_polyValue)
				p.witness_init[length-1].Set(witnessFromDist)
				p.witness_init_indexes[length-1].Set(gmp.NewInt(int64(msg.Sender + 1))) //change this name later.
			} else {
				fmt.Printf("Party %v verifies Distribute message from %v, FAIL, C_R[%v]=%v, valueFromDist=%v, witnessFromDist=%v\n", p.PID, msg.Sender, msg.Sender+1, C_R[msg.Sender+1], valueFromDist, witnessFromDist)
			}
			mutexCW.Unlock()

			if uint32(len(S_full_polyValue)) >= 2*p.F+1 && !fullShareInterpolated {
				// fmt.Println(p.PID, "starts to interpolate")
				fullShare, err := interpolation.LagrangeInterpolate(int(2*p.F), S_full_indexes, S_full_polyValue, ecparamN)
				if err != nil {
					fmt.Printf("Party %v interpolation error: %v\n", p.PID, err)
					// continue
				} else {
					//set the final reduceShare and witnesses, then break
					p.fullShare.ResetTo(fullShare)
					fmt.Printf("Party %v gets its full share B(i,y):\n", p.PID)
					p.fullShare.Print()
					fullShareInterpolated = true
					VSSshareFinished <- true
					break
				}
			}
		}
	}()

	<-VSSshareFinished
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

	polyring.GetLagrangeCoefficients(int(2*p.F), knownIndexes, ecparamN, gmp.NewInt(0), lambda)
	tmp := KZG.NewG1()
	tmp.Set0()
	for j := uint32(1); j < 2*p.F+2; j++ {
		tmp2 := KZG.NewG1()
		// tmp2.Set1()
		tmp2.MulBig(pi_received.Pi_contents[j].g_Fj, conv.GmpInt2BigInt(lambda[j-1])) // the x value of index j-1 is j
		// tmp2.PowBig(p.Proof.Pi_contents[j].g_Fj, conv.GmpInt2BigInt(lambda[j-1])) // the x value of index j-1 is j
		tmp.ThenAdd(tmp2)
		// tmp.ThenMul(tmp2)
	}
	if !tmp.Equals(pi_received.G_s) {
		fmt.Printf("Party %v VSSSend Verify Failed, g_s=%v, but prod(g^F(j))=%v \n", p.PID, pi_received.G_s.String(), tmp.String())
		return false
	}
	//Verify KZG.VerifyEval(CZjk,0,0,WZjk0) == 1 && CRjk == CZjk * g^Fj(k) for k in [1,2t+1]
	for k := uint32(1); k < 2*p.F+2; k++ {
		verifyEval := KZG.VerifyEval(pi_received.Pi_contents[k].CZ_j, gmp.NewInt(0), gmp.NewInt(0), pi_received.Pi_contents[k].WZ_0)

		var verifyRj bool
		tmp3 := KZG.NewG1()
		tmp3.Set0()
		tmp3.Add(pi_received.Pi_contents[k].CZ_j, pi_received.Pi_contents[k].g_Fj)
		verifyRj = tmp3.Equals(pi_received.Pi_contents[k].CR_j)
		if !verifyEval || !verifyRj {
			fmt.Printf("Party %v VSSSend Verify Failed at k=%v\n", p.PID, k)
			return false
		}
	}

	//Verify v'ji,w'ji w.r.t pi'
	for j := uint32(1); j < 2*p.F+2; j++ {
		//KZG Verify
		verifyPoint := KZG.VerifyEval(pi_received.Pi_contents[j].CR_j, gmp.NewInt(int64((p.PID + 1))), polyValue[j], witness[j])
		if !verifyPoint {
			fmt.Printf("Party %v VSSSend KZGVerify Failed when verify v'ji and w'ji, i=%v, CR_j[%v]=%v, polyValue[%v]=%v, witness[%v]=%v\n", p.PID, p.PID+1, j, pi_received.Pi_contents[j].CR_j, j, polyValue[j], j, witness[j])
			return false
		}
	}

	return true
}
