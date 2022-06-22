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
	var mutex_pi sync.Mutex
	var PiChecked bool = false
	var PiCheckedChannel chan bool = make(chan bool, 1)
	var InitDoneChannel chan bool = make(chan bool, 1)
	var InitDoneChannel2 chan bool = make(chan bool, 1)
	var InitDoneChannel3 chan bool = make(chan bool, 1)
	var HandleSendDoneChannel chan bool = make(chan bool, 1)
	var StartDist chan bool = make(chan bool, 1)
	var VSSshareFinished chan bool = make(chan bool, 1) // indicate the whole process finishes.

	var C_R = make([]*pbc.Element, p.N+1, p.N+1) //C_R_l for l=1...n
	for i := uint32(0); i <= p.N; i++ {
		C_R[i] = KZG.NewG1()
	}

	var C_R_temp = make([]*pbc.Element, p.N+1, p.N+1) //l=1...n
	for i := uint32(0); i <= p.N; i++ {
		C_R_temp[i] = KZG.NewG1()
	}

	fullShare_from_Send := polyring.NewEmpty() //B*(i,y)
	S_full_indexes := make([]*gmp.Int, 0, p.N) // init as empty set
	S_full_polyValue := make([]*gmp.Int, 0, p.N)

	witnessReceivedinSend := make([]*pbc.Element, 2*p.F+2, p.N+1)
	polyValueReceivedinSend := make([]*gmp.Int, 2*p.F+2, p.N+1)
	for i := uint32(0); i <= 2*p.F+1; i++ {
		witnessReceivedinSend[i] = KZG.NewG1()
		polyValueReceivedinSend[i] = gmp.NewInt(0)
	}
	witnessInterpolated := make([]*pbc.Element, p.N+1, p.N+1)
	for i := uint32(0); i <= p.N; i++ {
		witnessInterpolated[i] = KZG.NewG1()
	}
	InitDoneChannel <- true
	InitDoneChannel2 <- true
	InitDoneChannel3 <- true

	// go p.handleVSSSend()

	//handle VSSSend Message
	go func() {
		<-InitDoneChannel
		var verifyOK = false
		// for {
		m := <-p.GetMessage("VSSSend", ID)
		// fmt.Println("Party ", p.PID, " receive VSSSend Message")
		var payloadMessage protobuf.VSSSend
		proto.Unmarshal(m.Data, &payloadMessage)

		mutex_pi.Lock()
		// there are cases when a party receives ECHO or Ready messages bedore receive Send message
		if !PiChecked {
			p.Proof.SetFromVSSMessage(payloadMessage.Pi, p.F)
			// start from j=1
			for j := uint32(1); j <= 2*p.F+1; j++ {
				witnessReceivedinSend[j].SetCompressedBytes(payloadMessage.WRjiList[j])
				polyValueReceivedinSend[j].SetBytes(payloadMessage.RjiList[j])
			}
			verifyOK = p.VerifyVSSSendReceived(polyValueReceivedinSend, witnessReceivedinSend)
			if !verifyOK {
				fmt.Printf("Party %v verifies VSSSend Failed\n", p.PID)
				//revert
				p.Proof.Init(p.F)
				mutex_pi.Unlock()
			} else {
				//interpolate C_R[j] and w_B*(i,j), witness is interpolated, rather than computed from full shares
				for j := uint32(1); j <= 2*p.F+1; j++ {
					C_R[j].Set(p.Proof.Pi_contents[j].CR_j)
					// witnessInterpolated[j].Set(witnessReceivedinSend[j])
					witnessInterpolated[j].SetCompressedBytes(payloadMessage.WRjiList[j])
				}
				//interpolate the remaining C_R[j] and w_B*(i,j)
				for j := 2*p.F + 2; j <= p.N; j++ {
					C_R[j] = InterpolateComOrWit(2*p.F, j, C_R[1:2*p.F+2])
					witnessInterpolated[j] = InterpolateComOrWit(2*p.F, j, witnessInterpolated[1:2*p.F+2])
				}

				//interpolate 2t-degree polynomial B*(i,y)
				x := make([]*gmp.Int, 2*p.F+1) //start from 0
				y := make([]*gmp.Int, 2*p.F+1)
				for j := uint32(0); j < 2*p.F+1; j++ {
					x[j] = gmp.NewInt(0)
					x[j].Set(gmp.NewInt(int64(j + 1)))
					y[j] = gmp.NewInt(0)
					y[j].Set(polyValueReceivedinSend[j+1])
				}
				tmp_poly, _ := interpolation.LagrangeInterpolate(int(2*p.F), x, y, ecparamN)
				fullShare_from_Send.ResetTo(tmp_poly)
				fmt.Printf("Party %v interpolate B*(i,x) polynomial when receive Send Message:\n", p.PID)
				fullShare_from_Send.Print()
				HandleSendDoneChannel <- true

				//sendEcho
				EchoData := Encapsulate_VSSEcho(p.Proof, p.N, p.F)
				EchoMessage := &protobuf.Message{
					Type:   "VSSEcho",
					Id:     ID,
					Sender: p.PID,
					Data:   EchoData,
				}
				p.Broadcast(EchoMessage)
				// fmt.Printf("Party %v broadcasts Echo Message\n", p.PID)
				mutex_pi.Unlock()
			}

			// break
		}
		// }
	}()

	var ReadySent bool = false
	var mutex_ReadySent sync.Mutex

	var EchoMap = make(map[string]int)
	var ReadyMap = make(map[string]int)
	var mutex_EchoMap sync.Mutex
	var mutex_ReadyMap sync.Mutex

	var ReadyContent = make(map[string][]polypoint.PolyPoint)
	var mutex_ReadyContent sync.Mutex

	//handle VSSEcho Message
	go func() {
		<-InitDoneChannel2
		for {
			//FIXME: break the infinite loop
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

			mutex_EchoMap.Lock()
			counter, ok := EchoMap[pi_hash_str]
			if ok {
				EchoMap[pi_hash_str] = counter + 1
			} else {
				EchoMap[pi_hash_str] = 1
			}

			if uint32(EchoMap[pi_hash_str]) >= p.N-p.F {
				mutex_ReadySent.Lock()
				if !ReadySent {
					mutex_pi.Lock()
					if p.Proof.Equals(pi_from_Echo, p.F) {
						//in this case (pi = pi'), this party must have received a valid VSSSend message
						//wait for the related interpolations done
						<-HandleSendDoneChannel
						for l := uint32(0); l < p.N; l++ {
							v_l := gmp.NewInt(0) //value at l+1
							fullShare_from_Send.EvalMod(gmp.NewInt(int64(l+1)), ecparamN, v_l)
							Readydata := Encapsulate_VSSReady(p.Proof, "SHARE", v_l, witnessInterpolated[l+1], p.N, p.F)
							p.Send(&protobuf.Message{Type: "VSSReady", Id: ID, Sender: p.PID, Data: Readydata}, l)
						}
						// fmt.Printf("Collected n-t=%v VSSEcho messages, VSSReady sent, PID: %v, ReadyType: SHARE\n", EchoMap[pi_hash_str], p.PID)
						ReadySent = true
						PiChecked = true
						PiCheckedChannel <- true
						mutex_ReadySent.Unlock()
						// break
					} else {
						fmt.Println("Party", p.PID, "resets")
						p.Proof.Set(pi_from_Echo, p.F)
						//discard full share
						fullShare_from_Send.ResetTo(polyring.NewEmpty())
						//reset CRl
						for l := 0; uint32(l) <= p.N; l++ {
							C_R[l] = KZG.NewG1()
						}
						Readydata := Encapsulate_VSSReady(p.Proof, "NOSHARE", nil, nil, p.N, p.F)
						p.Broadcast(&protobuf.Message{Type: "VSSReady", Id: ID, Sender: p.PID, Data: Readydata})
						// fmt.Printf("Collected n-t=%v VSSEcho message, VSSReady sent, PID: %v, ReadyType: NOSHARE\n", EchoMap[pi_hash_str], p.PID)
						ReadySent = true
						PiChecked = true
						PiCheckedChannel <- true
						mutex_ReadySent.Unlock()
						// break
					}
					mutex_pi.Unlock()
				} else {
					mutex_ReadySent.Unlock()
					break
				}
			}
			mutex_EchoMap.Unlock()
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
			// fmt.Printf("Party %v has received VSSReady from %v, ReadyType: %v\n", p.PID, m.Sender, payloadMessage.ReadyType)
			pi_from_Ready.SetFromVSSMessage(payloadMessage.Pi, p.F)
			pi_hash := sha256.New()
			pi_byte, _ := proto.Marshal(payloadMessage.Pi)
			pi_hash.Write(pi_byte)
			pi_hash_str := string(pi_hash.Sum(nil))
			mSender := m.Sender  //senderID
			v_l := gmp.NewInt(0) //l = senderID + 1
			w_l := KZG.NewG1()

			if payloadMessage.ReadyType == "SHARE" {
				//verify READY-SHARE messages
				v_l.SetBytes(payloadMessage.BIl)
				w_l.SetCompressedBytes(payloadMessage.WBIl)
				//start from 1
				for j := uint32(1); j <= 2*p.F+1; j++ {
					C_R_temp[j].Set(pi_from_Ready.Pi_contents[j].CR_j)
				}

				//P_s sends {VSSReady, B*(s,r)} to P_r, so P_r interpolates C_B(x,r) to verify the evaluation at x=s
				C := KZG.NewG1()
				if p.PID <= 2*p.F+1 {
					C = C_R_temp[p.PID+1]
				} else {
					C = InterpolateComOrWit(2*p.F, p.PID+1, C_R_temp[1:2*p.F+2])
				}
				// fmt.Printf("Verifying, C:%s, mSender+1: %v, v_l: %s, w_l: %s\n", C.String(), mSender+1, v_l.String(), w_l.String())
				verified := KZG.VerifyEval(C, gmp.NewInt(int64(mSender+1)), v_l, w_l)

				if verified {
					//count++
					// fmt.Printf("Party %v verified: %v, sender: %v\n", p.PID, verified, mSender)
					mutex_ReadyMap.Lock()
					_, ok := ReadyMap[pi_hash_str]
					if ok {
						ReadyMap[pi_hash_str] = ReadyMap[pi_hash_str] + 1
					} else {
						ReadyMap[pi_hash_str] = 1
					}
					// fmt.Printf("ReadyMap[pi_hash_str]: %v, PID: %v\n", ReadyMap[pi_hash_str], p.PID)
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
						mutex_ReadyContent.Unlock()
					} else {
						ReadyContent[pi_hash_str] = make([]polypoint.PolyPoint, 0)
						ReadyContent[pi_hash_str] = append(ReadyContent[pi_hash_str], polypoint.PolyPoint{
							X:       int32(mSender + 1),
							Y:       v_l,
							PolyWit: w_l,
						})
						mutex_ReadyContent.Unlock()
					}
				} else {
					fmt.Printf("Party %v not verified: %v, sender: %v\n", p.PID, verified, mSender)
				}
			}

			if payloadMessage.ReadyType == "NOSHARE" {
				mutex_ReadyMap.Lock()
				_, ok := ReadyMap[pi_hash_str]
				if ok {
					ReadyMap[pi_hash_str] = ReadyMap[pi_hash_str] + 1
				} else {
					ReadyMap[pi_hash_str] = 1
				}
				mutex_ReadyMap.Unlock()
			}

			//send Ready Message
			mutex_ReadyMap.Lock()
			if uint32(ReadyMap[pi_hash_str]) >= p.F+1 {
				// fmt.Printf("Sending Ready message, ReadyMap[pi_hash_str]: %v, PID: %v\n", ReadyMap[pi_hash_str], p.PID)
				mutex_ReadySent.Lock()
				if !ReadySent {
					mutex_pi.Lock()
					if p.Proof.Equals(pi_from_Ready, p.F) {
						// send Ready-SHARE
						for l := uint32(0); l < p.N; l++ {
							v_l_Send := gmp.NewInt(0) //value at l+1
							fullShare_from_Send.EvalMod(gmp.NewInt(int64(l+1)), ecparamN, v_l_Send)
							Readydata := Encapsulate_VSSReady(p.Proof, "SHARE", v_l_Send, witnessInterpolated[l+1], p.N, p.F)
							p.Send(&protobuf.Message{Type: "VSSReady", Id: ID, Sender: p.PID, Data: Readydata}, uint32(l))
						}
						ReadySent = true
						PiChecked = true
						PiCheckedChannel <- true
						// fmt.Printf("Collected t+1 VSSReady message, VSSReady sent, PID: %v, ReadyType: SHARE\n", p.PID)
					} else {
						//send Ready-NOSHARE
						p.Proof.Set(pi_from_Ready, p.F)
						fullShare_from_Send.ResetTo(polyring.NewEmpty())
						for l := 0; uint32(l) <= p.N; l++ {
							C_R[l] = KZG.NewG1()
						}
						Readydata := Encapsulate_VSSReady(p.Proof, "NOSHARE", nil, nil, p.N, p.F)
						p.Broadcast(&protobuf.Message{Type: "VSSReady", Id: ID, Sender: p.PID, Data: Readydata})

						ReadySent = true
						PiChecked = true
						PiCheckedChannel <- true
						// fmt.Printf("Collected t+1 VSSReady message, VSSReady sent, PID: %v, ReadyType: NOSHARE\n", p.PID)
					}
					mutex_pi.Unlock()
				}
				mutex_ReadySent.Unlock()
			}
			if uint32(ReadyMap[pi_hash_str]) >= p.N-p.F {
				// fmt.Printf("Party %v has collected n-t=%v Ready messages\n", p.PID, ReadyMap[pi_hash_str])
				StartDist <- true
			}
			mutex_ReadyMap.Unlock()

			// if ReadySent {
			// 	fmt.Printf("Party %v has sent VSSReady\n", p.PID)
			// 	// break
			// }
		}
	}()

	//send Distribute Message
	go func() {
		var DistSent = false
		<-StartDist
		for {
			mutex_ReadyMap.Lock()
			for pi_hash_str, count := range ReadyMap {
				if uint32(count) >= p.N-p.F {
					// fmt.Printf("Party %v has collected %v Ready messages\n", p.PID, count)
					for {
						mutex_ReadyContent.Lock()
						if uint32(len(ReadyContent[pi_hash_str])) >= p.F+1 {
							// fmt.Println("Party", p.PID, "starts to interpolate reduced share B(x,i)")
							//interpolate B(x,i)
							var witnessReceivedinReady []*pbc.Element = make([]*pbc.Element, p.F+1)
							var reducedShare_x []*gmp.Int = make([]*gmp.Int, p.F+1)
							var reducedShare_y []*gmp.Int = make([]*gmp.Int, p.F+1)
							for k := 0; uint32(k) < p.F+1; k++ {
								reducedShare_x[k] = gmp.NewInt(0)
								reducedShare_x[k].Set(gmp.NewInt(int64(ReadyContent[pi_hash_str][k].X)))
								reducedShare_y[k] = gmp.NewInt(0)
								reducedShare_y[k].Set(ReadyContent[pi_hash_str][k].Y)
								witnessReceivedinReady[k] = KZG.NewG1()
								witnessReceivedinReady[k].Set(ReadyContent[pi_hash_str][k].PolyWit)
							}
							mutex_ReadyContent.Unlock()

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
							DistSent = true
							// fmt.Printf("Party %v has sent VSSDistribute message, breaking the inner loop\n", p.PID)
							break //break the inner for loop
						} else {
							mutex_ReadyContent.Unlock()
						}
					}
					if DistSent {
						// fmt.Printf("Party %v has sent VSSDistribute message, breaking the for-range loop\n", p.PID)
						break //break the for-range loop
					}
				}
			}
			mutex_ReadyMap.Unlock()
			if DistSent {
				fmt.Println("Party", p.PID, "Distribute breaks now")
				break
			}
			// time.Sleep(1000)
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
			// fmt.Printf("Party %v has received VSSDistribute from %v \n", p.PID, msg.Sender)

			valueReceivedinDist := gmp.NewInt(0)
			valueReceivedinDist.SetBytes(payloadMessage.BLi)
			witnessReceivedinDist := KZG.NewG1()
			witnessReceivedinDist.SetCompressedBytes(payloadMessage.WBLi)

			if KZG.VerifyEval(C_R[msg.Sender+1], gmp.NewInt(int64(p.PID+1)), valueReceivedinDist, witnessReceivedinDist) {
				// fmt.Printf("Party %v verifies Distribute message from %v, ok\n", p.PID, msg.Sender)
				S_full_polyValue = append(S_full_polyValue, valueReceivedinDist)
				S_full_indexes = append(S_full_indexes, gmp.NewInt(int64(msg.Sender+1)))
				length := len(S_full_polyValue)
				p.witness_init[length-1].Set(witnessReceivedinDist)
				p.witness_init_indexes[length-1].Set(gmp.NewInt(int64(msg.Sender + 1))) //change this name later.
			} else {
				fmt.Printf("Party %v verifies Distribute message from %v, FAIL\n", p.PID, msg.Sender)
			}

			if uint32(len(S_full_polyValue)) == 2*p.F+1 && !fullShareInterpolated {
				// fmt.Println(p.PID, "starts to interpolate")
				fullShare, err := interpolation.LagrangeInterpolate(int(2*p.F), S_full_indexes, S_full_polyValue, ecparamN)
				if err != nil {
					fmt.Printf("Party %v interpolation error: %v\n", p.PID, err)
					continue
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
	// return
}

// func (p *HonestParty) handleVSSSend(ID []byte) {

// }

//Verify pi' and v'ji ,w'ji received
func (p *HonestParty) VerifyVSSSendReceived(polyValue []*gmp.Int, witness []*pbc.Element) bool {
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
	for j := 1; uint32(j) <= 2*p.F+1; j++ {
		tmp2 := KZG.NewG1()
		// tmp2.Set1()
		tmp2.MulBig(p.Proof.Pi_contents[j].g_Fj, conv.GmpInt2BigInt(lambda[j-1])) // the x value of index j-1 is j
		// tmp2.PowBig(p.Proof.Pi_contents[j].g_Fj, conv.GmpInt2BigInt(lambda[j-1])) // the x value of index j-1 is j
		tmp.ThenAdd(tmp2)
		// tmp.ThenMul(tmp2)
	}
	if !tmp.Equals(p.Proof.G_s) {
		fmt.Printf("Party %v VSSSend Verify Failed, g_s=%v, but prod(g^F(j))=%v \n", p.PID, p.Proof.G_s.String(), tmp.String())
		return false
	}
	//Verify KZG.VerifyEval(CZjk,0,0,WZjk0) == 1 && CRjk == CZjk * g^Fj(k) for k in [1,2t+1]
	for k := 1; uint32(k) <= 2*p.F+1; k++ {
		verifyEval := KZG.VerifyEval(p.Proof.Pi_contents[k].CZ_j, gmp.NewInt(0), gmp.NewInt(0), p.Proof.Pi_contents[k].WZ_0)

		var verifyRj bool
		tmp3 := KZG.NewG1()
		tmp3.Set0()
		tmp3.Add(p.Proof.Pi_contents[k].CZ_j, p.Proof.Pi_contents[k].g_Fj)
		verifyRj = tmp3.Equals(p.Proof.Pi_contents[k].CR_j)
		if !verifyEval || !verifyRj {
			fmt.Printf("Party %v VSSSend Verify Failed at k=%v\n", p.PID, k)
			return false
		}
	}

	//Verify v'ji,w'ji w.r.t pi'
	for j := 1; uint32(j) <= 2*p.F+1; j++ {
		//KZG Verify
		verifyPoint := KZG.VerifyEval(p.Proof.Pi_contents[j].CR_j, gmp.NewInt(int64((p.PID + 1))), polyValue[j], witness[j])
		if !verifyPoint {
			fmt.Printf("Party %v VSSSend Verify Failed when verify v'ji and w'ji, j = %v, i=%v", p.PID, j, p.PID+1)
			return false
		}
	}

	return true
}
