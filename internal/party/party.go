package party

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"time"

	"github.com/Nik-U/pbc"
	"github.com/golang/protobuf/proto"
	"github.com/ncw/gmp"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/tbls"

	"github.com/DyCAPSTeam/DyCAPS/internal/conv"
	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/interpolation"
	"github.com/DyCAPSTeam/DyCAPS/internal/polypoint"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
)

//Party is a interface of committee members
type Party interface {
	send(m *protobuf.Message, des uint32) error
	broadcast(m *protobuf.Message) error
	getMessageWithType(messageType string) (*protobuf.Message, error)
}

//HonestParty is a struct of honest committee members
type HonestParty struct {
	N            uint32   // committee size
	F            uint32   // number of corrupted parties
	PID          uint32   // id of this party
	ipList       []string // ip list of the current committee
	portList     []string // port list of the current committee
	sendChannels []chan *protobuf.Message

	ipList_next        []string // ip list of the new committee
	portList_next      []string // port list of the new committee
	sendtoNextChannels []chan *protobuf.Message

	dispatcheChannels *sync.Map

	SigPK *share.PubPoly  //tss pk
	SigSK *share.PriShare //tss sk

	Proof *Pi //pi

	fullShare polyring.Polynomial // B(p.PID+1,y)
	halfShare polyring.Polynomial // B(x,p.PID+1)

	witness_init         []*pbc.Element
	witness_init_indexes []*gmp.Int //TODO: change this name later. witness_init_indexes[j] means the witness of Rj+1(p.PID+1)
}

// set of elements for recover
type S_rec_Element struct {
	j int
	v *gmp.Int
}

// set of signatures
type S_sig_Element struct {
	j   int
	Sig []byte
}

// set of commitments
type S_com_Element struct {
	j  int
	CB *pbc.Element
}

// set of elements for full shares
type S_B_Element struct {
	j  int
	CB *pbc.Element
	v  *gmp.Int
	w  *pbc.Element
}

//NewHonestParty return a new honest party object
//FIXME: witness_init may bring the problem of null pointers.
func NewHonestParty(N uint32, F uint32, pid uint32, ipList []string, portList []string, ipList_next []string, portList_next []string, sigPK *share.PubPoly, sigSK *share.PriShare, Proof *Pi, witness []*pbc.Element, witness_indexes []*gmp.Int) *HonestParty {
	p := HonestParty{
		N:                  N,
		F:                  F,
		PID:                pid,
		ipList:             ipList,
		portList:           portList,
		ipList_next:        ipList_next,
		portList_next:      portList_next,
		sendChannels:       make([]chan *protobuf.Message, N),
		sendtoNextChannels: make([]chan *protobuf.Message, N),

		SigPK: sigPK,
		SigSK: sigSK,

		Proof: Proof,

		fullShare:            polyring.NewEmpty(),
		halfShare:            polyring.NewEmpty(),
		witness_init:         witness,
		witness_init_indexes: witness_indexes,
	}
	return &p
}

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
	//FIXME: this verification sometimes fails
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

func (p *HonestParty) ShareReduceSend(ID []byte) {
	ecparamN := ecparam.PBC256.Ngmp
	//interpolate  N commitments by p.Proof
	var CB_temp = make([]*pbc.Element, p.N+1) //start from 1
	var WB_temp = make([]*pbc.Element, p.N+1) //start from 1
	for i := 0; uint32(i) <= p.N; i++ {
		CB_temp[i] = KZG.NewG1()
		WB_temp[i] = KZG.NewG1()
	}
	C_R_known := make([]*pbc.Element, 2*p.F+2)
	for j := uint32(0); j <= 2*p.F+1; j++ {
		C_R_known[j] = KZG.NewG1()
		C_R_known[j].Set(p.Proof.Pi_contents[j].CR_j)
	}
	// for j := uint32(1); j <= p.N; j++ {
	for j := 2*p.F + 1; j <= p.N; j++ {
		CB_temp[j] = InterpolateComOrWit(2*p.F, j, C_R_known[1:])
		WB_temp[j] = InterpolateComOrWitbyKnownIndexes(2*p.F, j, p.witness_init_indexes, p.witness_init)
	}
	for j := 0; uint32(j) < p.N; j++ {
		polyValue := gmp.NewInt(0)
		p.fullShare.EvalMod(gmp.NewInt(int64(j+1)), ecparamN, polyValue)
		ShareReduceMessage := protobuf.ShareReduce{
			C: CB_temp[j+1].CompressedBytes(),
			V: polyValue.Bytes(),
			W: WB_temp[j+1].CompressedBytes(),
		}
		data, _ := proto.Marshal(&ShareReduceMessage)
		p.SendtoNext(&protobuf.Message{
			Type:   "ShareReduce",
			Id:     ID,
			Sender: p.PID,
			Data:   data,
		}, uint32(j))
	}
}

func (p *HonestParty) ShareReduceReceiver(ID []byte) {
	ecparamN := ecparam.PBC256.Ngmp
	var ShareReduce_wg sync.WaitGroup
	var ShareReduce_map = make(map[string][]polypoint.PolyPoint)
	var ShareReduce_C_count = make(map[string]uint32)
	var mutex_ShareReduceMap sync.Mutex
	var Most_Counted_C string

	var v_j *gmp.Int
	var C, w_j *pbc.Element
	var deg = 0
	var poly_x, poly_y []*gmp.Int
	v_j = gmp.NewInt(0)
	C = KZG.NewG1()
	w_j = KZG.NewG1()

	ShareReduce_wg.Add(1)
	go func() {
		for {
			m := <-p.GetMessage("ShareReduce", ID)
			fmt.Println(p.PID, " receive ShareReduce Message from ", m.Sender)
			var ShareReduceData protobuf.ShareReduce
			proto.Unmarshal(m.Data, &ShareReduceData)
			C.SetCompressedBytes(ShareReduceData.C)
			w_j.SetCompressedBytes(ShareReduceData.W)
			v_j.SetBytes(ShareReduceData.V)
			mutex_ShareReduceMap.Lock()
			//fmt.Println("Party", p.PID, KZG.VerifyEval(C, gmp.NewInt(int64(m.Sender+1)), v_j, w_j))
			//if KZG.VerifyEval(C, gmp.NewInt(int64(m.Sender+1)), v_j, w_j) {
			//TODO:Add KZG verification here
			_, ok2 := ShareReduce_map[string(ShareReduceData.C)]
			if ok2 {
				ShareReduce_map[string(ShareReduceData.C)] = append(ShareReduce_map[string(ShareReduceData.C)], polypoint.PolyPoint{
					X:       0,
					Y:       gmp.NewInt(0),
					PolyWit: KZG.NewG1(),
				})
				count := ShareReduce_C_count[string(ShareReduceData.C)]
				//fmt.Println(count)
				ShareReduce_map[string(ShareReduceData.C)][count].X = int32(m.Sender + 1)
				ShareReduce_map[string(ShareReduceData.C)][count].Y.Set(v_j)
				ShareReduce_map[string(ShareReduceData.C)][count].PolyWit.Set(w_j)
				ShareReduce_C_count[string(ShareReduceData.C)] += 1
			} else {
				ShareReduce_map[string(ShareReduceData.C)] = make([]polypoint.PolyPoint, 0)
				ShareReduce_map[string(ShareReduceData.C)] = append(ShareReduce_map[string(ShareReduceData.C)], polypoint.PolyPoint{
					X:       0,
					Y:       gmp.NewInt(0),
					PolyWit: KZG.NewG1(),
				})
				ShareReduce_map[string(ShareReduceData.C)][0].X = int32(m.Sender + 1)
				ShareReduce_map[string(ShareReduceData.C)][0].Y.Set(v_j)
				ShareReduce_map[string(ShareReduceData.C)][0].PolyWit.Set(w_j)
				ShareReduce_C_count[string(ShareReduceData.C)] = 1
			}
			//}
			if uint32(ShareReduce_C_count[string(ShareReduceData.C)]) >= p.F+1 {
				Most_Counted_C = string(ShareReduceData.C)
				ShareReduce_wg.Done()
				mutex_ShareReduceMap.Unlock()
				return
			}
			mutex_ShareReduceMap.Unlock()
		}
	}()
	ShareReduce_wg.Wait()
	mutex_ShareReduceMap.Lock()
	poly_x = make([]*gmp.Int, p.F+1)
	poly_y = make([]*gmp.Int, p.F+1)
	for i := uint32(0); i <= p.F; i++ {

		poly_x[deg] = gmp.NewInt(0)
		poly_x[deg].Set(gmp.NewInt(int64(ShareReduce_map[Most_Counted_C][i].X)))
		poly_y[deg] = gmp.NewInt(0)
		poly_y[deg].Set(ShareReduce_map[Most_Counted_C][i].Y)
		deg++
	}
	//fmt.Println(poly_x)
	//fmt.Println(poly_y)
	mutex_ShareReduceMap.Unlock()
	p.halfShare, _ = interpolation.LagrangeInterpolate(int(p.F), poly_x, poly_y, ecparamN)
	fmt.Println("Party ", p.PID, " recover its halfShare:")
	p.halfShare.Print()
}

//TODO:find out why the secret after the Proactivize phase is not correct.
func (p *HonestParty) ProactivizeAndShareDist(ID []byte) {

	// Init
	ecparamN := ecparam.PBC256.Ngmp
	var flg_C = make([]uint32, p.N+1)
	var flg_Rec = make([]uint32, p.N+1)
	var sig []Pi_Content = make([]Pi_Content, 0)

	for i := 0; i <= int(p.N); i++ {
		flg_C[i] = 0
		flg_Rec[i] = 0
	}
	var rnd = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	var poly_F, _ = polyring.NewRand(int(2*p.F), rnd, ecparamN)
	poly_F.SetCoefficientBig(0, gmp.NewInt(0))
	//fmt.Println("Party ", p.PID, " generate poly_F:")
	//poly_F.Print()
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
		//fmt.Println("Party ", p.PID, " generate R", p.PID+1, j, "(x)")
		//R[p.PID+1][j].Print()
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
		//fmt.Println("Party ", p.PID, " commit Fj_C:", Fj_C.String())
		Z[j].Sub(R[p.PID+1][j], tmp_poly)
		KZG.Commit(CR[p.PID+1][j], R[p.PID+1][j])
		KZG.Commit(CZ[j], Z[j])
		KZG.CreateWitness(wz[j], Z[j], gmp.NewInt(0))
		// pi_i
		sig = append(sig, Pi_Content{j, KZG.NewG1(), KZG.NewG1(), KZG.NewG1(), KZG.NewG1()})
		sig[j-1].WZ_0.Set(wz[j])
		sig[j-1].CZ_j.Set(CZ[j])
		sig[j-1].CR_j.Set(CR[p.PID+1][j])
		sig[j-1].g_Fj.Set(Fj_C)
	}
	/*
		if p.PID == uint32(3) {
			fmt.Println("In init phase, the C_Rist is:")
			for l := 1; uint32(l) <= 2*p.F+1; l++ {
				fmt.Println("CR", p.PID+1, l, "=", CR[p.PID+1][l])
			}
		}*/
	//flg_C[p.PID+1] = 1 //temp (for debugging)
	//for j := 0; uint32(j) < 2*p.F+1; j++ {
	//	fmt.Println("node ", p.PID, " g_F^j j = ", j, " in sig is:", sig[j].g_Fj)
	//	fmt.Println("node ", p.PID, " j = ", sig[j].j)
	//}
	var Commit_Message = new(protobuf.Commit)
	Commit_Message.Sig = make([]*protobuf.PiContent, 2*p.F+1)
	for j := 0; j < int(2*p.F+1); j++ {
		Commit_Message.Sig[j] = new(protobuf.PiContent)
		Commit_Message.Sig[j].J = int32(sig[j].j)
		Commit_Message.Sig[j].WZ_0 = sig[j].WZ_0.CompressedBytes()
		Commit_Message.Sig[j].CRJ = sig[j].CR_j.CompressedBytes()
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
				var Verify_Flag = KZG.NewG1()
				Verify_Flag = Verify_Flag.Set1()
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
					CR_k.SetCompressedBytes(Received_Data.Sig[k].CRJ)
					CR[m.Sender+1][k+1].Set(CR_k) //added by ch
					CZ_k.SetCompressedBytes(Received_Data.Sig[k].CZJ)
					wz_k.SetCompressedBytes(Received_Data.Sig[k].WZ_0)
					Gj_k.SetCompressedBytes(Received_Data.Sig[k].G_Fj)
					mul_res := KZG.NewG1()
					mul_res.Mul(CZ_k, Gj_k)
					if KZG.VerifyEval(CZ_k, gmp.NewInt(0), gmp.NewInt(0), wz_k) == false || CR_k.Equals(mul_res) == false {
						revert_flag = true
						break
					}
				}
				if revert_flag == true {
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
				/*
					if p.PID == uint32(3) {
						if j == int(p.PID+1) {
							fmt.Println("In verify phase, the C_Rist is:")
							for l := 1; uint32(l) <= 2*p.F+1; l++ {
								fmt.Println("CR", j, l, "=", CR[j][l])
							}
						}
					}*/
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
			/*
				if p.PID == uint32(3) {
					fmt.Println("In Sending phase, the C_Rist before commit is:")
					for l := 1; uint32(l) <= 2*p.F+1; l++ {
						fmt.Println("CR", p.PID+1, l, "=", CR[p.PID+1][l])
					}
				}*/
			/*KZG.Commit(CR[p.PID+1][j], R[p.PID+1][j]) //temp
			if p.PID == uint32(3) {
				fmt.Println("In Sending phase, the C_Rist after commit is:")
				for l := 1; uint32(l) <= 2*p.F+1; l++ {
					fmt.Println("CR", p.PID+1, l, "=", CR[p.PID+1][l])
				}
			}*/
			KZG.CreateWitness(wf[k][j], R[p.PID+1][j], gmp.NewInt(int64(k))) // changed.
			var Fkj = gmp.NewInt(0)
			//Denote Ri,j(k) as [Fi(j)]k
			R[p.PID+1][j].EvalMod(gmp.NewInt(int64(k)), ecparamN, Fkj)
			//if flg_C[p.PID+1] == 1 {
			//fmt.Println("node", p.PID, "j = ", j, "CRij = ", "send to ", k, "CRij = ", CR[p.PID+1][j].String())
			//fmt.Println("node", p.PID, "verfify", j, "send to", k, "result=", KZG.VerifyEval(CR[p.PID+1][j], gmp.NewInt(int64(k)), Fkj, wf[k][j]))
			//}
			F_val[p.PID+1][j][k].Set(Fkj)
			w_F_val[p.PID+1][j][k].Set(wf[k][j])
			reshare_message.Wk[j-1] = wf[k][j].CompressedBytes()
			reshare_message.Fk[j-1] = Fkj.Bytes()
		}

		//fmt.Println("Party", p.PID, "reshare_message.Fk  = ", reshare_message.Fk)
		reshare_data, _ := proto.Marshal(&reshare_message)
		p.Send(&protobuf.Message{Type: "Reshare", Id: ID, Sender: p.PID, Data: reshare_data}, uint32(k-1))
		//fmt.Println("Party", p.PID, "send reshare message to", k-1, "the content is", reshare_message.Wk)
		fmt.Println("Party ", p.PID, "send Reshare message to", k-1, "the content is", reshare_message)
	}
	/*
		if p.PID == uint32(2) {
			fmt.Println("In verify phase, the wf_list is:")
			for i := 1; uint32(i) <= p.N; i++ {
				for j := 1; uint32(j) <= 2*p.F+1; j++ {
					fmt.Println("wf", i, j, "=", wf[i][j].String())
				}
			}
		}*/

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
					Sig[j][int(p.PID+1)], _ = tbls.Sign(Sys_Suite, p.SigSK, []byte((strconv.Itoa(j))))
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
	var S_rec [][]S_rec_Element = make([][]S_rec_Element, p.N+1) // start from 1
	var S_sig [][]S_sig_Element = make([][]S_sig_Element, p.N+1) // start from 1
	for i := 0; i <= int(p.N); i++ {
		S_rec[i] = make([]S_rec_Element, 0)
		S_sig[i] = make([]S_sig_Element, 0)
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
							continue
						}
						var w_k_i_j *pbc.Element
						var v_k_i_j *gmp.Int
						v_k_i_j = gmp.NewInt(0)
						w_k_i_j = KZG.NewG1()
						v_k_i_j.SetBytes(now_Recover_Data.V)
						w_k_i_j.SetCompressedBytes(now_Recover_Data.W)

						Received_Sig := now_Recover_Data.Sig
						//Check_Sig_Hash := sha256.Sum256([]byte(string(j)))
						//fmt.Println(tbls.Verify(Sys_Suite, p.SigPK, []byte(strconv.Itoa(k)), Received_Sig))
						if KZG.VerifyEval(CR[k][p.PID+1], gmp.NewInt(int64(j)), v_k_i_j, w_k_i_j) == false || (tbls.Verify(Sys_Suite, p.SigPK, []byte(strconv.Itoa(k)), Received_Sig) != nil) {
							delete(Recover_Data_Map[k], j) // discard this message
							continue                       // ch change break to continue.
						}
						S_rec[k] = append(S_rec[k], S_rec_Element{j, v_k_i_j})
						if len(S_rec[k]) >= int(p.F+1) && flg_Rec[k] == 0 {
							for t := 0; t < len(S_rec[k]); t++ {
								Interpolate_poly_x[t] = gmp.NewInt(int64(S_rec[k][t].j))
								Interpolate_poly_y[t] = S_rec[k][t].v
							}
							//fmt.Println("Party", p.PID, "get list for interpolation:", Interpolate_poly_x, Interpolate_poly_y)
							R[k][int(p.PID+1)], _ = interpolation.LagrangeInterpolate(int(p.F), Interpolate_poly_x[:p.F+1], Interpolate_poly_y[:p.F+1], ecparamN) //ch add :p.F+1
							//fmt.Println("Party", p.PID, "interpolate R[k][p.PID+1]:")
							//R[k][int(p.PID+1)].Print()
							flg_Rec[k] = 1
						}
						S_sig[k] = append(S_sig[k], S_sig_Element{j, Received_Sig})
						if len(S_sig[k]) >= int(2*p.F+1) && Combined_flag[k] == false {
							var tmp_Sig = make([][]byte, len(S_sig))
							for t := 0; t < len(S_sig[k]); t++ {
								tmp_Sig[t] = S_sig[k][t].Sig
							}
							Combined_Sig[k], _ = tbls.Recover(Sys_Suite, p.SigPK, []byte(strconv.Itoa(k)), tmp_Sig, int(2*p.F), int(p.N))
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
				continue
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
		fmt.Println("Party", p.PID, "previous halfShare:")
		p.halfShare.Print()
		copyed_halfShare := polyring.NewEmpty()
		copyed_halfShare.ResetTo(p.halfShare)
		p.halfShare.Add(Q, copyed_halfShare)
		p.halfShare.Mod(ecparamN)
		fmt.Println("Party ", p.PID, "get its new halfShare:")
		p.halfShare.Print()
		break
	}

	//-------------------------------------ShareDist-------------------------------------
	//Init
	var S_com = make(map[int]S_com_Element)
	var S_B []S_B_Element = make([]S_B_Element, 0)
	var S_com_Mutex sync.Mutex

	//Commit
	var C_B = make([]*pbc.Element, p.N+1)
	for i := 0; i <= int(p.N); i++ {
		C_B[i] = KZG.NewG1()
	}
	KZG.Commit(C_B[p.PID+1], p.halfShare)
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
		p.halfShare.EvalMod(gmp.NewInt(int64(j)), ecparamN, B_i_j)
		KZG.CreateWitness(w_B_i_j, p.halfShare, gmp.NewInt(int64(j)))
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
			S_com[int(m.Sender+1)] = S_com_Element{
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
						S_B = append(S_B, S_B_Element{
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
	<-Success_Sent_chan //added by ch
	go func() {
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
