package party

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/DyCAPSTeam/DyCAPS/internal/conv"
	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/Nik-U/pbc"
	"github.com/ncw/gmp"
	"sync"

	"github.com/DyCAPSTeam/DyCAPS/pkg/core"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"github.com/DyCAPSTeam/DyCAPS/pkg/utils"
	"google.golang.org/protobuf/proto"

	"github.com/klauspost/reedsolomon"
	"go.dedis.ch/kyber/v3/share"
)

//Party is a interface of consensus parties
type Party interface {
	send(m *protobuf.Message, des uint32) error
	broadcast(m *protobuf.Message) error
	getMessageWithType(messageType string) (*protobuf.Message, error)
}

//HonestParty is a struct of honest consensus parties
type HonestParty struct {
	N                 uint32
	F                 uint32
	PID               uint32
	ipList            []string
	portList          []string
	sendChannels      []chan *protobuf.Message
	dispatcheChannels *sync.Map

	SigPK *share.PubPoly  //tss pk
	SigSK *share.PriShare //tss sk

	Proof *Pi //pi in DPSS.Share
}

//NewHonestParty return a new honest party object
func NewHonestParty(N uint32, F uint32, pid uint32, ipList []string, portList []string, sigPK *share.PubPoly, sigSK *share.PriShare, Proof *Pi) *HonestParty {
	p := HonestParty{
		N:            N,
		F:            F,
		PID:          pid,
		ipList:       ipList,
		portList:     portList,
		sendChannels: make([]chan *protobuf.Message, N),

		SigPK: sigPK,
		SigSK: sigSK,

		Proof: Proof,
	}
	return &p
}

//InitReceiveChannel setup the listener and Init the receiveChannel
func (p *HonestParty) InitReceiveChannel() error {
	p.dispatcheChannels = core.MakeDispatcheChannels(core.MakeReceiveChannel(p.portList[p.PID]), p.N)
	return nil
}

//InitSendChannel setup the sender and Init the sendChannel, please run this after initializing all party's receiveChannel
func (p *HonestParty) InitSendChannel() error {
	for i := uint32(0); i < p.N; i++ {
		p.sendChannels[i] = core.MakeSendChannel(p.ipList[i], p.portList[i])
	}
	// fmt.Println(p.sendChannels, "====")
	return nil
}

//Send a message to party des
func (p *HonestParty) Send(m *protobuf.Message, des uint32) error {
	if !p.checkInit() {
		return errors.New("This party hasn't been initialized")
	}
	if des < p.N {
		p.sendChannels[des] <- m
		return nil
	}
	return errors.New("Destination id is too large")
}

//Broadcast a message to all parties
func (p *HonestParty) Broadcast(m *protobuf.Message) error {
	if !p.checkInit() {
		return errors.New("This party hasn't been initialized")
	}
	for i := uint32(0); i < p.N; i++ {
		err := p.Send(m, i)
		if err != nil {
			return err
		}
	}
	return nil
}

//GetMessage Try to get a message according to messageType, ID
func (p *HonestParty) GetMessage(messageType string, ID []byte) chan *protobuf.Message {
	value1, _ := p.dispatcheChannels.LoadOrStore(messageType, new(sync.Map))

	value2, _ := value1.(*sync.Map).LoadOrStore(string(ID), make(chan *protobuf.Message, p.N))

	return value2.(chan *protobuf.Message)
}

func (p *HonestParty) checkInit() bool {
	if p.sendChannels == nil {
		return false
	}
	return true
}

//RBC
func (p *HonestParty) RBCSender(m *protobuf.Message, ID []byte) {
	//encapsulation?
	data, _ := proto.Marshal(m)
	p.Broadcast(&protobuf.Message{Type: "Propose", Sender: p.PID, Id: ID, Data: data})
}

func (p *HonestParty) RBCReceiver(ID []byte) *protobuf.Message {
	//Denote Th, M', h
	h_local := sha256.New()
	var M1 = make([][]byte, p.N) //  M' in RBC paper. Must assign length(or copy will fail)

	//here we ignore P(.)

	//handle "Propose" message
	go func() {
		m := <-p.GetMessage("Propose", ID)
		M_i := m.Data
		fmt.Println(p.PID, " m_initial: ", M_i)
		h_local.Write(M_i)
		RSEncoder, _ := reedsolomon.New(int(p.N-(p.F+1)), int(p.F+1))
		shards, _ := RSEncoder.Split(M_i)
		fmt.Println("shards = ", shards)
		RSEncoder.Encode(shards)
		fmt.Println("encoded shards = ", shards)
		copy(M1, shards) //avoid this: "shards" is released when this go routine end, and M1 becomes nullPointer as a result.
		for j := uint32(0); j < p.N; j++ {
			//encapsulate
			EchoData, _ := proto.Marshal(&protobuf.RBCEcho{Hash: h_local.Sum(nil), M: M1[j]})
			p.Send(&protobuf.Message{Type: "RBCEcho", Sender: p.PID, Id: ID, Data: EchoData}, j)
			fmt.Println(p.PID, " broadcast Echo")
		}
	}()

	var EchoMessageMap = make(map[string]map[string]int) // key value doesn't support []byte, so we transform it into string type.
	var MaxEchoNumber = int(0)

	type m_received struct {
		j  int
		mj []byte
	}
	var T = make(map[string][]m_received)
	var MaxReadyNumber = int(0)
	var MaxReadyHash []byte

	var readyIsSent = false
	var mutex sync.Mutex // sendReadyOK and readyIsSent will be written by two goroutines.
	var mutex_EchoMap sync.Mutex
	var mutex_ReadyMap sync.Mutex

	//handle Echo Message
	go func() {
		for {
			m := <-p.GetMessage("RBCEcho", ID)
			fmt.Println(p.PID, " receive Echo from ", m.Sender)
			var payloadMessage protobuf.RBCEcho
			proto.Unmarshal(m.Data, &payloadMessage)
			mutex_EchoMap.Lock()
			_, ok1 := EchoMessageMap[string(payloadMessage.Hash)]
			//change the EchoMessageMap
			if ok1 {
				counter, ok2 := EchoMessageMap[string(payloadMessage.Hash)][string(payloadMessage.M)]
				if ok2 {
					EchoMessageMap[string(payloadMessage.Hash)][string(payloadMessage.M)] = counter + 1
				} else {
					EchoMessageMap[string(payloadMessage.Hash)][string(payloadMessage.M)] = 1
				}
			} else {
				EchoMessageMap[string(payloadMessage.Hash)] = make(map[string]int)
				EchoMessageMap[string(payloadMessage.Hash)][string(payloadMessage.M)] = 1
			}
			// change MaxEchoNumber
			if EchoMessageMap[string(payloadMessage.Hash)][string(payloadMessage.M)] > MaxEchoNumber {
				MaxEchoNumber = EchoMessageMap[string(payloadMessage.Hash)][string(payloadMessage.M)]
			}
			//send messages
			if uint32(EchoMessageMap[string(payloadMessage.Hash)][string(payloadMessage.M)]) == 2*p.F+1 {
				mutex.Lock()
				if !readyIsSent {
					readyIsSent = true
					ready_data, _ := proto.Marshal(&protobuf.RBCReady{Hash: payloadMessage.Hash, M: payloadMessage.M})
					p.Broadcast(&protobuf.Message{Type: "RBCReady", Sender: p.PID, Id: ID, Data: ready_data})
				}
				mutex.Unlock()
			}
			mutex_EchoMap.Unlock()
		}
	}()

	var RSDecOk = make(chan bool, 1)
	//handle Ready Message
	go func() {
		for {
			m := <-p.GetMessage("RBCReady", ID)
			fmt.Println(p.PID, " receive Ready from ", m.Sender)
			var payloadMessage protobuf.RBCReady
			proto.Unmarshal(m.Data, &payloadMessage)
			hash := payloadMessage.Hash
			m_j := payloadMessage.M
			fmt.Println(p.PID, " receive m_j: ", m_j, " from ", m.Sender)
			j := m.Sender
			mutex_ReadyMap.Lock()
			_, ok := T[string(hash)]
			if ok {
				T[string(hash)] = append(T[string(hash)], m_received{int(j), m_j})
			} else {
				T[string(hash)] = make([]m_received, 0) // possible bug
				T[string(hash)] = append(T[string(hash)], m_received{int(j), m_j})
			}

			if len(T[string(hash)]) > MaxReadyNumber {
				MaxReadyNumber = len(T[string(hash)])
				MaxReadyHash = hash
			}
			//send  ready message
			if uint32(len(T[string(hash)])) == p.F+1 {
				mutex.Lock()
				if !readyIsSent {
					mutex_EchoMap.Lock()
					for m_i, count := range EchoMessageMap[string(hash)] {
						if uint32(count) >= p.F+1 {
							readyIsSent = true
							ready_data, _ := proto.Marshal(&protobuf.RBCReady{Hash: hash, M: []byte(m_i)}) //possible bug
							p.Broadcast(&protobuf.Message{Type: "RBCReady", Sender: p.PID, Id: ID, Data: ready_data})
							break
						}
					}
					mutex_EchoMap.Unlock()
				}
				mutex.Unlock()
			}

			if uint32(len(T[string(hash)])) == 2*p.F+1 {
				RSDecOk <- true
				fmt.Println(p.PID, "has sent RSDecOk")
			}
			mutex_ReadyMap.Unlock()
		}

	}()

	<-RSDecOk // this method is not so good
	fmt.Println(p.PID, " has received RSDecOK")
	for r := uint32(0); r <= p.F; r++ {
		for {
			if uint32(MaxReadyNumber) >= 2*p.F+r+1 {
				break
			}
		}
		fmt.Println(p.PID, " running r = ", r)
		var m_received_temp = make([]m_received, 2*p.F+r+1)
		mutex_ReadyMap.Lock()
		copy(m_received_temp, T[string(MaxReadyHash)])
		mutex_ReadyMap.Unlock()
		//
		var M = make([][]byte, p.N)
		for i := uint32(0); i < 2*p.F+r+1; i++ {
			M[m_received_temp[i].j] = m_received_temp[i].mj
		}
		//
		RSEncoder, _ := reedsolomon.New(int(p.N-(p.F+1)), int(p.F+1))
		ok, _ := RSEncoder.Verify(M)
		if !ok {
			RSEncoder.Reconstruct(M)
		}
		fmt.Println(p.PID, " Reconstructed M = ", M)
		var m_reconstructed = make([]byte, 0)
		for i := uint32(0); i < p.N-(p.F+1); i++ {
			m_reconstructed = append(m_reconstructed, M[i]...)
		}
		m_reconstructed = utils.DeleteZero(m_reconstructed) // assume there is no 0 at the end originally.
		fmt.Println(p.PID, " m_reconstructed: ", m_reconstructed)
		h_new := sha256.New()
		h_new.Write(m_reconstructed)
		if bytes.Compare(h_new.Sum(nil), MaxReadyHash) == 0 {
			var replyMessage protobuf.Message
			proto.Unmarshal(m_reconstructed, &replyMessage)
			return &replyMessage //possible bug
		}
	}
	return nil //temp solution
}

//Receiving Initial Shares
/*
func (p *HonestParty) InitShareReceiver(ID []byte) {
	primitive := ecparam.PBC256.Ngmp
	var mutex sync.Mutex
	var ReadySent bool = false // indicate whether this node has sent Echo

	var CR_l = make([]*pbc.Element, p.N+1) //start from 1
	reducedShare := polyring.NewEmpty()
	for i := 0; uint32(i) <= p.N; i++ {
		CR_l[i] = KZG.NewG1()
	}

	S_full_indexes := make([]int, p.N) // start from 0
	S_full_polyValue := make([]*gmp.Int, p.N)

	for i := 0; uint32(i) < p.N; i++ {
		S_full_polyValue[i] = gmp.NewInt(0)
	}

	//handle VSSSend Message
	go func() {
		witnessReceived := make([]*pbc.Element, 2*p.F+2)
		polyValueReceived := make([]*gmp.Int, 2*p.F+2)
		for i := 0; uint32(i) <= 2*p.F+1; i++ {
			witnessReceived[i] = KZG.NewG1()
			polyValueReceived[i] = gmp.NewInt(0)
		}

		//decapsulate
		m := <-p.GetMessage("VSSSend", ID)
		var payloadMessage protobuf.VSSSend
		proto.Unmarshal(m.Data, &payloadMessage)

		//use functions instead of methods.
		mutex.Lock()
		if !ReadySent {
			p.Proof.SetFromVSSMessage(payloadMessage.Pi, p.F)
			for j := 1; uint32(j) <= 2*p.F+1; j++ {
				witnessReceived[j].SetCompressedBytes(payloadMessage.WRjiList[j])
				polyValueReceived[j].SetBytes(payloadMessage.RjiList[j])
			}
			verifyOK := p.VerifyVSSSendReceived(polyValueReceived, witnessReceived)
			if !verifyOK {
				fmt.Println("Node ", p.PID, " Verify VSSSend Failed")
				p.Proof.Init(p.F)
				mutex.Unlock()
				return
			}

			//interpolate CRl from pi'
			for j := 1; uint32(j) <= p.N; j++ {
				witnessReceived[j].SetCompressedBytes(payloadMessage.WRjiList[j])
				polyValueReceived[j].SetBytes(payloadMessage.RjiList[j])
			}
			C_known := make([]*pbc.Element, 2*p.F+2)
			for j := 0; uint32(j) <= 2*p.F+1; j++ {
				C_known[j] = KZG.NewG1()
				C_known[j].Set(p.Proof.Pi_contents[j].CR_j)
			}
			for j := 1; uint32(j) <= p.N; j++ {
				CommitInterpolation(int(2*p.F), j, C_known, CR_l[j])
			}
			//interpolate 2t-degree polynomial B*(i,y)
			x := make([]*gmp.Int, 2*p.F+1) //start from 0
			y := make([]*gmp.Int, 2*p.F+1)
			for j := 0; uint32(j) < 2*p.F+1; j++ {
				x[j].Set(gmp.NewInt(int64(j + 1)))
				y[j].Set(polyValueReceived[j+1])
				reducedShare, _ = interpolation.LagrangeInterpolate(int(2*p.F), x, y, primitive)
				fmt.Print("Node ", p.PID, " interpolate polynomial when receive Send Message:")
				reducedShare.Print()
			}
			//sendEcho
			EchoData := Encapsulate_VSSEcho(p.Proof, p.N, p.F)
			EchoMessage := &protobuf.Message{
				Type:   "Echo",
				Id:     ID,
				Sender: p.PID,
				Data:   EchoData,
			}
			p.Broadcast(EchoMessage)
		}
		mutex.Unlock()
	}()

	var N_EchoReceived int = 0
	var N_ReadyReceived int = 0
	var mutex_for_EchoMessage sync.Mutex
	var mutex_for_ReadyMessage sync.Mutex

	var EchoMap = make(map[string]int)
	var ReadyContent = make(map[string][]polypoint.PolyPoint)

	//handle VSSEcho Message
	go func() {
		for {
			m := <-p.GetMessage("VSSEcho", ID)
			var payloadMessage protobuf.VSSEcho
			proto.Unmarshal(m.Data, &payloadMessage)
			var pi_from_Echo Pi
			pi_from_Echo.Init(p.F)
			pi_from_Echo.SetFromVSSMessage(payloadMessage.Pi, p.F)
			pi_hash := sha256.New()
			pi_byte, _ := proto.Marshal(payloadMessage.Pi)
			pi_hash.Write(pi_byte)
			_, ok := EchoMap[string(pi_hash.Sum(nil))]
			if ok {
				EchoMap[string(pi_hash.Sum(nil))] += 1
			} else {
				EchoMap[string(pi_hash.Sum(nil))] = 1
			}

			// remember to add mutex
			if uint32(EchoMap[string(pi_hash.Sum(nil))]) == 2*p.F+1 {

			}

		}
	}()
	//handle VSSReady Message
	go func() {
		for {
			m := <-p.GetMessage("VSSReady", ID)

		}
	}()
	//handle VSSDistribute Message

}
*/
//Verify pi' and v'ji ,w'ji received
func (p *HonestParty) VerifyVSSSendReceived(polyValue []*gmp.Int, witness []*pbc.Element) bool {
	var ans bool = true
	primitive := ecparam.PBC256.Ngmp
	//Verify g^s == sigma((g^F_j)^lambda_j)
	lambda := make([]*gmp.Int, 2*p.F+1)
	knownIndexes := make([]*gmp.Int, 2*p.F+1)
	for j := 0; uint32(j) < 2*p.F+1; j++ {
		lambda[j] = gmp.NewInt(0)
	}
	for j := 0; uint32(j) < 2*p.F+1; j++ {
		knownIndexes[j] = gmp.NewInt(int64(j + 1))
	}
	polyring.GetLagrangeCoefficients(int(2*p.F), knownIndexes, primitive, gmp.NewInt(0), lambda)
	tmp := KZG.NewG1()
	tmp.Set1()
	for j := 1; uint32(j) <= 2*p.F+1; j++ {
		tmp2 := KZG.NewG1()
		tmp2.Set1()
		tmp2.PowBig(p.Proof.Pi_contents[j].g_Fj, conv.GmpInt2BigInt(lambda[j-1])) // the x value of index j-1 is j
		tmp.Mul(tmp, tmp2)
	}
	if !tmp.Equals(p.Proof.G_s) {
		fmt.Println("Node ", p.PID, " VSSSend Verify Failed")
		ans = false
	}
	//Verify KZG.VerifyEval(CZjk,0,0,WZjk0) == 1 && CRjk == CZjk * g^Fj(k) for k in [1,2t+1]
	for j := 1; uint32(j) <= 2*p.F+1; j++ {
		verifyEval := KZG.VerifyEval(p.Proof.Pi_contents[j].CZ_j, gmp.NewInt(0), gmp.NewInt(0), p.Proof.Pi_contents[j].WZ_0)

		var verifyRj bool
		tmp3 := KZG.NewG1()
		tmp3.Set1()
		tmp3.Mul(p.Proof.Pi_contents[j].CZ_j, p.Proof.Pi_contents[j].g_Fj)
		verifyRj = tmp3.Equals(p.Proof.Pi_contents[j].CR_j)
		if !verifyEval || !verifyRj {
			fmt.Println("Node ", p.PID, " VSSSend Verify Failed")
			ans = false
		}
	}

	//Verify v'ji,w'ji w.r.t pi'
	for j := 1; uint32(j) <= 2*p.F+1; j++ {
		//KZG Verify
		verifyPoint := KZG.VerifyEval(p.Proof.Pi_contents[j].CR_j, gmp.NewInt(int64((p.PID + 1))), polyValue[j], witness[j])
		if !verifyPoint {
			fmt.Println("Node ", p.PID, " VSSSend Verify Failed")
			ans = false
		}
	}

	return ans
}
