package party

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
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
}

//NewHonestParty return a new honest party object
func NewHonestParty(N uint32, F uint32, pid uint32, ipList []string, portList []string, sigPK *share.PubPoly, sigSK *share.PriShare) *HonestParty {
	p := HonestParty{
		N:            N,
		F:            F,
		PID:          pid,
		ipList:       ipList,
		portList:     portList,
		sendChannels: make([]chan *protobuf.Message, N),

		SigPK: sigPK,
		SigSK: sigSK,
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
