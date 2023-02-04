package party

import (
	"errors"
	"github.com/DyCAPSTeam/DyCAPS/pkg/core"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"log"
	"sync"
)

//InitReceiveChannel sets up the listener and Init the receiveChannel
func (p *HonestParty) InitReceiveChannel() error {
	p.dispatchChannels = core.MakeDispatcheChannels(core.MakeReceiveChannel(p.portList[p.PID]), p.N)
	return nil
}

//InitSendChannel sets up the sender and Init the sendChannel, please run this after initializing all party's receiveChannel
func (p *HonestParty) InitSendChannel() error {
	for i := uint32(0); i < p.N; i++ {
		p.sendChannels[i] = core.MakeSendChannel(p.ipList[i], p.portList[i])
	}
	// fmt.Println(p.sendChannels, "====")
	return nil
}

func (p *HonestParty) InitSendToNextChannel() error {
	for i := uint32(0); i < p.N; i++ {
		p.sendToNextChannels[i] = core.MakeSendChannel(p.ipListNext[i], p.portListNext[i])
	}
	// fmt.Println(p.sendChannels, "====")
	return nil
}

//Send a message to a party with des as its pid, 0 =< des < p.N
func (p *HonestParty) Send(m *protobuf.Message, des uint32) error {
	if !p.checkSendChannelsInit() {
		return errors.New("this party's send channels are not initialized yet")
	}
	if des < p.N {
		p.sendChannels[des] <- m
		return nil
	} else {
		return errors.New("this pid is too large")
	}
}

//SendToNextCommittee sends a message to a new committtee party with des as its pid, 0 =< des < p.N
func (p *HonestParty) SendToNextCommittee(m *protobuf.Message, des uint32) error {
	if !p.checkInitSendChannelsToNext() {
		return errors.New("this party's send channels are not initialized yet")
	}
	if des < p.N {
		p.sendToNextChannels[des] <- m
		return nil
	}
	return errors.New("this pid is too large")
}

//Broadcast a message to all parties
func (p *HonestParty) Broadcast(m *protobuf.Message) error {
	if !p.checkSendChannelsInit() {
		return errors.New("this party's send channels are not initialized yet")
	}
	for i := uint32(0); i < p.N; i++ {
		err := p.Send(m, i)
		if err != nil {
			return err
		}
	}
	return nil
}

//BroadcastExclude broadcasts a message to all parties except pid, used for RBC_test
func (p *HonestParty) BroadcastExclude(m *protobuf.Message, pid uint32) error {
	if !p.checkSendChannelsInit() {
		return errors.New("this party's send channels are not initialized yet")
	}
	for i := uint32(0); i < p.N; i++ {
		if i != pid {
			err := p.Send(m, i)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

//BroadcastToNextCommittee broadcasts a message m to all parties in the new committee
func (p *HonestParty) BroadcastToNextCommittee(m *protobuf.Message) error {
	if !p.checkInitSendChannelsToNext() {
		return errors.New("this party's send channels are not initialized yet")
	}
	for i := uint32(0); i < p.N; i++ {
		err := p.SendToNextCommittee(m, i)
		if err != nil {
			return err
		}
	}
	return nil
}

//GetMessage tries to get a message according to messageType and ID
func (p *HonestParty) GetMessage(messageType string, ID []byte) chan *protobuf.Message {
	value1, _ := p.dispatchChannels.LoadOrStore(messageType, new(sync.Map))

	value2, _ := value1.(*sync.Map).LoadOrStore(string(ID), make(chan *protobuf.Message, p.N*p.N)) // ch change the size to N^2

	return value2.(chan *protobuf.Message)
}

func (p *HonestParty) checkSendChannelsInit() bool {
	return p.sendToNextChannels != nil
}

func (p *HonestParty) checkInitSendChannelsToNext() bool {
	return p.sendToNextChannels != nil
}

//w_0,w_1,...,w^(3f+1) will be used to represent values of a polynomial.
//The total number of values is 3f+2.So in this function we use size+1
func GetScaleByCommitteeSize(size uint32) uint8 {
	if size+1 > 1 && size+1 <= 2 {
		return 1
	}
	if size+1 > 2 && size+1 <= 4 {
		return 2
	}
	if size+1 > 4 && size+1 <= 8 {
		return 3
	}
	if size+1 > 8 && size+1 <= 16 {
		return 4
	}
	if size+1 > 16 && size+1 <= 32 {
		return 5
	}
	if size+1 > 32 && size+1 <= 64 {
		return 6
	}
	if size+1 > 64 && size+1 <= 128 {
		return 7
	}
	log.Panicln("invalid input at function GetScaleByCommitteeSize. size should be in [1,127].")
	return 0
}

func (pi *Pi) Init(F uint32) {
	pi.PiContents = make([]PiContent, 2*F+2)
	for i := uint32(0); i <= 2*F+1; i++ {
		pi.PiContents[i].j = i
	}
}
