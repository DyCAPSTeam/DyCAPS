package party

import (
	"errors"
	"sync"

	"github.com/DyCAPSTeam/DyCAPS/internal/conv"
	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/DyCAPSTeam/DyCAPS/pkg/core"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"github.com/Nik-U/pbc"
	"github.com/golang/protobuf/proto"
	"github.com/ncw/gmp"
)

//indexes of polyValue[] start from 1!
func ParseSendMessage(message *protobuf.VSSSend, pi *Pi, N uint32, F uint32, polyValues []*gmp.Int, witnesses []*pbc.Element) {

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

func (p *HonestParty) InitSendtoNextChannel() error {
	for i := uint32(0); i < p.N; i++ {
		p.sendtoNextChannels[i] = core.MakeSendChannel(p.ipList_next[i], p.portList_next[i])
	}
	// fmt.Println(p.sendChannels, "====")
	return nil
}

//Send a message to a party with des as its pid, 0 =< des < p.N
func (p *HonestParty) Send(m *protobuf.Message, des uint32) error {
	if !p.checkSendChannelsInit() {
		return errors.New("This party's send channels are not initialized yet")
	}
	if des < p.N {
		p.sendChannels[des] <- m
		return nil
	} else {
		return errors.New("This pid is too large")
	}
}

//TODO: change this name to SendtoNewCommittee later
//Send a message to a new committtee party with des as its pid, 0 =< des < p.N
func (p *HonestParty) SendtoNext(m *protobuf.Message, des uint32) error {
	if !p.checkInitSendChannelstoNext() {
		return errors.New("This party's send channels are not initialized yet")
	}
	if des < p.N {
		p.sendtoNextChannels[des] <- m
		return nil
	}
	return errors.New("This pid is too large")
}

//Broadcast a message to all parties
func (p *HonestParty) Broadcast(m *protobuf.Message) error {
	if !p.checkSendChannelsInit() {
		return errors.New("This party's send channels are not initialized yet")
	}
	for i := uint32(0); i < p.N; i++ {
		err := p.Send(m, i)
		if err != nil {
			return err
		}
	}
	return nil
}

//Broadcast a message to all parties except pid, used for RBC_test
func (p *HonestParty) BroadcastExclude(m *protobuf.Message, pid uint32) error {
	if !p.checkSendChannelsInit() {
		return errors.New("This party's send channels are not initialized yet")
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

//TODO: change this name to BroadcasttoNewCommittee later
//Broadcast a message to all parties in the new committee
func (p *HonestParty) BroadcasttoNext(m *protobuf.Message) error {
	if !p.checkInitSendChannelstoNext() {
		return errors.New("This party's send channels are not initialized yet")
	}
	for i := uint32(0); i < p.N; i++ {
		err := p.SendtoNext(m, i)
		if err != nil {
			return err
		}
	}
	return nil
}

//Try to get a message according to messageType and ID
func (p *HonestParty) GetMessage(messageType string, ID []byte) chan *protobuf.Message {
	value1, _ := p.dispatcheChannels.LoadOrStore(messageType, new(sync.Map))

	value2, _ := value1.(*sync.Map).LoadOrStore(string(ID), make(chan *protobuf.Message, p.N*p.N)) // ch change the size to N^2

	return value2.(chan *protobuf.Message)
}

func (p *HonestParty) checkSendChannelsInit() bool {
	if p.sendChannels == nil {
		return false
	}
	return true
}

func (p *HonestParty) checkInitSendChannelstoNext() bool {
	if p.sendtoNextChannels == nil {
		return false
	}
	return true
}

func (pi *Pi) Init(F uint32) {
	pi.G_s = KZG.NewG1()
	pi.Pi_contents = make([]Pi_Content, 2*F+2)
	for i := 0; uint32(i) <= 2*F+1; i++ {
		pi.Pi_contents[i].CR_j = KZG.NewG1()
		pi.Pi_contents[i].WZ_0 = KZG.NewG1()
		pi.Pi_contents[i].g_Fj = KZG.NewG1()
		pi.Pi_contents[i].CZ_j = KZG.NewG1()
		pi.Pi_contents[i].j = i
	}
}

func (pi *Pi) SetFromVSSMessage(m *protobuf.Pi, F uint32) {
	pi.G_s.SetCompressedBytes(m.Gs)
	for j := 1; uint32(j) <= 2*F+1; j++ {
		pi.Pi_contents[j].CR_j.SetCompressedBytes(m.PiContents[j].CRJ)
		pi.Pi_contents[j].CZ_j.SetCompressedBytes(m.PiContents[j].CZJ)
		pi.Pi_contents[j].WZ_0.SetCompressedBytes(m.PiContents[j].WZ_0)
		pi.Pi_contents[j].g_Fj.SetCompressedBytes(m.PiContents[j].G_Fj)
	}
}

func (pi *Pi) Set(src *Pi, F uint32) {

	pi.G_s.Set(src.G_s)
	for j := 1; uint32(j) <= 2*F+1; j++ {
		pi.Pi_contents[j].CR_j.Set(src.Pi_contents[j].CR_j)
		pi.Pi_contents[j].CZ_j.Set(src.Pi_contents[j].CZ_j)
		pi.Pi_contents[j].WZ_0.Set(src.Pi_contents[j].WZ_0)
		pi.Pi_contents[j].g_Fj.Set(src.Pi_contents[j].g_Fj)
	}
}

func InterpolateComOrWit(degree uint32, targetindex uint32, C_list []*pbc.Element) *pbc.Element {
	ecparamN := ecparam.PBC256.Ngmp
	lambda := make([]*gmp.Int, degree+1)
	knownIndexes := make([]*gmp.Int, degree+1)
	for j := uint32(0); j < degree+1; j++ {
		lambda[j] = gmp.NewInt(int64(j + 1))
	}
	for j := uint32(0); j < degree+1; j++ {
		knownIndexes[j] = gmp.NewInt(int64(j + 1))
	}
	polyring.GetLagrangeCoefficients(int(degree), knownIndexes, ecparamN, gmp.NewInt(int64(targetindex)), lambda)

	ans := KZG.NewG1()
	ans.Set1()
	for j := uint32(0); j < degree+1; j++ {
		tmp := KZG.NewG1()
		// tmp.Set1()
		tmp.PowBig(C_list[j], conv.GmpInt2BigInt(lambda[j]))
		ans.ThenMul(tmp)
	}
	return ans
}

func InterpolateComOrWitbyKnownIndexes(degree uint32, targetindex uint32, knownIndexes []*gmp.Int, C_list []*pbc.Element) *pbc.Element {
	ecparamN := ecparam.PBC256.Ngmp
	lambda := make([]*gmp.Int, degree+1)
	for j := uint32(0); j < degree+1; j++ {
		lambda[j] = gmp.NewInt(int64(j))
	}
	polyring.GetLagrangeCoefficients(int(degree), knownIndexes, ecparamN, gmp.NewInt(int64(targetindex)), lambda)

	ans := KZG.NewG1()
	ans.Set1()
	for j := uint32(0); j < degree+1; j++ {
		tmp := KZG.NewG1()
		tmp.Set1()
		tmp.PowBig(C_list[j], conv.GmpInt2BigInt(lambda[j]))
		ans.ThenMul(tmp)
	}
	return ans
}

func Encapsulate_VSSSend(pi *Pi, Rji_list []*gmp.Int, Wji_list []*pbc.Element, N uint32, F uint32) []byte {
	var msg = new(protobuf.VSSSend)
	msg.Pi = new(protobuf.Pi)
	msg.Pi.Gs = pi.G_s.CompressedBytes()

	for j := 0; uint32(j) <= 2*F+1; j++ {
		if j == 0 {
			msg.RjiList = make([][]byte, 2*F+2) // 0 is not used.
			msg.WRjiList = make([][]byte, 2*F+2)
			msg.WRjiList[0] = []byte{}
			msg.RjiList[0] = []byte{}
			msg.Pi.PiContents = make([]*protobuf.PiContent, 2*F+2)
			for k := 0; uint32(k) <= 2*F+1; k++ {
				msg.Pi.PiContents[k] = new(protobuf.PiContent)
			}
			msg.Pi.PiContents[0].J = 0
			msg.Pi.PiContents[0].WZ_0 = []byte{}
			msg.Pi.PiContents[0].CRJ = []byte{}
			msg.Pi.PiContents[0].CZJ = []byte{}
			msg.Pi.PiContents[0].G_Fj = []byte{}
		} else {
			msg.WRjiList[j] = Wji_list[j].CompressedBytes()
			msg.RjiList[j] = Rji_list[j].Bytes()
			msg.Pi.PiContents[j].J = int32(j)
			msg.Pi.PiContents[j].CZJ = pi.Pi_contents[j].CZ_j.CompressedBytes()
			msg.Pi.PiContents[j].CRJ = pi.Pi_contents[j].CR_j.CompressedBytes()
			msg.Pi.PiContents[j].WZ_0 = pi.Pi_contents[j].WZ_0.CompressedBytes()
			msg.Pi.PiContents[j].G_Fj = pi.Pi_contents[j].g_Fj.CompressedBytes()
		}
	}
	data, _ := proto.Marshal(msg)
	return data
}

func Encapsulate_VSSEcho(pi *Pi, N uint32, F uint32) []byte {
	var msg = new(protobuf.VSSEcho)
	msg.Pi = new(protobuf.Pi)
	msg.Pi.Gs = pi.G_s.CompressedBytes()

	for j := 0; uint32(j) <= 2*F+1; j++ {
		if j == 0 {
			msg.Pi.PiContents = make([]*protobuf.PiContent, 2*F+2)
			for k := 0; uint32(k) <= 2*F+1; k++ {
				msg.Pi.PiContents[k] = new(protobuf.PiContent)
			}
			msg.Pi.PiContents[0].J = 0
			msg.Pi.PiContents[0].WZ_0 = []byte{}
			msg.Pi.PiContents[0].CRJ = []byte{}
			msg.Pi.PiContents[0].CZJ = []byte{}
			msg.Pi.PiContents[0].G_Fj = []byte{}
		} else {
			msg.Pi.PiContents[j].J = int32(j)
			msg.Pi.PiContents[j].CZJ = pi.Pi_contents[j].CZ_j.CompressedBytes()
			msg.Pi.PiContents[j].CRJ = pi.Pi_contents[j].CR_j.CompressedBytes()
			msg.Pi.PiContents[j].WZ_0 = pi.Pi_contents[j].WZ_0.CompressedBytes()
			msg.Pi.PiContents[j].G_Fj = pi.Pi_contents[j].g_Fj.CompressedBytes()
		}
	}
	data, _ := proto.Marshal(msg)
	return data
}

func Encapsulate_VSSReady(pi *Pi, ReadyType string, B_li *gmp.Int, w_li *pbc.Element, N uint32, F uint32) []byte {
	var msg = new(protobuf.VSSReady)
	msg.Pi = new(protobuf.Pi)
	msg.Pi.Gs = pi.G_s.CompressedBytes()
	msg.ReadyType = ReadyType // possible bug
	if msg.ReadyType == "SHARE" {
		msg.BIl = B_li.Bytes()
		msg.WBIl = w_li.CompressedBytes()
	}
	for j := 0; uint32(j) <= 2*F+1; j++ {
		if j == 0 {

			msg.Pi.PiContents = make([]*protobuf.PiContent, 2*F+2)
			for k := 0; uint32(k) <= 2*F+1; k++ {
				msg.Pi.PiContents[k] = new(protobuf.PiContent)
			}
			msg.Pi.PiContents[0].J = 0
			msg.Pi.PiContents[0].WZ_0 = []byte{}
			msg.Pi.PiContents[0].CRJ = []byte{}
			msg.Pi.PiContents[0].CZJ = []byte{}
			msg.Pi.PiContents[0].G_Fj = []byte{}
		} else {
			msg.Pi.PiContents[j].J = int32(j)
			msg.Pi.PiContents[j].CZJ = pi.Pi_contents[j].CZ_j.CompressedBytes()
			msg.Pi.PiContents[j].CRJ = pi.Pi_contents[j].CR_j.CompressedBytes()
			msg.Pi.PiContents[j].WZ_0 = pi.Pi_contents[j].WZ_0.CompressedBytes()
			msg.Pi.PiContents[j].G_Fj = pi.Pi_contents[j].g_Fj.CompressedBytes()
		}
	}
	data, _ := proto.Marshal(msg)
	return data
}

func Encapsulate_VSSDistribute(B_li *gmp.Int, w_li *pbc.Element, N uint32, F uint32) []byte {
	var msg = new(protobuf.VSSDistribute)
	msg.BLi = B_li.Bytes()
	msg.WBLi = w_li.CompressedBytes()
	data, _ := proto.Marshal(msg)
	return data
}

func (pi *Pi) Equals(other *Pi, F uint32) bool {
	var ans bool = true
	if !pi.G_s.Equals(other.G_s) {
		ans = false
	}
	for j := 1; uint32(j) <= 2*F+1; j++ {
		if pi.Pi_contents[j].j != other.Pi_contents[j].j {
			ans = false
		}
		if !pi.Pi_contents[j].CR_j.Equals(other.Pi_contents[j].CR_j) {
			ans = false
		}
		if !pi.Pi_contents[j].CZ_j.Equals(other.Pi_contents[j].CZ_j) {
			ans = false
		}
		if !pi.Pi_contents[j].WZ_0.Equals(other.Pi_contents[j].WZ_0) {
			ans = false
		}
		if !pi.Pi_contents[j].g_Fj.Equals(other.Pi_contents[j].g_Fj) {
			ans = false
		}
	}
	return ans
}
