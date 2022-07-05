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
	"github.com/ncw/gmp"
	"google.golang.org/protobuf/proto"
)

//indexes of polyValue[] start from 1!
func ParseSendMessage(message *protobuf.VSSSend, pi *Pi, N uint32, F uint32, polyValues []*gmp.Int, witnesses []*pbc.Element) {

}

//InitReceiveChannel setup the listener and Init the receiveChannel
func (p *HonestParty) InitReceiveChannel() error {
	p.dispatchChannels = core.MakeDispatcheChannels(core.MakeReceiveChannel(p.portList[p.PID]), p.N)
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

//TODO: change this name to SendtoNewCommittee later
//Send a message to a new committtee party with des as its pid, 0 =< des < p.N
func (p *HonestParty) SendtoNext(m *protobuf.Message, des uint32) error {
	if !p.checkInitSendChannelstoNext() {
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

//Broadcast a message to all parties except pid, used for RBC_test
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

//TODO: change this name to BroadcasttoNewCommittee later
//Broadcast a message to all parties in the new committee
func (p *HonestParty) BroadcasttoNext(m *protobuf.Message) error {
	if !p.checkInitSendChannelstoNext() {
		return errors.New("this party's send channels are not initialized yet")
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
	value1, _ := p.dispatchChannels.LoadOrStore(messageType, new(sync.Map))

	value2, _ := value1.(*sync.Map).LoadOrStore(string(ID), make(chan *protobuf.Message, p.N*p.N)) // ch change the size to N^2

	return value2.(chan *protobuf.Message)
}

func (p *HonestParty) checkSendChannelsInit() bool {
	return p.sendToNextChannels != nil
}

func (p *HonestParty) checkInitSendChannelstoNext() bool {
	return p.sendToNextChannels != nil
}

func (pi *Pi) Init(F uint32) {
	pi.Gs = KZG.NewG1()
	pi.PiContents = make([]PiContent, 2*F+2)
	for i := 0; uint32(i) <= 2*F+1; i++ {
		pi.PiContents[i].CB_j = KZG.NewG1()
		pi.PiContents[i].WZ_0 = KZG.NewG1()
		pi.PiContents[i].g_Fj = KZG.NewG1()
		pi.PiContents[i].CZ_j = KZG.NewG1()
		pi.PiContents[i].j = i
	}
}

func (pi *Pi) SetFromVSSMessage(m *protobuf.Pi, F uint32) {

	pi.Gs.SetCompressedBytes(m.Gs)
	for j := 1; uint32(j) <= 2*F+1; j++ {
		pi.PiContents[j].CB_j.SetCompressedBytes(m.PiContents[j].CBJ)
		pi.PiContents[j].CZ_j.SetCompressedBytes(m.PiContents[j].CZJ)
		pi.PiContents[j].WZ_0.SetCompressedBytes(m.PiContents[j].WZ_0)
		pi.PiContents[j].g_Fj.SetCompressedBytes(m.PiContents[j].G_Fj)
	}
}

func (pi *Pi) Set(src *Pi, F uint32) {
	pi.Gs.Set(src.Gs)
	for j := 1; uint32(j) <= 2*F+1; j++ {
		pi.PiContents[j].CB_j.Set(src.PiContents[j].CB_j)
		pi.PiContents[j].CZ_j.Set(src.PiContents[j].CZ_j)
		pi.PiContents[j].WZ_0.Set(src.PiContents[j].WZ_0)
		pi.PiContents[j].g_Fj.Set(src.PiContents[j].g_Fj)
	}
}

//Interpolate commitment or witness according to the first 2t+1 elements
func InterpolateComOrWit(degree uint32, targetIndex uint32, List []*pbc.Element) *pbc.Element {
	CWList := make([]*pbc.Element, degree+1)
	copy(CWList, List)

	// degree=2t
	if targetIndex > 0 && targetIndex < degree+1 {
		return CWList[targetIndex]
	} else {
		ecparamN := ecparam.PBC256.Ngmp
		lambda := make([]*gmp.Int, degree+1)
		knownIndexes := make([]*gmp.Int, degree+1)

		for j := uint32(0); j < degree+1; j++ {
			lambda[j] = gmp.NewInt(0)
			knownIndexes[j] = gmp.NewInt(int64(j + 1)) //known indexes: 1, ..., deg+1
		}

		polyring.GetLagrangeCoefficients(int(degree), knownIndexes, ecparamN, gmp.NewInt(int64(targetIndex)), lambda)

		ans := KZG.NewG1()
		ans.Set0()
		for j := uint32(0); j < degree+1; j++ {
			tmp := KZG.NewG1()
			tmp.Set1()
			// fmt.Printf("j: %v,  C_list[j]: %s, lambda[j]: %s\n", j, C_list[j].String(), lambda[j].String())
			tmp.MulBig(CWList[j], conv.GmpInt2BigInt(lambda[j]))
			ans.ThenAdd(tmp)
		}
		return ans
	}
}

func InterpolateComOrWitbyKnownIndexes(degree uint32, targetIndex uint32, knownIndexes []*gmp.Int, List []*pbc.Element) *pbc.Element {
	CWList := make([]*pbc.Element, degree+1)
	copy(CWList, List)

	var known bool = false
	for _, a := range knownIndexes {
		if a == gmp.NewInt(int64(targetIndex)) {
			known = true
		}
	}
	if known {
		return CWList[targetIndex]
	} else {
		ecparamN := ecparam.PBC256.Ngmp
		lambda := make([]*gmp.Int, degree+1)
		for j := uint32(0); j < degree+1; j++ {
			lambda[j] = gmp.NewInt(0)
		}
		polyring.GetLagrangeCoefficients(int(degree), knownIndexes, ecparamN, gmp.NewInt(int64(targetIndex)), lambda)

		ans := KZG.NewG1()
		ans.Set0()
		for j := uint32(0); j < degree+1; j++ {
			tmp := KZG.NewG1()
			tmp.Set1()
			tmp.MulBig(CWList[j], conv.GmpInt2BigInt(lambda[j]))
			ans.ThenAdd(tmp)
		}
		return ans
	}
}

func EncapsulateVSSSend(pi *Pi, RjiList []*gmp.Int, WjiList []*pbc.Element, N uint32, F uint32) []byte {
	var msg = new(protobuf.VSSSend)
	msg.Pi = new(protobuf.Pi)
	msg.Pi.Gs = pi.Gs.CompressedBytes()

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
			msg.Pi.PiContents[0].CBJ = []byte{}
			msg.Pi.PiContents[0].CZJ = []byte{}
			msg.Pi.PiContents[0].G_Fj = []byte{}
		} else {
			msg.WRjiList[j] = WjiList[j].CompressedBytes()
			msg.RjiList[j] = RjiList[j].Bytes()
			msg.Pi.PiContents[j].J = int32(j)
			msg.Pi.PiContents[j].CZJ = pi.PiContents[j].CZ_j.CompressedBytes()
			msg.Pi.PiContents[j].CBJ = pi.PiContents[j].CB_j.CompressedBytes()
			msg.Pi.PiContents[j].WZ_0 = pi.PiContents[j].WZ_0.CompressedBytes()
			msg.Pi.PiContents[j].G_Fj = pi.PiContents[j].g_Fj.CompressedBytes()
		}
	}
	data, _ := proto.Marshal(msg)
	return data
}

func EncapsulateVSSEcho(pi *Pi, N uint32, F uint32) []byte {
	var msg = new(protobuf.VSSEcho)
	msg.Pi = new(protobuf.Pi)
	msg.Pi.Gs = pi.Gs.CompressedBytes()

	for j := 0; uint32(j) <= 2*F+1; j++ {
		if j == 0 {
			msg.Pi.PiContents = make([]*protobuf.PiContent, 2*F+2)
			for k := 0; uint32(k) <= 2*F+1; k++ {
				msg.Pi.PiContents[k] = new(protobuf.PiContent)
			}
			msg.Pi.PiContents[0].J = 0
			msg.Pi.PiContents[0].WZ_0 = []byte{}
			msg.Pi.PiContents[0].CBJ = []byte{}
			msg.Pi.PiContents[0].CZJ = []byte{}
			msg.Pi.PiContents[0].G_Fj = []byte{}
		} else {
			msg.Pi.PiContents[j].J = int32(j)
			msg.Pi.PiContents[j].CZJ = pi.PiContents[j].CZ_j.CompressedBytes()
			msg.Pi.PiContents[j].CBJ = pi.PiContents[j].CB_j.CompressedBytes()
			msg.Pi.PiContents[j].WZ_0 = pi.PiContents[j].WZ_0.CompressedBytes()
			msg.Pi.PiContents[j].G_Fj = pi.PiContents[j].g_Fj.CompressedBytes()
		}
	}
	data, _ := proto.Marshal(msg)
	return data
}

func EncapsulateVSSReady(pi *Pi, ReadyType string, B_li *gmp.Int, w_li *pbc.Element, N uint32, F uint32) []byte {
	var msg = new(protobuf.VSSReady)
	msg.Pi = new(protobuf.Pi)
	msg.Pi.Gs = pi.Gs.CompressedBytes()
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
			msg.Pi.PiContents[0].CBJ = []byte{}
			msg.Pi.PiContents[0].CZJ = []byte{}
			msg.Pi.PiContents[0].G_Fj = []byte{}
		} else {
			msg.Pi.PiContents[j].J = int32(j)
			msg.Pi.PiContents[j].CZJ = pi.PiContents[j].CZ_j.CompressedBytes()
			msg.Pi.PiContents[j].CBJ = pi.PiContents[j].CB_j.CompressedBytes()
			msg.Pi.PiContents[j].WZ_0 = pi.PiContents[j].WZ_0.CompressedBytes()
			msg.Pi.PiContents[j].G_Fj = pi.PiContents[j].g_Fj.CompressedBytes()
		}
	}
	data, _ := proto.Marshal(msg)
	return data
}

func EncapsulateVSSDistribute(B_li *gmp.Int, w_li *pbc.Element, N uint32, F uint32) []byte {
	var msg = new(protobuf.VSSDistribute)
	msg.BLi = B_li.Bytes()
	msg.WBLi = w_li.CompressedBytes()
	data, _ := proto.Marshal(msg)
	return data
}

func (pi *Pi) Equals(other *Pi, F uint32) bool {
	if !pi.Gs.Equals(other.Gs) {
		return false
	}
	for j := 1; uint32(j) <= 2*F+1; j++ {
		if pi.PiContents[j].j != other.PiContents[j].j {
			return false
		}
		if !pi.PiContents[j].CB_j.Equals(other.PiContents[j].CB_j) {
			return false
		}
		if !pi.PiContents[j].CZ_j.Equals(other.PiContents[j].CZ_j) {
			return false
		}
		if !pi.PiContents[j].WZ_0.Equals(other.PiContents[j].WZ_0) {
			return false
		}
		if !pi.PiContents[j].g_Fj.Equals(other.PiContents[j].g_Fj) {
			return false
		}
	}
	return true
}
