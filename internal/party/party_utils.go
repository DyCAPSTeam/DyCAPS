package party

import (
	"errors"
	"github.com/DyCAPSTeam/DyCAPS/internal/commitment"
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

func (pi *Pi) Init(F uint32, KZG *commitment.DLPolyCommit) {
	pi.Gs = KZG.NewG1()
	pi.PiContents = make([]PiContent, 2*F+2)
	for i := uint32(0); i <= 2*F+1; i++ {
		pi.PiContents[i].CBj = KZG.NewG1()
		pi.PiContents[i].WZ0 = KZG.NewG1()
		pi.PiContents[i].gFj = KZG.NewG1()
		pi.PiContents[i].CZj = KZG.NewG1()
		pi.PiContents[i].j = i
	}
}

func (pi *Pi) SetFromVSSMessage(m *protobuf.Pi, F uint32) {
	pi.Gs.SetCompressedBytes(m.Gs)
	for j := uint32(1); j <= 2*F+1; j++ {
		pi.PiContents[j].CBj.SetCompressedBytes(m.PiContents[j].CBj)
		pi.PiContents[j].CZj.SetCompressedBytes(m.PiContents[j].CZj)
		pi.PiContents[j].WZ0.SetCompressedBytes(m.PiContents[j].WZ0)
		pi.PiContents[j].gFj.SetCompressedBytes(m.PiContents[j].GFj)
		pi.PiContents[j].j = j
	}
}

func (pi *Pi) Set(src *Pi, F uint32) {
	pi.Gs.Set(src.Gs)
	for j := 1; uint32(j) <= 2*F+1; j++ {
		pi.PiContents[j].CBj.Set(src.PiContents[j].CBj)
		pi.PiContents[j].CZj.Set(src.PiContents[j].CZj)
		pi.PiContents[j].WZ0.Set(src.PiContents[j].WZ0)
		pi.PiContents[j].gFj.Set(src.PiContents[j].gFj)
		pi.PiContents[j].j = src.PiContents[j].j
	}
}

//InterpolateComOrWit interpolates commitment or witness according to the first 2t+1 elements
func InterpolateComOrWit(degree uint32, targetIndex uint32, List []*pbc.Element, KZG *commitment.DLPolyCommit) *pbc.Element {
	CWList := make([]*pbc.Element, degree+1)
	copy(CWList, List)

	// degree=2t
	if targetIndex > 0 && targetIndex < degree+1 {
		return CWList[targetIndex-1]
	} else {
		ecparamN := ecparam.PBC256.Ngmp
		lambda := make([]*gmp.Int, degree+1)
		knownIndexes := make([]*gmp.Int, degree+1)

		for j := uint32(0); j < degree+1; j++ {
			lambda[j] = gmp.NewInt(0)
			knownIndexes[j] = gmp.NewInt(int64(j + 1)) //known indexes: 1, ..., deg+1
		}

		polyring.GetLagrangeCoefficients(degree, knownIndexes, ecparamN, gmp.NewInt(int64(targetIndex)), lambda)

		ans := KZG.NewG1()
		ans.Set0()
		for j := uint32(0); j < degree+1; j++ {
			tmp := KZG.NewG1()
			tmp.Set1()
			// fmt.Printf("index: %v,  C_list[index]: %s, lambda[index]: %s\n", index, C_list[index].String(), lambda[index].String())
			tmp.MulBig(CWList[j], conv.GmpInt2BigInt(lambda[j]))
			ans.ThenAdd(tmp)
		}
		return ans
	}
}

func InterpolateComOrWitByKnownIndexes(degree uint32, targetIndex uint32, knownIndexes []*gmp.Int, List []*pbc.Element, KZG *commitment.DLPolyCommit) *pbc.Element {
	CWList := make([]*pbc.Element, degree+1)
	copy(CWList, List)

	var known = false
	for _, a := range knownIndexes {
		if a == gmp.NewInt(int64(targetIndex)) {
			known = true
		}
	}
	if known {
		return CWList[targetIndex-1]
	} else {
		ecparamN := ecparam.PBC256.Ngmp
		lambda := make([]*gmp.Int, degree+1)
		for j := uint32(0); j < degree+1; j++ {
			lambda[j] = gmp.NewInt(0)
		}
		polyring.GetLagrangeCoefficients(degree, knownIndexes, ecparamN, gmp.NewInt(int64(targetIndex)), lambda)

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

func EncapsulateVSSSend(pi *Pi, BijList []*gmp.Int, WBijList []*pbc.Element, F uint32) []byte {
	var msg = new(protobuf.VSSSend)
	msg.Pi = new(protobuf.Pi)
	msg.Pi.Gs = pi.Gs.CompressedBytes()

	for j := uint32(0); j <= 2*F+1; j++ {
		if j == 0 {
			msg.BijList = make([][]byte, 2*F+2) // 0 is not used.
			msg.WBijList = make([][]byte, 2*F+2)
			msg.WBijList[0] = []byte{}
			msg.BijList[0] = []byte{}
			msg.Pi.PiContents = make([]*protobuf.PiContent, 2*F+2)
			for k := 0; uint32(k) <= 2*F+1; k++ {
				msg.Pi.PiContents[k] = new(protobuf.PiContent)
			}
			msg.Pi.PiContents[0].J = 0
			msg.Pi.PiContents[0].WZ0 = []byte{}
			msg.Pi.PiContents[0].CBj = []byte{}
			msg.Pi.PiContents[0].CZj = []byte{}
			msg.Pi.PiContents[0].GFj = []byte{}
		} else {
			msg.WBijList[j] = WBijList[j].CompressedBytes()
			msg.BijList[j] = BijList[j].Bytes()
			msg.Pi.PiContents[j].J = j
			msg.Pi.PiContents[j].CZj = pi.PiContents[j].CZj.CompressedBytes()
			msg.Pi.PiContents[j].CBj = pi.PiContents[j].CBj.CompressedBytes()
			msg.Pi.PiContents[j].WZ0 = pi.PiContents[j].WZ0.CompressedBytes()
			msg.Pi.PiContents[j].GFj = pi.PiContents[j].gFj.CompressedBytes()
		}
	}
	data, _ := proto.Marshal(msg)
	return data
}

func EncapsulateVSSEcho(pi *Pi, F uint32) []byte {
	var msg = new(protobuf.VSSEcho)
	msg.Pi = new(protobuf.Pi)
	msg.Pi.Gs = pi.Gs.CompressedBytes()

	for j := uint32(0); j <= 2*F+1; j++ {
		if j == 0 {
			msg.Pi.PiContents = make([]*protobuf.PiContent, 2*F+2)
			for k := 0; uint32(k) <= 2*F+1; k++ {
				msg.Pi.PiContents[k] = new(protobuf.PiContent)
			}
			msg.Pi.PiContents[0].J = 0
			msg.Pi.PiContents[0].WZ0 = []byte{}
			msg.Pi.PiContents[0].CBj = []byte{}
			msg.Pi.PiContents[0].CZj = []byte{}
			msg.Pi.PiContents[0].GFj = []byte{}
		} else {
			msg.Pi.PiContents[j].J = j
			msg.Pi.PiContents[j].CZj = pi.PiContents[j].CZj.CompressedBytes()
			msg.Pi.PiContents[j].CBj = pi.PiContents[j].CBj.CompressedBytes()
			msg.Pi.PiContents[j].WZ0 = pi.PiContents[j].WZ0.CompressedBytes()
			msg.Pi.PiContents[j].GFj = pi.PiContents[j].gFj.CompressedBytes()
		}
	}
	data, _ := proto.Marshal(msg)
	return data
}

func EncapsulateVSSReady(pi *Pi, ReadyType string, Bli *gmp.Int, wli *pbc.Element, F uint32) []byte {
	var msg = new(protobuf.VSSReady)
	msg.Pi = new(protobuf.Pi)
	msg.Pi.Gs = pi.Gs.CompressedBytes()
	msg.ReadyType = ReadyType // possible bug
	if msg.ReadyType == "SHARE" {
		msg.Bil = Bli.Bytes()
		msg.WBil = wli.CompressedBytes()
	}
	for j := uint32(0); j <= 2*F+1; j++ {
		if j == 0 {
			msg.Pi.PiContents = make([]*protobuf.PiContent, 2*F+2)
			for k := 0; uint32(k) <= 2*F+1; k++ {
				msg.Pi.PiContents[k] = new(protobuf.PiContent)
			}
			msg.Pi.PiContents[0].J = 0
			msg.Pi.PiContents[0].WZ0 = []byte{}
			msg.Pi.PiContents[0].CBj = []byte{}
			msg.Pi.PiContents[0].CZj = []byte{}
			msg.Pi.PiContents[0].GFj = []byte{}
		} else {
			msg.Pi.PiContents[j].J = j
			msg.Pi.PiContents[j].CZj = pi.PiContents[j].CZj.CompressedBytes()
			msg.Pi.PiContents[j].CBj = pi.PiContents[j].CBj.CompressedBytes()
			msg.Pi.PiContents[j].WZ0 = pi.PiContents[j].WZ0.CompressedBytes()
			msg.Pi.PiContents[j].GFj = pi.PiContents[j].gFj.CompressedBytes()
		}
	}
	data, _ := proto.Marshal(msg)
	return data
}

func EncapsulateVSSDistribute(Bli *gmp.Int, wli *pbc.Element) []byte {
	var msg = new(protobuf.VSSDistribute)
	msg.Bli = Bli.Bytes()
	msg.WBli = wli.CompressedBytes()
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
		if !pi.PiContents[j].CBj.Equals(other.PiContents[j].CBj) {
			return false
		}
		if !pi.PiContents[j].CZj.Equals(other.PiContents[j].CZj) {
			return false
		}
		if !pi.PiContents[j].WZ0.Equals(other.PiContents[j].WZ0) {
			return false
		}
		if !pi.PiContents[j].gFj.Equals(other.PiContents[j].gFj) {
			return false
		}
	}
	return true
}
