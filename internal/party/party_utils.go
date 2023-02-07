package party

import (
	"errors"
	"fmt"
	"github.com/DyCAPSTeam/DyCAPS/internal/bls"
	"github.com/DyCAPSTeam/DyCAPS/pkg/core"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"google.golang.org/protobuf/proto"
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

//pad a polynomial in coefficient form to MaxWidth
func PadCoeff(poly_coeff []bls.Fr, MaxWidth uint64) []bls.Fr {
	n := len(poly_coeff)
	if uint64(n) > MaxWidth {
		log.Fatalln("len(poly_coeff)>Maxwidth in function PadCoeff.n=", len(poly_coeff), "and MaxWidth=", MaxWidth)
	}
	ans := make([]bls.Fr, MaxWidth)
	for i := 0; i < n; i++ {
		bls.CopyFr(&ans[i], &poly_coeff[i])
	}
	for i := n; uint64(i) < MaxWidth; i++ {
		ans[i] = bls.ZERO
	}
	return ans
}

//get the lagrange coefficients at index "targetIndex", with known indexes x[].
//remenber to allocate memory for target[] before using this function.
func GetLagrangeCoefficients(deg uint32, x []bls.Fr, targetIndex bls.Fr, lambda []bls.Fr) {
	if uint32(len(x)) != deg+1 {
		panic("number of known indexes != deg + 1")
	}

	for i := uint32(0); i <= deg; i++ {
		res := bls.ONE
		for j := uint32(0); j <= deg; j++ {
			if j != i {
				tmp := bls.ZERO
				bls.SubModFr(&tmp, &targetIndex, &x[j])
				tmp2 := bls.ZERO
				bls.MulModFr(&tmp2, &res, &tmp)
				bls.CopyFr(&res, &tmp2)

				bls.SubModFr(&tmp, &x[i], &x[j])
				bls.InvModFr(&tmp2, &tmp)
				bls.MulModFr(&tmp, &tmp2, &res)
				bls.CopyFr(&res, &tmp)
			}
		}
		bls.CopyFr(&lambda[i], &res)
	}
}

func EncapsulateVSSSend(pi *Pi, BijList []bls.Fr, WBijList []bls.G1Point, F uint32) []byte {
	var msg = new(protobuf.VSSSend)
	msg.Pi = new(protobuf.Pi)
	msg.Pi.Gs = bls.ToCompressedG1(&pi.Gs)

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
			msg.WBijList[j] = bls.ToCompressedG1(&WBijList[j])

			tmp1 := bls.FrTo32(&BijList[j]) //from array to slice
			tmp2 := make([]byte, 32)
			copy(tmp2, tmp1[:])
			msg.BijList[j] = tmp2

			msg.Pi.PiContents[j].J = j
			msg.Pi.PiContents[j].CZj = bls.ToCompressedG1(&pi.PiContents[j].CZj)
			msg.Pi.PiContents[j].CBj = bls.ToCompressedG1(&pi.PiContents[j].CBj)
			msg.Pi.PiContents[j].WZ0 = bls.ToCompressedG1(&pi.PiContents[j].WZ0)
			msg.Pi.PiContents[j].GFj = bls.ToCompressedG1(&pi.PiContents[j].gFj)
		}
	}
	data, _ := proto.Marshal(msg)
	return data
}

func (pi *Pi) SetFromVSSMessage(m *protobuf.Pi, F uint32) {

	Gs_raw, _ := bls.FromCompressedG1(m.Gs)
	bls.CopyG1(&pi.Gs, Gs_raw)

	for j := uint32(1); j <= 2*F+1; j++ {

		CBj_raw, _ := bls.FromCompressedG1(m.PiContents[j].CBj)
		CZj_raw, _ := bls.FromCompressedG1(m.PiContents[j].CZj)
		WZ0_raw, _ := bls.FromCompressedG1(m.PiContents[j].WZ0)
		gFj_raw, _ := bls.FromCompressedG1(m.PiContents[j].GFj)

		bls.CopyG1(&pi.PiContents[j].CBj, CBj_raw)
		bls.CopyG1(&pi.PiContents[j].CZj, CZj_raw)
		bls.CopyG1(&pi.PiContents[j].WZ0, WZ0_raw)
		bls.CopyG1(&pi.PiContents[j].gFj, gFj_raw)

		pi.PiContents[j].j = j
	}
}

func (pi *Pi) Set(src *Pi, F uint32) {
	bls.CopyG1(&pi.Gs, &src.Gs)
	for j := 1; uint32(j) <= 2*F+1; j++ {
		bls.CopyG1(&pi.PiContents[j].CBj, &src.PiContents[j].CBj)
		bls.CopyG1(&pi.PiContents[j].CZj, &src.PiContents[j].CZj)
		bls.CopyG1(&pi.PiContents[j].WZ0, &src.PiContents[j].WZ0)
		bls.CopyG1(&pi.PiContents[j].gFj, &src.PiContents[j].gFj)
		pi.PiContents[j].j = src.PiContents[j].j
	}
}

func GetSamples(ExpIndexes []int, Values []bls.Fr, MaxWidth uint64) []*bls.Fr {
	if !bls.IsPowerOfTwo(MaxWidth) {
		log.Fatalln("maxWidth not power of 2 in function GetSamples().")
	}
	if len(ExpIndexes) != len(Values) {
		log.Fatalln("len(ExpIndexes) != len(Values) in function GetSamples()")
	}
	if uint64(len(ExpIndexes)) > MaxWidth {
		log.Fatalln("len(ExpIndexes) > MaxWidth in function GetSamples()")
	}
	ans := make([]*bls.Fr, MaxWidth)

	for i := 0; i < len(ExpIndexes); i++ {
		ans[ExpIndexes[i]] = &Values[i]
	}

	return ans
}

func PolyToString(poly_coeff []bls.Fr) string {
	var s = ""

	for i := len(poly_coeff) - 1; i >= 0; i-- {
		// skip zero coefficients but the constant term
		if i != 0 && bls.EqualZero(&poly_coeff[i]) == true {
			continue
		}
		if i > 0 {
			s += fmt.Sprintf("%s x^%d + ", poly_coeff[i].String(), i)
		} else {
			// constant term
			s += fmt.Sprintf("%s", poly_coeff[i].String())
		}
	}
	return s
}

//InterpolateComOrWit interpolates commitment or witness according to the first 2t+1 elements
func (p *HonestParty) InterpolateComOrWit(degree uint32, targetIndex uint32, List []bls.G1Point) bls.G1Point {
	CWList := make([]bls.G1Point, degree+1)
	copy(CWList, List)

	// degree=2t

	if targetIndex > 0 && targetIndex < degree+1 {
		return CWList[targetIndex-1]
	} else {
		if targetIndex == 0 || targetIndex <= 3*p.F+1 {
			return *bls.LinCombG1(List, p.LagrangeCoefficients[targetIndex])
		}

		lambda := make([]bls.Fr, degree+1)
		knownIndexes := make([]bls.Fr, degree+1)

		for j := uint32(0); j < degree+1; j++ {
			bls.AsFr(&knownIndexes[j], uint64(j+1)) //known indexes: 1, ..., deg+1
		}

		var target bls.Fr
		bls.AsFr(&target, uint64(targetIndex))
		GetLagrangeCoefficients(degree, knownIndexes, target, lambda)

		return *bls.LinCombG1(List, lambda)
	}
}

func (p *HonestParty) InterpolateComOrWitByKnownIndexes(degree uint32, targetIndex uint32, knownIndexes []bls.Fr, List []bls.G1Point) bls.G1Point {

	//check whether to use InterpolateComOrWit()
	var isSimple = true
	for i := 0; uint32(i) < degree+1; i++ {
		var tmp bls.Fr
		bls.AsFr(&tmp, uint64(i+1))
		if !bls.EqualFr(&knownIndexes[i], &tmp) {
			isSimple = false
			break
		}
	}
	if isSimple {
		return p.InterpolateComOrWit(degree, targetIndex, List)
	} else {
		lambda := make([]bls.Fr, degree+1)
		var target bls.Fr
		bls.AsFr(&target, uint64(targetIndex))
		GetLagrangeCoefficients(degree, knownIndexes, target, lambda)
		return *bls.LinCombG1(List, lambda)
	}
}
