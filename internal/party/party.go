package party

import (
	"github.com/DyCAPSTeam/DyCAPS/internal/bls"
	"github.com/DyCAPSTeam/DyCAPS/internal/polycommit"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"sync"
	"time"
)

//Party is an interface of committee members
type Party interface {
	send(m *protobuf.Message, des uint32) error
	broadcast(m *protobuf.Message) error
	getMessageWithType(messageType string) (*protobuf.Message, error)
}

type PiContent struct {
	j uint32
	//In DyCAPS.Share, CBj refers to commitment to B(x,w^index) generated by dealer.
	//In DyCAPS.Handoff, CBj refers to commitment to Q_i(x,w^index) generated by Party i
	CBj bls.G1Point
	CZj bls.G1Point //Z_j(x)=R_j(x)-R_j(w^0)
	WZ0 bls.G1Point //witness of Z_j(w^0)=0
	gFj bls.G1Point //g^F(w^j), F(w^j) is of t degree
}

type Pi struct {
	Gs         bls.G1Point // g^s
	PiContents []PiContent //indices start from 1
}

//HonestParty is a struct of honest committee members
//TODO: add epoch number into this struct
type HonestParty struct {
	e            uint32   // epoch number
	N            uint32   // committee size
	F            uint32   // number of corrupted parties
	PID          uint32   // id of this party
	ipList       []string // ip list of the current committee
	portList     []string // port list of the current committee
	sendChannels []chan *protobuf.Message

	ipListNext         []string // ip list of the new committee
	portListNext       []string // port list of the new committee
	sendToNextChannels []chan *protobuf.Message

	dispatchChannels *sync.Map

	FS       *polycommit.FFTSettings
	KZG      *polycommit.KZGSettings
	mutexKZG *sync.Mutex

	SysSuite *pairing.SuiteBn256
	SigPK    *share.PubPoly  //tss pk
	SigSK    *share.PriShare //tss sk

	Proof *Pi //pi

	fullShare    []bls.Fr // B(i,y), i=p.PID+1
	reducedShare []bls.Fr // B(x,index), index=p.PID+1

	witness        []bls.G1Point //witness[index] = w_B(i,*), each party has at least 2t+1 witness
	witnessIndexes []bls.Fr      //witnessIndexes[index] means the * value of witness[index]

	LagrangeCoefficients [][]bls.Fr //lagrange coefficients when using f(1),f(2),...,f(2t+1) to calculate f(k) for 0 <= k <= 3*f+1.Indices start from 0

	VSSStart             time.Time
	VSSEnd               time.Time
	PrepareStart_old     time.Time
	PrepareEnd_old       time.Time
	PrepareStart_new     time.Time
	PrepareEnd_new       time.Time
	ShareReduceStart_old time.Time
	ShareReduceEnd_old   time.Time
	ShareReduceStart_new time.Time
	ShareReduceEnd_new   time.Time
	ProactivizeStart     time.Time
	ProactivizeEnd       time.Time
	ShareDistStart       time.Time
	ShareDistEnd         time.Time
}

//
//// SRecElement is the set of elements for recover
//type SRecElement struct {
//	index uint32
//	v     *gmp.Int
//}
//
//// SSigElement is the set of signatures
//type SSigElement struct {
//	index uint32
//	Sig   []byte
//}
//
//// SComElement is the set of commitments
//type SComElement struct {
//	index uint32
//	CB    *pbc.Element
//}
//
//// SBElement is the set of elements for full shares
//type SBElement struct {
//	index uint32
//	CB    *pbc.Element
//	v     *gmp.Int
//	w     *pbc.Element
//}
//
//type RecoverMsg struct {
//	sender   uint32
//	index    uint32
//	v        *gmp.Int
//	w        *pbc.Element
//	sigShare []byte
//}

//NewHonestParty returns a new honest party object
func NewHonestParty(e uint32, N uint32, F uint32, pid uint32, ipList []string, portList []string, ipListNext []string, portListNext []string, sigPK *share.PubPoly, sigSK *share.PriShare) *HonestParty {
	var SysSuite = pairing.NewSuiteBn256()

	secretG1, secretG2 := polycommit.GenerateTestingSetup("46015081477078601964787943834255776126696019968430095991502055467779756761969", uint64(F+1))
	KZG := polycommit.NewKZGSettings(nil, secretG1, secretG2)

	var mutexKZG sync.Mutex

	piInit := new(Pi)
	piInit.Init(F)
	witness := make([]bls.G1Point, 2*F+1)
	witnessIndexes := make([]bls.Fr, 2*F+1)

	for i := 0; uint32(i) < 2*F+1; i++ {
		witness[i] = bls.ZeroG1
		witnessIndexes[i] = bls.ZERO
	}

	LagrangeCoefficients := make([][]bls.Fr, N+1)
	knownIndices := make([]bls.Fr, 2*F+1)
	for i := 0; uint32(i) < 2*F+1; i++ {
		bls.AsFr(&knownIndices[i], uint64(i+1))
	}

	for i := 0; uint32(i) <= N; i++ {
		LagrangeCoefficients[i] = make([]bls.Fr, 2*F+1)
		var target bls.Fr
		bls.AsFr(&target, uint64(i))
		GetLagrangeCoefficients(2*F, knownIndices, target, LagrangeCoefficients[i])
	}

	p := HonestParty{
		e:                  e,
		N:                  N,
		F:                  F,
		PID:                pid,
		ipList:             ipList,
		portList:           portList,
		ipListNext:         ipListNext,
		portListNext:       portListNext,
		sendChannels:       make([]chan *protobuf.Message, N),
		sendToNextChannels: make([]chan *protobuf.Message, N),

		SysSuite: SysSuite,
		SigPK:    sigPK,
		SigSK:    sigSK,

		KZG:      KZG,
		mutexKZG: &mutexKZG,

		Proof: piInit,

		fullShare:      make([]bls.Fr, 2*F+1),
		reducedShare:   make([]bls.Fr, F+1),
		witness:        witness,
		witnessIndexes: witnessIndexes,

		LagrangeCoefficients: LagrangeCoefficients,

		VSSStart:             time.Now(),
		VSSEnd:               time.Now(),
		PrepareStart_old:     time.Now(),
		PrepareEnd_old:       time.Now(),
		PrepareStart_new:     time.Now(),
		PrepareEnd_new:       time.Now(),
		ShareReduceStart_old: time.Now(),
		ShareReduceEnd_old:   time.Now(),
		ShareReduceStart_new: time.Now(),
		ShareReduceEnd_new:   time.Now(),
		ProactivizeStart:     time.Now(),
		ProactivizeEnd:       time.Now(),
		ShareDistStart:       time.Now(),
		ShareDistEnd:         time.Now(),
	}
	return &p
}
