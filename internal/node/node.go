package node

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DyCAPSTeam/DyCAPS/pkg/core"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/DyCAPSTeam/DyCAPS/internal/commitment"
	// "github.com/DyCAPSTeam/DyCAPS/internal/interpolation"
	"github.com/DyCAPSTeam/DyCAPS/internal/polypoint"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"

	// pb "github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"github.com/Nik-U/pbc"
	"github.com/ncw/gmp"
	// "github.com/golang/protobuf/proto"
	// "github.com/ncw/gmp"
	// "google.golang.org/grpc"
)

//Party is a interface of consensus parties
type Party interface {
	send(m *protobuf.Message, des uint32) error
	broadcast(m *protobuf.Message) error
	getMessageWithType(messageType string) (*protobuf.Message, error)
}

// Network Node Structure
type Node struct {
	// Metadata Path
	metadataPath string
	// Basic Sharing Information
	// [+] Label of Node
	label int
	// [+] Number of Nodes
	counter int
	// [+] Polynomial Degree
	degree int
	// [+] Prime Defining Group Z_p
	p *gmp.Int

	// IP Information
	// [+] Node IP Address List
	ipList []string
	// [+] Node send channel list
	sendChannels []chan *protobuf.Message
	// [+] Node dispatche channel List
	dispatcheChannels [](*sync.Map)

	// Utilities
	// [+] Rand Source
	randState *rand.Rand
	// [+] Commitment
	dc  *commitment.DLCommit
	dpc *commitment.DLPolyCommit

	// Sharing State
	// [+] Polynomial State
	secretShares []*polypoint.PolyPoint

	// Reconstruction Phase
	// [+] Polynomial Reconstruction State
	recShares []*polypoint.PolyPoint
	// [+] Counter of Polynomial Reconstruction State
	recCnt *int
	// [+] Mutex for everything
	mutex sync.Mutex
	// [+] Reconstructed Polynomial
	recPoly *polyring.Polynomial

	// Proactivization Phase
	// [+] Lagrange Coefficient
	lambda []*gmp.Int
	// [+] Zero Shares
	zeroShares []*gmp.Int
	// [+] Counter of Messages Received
	zeroCnt *int
	// [+] Zero Share
	zeroShare *gmp.Int
	// [+] Proactivization Polynomial
	proPoly *polyring.Polynomial
	// [+] Commitment & Witness in Phase 2
	zeroShareCmt *pbc.Element
	zeroPolyCmt  *pbc.Element
	zeroPolyWit  *pbc.Element

	// Share Distribution Phase
	// [+] New Poynomials
	newPoly *polyring.Polynomial
	// [+] Counter for New Secret Shares
	shareCnt *int

	// Commitment and Witness from BulletinBoard
	oldPolyCmt      []*pbc.Element
	zerosumShareCmt []*pbc.Element
	zerosumPolyCmt  []*pbc.Element
	zerosumPolyWit  []*pbc.Element
	midPolyCmt      []*pbc.Element
	newPolyCmt      []*pbc.Element

	// Metrics
	// measuring the time for each phase
	totMsgSize *int
	s1         *time.Time
	e1         *time.Time
	s2         *time.Time
	e2         *time.Time
	s3         *time.Time
	e3         *time.Time

	// Initialize Flag
	iniflag *bool
}

//InitReceiveChannel setup the listener and Init the receiveChannel
func (p *Node) InitReceiveChannel() error {
	port := strings.Split(p.ipList[p.label], ":")[1]
	p.dispatcheChannels = core.MakeDispatcheChannels(core.MakeReceiveChannel(port), uint32(p.counter))
	return nil
}

//InitSendChannel setup the sender and Init the sendChannel, please run this after initializing all party's receiveChannel
func (p *Node) InitSendChannel() error {
	for i := uint32(0); i < uint32(p.counter); i++ {
		p.sendChannels[i] = core.MakeSendChannel(p.ipList[i])
	}
	fmt.Println(p.sendChannels, "====")
	return nil
}

//Send a message to party des
func (p *Node) Send(m *protobuf.Message, des uint32) error {
	if !p.checkInit() {
		return errors.New("This party hasn't been initialized")
	}
	if des < uint32(p.counter) {
		p.sendChannels[des] <- m
		return nil
	}
	return errors.New("Destination id is too large")
}

//Broadcast a message to all parties
func (p *Node) Broadcast(m *protobuf.Message) error {
	if !p.checkInit() {
		return errors.New("This party hasn't been initialized")
	}
	for i := uint32(0); i < uint32(p.counter); i++ {
		err := p.Send(m, i)
		if err != nil {
			return err
		}
	}
	return nil
}

//GetMessage Try to get a message according to senderID, messageType, ID
func (p *Node) GetMessage(sender uint32, messageType string, ID []byte) (*protobuf.Message, bool) {
	if !p.checkInit() {
		log.Fatalln("This party hasn't been initialized")
		return nil, false
	}
	channel, ok := core.GetDispatcheChannel(messageType, ID, p.dispatcheChannels[sender])
	if ok {
		m := <-channel
		return m, true
	}
	return nil, false
}

func (p *Node) checkInit() bool {
	if p.sendChannels == nil {
		return false
	}
	return true
}

func ReadIpList(metadataPath string) []string {
	ipData, err := ioutil.ReadFile(metadataPath + "/ip_list")
	if err != nil {
		log.Fatalf("node failed to read iplist %v\n", err)
	}
	return strings.Split(string(ipData), "\n")
}

// New a Node
func New(degree int, label int, counter int, metadataPath string) (Node, error) {
	f, _ := os.Create(metadataPath + "/log" + strconv.Itoa(label))
	defer f.Close()

	ipRaw := ReadIpList(metadataPath)[0 : counter+1]
	ipList := ipRaw[1 : counter+1]

	sendChannels := make([]chan *protobuf.Message, counter)
	dispatcheChannels := make([]*sync.Map, counter)

	if label < 0 {
		return Node{}, errors.New(fmt.Sprintf("label must be non-negative, got %d", label))
	}

	if counter < 0 {
		return Node{}, errors.New(fmt.Sprintf("counter must be non-negtive, got %d", counter))
	}

	randState := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	fixedRandState := rand.New(rand.NewSource(int64(3)))
	dc := commitment.DLCommit{}
	dc.SetupFix()
	dpc := commitment.DLPolyCommit{}
	dpc.SetupFix(counter)

	p := gmp.NewInt(0)
	p.SetString("57896044618658097711785492504343953926634992332820282019728792006155588075521", 10)
	lambda := make([]*gmp.Int, counter)
	// Calculate Lagrange Interpolation
	denominator := polyring.NewOne()
	tmp, _ := polyring.New(1)
	tmp.SetCoefficient(1, 1)
	for i := 0; i < counter; i++ {
		tmp.GetPtrToConstant().Neg(gmp.NewInt(int64(i + 1)))
		denominator.MulSelf(tmp)
	}
	for i := 0; i < counter; i++ {
		lambda[i] = gmp.NewInt(0)
		deno, _ := polyring.New(0)
		tmp.GetPtrToConstant().Neg(gmp.NewInt(int64(i + 1)))
		deno.Div2(denominator, tmp)
		deno.EvalMod(gmp.NewInt(0), p, lambda[i])
		inter := gmp.NewInt(0)
		deno.EvalMod(gmp.NewInt(int64(i+1)), p, inter)
		interInv := gmp.NewInt(0)
		interInv.ModInverse(inter, p)
		lambda[i].Mul(lambda[i], interInv)
		lambda[i].Mod(lambda[i], p)
	}

	zeroShares := make([]*gmp.Int, counter)
	for i := 0; i < counter; i++ {
		zeroShares[i] = gmp.NewInt(0)
	}
	zeroCnt := 0
	zeroShare := gmp.NewInt(0)

	recShares := make([]*polypoint.PolyPoint, counter)
	recCnt := 0

	secretShares := make([]*polypoint.PolyPoint, counter)
	poly, err := polyring.NewRand(degree, fixedRandState, p)
	for i := 0; i < counter; i++ {
		if err != nil {
			panic("Error initializing random poly")
		}
		x := int32(label)
		y := gmp.NewInt(0)
		w := dpc.NewG1()
		poly.EvalMod(gmp.NewInt(int64(x)), p, y)
		dpc.CreateWitness(w, poly, gmp.NewInt(int64(x)))
		secretShares[i] = polypoint.NewPoint(x, y, w)
	}

	proPoly, _ := polyring.New(degree)
	recPoly, _ := polyring.New(degree)
	newPoly, _ := polyring.New(degree)
	shareCnt := 0

	oldPolyCmt := make([]*pbc.Element, counter)
	midPolyCmt := make([]*pbc.Element, counter)
	newPolyCmt := make([]*pbc.Element, counter)
	for i := 0; i < counter; i++ {
		oldPolyCmt[i] = dpc.NewG1()
		midPolyCmt[i] = dpc.NewG1()
		newPolyCmt[i] = dpc.NewG1()
	}

	zeroShareCmt := dc.NewG1()
	zeroPolyCmt := dpc.NewG1()
	zeroPolyWit := dpc.NewG1()

	zerosumShareCmt := make([]*pbc.Element, counter)
	zerosumPolyCmt := make([]*pbc.Element, counter)
	zerosumPolyWit := make([]*pbc.Element, counter)

	for i := 0; i < counter; i++ {
		zerosumShareCmt[i] = dc.NewG1()
		zerosumPolyCmt[i] = dpc.NewG1()
		zerosumPolyWit[i] = dpc.NewG1()
	}

	totMsgSize := 0
	s1 := time.Now()
	e1 := time.Now()
	s2 := time.Now()
	e2 := time.Now()
	s3 := time.Now()
	e3 := time.Now()

	iniflag := true
	return Node{
		metadataPath:      metadataPath,
		ipList:            ipList,
		sendChannels:      sendChannels,
		dispatcheChannels: dispatcheChannels,
		degree:            degree,
		label:             label,
		counter:           counter,
		randState:         randState,
		dc:                &dc,
		dpc:               &dpc,
		p:                 p,
		lambda:            lambda,
		zeroShares:        zeroShares,
		zeroCnt:           &zeroCnt,
		zeroShare:         zeroShare,
		secretShares:      secretShares,
		recShares:         recShares,
		recCnt:            &recCnt,
		recPoly:           &recPoly,
		proPoly:           &proPoly,
		newPoly:           &newPoly,
		shareCnt:          &shareCnt,
		oldPolyCmt:        oldPolyCmt,
		midPolyCmt:        midPolyCmt,
		newPolyCmt:        newPolyCmt,
		zeroShareCmt:      zeroShareCmt,
		zeroPolyCmt:       zeroPolyCmt,
		zeroPolyWit:       zeroPolyWit,
		zerosumShareCmt:   zerosumShareCmt,
		zerosumPolyCmt:    zerosumPolyCmt,
		zerosumPolyWit:    zerosumPolyWit,
		totMsgSize:        &totMsgSize,
		s1:                &s1,
		e1:                &e1,
		s2:                &s2,
		e2:                &e2,
		s3:                &s3,
		e3:                &e3,
		// nConn:           nConn,
		// nClient:         nClient,
		iniflag: &iniflag,
	}, nil
}

// start a node
//TODO
func (node *Node) Serve(aws bool) {
	port := node.ipList[node.label-1]
	if aws {
		port = "0.0.0.0:12001"
	}
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("node failed to listen %v", err)
	}
	s := grpc.NewServer()
	// pb.RegisterNodeServiceServer(s, node)
	reflection.Register(s)
	log.Printf("node %d serve on %s", node.label, port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("node failed to serve %v", err)
	}
}
