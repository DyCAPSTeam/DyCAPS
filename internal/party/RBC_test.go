package party

import (
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	_ "github.com/DyCAPSTeam/DyCAPS/pkg/utils"
	"github.com/Nik-U/pbc"
	"github.com/ncw/gmp"
)

func TestRBC(t *testing.T) {

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886"}
	ipList_next := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList_next := []string{"8887", "8888", "8889", "8890", "8891", "8892", "8893"}
	N := uint32(7)
	F := uint32(2)
	KZG.SetupFix(int(2 * F))
	sk, pk := SigKeyGen(N, N-F)
	pi_init := new(Pi)
	pi_init.Init(F)
	witness_init := make([]*pbc.Element, N-F)
	witness_init_indexes := make([]*gmp.Int, N-F)
	for i := 0; uint32(i) < N-F; i++ {
		witness_init[i] = KZG.NewG1()
		witness_init_indexes[i] = gmp.NewInt(0)
	}

	var p []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(N, F, i, ipList, portList, ipList_next, portList_next, pk, sk[i], pi_init, witness_init, witness_init_indexes)
	}
	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
	}

	var wg sync.WaitGroup
	var ID = []byte("abc")
	wg.Add(int(N))
	for i := uint32(0); i < N; i++ { // there is one malicious node, who doesn't send any Message
		go func(i uint32) {
			m := p[i].RBCReceive(ID)
			fmt.Println(i, " output RBC message: ", m)
			wg.Done()
		}(i)
	}

	go func() {
		p[0].RBCSend(&protobuf.Message{Type: "Test", Sender: uint32(0), Id: ID, Data: []byte("helloworld")}, ID)
	}()

	wg.Wait()
	fmt.Println("RBC Finish")
}

func TestRBCExlude(t *testing.T) {
	// test malicious sender: excluding one party
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886"}
	ipList_next := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList_next := []string{"8887", "8888", "8889", "8890", "8891", "8892", "8893"}
	N := uint32(7)
	F := uint32(1)
	KZG.SetupFix(int(2 * F))
	sk, pk := SigKeyGen(N, N-F)
	pi_init := new(Pi)
	pi_init.Init(F)
	witness_init := make([]*pbc.Element, N-F)
	witness_init_indexes := make([]*gmp.Int, N-F)
	for i := 0; uint32(i) < N-F; i++ {
		witness_init[i] = KZG.NewG1()
		witness_init_indexes[i] = gmp.NewInt(0)
	}

	var p []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(N, F, i, ipList, portList, ipList_next, portList_next, pk, sk[i], pi_init, witness_init, witness_init_indexes)
	}
	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
	}

	var wg sync.WaitGroup
	var ID = []byte("abc")
	wg.Add(int(N))
	for i := uint32(0); i < N; i++ { // there is one malicious node, who doesn't send any Message
		go func(i uint32) {
			m := p[i].RBCReceive(ID)
			fmt.Println(i, " output RBC message: ", m)
			wg.Done()
		}(i)
	}

	go func() {
		excludedID := uint32(2)
		p[0].RBCSendExclude(&protobuf.Message{Type: "Test", Sender: uint32(0), Id: ID, Data: []byte("helloworld")}, ID, excludedID)
	}()

	wg.Wait()
	fmt.Println("RBC Finish")
}

func TestMultiRBC(t *testing.T) {

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886"}
	ipList_next := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList_next := []string{"8887", "8888", "8889", "8890", "8891", "8892", "8893"}
	N := uint32(4)
	F := uint32(1)
	KZG.SetupFix(int(2 * F))
	sk, pk := SigKeyGen(N, 2*F+1)
	pi_init := new(Pi)
	pi_init.Init(F)
	witness_init := make([]*pbc.Element, 2*F+1)
	witness_init_indexes := make([]*gmp.Int, 2*F+1)
	for i := 0; uint32(i) < 2*F+1; i++ {
		witness_init[i] = KZG.NewG1()
		witness_init_indexes[i] = gmp.NewInt(0)
	}

	var p []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(N, F, i, ipList, portList, ipList_next, portList_next, pk, sk[i], pi_init, witness_init, witness_init_indexes)
	}
	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
	}

	var wg sync.WaitGroup
	var ID = []byte("abc")
	wg.Add(int(3*F+1) * int(3*F+1))
	for i := uint32(0); i < N; i++ { // there is one malicious node,who doesn't send any Message
		for j := uint32(0); j < N; j++ {
			go func(i uint32, j uint32) {
				m := p[j].RBCReceive([]byte(string(ID) + strconv.Itoa(int(i))))
				fmt.Println(j, " output RBC message from ", i, ": ", m)
				wg.Done()
			}(i, j)
			time.Sleep(250000000)
		}
	}

	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			p[i].RBCSend(&protobuf.Message{Type: "Test", Sender: uint32(i), Id: ID, Data: []byte("helloworld by " + strconv.Itoa(int(i)))}, []byte(string(ID)+strconv.Itoa(int(i))))
		}(i)
	}

	wg.Wait()
	fmt.Println("RBC Finish")
}
