package party

import (
	"fmt"
	"strconv"
	"sync"
	"testing"

	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	_ "github.com/DyCAPSTeam/DyCAPS/pkg/utils"
)

func TestRBC(t *testing.T) {
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"10080", "10081", "10082", "10083", "10084", "10085", "10086", "10087", "10088", "10089", "10090", "10091", "10092"}
	ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portListNext := []string{"10190", "10191", "10192", "10193", "10194", "10195", "10196", "10197", "10198", "10199", "10200", "10201", "10202"}
	N := uint32(13)
	F := uint32(4)
	//KZG.SetupFix(int(2 * F))
	sk, pk := SigKeyGen(N, N-F)

	var p []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(0, N, F, i, ipList, portList, ipListNext, portListNext, pk, sk[i])
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
	for i := uint32(0); i < N; i++ {
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
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"10080", "10081", "10082", "10083", "10084", "10085", "10086", "10087", "10088", "10089", "10090", "10091", "10092"}
	ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portListNext := []string{"10190", "10191", "10192", "10193", "10194", "10195", "10196", "10197", "10198", "10199", "10200", "10201", "10202"}
	N := uint32(7)
	F := uint32(1)
	//KZG.SetupFix(int(2 * F))
	sk, pk := SigKeyGen(N, N-F)

	var p []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(0, N, F, i, ipList, portList, ipListNext, portListNext, pk, sk[i])
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

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"10080", "10081", "10082", "10083", "10084", "10085", "10086", "10087", "10088", "10089", "10090", "10091", "10092"}
	ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portListNext := []string{"10190", "10191", "10192", "10193", "10194", "10195", "10196", "10197", "10198", "10199", "10200", "10201", "10202"}
	N := uint32(13)
	F := uint32(4)
	//KZG.SetupFix(int(2 * F))
	sk, pk := SigKeyGen(N, 2*F+1)

	var p []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(0, N, F, i, ipList, portList, ipListNext, portListNext, pk, sk[i])
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
			// time.Sleep(250000000)
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
