package party

import (
	"fmt"
	"sync"
	"testing"

	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	_ "github.com/DyCAPSTeam/DyCAPS/pkg/utils"
)

func TestRBC(t *testing.T) {
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886"}

	N := uint32(7)
	F := uint32(2)
	sk, pk := SigKeyGen(N, 2*F+1)

	var p []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(N, F, i, ipList, portList, pk, sk[i])
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
	}

	var wg sync.WaitGroup

	var ID = []byte("abc")
	wg.Add(int(3*F + 1))
	for i := uint32(0); i < N; i++ { // there is one malicious node,who doesn't send any Message
		if i != 1 && i != 2 {
			go func(i uint32) {
				m := p[i].RBCReceiver(ID)
				fmt.Println(i, " output RBC message: ", m)
				wg.Done()
			}(i)
		}
	}

	go func() {
		p[0].RBCSender(&protobuf.Message{Type: "Test", Sender: uint32(0), Id: ID, Data: []byte("hello")}, ID)
	}()

	wg.Wait()
	fmt.Println("RBC Finish")
}
