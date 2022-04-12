package party

import (
	"Buada_BFT/pkg/protobuf"
	"fmt"
	"strconv"
	"testing"
)

func TestParty(t *testing.T) {
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883"}

	N := uint32(4)
	F := uint32(1)
	sk, pk := SigKeyGen(N, F)

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

	for i := uint32(0); i < N; i++ {
		go p[i].Broadcast(&protobuf.Message{
			Type:   "Hello",
			Sender: uint32(i),
			Data:   []byte("This is party " + strconv.Itoa(int(i))),
		})
	}

	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			for j := uint32(0); j < N; j++ {
				m, _ := p[i].GetMessage(j, "Hello", []byte{0})

				fmt.Println("Party " + strconv.Itoa(int(i)) + ": Receive a Message:" + string(m.GetData()) + " from " + strconv.Itoa(int(j)))
			}
		}(i)
	}

	for {

	}
}
