package smvba

/*
forked from https://github.com/xygdys/Buada_BFT
*/

import (
	"fmt"
	"sync"
	"testing"

	"github.com/DyCAPSTeam/DyCAPS/internal/party"
	"github.com/DyCAPSTeam/DyCAPS/pkg/utils"
)

func TestMainProcess(t *testing.T) {
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883"}

	N := uint32(4)
	F := uint32(1)
	sk, pk := party.SigKeyGen(N, 2*F+1)

	var p []*party.HonestParty = make([]*party.HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = party.NewHonestParty(N, F, i, ipList, portList, pk, sk[i])
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
	}

	testNum := 200
	var wg sync.WaitGroup
	var mu sync.Mutex
	result := make([][][]byte, testNum)

	for k := 0; k < testNum; k++ {
		ID := utils.IntToBytes(k)
		for i := uint32(0); i < N; i++ {
			wg.Add(1)
			value := make([]byte, 1)
			value[0] = byte(i)
			validation := make([]byte, 1)

			go func(i uint32, k int) {
				ans := MainProcess(p[i], ID, value, validation)
				fmt.Println("epoch", k, "party", i, "decide:", ans)
				mu.Lock()
				result[k] = append(result[k], ans)
				mu.Unlock()
				wg.Done()

			}(i, k)

		}

	}
	wg.Wait()
	for k := 0; k < testNum; k++ {
		for i := uint32(1); i < N; i++ {
			if result[k][i][0] != result[k][i-1][0] {
				t.Error()
			}
		}
	}
}
