package main

// import (
// 	"fmt"
// 	"sync"
// 	"time"

// 	"github.com/DyCAPSTeam/DyCAPS/internal/party"
// 	"github.com/DyCAPSTeam/DyCAPS/internal/smvba"
// )

// func main() {
// 	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
// 	portList := []string{"8880", "8881", "8882", "8883"}

// 	N := uint32(4)
// 	F := uint32(1)
// 	sk, pk := party.SigKeyGen(N, 2*F+1)

// 	var p []*party.HonestParty = make([]*party.HonestParty, N)
// 	for i := uint32(0); i < N; i++ {
// 		p[i] = party.NewHonestParty(N, F, i, ipList, portList, pk, sk[i])
// 	}

// 	for i := uint32(0); i < N; i++ {
// 		p[i].InitReceiveChannel()
// 	}

// 	for i := uint32(0); i < N; i++ {
// 		p[i].InitSendChannel()
// 	}
// 	for k := 0; k < 10; k++ {
// 		var wg sync.WaitGroup

// 		ID := []byte{byte(k)}
// 		for i := uint32(0); i < N; i++ {
// 			wg.Add(1)
// 			value := make([]byte, 1)
// 			value[0] = byte(i)
// 			validation := make([]byte, 1)

// 			time.Sleep(time.Millisecond * 500)
// 			if i == 3 {
// 				time.Sleep(time.Millisecond * 100)
// 			}
// 			go func(i uint32) {
// 				result := smvba.MainProcess(p[i], ID, value, validation)
// 				fmt.Println("party", i, "decide:", result)
// 				wg.Done()
// 			}(i)
// 		}

// 		wg.Wait()
// 	}
// }
