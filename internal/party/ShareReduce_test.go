package party

import (
	"github.com/DyCAPSTeam/DyCAPS/internal/bls"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"log"
	"sync"
	"testing"
)

func TestShareReduce(t *testing.T) {

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886"}
	ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portListNext := []string{"8887", "8888", "8889", "8890", "8891", "8892", "8893"}
	N := uint32(7)
	F := uint32(2)
	sk, pk := SigKeyGen(N+1, 2*F+2) // wrong usage, but it doesn't matter here
	skNew, pkNew := SigKeyGen(N, 2*F+1)
	//KZG.SetupFix(int(2 * F))

	var p []*HonestParty = make([]*HonestParty, N)
	var pNext []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(0, N, F, i, ipList, portList, ipListNext, portListNext, pk, sk[i])
		pNext[i] = NewHonestParty(1, N, F, i, ipListNext, portListNext, nil, nil, pkNew, skNew[i])
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
		pNext[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
		p[i].InitSendToNextChannel()
		pNext[i].InitSendChannel()
	}

	var client Client

	bls.AsFr(&client.s, uint64(111111111111111))

	client.HonestParty = NewHonestParty(0, N, F, 0x7fffffff, ipList, portList, ipListNext, portListNext, pk, sk[2*F+1])
	err := client.InitSendChannel()
	if err != nil {
		log.Printf("[VSS] Client InitSendChannel err: %v\n", err)
	}

	client.Share([]byte("VSSshare"))
	log.Printf("[VSS] VSSshare done\n")

	var wg sync.WaitGroup

	wg.Add(int(N))
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			log.Printf("[VSS] Party %v starting...\n", i)
			p[i].VSSShareReceive([]byte("VSSshare"))
			wg.Done()
			log.Printf("[VSS] Party %v done\n", i)
		}(i)
	}
	wg.Wait()

	log.Printf("[VSS] VSS finished\n")
	log.Printf("[ShstreReduce] ShareReduce starting...\n")

	wg.Add(int(N))
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			pNext[i].PrepareReceive([]byte("shareReduce"))
			pNext[i].ShareReduceReceive([]byte("shareReduce"))
			wg.Done()
		}(i)
	}
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			p[i].PrepareSend([]byte("shareReduce"))
			p[i].ShareReduceSend([]byte("shareReduce"))
		}(i)
	}
	wg.Wait()

	var reducedShareAtZero = make([]bls.Fr, 2*F+1)
	var knownIndexes = make([]bls.Fr, 2*F+1)

	for i := 0; uint32(i) < 2*F+1; i++ {

		bls.AsFr(&knownIndexes[i], uint64(i+1))
		bls.EvalPolyAt(&reducedShareAtZero[i], pNext[i].reducedShare, &bls.ZERO)
	}
	sPoly := polyring.LagrangeInterpolate(int(2*F), knownIndexes, reducedShareAtZero)
	log.Println("F(x):", PolyToString(sPoly))
	var sRecovered bls.Fr
	bls.EvalPolyAt(&sRecovered, sPoly, &bls.ZERO)
	log.Println("[ShareReduce] Finally recovered secret:", sRecovered.String())
}
