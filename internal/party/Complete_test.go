package party

import (
	"github.com/DyCAPSTeam/DyCAPS/internal/bls"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"log"
	"sync"
	"testing"
)

func TestCompleteProcess(t *testing.T) {

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889", "8890", "8891", "8892"}
	ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portListNext := []string{"8893", "8894", "8895", "8896", "8897", "8898", "8899", "8900", "8901", "8902", "8903", "8904", "8905"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := SigKeyGen(N, 2*F+1)
	skNew, pkNew := SigKeyGen(N, 2*F+1)

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
	var secret bls.Fr
	bls.AsFr(&secret, uint64(1111111111111112345))
	client.SetSecret(secret)
	client.HonestParty = NewHonestParty(0, N, F, 0x7fffffff, ipList, portList, ipListNext, portListNext, pk, nil)
	err := client.InitSendChannel()
	if err != nil {
		log.Printf("[VSS] Client InitSendChannel err: %v\n", err)
	}

	client.Share([]byte("vssshare"))
	log.Printf("[VSS] VSSshare done\n")

	var wg sync.WaitGroup

	wg.Add(int(N))
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			log.Printf("[VSS] Party %v starting...\n", i)
			p[i].VSSShareReceive([]byte("vssshare"))
			wg.Done()
		}(i)
	}
	wg.Wait()

	log.Printf("[VSS] VSS finished\n")

	log.Printf("[Prepare] Prepare starting\n")
	wg.Add(int(N))
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			pNext[i].PrepareReceive([]byte("Prepare"))
			wg.Done()
		}(i)
	}

	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			p[i].PrepareSend([]byte("Prepare"))
		}(i)
	}
	wg.Wait()
	log.Printf("[Prepare] Prepare finished\n")

	log.Printf("[ShareReduce] ShareReduce starting...\n")

	wg.Add(int(N))
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			pNext[i].ShareReduceReceive([]byte("shareReduce"))
			wg.Done()
		}(i)
	}

	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			p[i].ShareReduceSend([]byte("shareReduce"))
		}(i)
	}
	wg.Wait()

	log.Printf("[ShstreReduce] ShareReduce finished\n")
	log.Printf("[Proactivize] Proactivize starting\n")

	wg.Add(int(N))
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			pNext[i].ProactivizeAndShareDist([]byte("ProactivizeAndShareDist"))
			wg.Done()
		}(i)
	}
	wg.Wait()
	log.Printf("[ShareDist] ShareDist finished\n")

	var reducedShareAtZero = make([]bls.Fr, 2*F+1)
	var fullShareAtZero = make([]bls.Fr, F+1)
	var knownIndexes = make([]bls.Fr, 2*F+1)

	for i := 0; uint32(i) < 2*F+1; i++ {
		bls.AsFr(&knownIndexes[i], uint64(i+1))
		bls.EvalPolyAt(&reducedShareAtZero[i], pNext[i].reducedShare, &bls.ZERO)
	}

	for i := 0; uint32(i) < F+1; i++ {
		bls.EvalPolyAt(&fullShareAtZero[i], pNext[i].fullShare, &bls.ZERO)
	}

	sPolyReduced := polyring.LagrangeInterpolate(int(2*F), knownIndexes, reducedShareAtZero)
	sReducedRecovered := sPolyReduced[0]
	log.Println("[Proactivize] Recovered secret from new reducedShares:", sReducedRecovered.String())

	sPolyFull := polyring.LagrangeInterpolate(int(F), knownIndexes, fullShareAtZero)
	// sPolyFull.Print("F(x)")
	sFullRecovered := sPolyFull[0]
	log.Println("[ShareDist] Recovered secret from new fullShares:", sFullRecovered.String())

}
