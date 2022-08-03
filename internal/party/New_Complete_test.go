package party

import (
	"log"
	"sync"
	"testing"

	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/interpolation"
	"github.com/ncw/gmp"
)

func TestCompleteProcess_New(t *testing.T) {
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"18880", "18881", "18882", "18883", "18884", "18885", "18886", "18887", "18888", "18889"}
	ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portListNext := []string{"18890", "18891", "18892", "18893", "18894", "18895", "18896", "18897", "18898", "18899"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := SigKeyGen(N, 2*F+1)
	skNew, pkNew := SigKeyGen(N, 2*F+1)
	// KZG.SetupFix(int(2 * F))

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
	client.s = new(gmp.Int)
	client.s.SetInt64(int64(111111111111111))
	client.HonestParty = NewHonestParty(0, N, F, 0x7fffffff, ipList, portList, ipListNext, portListNext, pk, nil)
	err := client.InitSendChannel()
	if err != nil {
		log.Printf("[VSS] Client InitSendChannel err: %v\n", err)
	}

	var wg sync.WaitGroup

	wg.Add(int(N))

	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			pNext[i].PrepareReceive([]byte("shareReduce"))
			pNext[i].ShareReduceReceive([]byte("shareReduce"))
			pNext[i].ProactivizeAndShareDist([]byte("ProactivizeAndShareReduce"))
			wg.Done()
		}(i)
	}

	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			p[i].VSSShareReceive([]byte("vssshare"))
			p[i].PrepareSend([]byte("shareReduce"))
			p[i].ShareReduceSend([]byte("shareReduce"))
		}(i)
	}

	client.Share([]byte("vssshare"))

	wg.Wait()

	var reducedShareAtZero = make([]*gmp.Int, 2*F+1)
	var fullShareAtZero = make([]*gmp.Int, F+1)
	var knownIndexes = make([]*gmp.Int, 2*F+1)

	for i := 0; uint32(i) < 2*F+1; i++ {
		reducedShareAtZero[i] = gmp.NewInt(0)
		knownIndexes[i] = gmp.NewInt(int64(i + 1))
		pNext[i].reducedShare.EvalMod(gmp.NewInt(0), ecparam.PBC256.Ngmp, reducedShareAtZero[i])
	}

	for i := 0; uint32(i) < F+1; i++ {
		fullShareAtZero[i] = gmp.NewInt(0)
		pNext[i].fullShare.EvalMod(gmp.NewInt(0), ecparam.PBC256.Ngmp, fullShareAtZero[i])
	}

	sPolyReduced, _ := interpolation.LagrangeInterpolate(int(2*F), knownIndexes, reducedShareAtZero, ecparam.PBC256.Ngmp)
	sReducedRecovered, _ := sPolyReduced.GetCoefficient(0)
	log.Println("[Proactivize] Recovered secret from new reducedShares:", sReducedRecovered.String())

	sPolyFull, _ := interpolation.LagrangeInterpolate(int(F), knownIndexes, fullShareAtZero, ecparam.PBC256.Ngmp)
	// sPolyFull.Print("F(x)")
	sFullRecovered, _ := sPolyFull.GetCoefficient(0)
	log.Println("[ShareDist] Recovered secret from new fullShares:", sFullRecovered.String())
}
