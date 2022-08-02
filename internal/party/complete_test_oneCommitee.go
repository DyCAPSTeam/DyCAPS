package party

import (
	"fmt"
	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/interpolation"
	"github.com/ncw/gmp"
	"sync"
	"testing"
)

func TestCompleteProcess_OneCommitee(t *testing.T) {
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"18880", "18881", "18882", "18883", "18884", "18885", "18886", "18887", "18888", "18889"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := SigKeyGen(N, 2*F+1)
	// KZG.SetupFix(int(2 * F))

	var p []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(0, N, F, i, ipList, portList, ipList, portList, pk, sk[i])
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
	}
	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
		p[i].InitSendToNextChannel()
	}

	var client Client
	client.s = new(gmp.Int)
	client.s.SetInt64(int64(111111111111111))
	client.HonestParty = NewHonestParty(0, N, F, 0x7fffffff, ipList, portList, nil, nil, pk, nil)
	err := client.InitSendChannel()
	if err != nil {
		fmt.Printf("[VSS] Client InitSendChannel err: %v\n", err)
	}

	var wg sync.WaitGroup

	wg.Add(int(N))

	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			p[i].VSSShareReceive([]byte("vssshare"))
			p[i].PrepareSend([]byte("shareReduce"))
			p[i].ShareReduceSend([]byte("shareReduce"))
			p[i].PrepareReceive([]byte("shareReduce"))
			p[i].ShareReduceReceive([]byte("shareReduce"))
			p[i].ProactivizeAndShareDist([]byte("ProactivizeAndShareReduce"))
			wg.Done()
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
		p[i].reducedShare.EvalMod(gmp.NewInt(0), ecparam.PBC256.Ngmp, reducedShareAtZero[i])
	}

	for i := 0; uint32(i) < F+1; i++ {
		fullShareAtZero[i] = gmp.NewInt(0)
		p[i].fullShare.EvalMod(gmp.NewInt(0), ecparam.PBC256.Ngmp, fullShareAtZero[i])
	}

	sPolyReduced, _ := interpolation.LagrangeInterpolate(int(2*F), knownIndexes, reducedShareAtZero, ecparam.PBC256.Ngmp)
	sReducedRecovered, _ := sPolyReduced.GetCoefficient(0)
	fmt.Println("[Proactivize] Recovered secret from new reducedShares:", sReducedRecovered.String())

	sPolyFull, _ := interpolation.LagrangeInterpolate(int(F), knownIndexes, fullShareAtZero, ecparam.PBC256.Ngmp)
	// sPolyFull.Print("F(x)")
	sFullRecovered, _ := sPolyFull.GetCoefficient(0)
	fmt.Println("[ShareDist] Recovered secret from new fullShares:", sFullRecovered.String())
}
