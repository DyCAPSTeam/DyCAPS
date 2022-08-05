package party

import (
	"log"
	"sync"
	"testing"

	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/interpolation"
	"github.com/ncw/gmp"
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

	//transfer the Proofs, equivalent to Prepare phase
	log.Printf("[Prepare] Prepare starts, transfering proofs to the new committee\n")
	for i := uint32(0); i < N; i++ {
		pNext[i].Proof.Gs.Set(p[i].Proof.Gs)
		for j := uint32(0); j < 2*F+2; j++ {
			pNext[i].Proof.PiContents[j].gFj.Set(p[i].Proof.PiContents[j].gFj)
			pNext[i].Proof.PiContents[j].CBj.Set(p[i].Proof.PiContents[j].CBj)
			pNext[i].Proof.PiContents[j].CZj.Set(p[i].Proof.PiContents[j].CZj)
			pNext[i].Proof.PiContents[j].WZ0.Set(p[i].Proof.PiContents[j].WZ0)
			pNext[i].Proof.PiContents[j].j = p[i].Proof.PiContents[j].j
		}
	}
	log.Printf("[Prepare] Prepare finished\n")

	log.Printf("[ShstreReduce] ShareReduce starting...\n")

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
