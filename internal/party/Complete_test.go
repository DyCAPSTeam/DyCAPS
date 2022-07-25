package party

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/interpolation"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/ncw/gmp"
)

func TestCompleteProcess(t *testing.T) {
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	ipList_next := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList_next := []string{"8890", "8891", "8892", "8893", "8894", "8895", "8896", "8897", "8898", "8899"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := SigKeyGen(N, 2*F+1)
	sk_new, pk_new := SigKeyGen(N, 2*F+1)
	KZG.SetupFix(int(2 * F))

	var p []*HonestParty = make([]*HonestParty, N)
	var p_next []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(N, F, i, ipList, portList, ipList_next, portList_next, pk, sk[i])
		p_next[i] = NewHonestParty(N, F, i, ipList_next, portList_next, nil, nil, pk_new, sk_new[i])
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
		p_next[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
		p[i].InitSendToNextChannel()
		p_next[i].InitSendChannel()
	}

	var client Client
	client.s = new(gmp.Int)
	client.s.SetInt64(int64(111111111111111))
	client.HonestParty = NewHonestParty(N, F, 0x7fffffff, ipList, portList, ipList_next, portList_next, pk, nil)
	err := client.InitSendChannel()
	if err != nil {
		fmt.Printf("[VSS] Client InitSendChannel err: %v\n", err)
	}

	client.Share([]byte("vssshare"))
	fmt.Printf("[VSS] VSSshare done\n")

	var wg sync.WaitGroup

	wg.Add(int(N))
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			fmt.Printf("[VSS] Party %v starting...\n", i)
			p[i].VSSShareReceive([]byte("vssshare"))
			wg.Done()
			// fmt.Printf("[VSS] Party %v done\n", i)
		}(i)
	}
	wg.Wait()

	fmt.Printf("[VSS] VSS finished\n")

	//transfer the Proofs, equivalent to the Prepare phase
	fmt.Printf("[Prepare] Prepare starts, transfering proofs to the new committee\n")
	for i := uint32(0); i < N; i++ {
		p_next[i].Proof.Gs.Set(p[i].Proof.Gs)
		for j := uint32(0); j < 2*F+2; j++ {
			p_next[i].Proof.PiContents[j].gFj.Set(p[i].Proof.PiContents[j].gFj)
			p_next[i].Proof.PiContents[j].CBj.Set(p[i].Proof.PiContents[j].CBj)
			p_next[i].Proof.PiContents[j].CZj.Set(p[i].Proof.PiContents[j].CZj)
			p_next[i].Proof.PiContents[j].WZ0.Set(p[i].Proof.PiContents[j].WZ0)
			p_next[i].Proof.PiContents[j].j = p[i].Proof.PiContents[j].j
		}
	}
	fmt.Printf("[Prepare] Prepare finished\n")

	fmt.Printf("[ShstreReduce] ShareReduce starting...\n")

	wg.Add(int(N))
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			p_next[i].ShareReduceReceive([]byte("shareReduce"))
			wg.Done()
		}(i)
	}

	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			p[i].ShareReduceSend([]byte("shareReduce"))
		}(i)
	}
	wg.Wait()

	fmt.Printf("[ShstreReduce] ShareReduce finished\n")
	fmt.Printf("[Proactivize] Proactivize starting\n")

	wg.Add(int(N))
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			p_next[i].ProactivizeAndShareDist([]byte("ProactivizeAndShareReduce"))
			wg.Done()
		}(i)
	}
	wg.Wait()
	fmt.Printf("[ShareDist] ShareDist finished\n")

	var reducedShareAtZero = make([]*gmp.Int, 2*F+1)
	var fullShareAtZero = make([]*gmp.Int, F+1)
	var knownIndexes = make([]*gmp.Int, 2*F+1)

	for i := 0; uint32(i) < 2*F+1; i++ {
		reducedShareAtZero[i] = gmp.NewInt(0)
		knownIndexes[i] = gmp.NewInt(int64(i + 1))
		p_next[i].reducedShare.EvalMod(gmp.NewInt(0), ecparam.PBC256.Ngmp, reducedShareAtZero[i])
	}

	for i := 0; uint32(i) < F+1; i++ {
		fullShareAtZero[i] = gmp.NewInt(0)
		p_next[i].fullShare.EvalMod(gmp.NewInt(0), ecparam.PBC256.Ngmp, fullShareAtZero[i])
	}

	sPolyReduced, _ := interpolation.LagrangeInterpolate(int(2*F), knownIndexes, reducedShareAtZero, ecparam.PBC256.Ngmp)
	sReducedRecovered, _ := sPolyReduced.GetCoefficient(0)
	fmt.Println("[Proactivize] Recovered secret from new reducedShares:", sReducedRecovered.String())

	sPolyFull, _ := interpolation.LagrangeInterpolate(int(F), knownIndexes, fullShareAtZero, ecparam.PBC256.Ngmp)
	// sPolyFull.Print("F(x)")
	sFullRecovered, _ := sPolyFull.GetCoefficient(0)
	fmt.Println("[ShareDist] Recovered secret from new fullShares:", sFullRecovered.String())
}

func TestProactivizeAndShareDist(t *testing.T) {
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886"}
	ipList_next := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList_next := []string{"8887", "8888", "8889", "8890", "8891", "8892", "8893"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := SigKeyGen(N, 2*F+1)
	KZG.SetupFix(int(2 * F))

	var p []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(N, F, i, ipList, portList, ipList_next, portList_next, pk, sk[i])
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
	}

	//FIXME: wrong use to generate reduced shares!
	for i := uint32(0); i < N; i++ {
		var rnd = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
		newPoly, _ := polyring.NewRand(int(F), rnd, ecparam.PBC256.Ngmp)
		p[i].reducedShare.ResetTo(newPoly)
	}

	var wg sync.WaitGroup
	wg.Add(int(3*F + 1))
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			p[i].ProactivizeAndShareDist([]byte("ProactivizeAndShareReduce"))
			wg.Done()
		}(i)
	}
	wg.Wait()

	var fullShareAtZero = make([]*gmp.Int, 2*F+1)
	var knownIndexes = make([]*gmp.Int, 2*F+1)

	for i := 0; uint32(i) < F+1; i++ {
		fullShareAtZero[i] = gmp.NewInt(0)
		knownIndexes[i] = gmp.NewInt(int64(i + 1))
		p[i].fullShare.EvalMod(gmp.NewInt(0), ecparam.PBC256.Ngmp, fullShareAtZero[i])
	}
	sPoly, _ := interpolation.LagrangeInterpolate(int(F), knownIndexes, fullShareAtZero, ecparam.PBC256.Ngmp)
	sPoly.Print("F(x)")
	sRecovered := gmp.NewInt(0)
	sPoly.EvalMod(gmp.NewInt(0), ecparam.PBC256.Ngmp, sRecovered)
	fmt.Println("[ShareReduce] Finally recovered secret:", sRecovered)
}
