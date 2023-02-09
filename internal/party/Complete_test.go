package party

import (
	"fmt"
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

func TestProactivizeAndShareDist(t *testing.T) {
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8080", "8081", "8082", "8083", "8084", "8085", "8086", "8087", "8088", "8089", "8090", "8091", "8092", "8093", "8094", "8095", "8096", "8097", "8098", "8099", "8100", "8101", "8102", "8103", "8104", "8105", "8106", "8107", "8108", "8109", "8110", "8111", "8112", "8113", "8114", "8115", "8116", "8117", "8118", "8119", "8120", "8121", "8122", "8123", "8124", "8125", "8126", "8127", "8128", "8129", "8130", "8131", "8132", "8133", "8134", "8135", "8136", "8137", "8138", "8139", "8140", "8141", "8142", "8143"}
	ipList_next := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList_next := []string{"8144", "8145", "8146", "8147", "8148", "8149", "8150", "8151", "8152", "8153", "8154", "8155", "8156", "8157", "8158", "8159", "8160", "8161", "8162", "8163", "8164", "8165", "8166", "8167", "8168", "8169", "8170", "8171", "8172", "8173", "8174", "8175", "8176", "8177", "8178", "8179", "8180", "8181", "8182", "8183", "8184", "8185", "8186", "8187", "8188", "8189", "8190", "8191", "8192", "8193", "8194", "8195", "8196", "8197", "8198", "8199", "8200", "8201", "8202", "8203", "8204", "8205", "8206", "8207"}

	N := uint32(7)
	F := uint32(2)
	sk, pk := SigKeyGen(N, 2*F+1)

	var p []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(0, N, F, i, ipList, portList, ipList_next, portList_next, pk, sk[i])
	}
	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
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

	fmt.Println("total:", p[0].ProactivizeEnd.Sub(p[0].ProactivizeStart).Nanoseconds())
	fmt.Println("Commit:", p[0].CommitEnd.Sub(p[0].CommitStart).Nanoseconds())
	fmt.Println("Verify:", p[0].VerifyEnd.Sub(p[0].VerifyStart).Nanoseconds())
	fmt.Println("Reshare:", p[0].ReshareEnd.Sub(p[0].ReshareStart).Nanoseconds())
	fmt.Println("Vote:", p[0].VoteEnd.Sub(p[0].VoteStart).Nanoseconds())
	fmt.Println("Recover:", p[0].RecoverEnd.Sub(p[0].RecoverStart).Nanoseconds())
	fmt.Println("MVBA:", p[0].MVBAEnd.Sub(p[0].MVBAStart).Nanoseconds())
	fmt.Println("Refresh:", p[0].RefreshEnd.Sub(p[0].RefreshStart).Nanoseconds())

}
