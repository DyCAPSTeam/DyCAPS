package party

import (
	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/Nik-U/pbc"
	"github.com/ncw/gmp"
	"math/rand"
	"sync"
	"testing"
	"time"
)

func TestCompleteProcess(t *testing.T) {
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	ipList_next := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList_next := []string{"8890", "8891", "8892", "8893", "8894", "8895", "8896", "8897", "8898", "8899"}
	N := uint32(10)
	F := uint32(3)
	sk, pk := SigKeyGen(N, 2*F+1)
	sk_new, pk_new := SigKeyGen(N, 2*F+1)
	KZG.SetupFix(int(2 * F))
	pi_init := new(Pi)
	pi_init.Init(F)
	witness_init := make([]*pbc.Element, 2*F+1)
	witness_init_indexes := make([]*gmp.Int, 2*F+1)
	for i := 0; uint32(i) < 2*F+1; i++ {
		witness_init[i] = KZG.NewG1()
		witness_init_indexes[i] = gmp.NewInt(0)
	}
	var p []*HonestParty = make([]*HonestParty, N)
	var p_next []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(N, F, i, ipList, portList, ipList_next, portList_next, pk, sk[i], pi_init, witness_init, witness_init_indexes)
		p_next[i] = NewHonestParty(N, F, i, ipList_next, portList_next, nil, nil, pk_new, sk_new[i], pi_init, witness_init, witness_init_indexes)
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
		p_next[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
		p[i].InitSendtoNextChannel()
		p_next[i].InitSendChannel()
	}

	var client Client
	client.s = new(gmp.Int)
	client.s.SetInt64(int64(111111111111111))
	client.HonestParty = NewHonestParty(N, F, 0x7fffffff, ipList, portList, ipList_next, portList_next, pk, nil, pi_init, witness_init, witness_init_indexes)
	client.InitSendChannel()

	client.Share([]byte("vssshare"))

	var wg sync.WaitGroup

	wg.Add(int(3*F + 1))
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			p[i].InitShareReceiver([]byte("vssshare"))
			wg.Done()
		}(i)
	}
	wg.Wait()

	wg.Add(int(3*F + 1))
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			p_next[i].ShareReduceReceiver([]byte("shareReduce"))
			wg.Done()
		}(i)
	}
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			p[i].ShareReduceSend([]byte("shareReduce"))
		}(i)
	}
	wg.Wait()

	wg.Add(int(3*F + 1))
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			p_next[i].ProactivizeAndShareDist([]byte("ProactivizeAndShareReduce"))
			wg.Done()
		}(i)
	}
	wg.Wait()
	/*
		var fullShare_at_zero = make([]*gmp.Int, F+1)
		var knownIndexes = make([]*gmp.Int, F+1)

		for i := 0; uint32(i) < F+1; i++ {
			fullShare_at_zero[i] = gmp.NewInt(0)
			knownIndexes[i] = gmp.NewInt(int64(i + 1))
			p_next[i].fullShare.EvalMod(gmp.NewInt(0), ecparam.PBC256.Ngmp, fullShare_at_zero[i])
		}
		s_poly, _ := interpolation.LagrangeInterpolate(int(F), knownIndexes, fullShare_at_zero, ecparam.PBC256.Ngmp)
		s_poly.Print()
		s_recovered := gmp.NewInt(0)
		s_poly.EvalMod(gmp.NewInt(0), ecparam.PBC256.Ngmp, s_recovered)
		fmt.Println("finally recover secret:", s_recovered)
	*/
	//s_recovered != s_init,555
	/*
		var halfShare_at_zero = make([]*gmp.Int, 2*F+1)
		var knownIndexes = make([]*gmp.Int, 2*F+1)

		for i := 0; uint32(i) < 2*F+1; i++ {
			halfShare_at_zero[i] = gmp.NewInt(0)
			knownIndexes[i] = gmp.NewInt(int64(i + 1))
			p_next[i].HalfShare.EvalMod(gmp.NewInt(0), ecparam.PBC256.Ngmp, halfShare_at_zero[i])
		}
		s_poly, _ := interpolation.LagrangeInterpolate(int(2*F), knownIndexes, halfShare_at_zero, ecparam.PBC256.Ngmp)
		s_poly.Print()
		s_recovered := gmp.NewInt(0)
		s_poly.EvalMod(gmp.NewInt(0), ecparam.PBC256.Ngmp, s_recovered)
		fmt.Println("finally recover secret:", s_recovered)
	*/
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
	pi_init := new(Pi)
	pi_init.Init(F)
	witness_init := make([]*pbc.Element, 2*F+1)
	witness_init_indexes := make([]*gmp.Int, 2*F+1)
	for i := 0; uint32(i) < 2*F+1; i++ {
		witness_init[i] = KZG.NewG1()
		witness_init_indexes[i] = gmp.NewInt(0)
	}
	var p []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(N, F, i, ipList, portList, ipList_next, portList_next, pk, sk[i], pi_init, witness_init, witness_init_indexes)
	}
	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
	}

	for i := uint32(0); i < N; i++ {
		var rnd = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
		newPoly, _ := polyring.NewRand(int(F), rnd, ecparam.PBC256.Ngmp)
		p[i].HalfShare.ResetTo(newPoly)
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
}
