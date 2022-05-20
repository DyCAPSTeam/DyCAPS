package party

import (
	"github.com/Nik-U/pbc"
	"github.com/ncw/gmp"
	"sync"
	"testing"
)

func TestShareReduce(t *testing.T) {

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886"}
	ipList_next := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList_next := []string{"8887", "8888", "8889", "8890", "8891", "8892", "8893"}
	N := uint32(7)
	F := uint32(2)
	sk, pk := SigKeyGen(N+1, 2*F+2) // wrong usage, but it doesn't matter here
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
	client.HonestParty = NewHonestParty(N, F, 0x7fffffff, ipList, portList, ipList_next, portList_next, pk, sk[2*F+1], pi_init, witness_init, witness_init_indexes)
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

}
