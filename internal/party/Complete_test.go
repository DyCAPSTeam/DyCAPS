package party

import (
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/ncw/gmp"
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
		p[i].InitSendtoNextChannel()
		p_next[i].InitSendChannel()
	}

	var client Client
	client.s = new(gmp.Int)
	client.s.SetInt64(int64(111111111111111))
	client.HonestParty = NewHonestParty(N, F, 0x7fffffff, ipList, portList, ipList_next, portList_next, pk, nil)
	client.InitSendChannel()

	client.Share([]byte("vssshare"))

	var wg sync.WaitGroup

	wg.Add(int(N))
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			p[i].VSSShareReceive([]byte("vssshare"))
			wg.Done()
		}(i)
	}
	wg.Wait()

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

	wg.Add(int(N))
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			p_next[i].ProactivizeAndShareDist([]byte("ProactivizeAndShareReduce"))
			wg.Done()
		}(i)
	}
	wg.Wait()
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
}
