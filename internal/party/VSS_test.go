package party

import (
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/DyCAPSTeam/DyCAPS/internal/conv"
	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"github.com/Nik-U/pbc"
	"github.com/golang/protobuf/proto"
	"github.com/ncw/gmp"
)

func TestDealer(t *testing.T) {

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	ipList_next := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList_next := []string{"8890", "8891", "8892", "8893", "8894", "8895", "8896", "8897", "8898", "8899"}
	N := uint32(10)
	F := uint32(3)
	sk, pk := SigKeyGen(N, 2*F+2) // FIXME: wrong usage, but it doesn't matter here

	KZG.SetupFix(2 * int(F))

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

	// send channels are initiated after all receive channels are initiated
	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
	}

	var client Client
	client.s = new(gmp.Int).SetInt64(int64(1111111111111112222))
	clientID := uint32(0x7fffffff)
	client.HonestParty = NewHonestParty(N, F, clientID, ipList, portList, ipList_next, portList_next, pk, sk[2*F+1], pi_init, witness_init, witness_init_indexes)
	client.InitSendChannel()

	client.Share([]byte("vssshare"))

	for i := 0; uint32(i) < N; i++ {
		m := <-p[i].GetMessage("VSSSend", []byte("vssshare"))
		var content protobuf.VSSSend
		proto.Unmarshal(m.Data, &content)
		gs := KZG.NewG1()
		gs.SetCompressedBytes(content.Pi.Gs)

		// fmt.Println("node", i+1, "receive", m.Sender, m.Id, m.Type, m.Data)
		// fmt.Println("the gs received is", gs.String())
		pi_test := new(Pi)
		pi_test.G_s = KZG.NewG1()
		pi_test.G_s.Set(gs)
		pi_test.Pi_contents = make([]Pi_Content, 2*F+2)
		for j := 0; uint32(j) <= 2*F+1; j++ {
			pi_test.Pi_contents[j].CR_j = KZG.NewG1()
			pi_test.Pi_contents[j].CZ_j = KZG.NewG1()
			pi_test.Pi_contents[j].WZ_0 = KZG.NewG1()
			pi_test.Pi_contents[j].g_Fj = KZG.NewG1()
		}

		// j starts from 1 here
		for j := 1; uint32(j) <= 2*F+1; j++ {
			pi_test.Pi_contents[j].CR_j.SetCompressedBytes(content.Pi.PiContents[j].CRJ)
			pi_test.Pi_contents[j].CZ_j.SetCompressedBytes(content.Pi.PiContents[j].CZJ)
			pi_test.Pi_contents[j].WZ_0.SetCompressedBytes(content.Pi.PiContents[j].WZ_0)
			pi_test.Pi_contents[j].g_Fj.SetCompressedBytes(content.Pi.PiContents[j].G_Fj)
			// fmt.Println("j= ", j, "; CRj= ", pi_test.Pi_contents[j].CR_j.String(), "; CZj= ", pi_test.Pi_contents[j].CZ_j.String(), "; WZj_0= ", pi_test.Pi_contents[j].WZ_0.String(), "; g_Fj= ", pi_test.Pi_contents[j].g_Fj.String())

			// verify CR_j=CZ_j*g_Fj
			tmp := KZG.NewG1()
			tmp.Set1()
			tmp.Mul(pi_test.Pi_contents[j].CZ_j, pi_test.Pi_contents[j].g_Fj)
			if !tmp.Equals(pi_test.Pi_contents[j].CR_j) {
				fmt.Println("Polynomial verification fails at j = ", j)
				os.Exit(1)
			}
		}

		//verify g^s = \prod g^{lambda[j]*F(j)} = \prod (g^F(j))^lambda[j]
		lambda := make([]*gmp.Int, 2*F+1)
		knownIndexes := make([]*gmp.Int, 2*F+1)
		for j := 0; uint32(j) < 2*F+1; j++ {
			lambda[j] = gmp.NewInt(int64(j + 1))
			knownIndexes[j] = gmp.NewInt(int64(j + 1))
		}

		polyring.GetLagrangeCoefficients(2*int(F), knownIndexes, ecparam.PBC256.Ngmp, gmp.NewInt(0), lambda)
		tmp := KZG.NewG1()
		tmp.Set1()
		for j := 1; uint32(j) <= 2*F+1; j++ {
			tmp2 := KZG.NewG1()
			tmp2.Set1()
			tmp2.PowBig(pi_test.Pi_contents[j].g_Fj, conv.GmpInt2BigInt(lambda[j-1])) // the x value of index j-1 is j
			tmp.Mul(tmp, tmp2)
		}

		if !tmp.Equals(pi_test.G_s) {
			fmt.Println("g_s != multiply(lambda_i,g_F(i)),gs = ", gs.String(), "multiply(lambda_i,g_F(i))= ", tmp.String())
			os.Exit(1)
		}

		//KZG verification
		for j := 1; uint32(j) <= 2*F+1; j++ {
			Rji := gmp.NewInt(0)
			WRji := KZG.NewG1()
			Rji.SetBytes(content.RjiList[j])
			WRji.SetCompressedBytes(content.WRjiList[j])
			if !KZG.VerifyEval(pi_test.Pi_contents[j].CR_j, gmp.NewInt(int64((i + 1))), Rji, WRji) {
				fmt.Println("KZG verification fails at j = ", j)
				os.Exit(1)
			}
		}
	}
}

func TestVSS(t *testing.T) {
	//TODO: this test only passes when F=1
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	ipList_next := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList_next := []string{"8890", "8891", "8892", "8893", "8894", "8895", "8896", "8897", "8898", "8899"}
	N := uint32(7)
	F := uint32(2)
	sk, pk := SigKeyGen(N, 2*F+2) // FIXME: wrong usage, but it doesn't matter here

	KZG.SetupFix(2 * int(F))

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

	var client Client
	client.s = new(gmp.Int).SetBytes([]byte("1111111111111111111111111"))
	clientID := uint32(0x7fffffff)
	client.HonestParty = NewHonestParty(N, F, clientID, ipList, portList, ipList_next, portList_next, pk, sk[2*F+1], pi_init, witness_init, witness_init_indexes)
	client.InitSendChannel()

	client.Share([]byte("VSSshare"))

	var wg sync.WaitGroup

	wg.Add(int(N))
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			p[i].VSSshareReceiver([]byte("VSSshare"))
			wg.Done()
		}(i)
	}

	wg.Wait()

	fmt.Println("VSS Finish")
}
